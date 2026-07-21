#!/usr/bin/env python3
"""Multi-source log correlation engine for Module 8.

Reads endpoint (Windows Security + Sysmon, as Windows Event XML) and cloud
(Azure AD sign-in + audit, as JSON) logs from a logs/ directory, normalizes
every record to a common schema, and correlates events that share an actor
(username) or IP address within a sliding time window.

The XML field-extraction idiom (System / EventData Name->value via ElementTree)
is modeled on ../../sysmon-parser/parser.py, generalized here beyond Sysmon
EventID 1 to any Security/Sysmon EventID, plus a JSON reader for the Azure AD
sources.

Stdlib only. Usage:
    python correlate.py --logs-dir logs/ [--user X] [--ip Y] [--window 30m]
                        [--format timeline|json|md|stats]
"""

import argparse
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

# Emit UTF-8 regardless of the console codepage (Windows consoles default to
# cp1252, which can't encode the arrow/em-dash used in the md/timeline output).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# DCSync control-access GUIDs (DS-Replication-Get-Changes / -All), used to flag
# a 4662 object-access event as a DCSync attempt.
DCSYNC_GUIDS = ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #

def parse_ts(raw):
    """Parse a timestamp from any source into an aware UTC datetime.

    Handles Windows Event XML SystemTime ('2026-07-19T14:12:03.4471120Z', up to
    7 fractional digits), AAD ISO8601 ('2026-07-19T14:02:37Z'), and Sysmon
    UtcTime ('2026-07-19 14:18:22.655', space-separated, no zone -> assume UTC).
    """
    if not raw:
        return None
    s = raw.strip().replace(" ", "T", 1)
    # Truncate fractional seconds to 6 digits (datetime max precision).
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def canon_actor(raw):
    """Canonicalize a username to (sam, domain).

    'INSECUREBANK\\j.rivera' -> ('j.rivera', 'INSECUREBANK')
    'j.rivera@insecurebank.local' -> ('j.rivera', 'insecurebank.local')
    'j.rivera' -> ('j.rivera', None)
    Returns (None, None) for empty input. The sam part is lowercased so the
    down-level and UPN forms of the same identity collapse to one key.
    """
    if not raw:
        return None, None
    raw = raw.strip()
    if "\\" in raw:
        dom, _, user = raw.partition("\\")
        return user.lower() or None, dom or None
    if "@" in raw:
        user, _, dom = raw.partition("@")
        return user.lower() or None, dom or None
    return raw.lower() or None, None


def parse_event_xml(path):
    """Parse a Windows Event XML file into raw dicts (one per <Event>).

    Generalizes parser.py:parse_file — keeps every EventData Name->value pair
    plus the System fields we correlate on, for any EventID (not just Sysmon 1).
    """
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag == f"{{{NS['e']}}}Event":
        elems = [root]
    else:
        elems = root.findall("e:Event", NS)

    records = []
    for ev in elems:
        system = ev.find("e:System", NS)
        if system is None:
            continue
        provider = system.find("e:Provider", NS)
        time_created = system.find("e:TimeCreated", NS)
        rec = {
            "EventID": system.findtext("e:EventID", namespaces=NS),
            "Computer": system.findtext("e:Computer", namespaces=NS),
            "Channel": system.findtext("e:Channel", namespaces=NS),
            "Provider": provider.get("Name") if provider is not None else None,
            "SystemTime": time_created.get("SystemTime") if time_created is not None else None,
        }
        data = ev.find("e:EventData", NS)
        if data is not None:
            for d in data.findall("e:Data", NS):
                name = d.get("Name")
                if name:
                    rec[name] = d.text or ""
        records.append(rec)
    return records


def detect_xml_source(rec):
    """Security vs Sysmon from a parsed XML record."""
    provider = (rec.get("Provider") or "")
    channel = (rec.get("Channel") or "")
    if "Sysmon" in provider or "Sysmon" in channel:
        return "sysmon"
    return "security"


# --------------------------------------------------------------------------- #
# Normalization: raw record -> common schema
# --------------------------------------------------------------------------- #
# Common event schema:
#   {ts, ts_raw, source, event_type, actor, actor_domain, host,
#    src_ip, dest_ip, summary, raw}

def _norm(ts_raw, source, event_type, actor_raw, host, src_ip, dest_ip, summary, raw):
    sam, dom = canon_actor(actor_raw)
    return {
        "ts": parse_ts(ts_raw),
        "ts_raw": ts_raw,
        "source": source,
        "event_type": event_type,
        "actor": sam,
        "actor_domain": dom,
        "host": host,
        "src_ip": src_ip or None,
        "dest_ip": dest_ip or None,
        "summary": summary,
        "raw": raw,
    }


def normalize_security(rec):
    eid = rec.get("EventID")
    host = rec.get("Computer")
    if eid == "4624":
        lt = rec.get("LogonType", "?")
        return _norm(
            rec.get("SystemTime"), "security", f"Security 4624 Logon (type {lt})",
            rec.get("TargetUserName"), host, rec.get("IpAddress"), None,
            f"Logon type {lt} for {rec.get('TargetDomainName')}\\{rec.get('TargetUserName')} "
            f"from {rec.get('IpAddress')}", rec)
    if eid == "4662":
        props = rec.get("Properties", "")
        is_dcsync = any(g in props for g in DCSYNC_GUIDS)
        label = "Security 4662 Object Access (DCSync rights)" if is_dcsync else "Security 4662 Object Access"
        return _norm(
            rec.get("SystemTime"), "security", label,
            rec.get("SubjectUserName"), host, None, None,
            f"{rec.get('SubjectDomainName')}\\{rec.get('SubjectUserName')} accessed directory object; "
            f"Properties={props}", rec)
    # Generic Security event: prefer Subject, fall back to Target.
    actor = rec.get("SubjectUserName") or rec.get("TargetUserName")
    return _norm(rec.get("SystemTime"), "security", f"Security {eid}",
                 actor, host, rec.get("IpAddress"), None,
                 f"Security event {eid} on {host}", rec)


def normalize_sysmon(rec):
    eid = rec.get("EventID")
    host = rec.get("Computer")
    ts = rec.get("SystemTime")  # System/TimeCreated is present on every event
    user = rec.get("User")
    if eid == "1":
        return _norm(ts, "sysmon", "Sysmon 1 Process Create", user, host, None, None,
                     f"{rec.get('Image')}  ::  {rec.get('CommandLine')}", rec)
    if eid == "3":
        return _norm(ts, "sysmon", "Sysmon 3 Network Connect", user, host,
                     rec.get("SourceIp"), rec.get("DestinationIp"),
                     f"{rec.get('Image')} -> {rec.get('DestinationIp')}:{rec.get('DestinationPort')} "
                     f"({rec.get('Protocol')})", rec)
    if eid == "10":
        target = rec.get("TargetImage", "")
        tag = " (LSASS access)" if target.lower().endswith("lsass.exe") else ""
        return _norm(ts, "sysmon", f"Sysmon 10 Process Access{tag}", user, host, None, None,
                     f"{rec.get('SourceImage')} -> {target} GrantedAccess={rec.get('GrantedAccess')}", rec)
    return _norm(ts, "sysmon", f"Sysmon {eid}", user, host, None, None,
                 f"Sysmon event {eid} on {host}", rec)


def normalize_aad_signin(rec):
    loc = rec.get("location") or {}
    where = ", ".join(v for v in (loc.get("city"), loc.get("countryOrRegion")) if v)
    risk = rec.get("riskLevelDuringSignIn", "none")
    detail = rec.get("riskDetail", "none")
    risk_tag = f" [risk={risk}, {detail}]" if risk and risk != "none" else ""
    status = (rec.get("status") or {}).get("errorCode", "?")
    return _norm(rec.get("createdDateTime"), "aad-signin", f"AAD Sign-in{risk_tag}",
                 rec.get("userPrincipalName"), None, rec.get("ipAddress"), None,
                 f"{rec.get('appDisplayName')} from {rec.get('ipAddress')} ({where}); "
                 f"errorCode={status}", rec)


def normalize_aad_audit(rec):
    initiated = ((rec.get("initiatedBy") or {}).get("user")) or {}
    targets = rec.get("targetResources") or []
    tnames = ", ".join(t.get("displayName") or t.get("userPrincipalName") or t.get("type", "")
                       for t in targets)
    return _norm(rec.get("activityDateTime"), "aad-audit",
                 f"AAD Audit: {rec.get('activityDisplayName')}",
                 initiated.get("userPrincipalName"), None, initiated.get("ipAddress"), None,
                 f"{rec.get('activityDisplayName')} ({rec.get('result')}) -> {tnames}", rec)


# --------------------------------------------------------------------------- #
# Load + normalize a logs directory
# --------------------------------------------------------------------------- #

def detect_json_source(records, path):
    fname = os.path.basename(path).lower()
    first = records[0] if records else {}
    if "audit" in fname or "activityDisplayName" in first or "initiatedBy" in first:
        return "aad-audit"
    if "signin" in fname or "sign-in" in fname or "userPrincipalName" in first:
        return "aad-signin"
    return None


def load_events(logs_dir):
    """Walk logs_dir, parse every .xml/.json file, return normalized events."""
    events = []
    for path in sorted(glob.glob(os.path.join(logs_dir, "**", "*"), recursive=True)):
        if os.path.isdir(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext == ".xml":
            for rec in parse_event_xml(path):
                src = detect_xml_source(rec)
                events.append(normalize_security(rec) if src == "security"
                              else normalize_sysmon(rec))
        elif ext == ".json":
            with open(path, encoding="utf-8") as fh:
                records = json.load(fh)
            if not isinstance(records, list):
                records = [records]
            src = detect_json_source(records, path)
            if src == "aad-signin":
                events.extend(normalize_aad_signin(r) for r in records)
            elif src == "aad-audit":
                events.extend(normalize_aad_audit(r) for r in records)
    # Chronological order; events with an unparseable ts sort last.
    events.sort(key=lambda e: (e["ts"] is None, e["ts"] or datetime.max.replace(tzinfo=timezone.utc)))
    return events


# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #

def _cluster(indexed_events, window):
    """Sliding-window cluster a list of (idx, event) sorted by ts.

    A new event joins the current cluster if it is within `window` of the
    previous event in that cluster; otherwise a new cluster starts.
    """
    clusters = []
    current = []
    prev_ts = None
    for idx, ev in indexed_events:
        if ev["ts"] is None:
            continue
        if prev_ts is not None and ev["ts"] - prev_ts > window:
            clusters.append(current)
            current = []
        current.append((idx, ev))
        prev_ts = ev["ts"]
    if current:
        clusters.append(current)
    return clusters


def correlate(events, window):
    """Find cross-source links keyed on actor and on IP.

    A link is a sliding-window cluster of events sharing one pivot value that
    spans >=2 distinct sources. Machine accounts (sam ending '$') are excluded
    as actor pivots to avoid host-account noise.
    """
    links = []

    # Actor pivots
    by_actor = {}
    for idx, ev in enumerate(events):
        actor = ev["actor"]
        if not actor or actor.endswith("$"):
            continue
        by_actor.setdefault(actor, []).append((idx, ev))
    for actor, items in by_actor.items():
        for cluster in _cluster(items, window):
            sources = sorted({ev["source"] for _, ev in cluster})
            if len(sources) >= 2:
                links.append(_make_link("actor", actor, cluster, sources))

    # IP pivots (union of src_ip and dest_ip)
    by_ip = {}
    for idx, ev in enumerate(events):
        for ip in (ev["src_ip"], ev["dest_ip"]):
            if ip:
                by_ip.setdefault(ip, []).append((idx, ev))
    for ip, items in by_ip.items():
        # An event can appear twice (src==dest); dedupe by index.
        seen, deduped = set(), []
        for idx, ev in items:
            if idx not in seen:
                seen.add(idx)
                deduped.append((idx, ev))
        deduped.sort(key=lambda p: p[1]["ts"] or datetime.max.replace(tzinfo=timezone.utc))
        for cluster in _cluster(deduped, window):
            sources = sorted({ev["source"] for _, ev in cluster})
            if len(sources) >= 2:
                links.append(_make_link("ip", ip, cluster, sources))

    # Strongest first: more sources, then more events, then earlier.
    links.sort(key=lambda l: (-len(l["sources"]), -len(l["event_indexes"]), l["start"] or ""))
    return links


def _make_link(pivot_type, pivot_value, cluster, sources):
    tss = [ev["ts"] for _, ev in cluster if ev["ts"]]
    return {
        "pivot_type": pivot_type,
        "pivot_value": pivot_value,
        "sources": sources,
        "event_indexes": [idx for idx, _ in cluster],
        "start": min(tss).isoformat() if tss else None,
        "end": max(tss).isoformat() if tss else None,
    }


def compute_stats(events):
    by_source = {}
    for e in events:
        by_source[e["source"]] = by_source.get(e["source"], 0) + 1
    actors = sorted({e["actor"] for e in events if e["actor"] and not e["actor"].endswith("$")})
    ips = sorted({ip for e in events for ip in (e["src_ip"], e["dest_ip"]) if ip})
    return {
        "total_events": len(events),
        "events_by_source": by_source,
        "distinct_actors": actors,
        "distinct_ips": ips,
    }


# --------------------------------------------------------------------------- #
# Filtering + output
# --------------------------------------------------------------------------- #

def apply_filters(events, user, ip):
    if user:
        sam, _ = canon_actor(user)
        events = [e for e in events if e["actor"] == sam]
    if ip:
        events = [e for e in events if ip in (e["src_ip"], e["dest_ip"])]
    return events


def _ts_str(ev):
    return ev["ts"].strftime("%Y-%m-%d %H:%M:%S") if ev["ts"] else (ev["ts_raw"] or "?")


def format_timeline(events, links):
    lines = ["# Unified timeline (UTC)"]
    for i, ev in enumerate(events):
        actor = ev["actor"] or "-"
        host = ev["host"] or "-"
        lines.append(f"[{i:>2}] {_ts_str(ev)}  {ev['source']:<10}  {ev['event_type']}")
        lines.append(f"       actor={actor}  host={host}  "
                     f"src_ip={ev['src_ip'] or '-'}  dest_ip={ev['dest_ip'] or '-'}")
        lines.append(f"       {ev['summary']}")
    lines.append("")
    lines.append("# Cross-source correlations")
    if not links:
        lines.append("(none)")
    for l in links:
        lines.append(f"- {l['pivot_type']}={l['pivot_value']}  sources={','.join(l['sources'])}  "
                     f"events={l['event_indexes']}  {l['start']} -> {l['end']}")
    return "\n".join(lines)


def format_md(events, links):
    out = ["## Correlation Timeline (UTC)", "",
           "| # | Time | Source | Event | Actor | Host | IP |",
           "|---|---|---|---|---|---|---|"]
    for i, ev in enumerate(events):
        ip = ev["dest_ip"] or ev["src_ip"] or "—"
        out.append(f"| {i} | {_ts_str(ev)} | {ev['source']} | {ev['event_type']} | "
                   f"{ev['actor'] or '—'} | {ev['host'] or '—'} | {ip} |")
    out += ["", "## Cross-Source Correlations", ""]
    if not links:
        out.append("_No cross-source correlations found._")
    for l in links:
        out.append(f"- **{l['pivot_type']} = `{l['pivot_value']}`** links "
                   f"{len(l['sources'])} sources ({', '.join(l['sources'])}) across "
                   f"events {l['event_indexes']} — {l['start']} → {l['end']}")
    return "\n".join(out)


def to_jsonable(events, links, stats):
    ev_out = []
    for e in events:
        d = dict(e)
        d["ts"] = e["ts"].isoformat() if e["ts"] else None
        d.pop("raw", None)  # keep JSON compact; raw is available via the source files
        ev_out.append(d)
    return {"events": ev_out, "correlations": links, "stats": stats}


def parse_window(s):
    """'30m' / '2h' / '90s' / '45' (minutes) -> timedelta."""
    s = s.strip().lower()
    m = re.fullmatch(r"(\d+)\s*([smh]?)", s)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid --window: {s!r} (use e.g. 30m, 2h, 90s)")
    n, unit = int(m.group(1)), m.group(2) or "m"
    return timedelta(seconds=n if unit == "s" else n * 60 if unit == "m" else n * 3600)


def main():
    ap = argparse.ArgumentParser(description="Multi-source endpoint/cloud log correlation.")
    ap.add_argument("--logs-dir", default="logs", help="Directory of logs (default: logs/)")
    ap.add_argument("--user", help="Filter to one user (any form: sam, DOMAIN\\user, or UPN)")
    ap.add_argument("--ip", help="Filter to events involving this IP")
    ap.add_argument("--window", type=parse_window, default=parse_window("30m"),
                    help="Correlation time window (default 30m; e.g. 90s, 2h)")
    ap.add_argument("--format", choices=["timeline", "json", "md", "stats"], default="timeline")
    args = ap.parse_args()

    if not os.path.isdir(args.logs_dir):
        ap.error(f"logs dir not found: {args.logs_dir}")

    events = load_events(args.logs_dir)
    events = apply_filters(events, args.user, args.ip)
    links = correlate(events, args.window)
    stats = compute_stats(events)

    if args.format == "stats":
        print(json.dumps(stats, indent=2))
    elif args.format == "json":
        print(json.dumps(to_jsonable(events, links, stats), indent=2))
    elif args.format == "md":
        print(format_md(events, links))
    else:
        print(format_timeline(events, links))


if __name__ == "__main__":
    main()
