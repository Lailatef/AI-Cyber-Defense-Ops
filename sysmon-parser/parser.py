#!/usr/bin/env python3
"""Parse Sysmon Event ID 1 (Process Creation) XML into JSON."""

import argparse
import csv
import io
import json
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

DATA_FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]

FIELD_ORDER = ["EventID"] + DATA_FIELDS + ["Computer"]


def parse_event(event_elem):
    system = event_elem.find("e:System", NS)
    event_id = system.findtext("e:EventID", namespaces=NS)
    if event_id != "1":
        return None

    record = {"EventID": int(event_id)}

    event_data = event_elem.find("e:EventData", NS)
    data_by_name = {
        data.get("Name"): (data.text or "")
        for data in event_data.findall("e:Data", NS)
    }
    for field in DATA_FIELDS:
        record[field] = data_by_name.get(field)

    record["Computer"] = system.findtext("e:Computer", namespaces=NS)

    return record


def parse_file(path):
    tree = ET.parse(path)
    root = tree.getroot()

    if root.tag == f"{{{NS['e']}}}Event":
        event_elems = [root]
    else:
        event_elems = root.findall("e:Event", NS)

    records = [r for r in (parse_event(e) for e in event_elems) if r is not None]
    return records


def matches_filters(record, args):
    if args.image and args.image.lower() not in (record["Image"] or "").lower():
        return False
    if args.user and args.user.lower() != (record["User"] or "").lower():
        return False
    if args.integrity_level and args.integrity_level != record["IntegrityLevel"]:
        return False
    if args.command_line and args.command_line.lower() not in (record["CommandLine"] or "").lower():
        return False
    return True


def format_json(records):
    if len(records) == 1:
        return json.dumps(records[0], indent=2)
    return json.dumps(records, indent=2)


def format_jsonl(records):
    return "\n".join(json.dumps(r) for r in records)


def format_csv(records):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELD_ORDER, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return buf.getvalue().rstrip("\n")


# This stats feature is for quick triage to understand what's in a file before deep analysis
def compute_stats(records):
    integrity_counts = {}
    for r in records:
        level = r["IntegrityLevel"] or "Unknown"
        integrity_counts[level] = integrity_counts.get(level, 0) + 1

    return {
        "total_events": len(records),
        "unique_processes": len({r["Image"] for r in records if r["Image"]}),
        "unique_users": len({r["User"] for r in records if r["User"]}),
        "events_by_integrity_level": integrity_counts,
    }


def main():
    parser = argparse.ArgumentParser(description="Parse Sysmon Event ID 1 (Process Creation) XML into JSON.")
    parser.add_argument("path", help="Path to Sysmon XML log file")
    parser.add_argument("--image", help="Filter by Image (substring match, case-insensitive)")
    parser.add_argument("--user", help="Filter by User (exact match, case-insensitive)")
    parser.add_argument(
        "--integrity-level",
        choices=["High", "Medium", "Low", "System"],
        help="Filter by IntegrityLevel (exact match)",
    )
    parser.add_argument("--command-line", help="Filter by CommandLine (substring match, case-insensitive)")
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="Output format: json (default, array or single object), jsonl (one JSON object per line), csv (with headers)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Output aggregate statistics (total events, unique processes/users, counts by IntegrityLevel) instead of events",
    )
    args = parser.parse_args()

    records = parse_file(args.path)
    records = [r for r in records if matches_filters(r, args)]

    if args.stats:
        print(json.dumps(compute_stats(records), indent=2))
        return

    if args.format == "jsonl":
        print(format_jsonl(records))
    elif args.format == "csv":
        print(format_csv(records))
    else:
        print(format_json(records))


if __name__ == "__main__":
    main()
