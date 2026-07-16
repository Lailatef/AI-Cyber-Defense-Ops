"""MCP server that wraps Hayabusa for EVTX analysis."""

import json
import os
import re
import subprocess
import tempfile
import uuid
from datetime import date
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")

HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
RULES_DIR = HAYABUSA_DIR / "rules"
SCAN_TIMEOUT_SECONDS = 600

# Curated detection knowledge base — distinct from RULES_DIR above (which
# holds the full upstream Hayabusa/Sigma rule set used by get_hayabusa_rules).
# These are our own hand-authored rules with ATT&CK technique mappings.
CURATED_RULES_DIR = Path(__file__).parent / "rules"
MAPPINGS_DIR = Path(__file__).parent / "mappings"
ATTACK_TECHNIQUES_PATH = MAPPINGS_DIR / "attack_techniques.json"

# Incident response playbooks — hand-authored YAML runbooks keyed to the
# same ATT&CK techniques and curated rule alert names as rules/, so a
# scan_evtx finding or a curated rule can be routed to a response procedure.
PLAYBOOKS_DIR = Path(__file__).parent / "playbooks"

# Environment-specific knowledge (hosts, services, behavior baselines) —
# one hand-authored YAML file per topic, referenced by name from rules/
# and playbooks/ notes (e.g. "see environment/baselines.yml").
ENVIRONMENT_DIR = Path(__file__).parent / "environment"

# Past investigation case notes — one hand-authored YAML file per case,
# filename stem == case_id (e.g. investigations/INV-2026-001.yml).
INVESTIGATIONS_DIR = Path(__file__).parent / "investigations"

SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
SEVERITY_RANK = {level: rank for rank, level in enumerate(SEVERITY_LEVELS)}
# Hayabusa's JSON output abbreviates some Level values (e.g. "info" instead
# of "informational") rather than using the same names as its CLI flags.
# All aliases below ("info", "med", "crit") have been directly observed in
# test output (see samples/CA_DCSync_4662.evtx for a "crit" example).
SEVERITY_ALIASES = {
    "info": "informational",
    "med": "medium",
    "crit": "critical",
}


def _normalize_severity(level: str) -> str | None:
    level = level.strip().lower()
    level = SEVERITY_ALIASES.get(level, level)
    return level if level in SEVERITY_RANK else None


def _finding_rank(finding: dict) -> int | None:
    level = finding.get("Level")
    if not isinstance(level, str):
        return None
    normalized = _normalize_severity(level)
    return SEVERITY_RANK.get(normalized) if normalized else None


OUTPUT_FORMATS = ["summary", "full"]

# Fields kept when output_format="summary" — enough to triage a finding
# without the verbose Details/ExtraFieldInfo payloads.
_SUMMARY_FIELDS = [
    "Timestamp",
    "RuleTitle",
    "Level",
    "Computer",
    "Channel",
    "EventID",
    "RecordID",
]


def _summarize_finding(finding: dict) -> dict:
    return {field: finding.get(field) for field in _SUMMARY_FIELDS}


def _matches_rule_filter(finding: dict, needle: str) -> bool:
    title = finding.get("RuleTitle")
    return isinstance(title, str) and needle.lower() in title.lower()


def _find_hayabusa_binary() -> Path | None:
    override = os.environ.get("HAYABUSA_BIN")
    if override:
        path = Path(override)
        return path if path.is_file() else None
    if not HAYABUSA_DIR.is_dir():
        return None
    candidates = [p for p in HAYABUSA_DIR.glob("hayabusa*") if p.is_file()]
    return candidates[0] if candidates else None


def _parse_jsonl(path: Path) -> list[dict]:
    findings = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            findings.append(json.loads(line))
    return findings


# Rule files rarely change during a server's lifetime, and parsing all
# ~5000 of them with PyYAML takes several seconds — build the index once
# and reuse it across get_hayabusa_rules calls.
_RULE_INDEX_CACHE: list[dict] | None = None


def _load_rule_index() -> list[dict]:
    global _RULE_INDEX_CACHE
    if _RULE_INDEX_CACHE is not None:
        return _RULE_INDEX_CACHE

    rules = []
    for path in RULES_DIR.rglob("*.yml"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                # A few correlation rules are multi-document YAML; the
                # rule's own metadata (title/id/level/...) is always in
                # the first document.
                doc = next(yaml.safe_load_all(f), None)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict) or "title" not in doc:
            continue
        rules.append(
            {
                "id": doc.get("id"),
                "title": doc.get("title"),
                "level": doc.get("level"),
                "status": doc.get("status"),
                "description": doc.get("description"),
                "tags": doc.get("tags") or [],
            }
        )

    _RULE_INDEX_CACHE = rules
    return rules


def _matches_keyword(rule: dict, needle: str) -> bool:
    needle = needle.lower()
    haystack = [rule.get("title"), rule.get("description"), *rule.get("tags", [])]
    return any(isinstance(h, str) and needle in h.lower() for h in haystack)


@mcp.tool()
def scan_evtx(
    file_path: str,
    severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Scan an EVTX file with Hayabusa and return structured results.

    Args:
        file_path: Path to the EVTX file to scan.
        severity: Optional minimum severity level to filter results by
            (one of: informational, low, medium, high, critical). Findings
            at or above this level are returned.
        rule_filter: Optional substring to match (case-insensitive) against
            the matched rule's title (e.g. "lateral" or "mimikatz"). Only
            findings from matching rules are returned.
        output_format: "summary" (default) returns a condensed set of
            fields per finding; "full" returns every field Hayabusa
            produced, including Details/ExtraFieldInfo.
        max_results: Optional cap on the number of findings returned.
            result_count still reflects the total number of matches.
    """
    evtx_path = Path(file_path)
    if not evtx_path.is_file():
        return {"error": f"File not found: {file_path}"}

    normalized_severity = None
    if severity is not None:
        normalized_severity = _normalize_severity(severity)
        if normalized_severity is None:
            return {
                "error": (
                    f"Invalid severity level: {severity!r}. "
                    f"Expected one of {SEVERITY_LEVELS}."
                )
            }

    if output_format not in OUTPUT_FORMATS:
        return {
            "error": (
                f"Invalid output_format: {output_format!r}. "
                f"Expected one of {OUTPUT_FORMATS}."
            )
        }

    if max_results is not None and max_results < 1:
        return {"error": f"max_results must be a positive integer, got {max_results}"}

    binary = _find_hayabusa_binary()
    if binary is None:
        return {
            "error": (
                "Hayabusa binary not found. Set HAYABUSA_BIN or run "
                "scripts/download_hayabusa.py first."
            )
        }

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"
        command = [
            str(binary),
            "json-timeline",
            "-f", str(evtx_path),
            "-o", str(output_path),
            "-L",  # JSONL output: one compact JSON object per line
            "-w",  # no-wizard: don't prompt interactively (would hang here)
            "-q",  # quiet: suppress launch banner
            "-Q",  # quiet-errors: don't write separate error log files
            "-K",  # no-color: avoid ANSI escape codes in captured output
            "-C",  # clobber: allow overwriting the output file
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"Hayabusa scan timed out after {SCAN_TIMEOUT_SECONDS}s"}
        except OSError as exc:
            return {"error": f"Failed to run Hayabusa binary: {exc}"}

        if result.returncode != 0:
            return {
                "error": "Hayabusa exited with a non-zero status",
                "returncode": result.returncode,
                "stderr": result.stderr.strip(),
            }

        try:
            findings = _parse_jsonl(output_path)
        except (OSError, json.JSONDecodeError) as exc:
            return {"error": f"Failed to parse Hayabusa output: {exc}"}

    if normalized_severity is not None:
        min_rank = SEVERITY_RANK[normalized_severity]
        findings = [
            finding
            for finding in findings
            if (rank := _finding_rank(finding)) is not None and rank >= min_rank
        ]

    if rule_filter is not None:
        findings = [f for f in findings if _matches_rule_filter(f, rule_filter)]

    result_count = len(findings)

    if max_results is not None:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [_summarize_finding(f) for f in findings]

    return {
        "file_path": str(evtx_path),
        "severity_filter": normalized_severity,
        "rule_filter": rule_filter,
        "output_format": output_format,
        "result_count": result_count,
        "returned_count": len(findings),
        "findings": findings,
    }


@mcp.tool()
def get_hayabusa_rules(keyword: str | None = None, max_results: int | None = None) -> dict:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Useful for seeing what Hayabusa can detect before running scan_evtx —
    e.g. checking whether a "lateral movement" or "mimikatz" rule exists.

    Args:
        keyword: Optional substring to match (case-insensitive) against a
            rule's title, description, or tags (e.g. "lateral" or
            "mimikatz"). If omitted, all rules are returned.
        max_results: Optional cap on the number of rules returned.
            result_count still reflects the total number of matches.
    """
    if not RULES_DIR.is_dir():
        return {"error": f"Rules directory not found: {RULES_DIR}"}

    if max_results is not None and max_results < 1:
        return {"error": f"max_results must be a positive integer, got {max_results}"}

    rules = _load_rule_index()
    total_rules = len(rules)

    if keyword is not None:
        rules = [r for r in rules if _matches_keyword(r, keyword)]

    result_count = len(rules)

    if max_results is not None:
        rules = rules[:max_results]

    return {
        "keyword_filter": keyword,
        "total_rules": total_rules,
        "result_count": result_count,
        "returned_count": len(rules),
        "rules": rules,
    }


# Matches Sigma tags like "attack.t1003.006" or "attack.t1558" (the
# sub-technique suffix is optional).
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TECHNIQUE_ID_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_RULE_NAME_RE = re.compile(r"^[\w\-]+$")


def _extract_techniques(tags: list) -> list[str]:
    techniques = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = _TECHNIQUE_TAG_RE.match(tag.strip())
        if match:
            techniques.append(match.group(1).upper())
    return techniques


def _normalize_technique_id(technique_id: str) -> str | None:
    technique_id = technique_id.strip()
    return technique_id.upper() if _TECHNIQUE_ID_RE.match(technique_id) else None


# Same rationale as _RULE_INDEX_CACHE above: the curated rule set is small,
# but there's no need to re-parse it from disk on every resource read.
_CURATED_RULE_CACHE: list[dict] | None = None


def _load_curated_rules() -> list[dict]:
    global _CURATED_RULE_CACHE
    if _CURATED_RULE_CACHE is not None:
        return _CURATED_RULE_CACHE

    rules = []
    for path in sorted(CURATED_RULES_DIR.glob("*.yml")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict) or "title" not in doc:
            continue
        tags = doc.get("tags") or []
        rules.append(
            {
                "name": path.stem,
                "title": doc.get("title"),
                "level": doc.get("level"),
                "techniques": _extract_techniques(tags),
                "tags": tags,
                "_path": path,
            }
        )

    _CURATED_RULE_CACHE = rules
    return rules


def _public_rule_fields(rule: dict) -> dict:
    return {k: v for k, v in rule.items() if k != "_path"}


_ATTACK_TECHNIQUES_CACHE: dict[str, dict] | None = None


def _load_attack_techniques() -> dict[str, dict]:
    global _ATTACK_TECHNIQUES_CACHE
    if _ATTACK_TECHNIQUES_CACHE is not None:
        return _ATTACK_TECHNIQUES_CACHE

    with open(ATTACK_TECHNIQUES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    _ATTACK_TECHNIQUES_CACHE = {
        technique["id"].upper(): technique
        for technique in data.get("techniques", [])
        if isinstance(technique, dict) and "id" in technique
    }
    return _ATTACK_TECHNIQUES_CACHE


@mcp.resource("detection://rules")
def list_curated_rules() -> dict:
    """List all curated detection rules (name, title, techniques, level)."""
    if not CURATED_RULES_DIR.is_dir():
        return {"error": f"Curated rules directory not found: {CURATED_RULES_DIR}"}

    rules = _load_curated_rules()
    return {
        "total_rules": len(rules),
        "rules": [_public_rule_fields(r) for r in rules],
    }


@mcp.resource("detection://rules/{rule_name}")
def get_curated_rule(rule_name: str) -> str | dict:
    """Return a specific curated rule's full YAML content."""
    if not CURATED_RULES_DIR.is_dir():
        return {"error": f"Curated rules directory not found: {CURATED_RULES_DIR}"}

    name = rule_name[:-4] if rule_name.endswith(".yml") else rule_name
    if not _RULE_NAME_RE.match(name):
        return {"error": f"Invalid rule name: {rule_name!r}"}

    path = CURATED_RULES_DIR / f"{name}.yml"
    if not path.is_file():
        return {"error": f"Rule not found: {rule_name}"}

    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"error": f"Failed to read rule {rule_name}: {exc}"}


@mcp.resource("detection://rules/by-technique/{technique_id}")
def list_rules_by_technique(technique_id: str) -> dict:
    """List curated rules tagged with a given ATT&CK technique ID."""
    if not CURATED_RULES_DIR.is_dir():
        return {"error": f"Curated rules directory not found: {CURATED_RULES_DIR}"}

    normalized = _normalize_technique_id(technique_id)
    if normalized is None:
        return {"error": f"Invalid ATT&CK technique ID: {technique_id!r}"}

    rules = [r for r in _load_curated_rules() if normalized in r["techniques"]]
    return {
        "technique_id": normalized,
        "result_count": len(rules),
        "rules": [_public_rule_fields(r) for r in rules],
    }


# Same rationale as _CURATED_RULE_CACHE: playbooks are small and static
# per server run, so parse them once from disk and reuse.
_PLAYBOOK_CACHE: list[dict] | None = None


def _load_playbooks() -> list[dict]:
    global _PLAYBOOK_CACHE
    if _PLAYBOOK_CACHE is not None:
        return _PLAYBOOK_CACHE

    playbooks = []
    for path in sorted(PLAYBOOKS_DIR.glob("*.yml")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict) or "title" not in doc:
            continue
        alert_names = doc.get("alert_names") or []
        playbooks.append(
            {
                "name": path.stem,
                "title": doc.get("title"),
                "severity": doc.get("severity"),
                "techniques": [
                    t.upper() for t in (doc.get("techniques") or []) if isinstance(t, str)
                ],
                "alert_names": alert_names,
                "summary": doc.get("summary"),
                "_path": path,
            }
        )

    _PLAYBOOK_CACHE = playbooks
    return playbooks


def _public_playbook_fields(playbook: dict) -> dict:
    return {k: v for k, v in playbook.items() if k != "_path"}


def _matches_alert_name(playbook: dict, needle: str) -> bool:
    needle = needle.lower()
    return any(isinstance(a, str) and needle in a.lower() for a in playbook["alert_names"])


@mcp.resource("detection://playbooks")
def list_playbooks() -> dict:
    """List all incident response playbooks (name, title, techniques, severity)."""
    if not PLAYBOOKS_DIR.is_dir():
        return {"error": f"Playbooks directory not found: {PLAYBOOKS_DIR}"}

    playbooks = _load_playbooks()
    return {
        "total_playbooks": len(playbooks),
        "playbooks": [_public_playbook_fields(p) for p in playbooks],
    }


@mcp.resource("detection://playbooks/{playbook_name}")
def get_playbook(playbook_name: str) -> str | dict:
    """Return a specific incident response playbook's full YAML content."""
    if not PLAYBOOKS_DIR.is_dir():
        return {"error": f"Playbooks directory not found: {PLAYBOOKS_DIR}"}

    name = playbook_name[:-4] if playbook_name.endswith(".yml") else playbook_name
    if not _RULE_NAME_RE.match(name):
        return {"error": f"Invalid playbook name: {playbook_name!r}"}

    path = PLAYBOOKS_DIR / f"{name}.yml"
    if not path.is_file():
        return {"error": f"Playbook not found: {playbook_name}"}

    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"error": f"Failed to read playbook {playbook_name}: {exc}"}


@mcp.resource("detection://playbooks/by-alert/{alert_name}")
def get_playbook_by_alert(alert_name: str) -> dict:
    """Find the incident response playbook(s) for a given alert.

    alert_name is matched (case-insensitive substring) against each
    playbook's alert_names — which include both curated rule names (e.g.
    "dcsync") and full rule/finding titles (e.g. the RuleTitle a scan_evtx
    finding or Hayabusa alert would show), so either form works.

    If no playbook's alert_names match directly, falls back to resolving
    alert_name against a curated rule's name/title, then matching
    playbooks by shared ATT&CK technique coverage instead.
    """
    if not PLAYBOOKS_DIR.is_dir():
        return {"error": f"Playbooks directory not found: {PLAYBOOKS_DIR}"}
    if not isinstance(alert_name, str) or not alert_name.strip():
        return {"error": "alert_name must be a non-empty string"}

    playbooks = _load_playbooks()
    direct_matches = [p for p in playbooks if _matches_alert_name(p, alert_name)]
    if direct_matches:
        return {
            "alert_name": alert_name,
            "match_type": "alert_name",
            "result_count": len(direct_matches),
            "playbooks": [_public_playbook_fields(p) for p in direct_matches],
        }

    if not CURATED_RULES_DIR.is_dir():
        return {
            "alert_name": alert_name,
            "match_type": "no_match",
            "result_count": 0,
            "playbooks": [],
        }

    needle = alert_name.lower()
    matched_rules = [
        r
        for r in _load_curated_rules()
        if needle in r["name"].lower() or (r["title"] and needle in r["title"].lower())
    ]
    matched_techniques = {t for r in matched_rules for t in r["techniques"]}
    technique_matches = [
        p for p in playbooks if matched_techniques & set(p["techniques"])
    ]
    if technique_matches:
        return {
            "alert_name": alert_name,
            "match_type": "technique_fallback",
            "matched_rules": [_public_rule_fields(r) for r in matched_rules],
            "result_count": len(technique_matches),
            "playbooks": [_public_playbook_fields(p) for p in technique_matches],
        }

    return {
        "alert_name": alert_name,
        "match_type": "no_match",
        "result_count": 0,
        "playbooks": [],
    }


# Environment YAML files are small, static documents (not glob-loaded
# collections like rules/playbooks) — cache each by filename once read.
_ENVIRONMENT_CACHE: dict[str, dict] = {}


def _load_environment_file(filename: str) -> dict:
    if filename in _ENVIRONMENT_CACHE:
        return _ENVIRONMENT_CACHE[filename]

    path = ENVIRONMENT_DIR / filename
    if not path.is_file():
        return {"error": f"Environment file not found: {path}"}

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as exc:
        return {"error": f"Failed to load {filename}: {exc}"}

    if not isinstance(doc, dict):
        return {"error": f"{filename} did not contain a YAML mapping"}

    _ENVIRONMENT_CACHE[filename] = doc
    return doc


@mcp.resource("detection://environment/hosts")
def get_environment_hosts() -> dict:
    """List known hosts and their roles in the environment (environment/hosts.yml)."""
    return _load_environment_file("hosts.yml")


@mcp.resource("detection://environment/services")
def get_environment_services() -> dict:
    """List critical services in the environment and the rules/hosts they relate to (environment/services.yml)."""
    return _load_environment_file("services.yml")


@mcp.resource("detection://environment/baselines")
def get_environment_baselines() -> dict:
    """List normal-behavior baselines used to triage curated-rule findings (environment/baselines.yml)."""
    return _load_environment_file("baselines.yml")


# Same rationale as _CURATED_RULE_CACHE/_PLAYBOOK_CACHE: past investigations
# are static within a server run, parse them once from disk and reuse.
_INVESTIGATION_CACHE: list[dict] | None = None


def _load_investigations() -> list[dict]:
    global _INVESTIGATION_CACHE
    if _INVESTIGATION_CACHE is not None:
        return _INVESTIGATION_CACHE

    investigations = []
    for path in sorted(INVESTIGATIONS_DIR.glob("*.yml")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict) or "case_id" not in doc:
            continue
        techniques = [
            t.upper() for t in (doc.get("techniques") or []) if isinstance(t, str)
        ]
        investigations.append(
            {
                "name": path.stem,
                "case_id": doc.get("case_id"),
                "title": doc.get("title"),
                "date": doc.get("date"),
                "status": doc.get("status"),
                "disposition": doc.get("disposition"),
                "severity": doc.get("severity"),
                "techniques": techniques,
                "hosts_involved": doc.get("hosts_involved") or [],
                "summary": doc.get("summary"),
                "_path": path,
            }
        )

    _INVESTIGATION_CACHE = investigations
    return investigations


def _public_investigation_fields(investigation: dict) -> dict:
    return {k: v for k, v in investigation.items() if k != "_path"}


@mcp.resource("detection://investigations")
def list_investigations() -> dict:
    """List all past investigation cases (case_id, title, date, techniques, status)."""
    if not INVESTIGATIONS_DIR.is_dir():
        return {"error": f"Investigations directory not found: {INVESTIGATIONS_DIR}"}

    investigations = _load_investigations()
    return {
        "total_investigations": len(investigations),
        "investigations": [_public_investigation_fields(i) for i in investigations],
    }


@mcp.resource("detection://investigations/{case_id}")
def get_investigation(case_id: str) -> str | dict:
    """Return a specific past investigation's full YAML content."""
    if not INVESTIGATIONS_DIR.is_dir():
        return {"error": f"Investigations directory not found: {INVESTIGATIONS_DIR}"}

    name = case_id[:-4] if case_id.endswith(".yml") else case_id
    if not _RULE_NAME_RE.match(name):
        return {"error": f"Invalid case ID: {case_id!r}"}

    path = INVESTIGATIONS_DIR / f"{name}.yml"
    if not path.is_file():
        return {"error": f"Investigation not found: {case_id}"}

    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"error": f"Failed to read investigation {case_id}: {exc}"}


@mcp.resource("detection://investigations/by-technique/{technique_id}")
def list_investigations_by_technique(technique_id: str) -> dict:
    """List past investigation cases that involved a given ATT&CK technique."""
    if not INVESTIGATIONS_DIR.is_dir():
        return {"error": f"Investigations directory not found: {INVESTIGATIONS_DIR}"}

    normalized = _normalize_technique_id(technique_id)
    if normalized is None:
        return {"error": f"Invalid ATT&CK technique ID: {technique_id!r}"}

    investigations = [i for i in _load_investigations() if normalized in i["techniques"]]
    return {
        "technique_id": normalized,
        "result_count": len(investigations),
        "investigations": [_public_investigation_fields(i) for i in investigations],
    }


def _technique_coverage(
    technique_id: str, techniques: dict[str, dict], curated_rules: list[dict]
) -> dict:
    covering_rules = [
        _public_rule_fields(r) for r in curated_rules if technique_id in r["techniques"]
    ]
    technique = techniques.get(technique_id)
    if technique is None:
        return {
            "technique_id": technique_id,
            "technique": None,
            "rules": covering_rules,
            "coverage_status": "unknown_technique",
        }
    return {
        "technique_id": technique_id,
        "technique": technique,
        "rules": covering_rules,
        "coverage_status": "covered" if covering_rules else "gap",
    }


@mcp.resource("detection://attack/techniques/{technique_id}")
def get_attack_technique(technique_id: str) -> dict:
    """Look up an ATT&CK technique and report our detection coverage for it."""
    if not ATTACK_TECHNIQUES_PATH.is_file():
        return {"error": f"ATT&CK techniques mapping not found: {ATTACK_TECHNIQUES_PATH}"}

    normalized = _normalize_technique_id(technique_id)
    if normalized is None:
        return {"error": f"Invalid ATT&CK technique ID: {technique_id!r}"}

    try:
        techniques = _load_attack_techniques()
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"Failed to load ATT&CK techniques mapping: {exc}"}

    return _technique_coverage(normalized, techniques, _load_curated_rules())


# The 14 MITRE ATT&CK Enterprise tactic short names, in the same
# kebab-case form used by Sigma tags (e.g. "attack.credential-access")
# and by the "tactic" field in mappings/attack_techniques.json.
ATTACK_TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}


def _normalize_tactic_name(tactic: str) -> str:
    return re.sub(r"[\s_]+", "-", tactic.strip().lower())


@mcp.tool()
def analyze_coverage(query: str) -> dict:
    """Report detection coverage for an ATT&CK technique ID or tactic.

    Args:
        query: Either a single ATT&CK technique ID (e.g. "T1110" or
            "T1003.001") or an ATT&CK tactic name (e.g. "credential-access").
            If a technique ID is given, only that technique's coverage is
            reported (covered/gap/unknown_technique). If a tactic name is
            given, every technique mapped to that tactic in
            mappings/attack_techniques.json is reported as covered or a
            gap.
    """
    if not ATTACK_TECHNIQUES_PATH.is_file():
        return {"error": f"ATT&CK techniques mapping not found: {ATTACK_TECHNIQUES_PATH}"}
    if not CURATED_RULES_DIR.is_dir():
        return {"error": f"Curated rules directory not found: {CURATED_RULES_DIR}"}

    if not isinstance(query, str) or not query.strip():
        return {
            "error": "query must be a non-empty ATT&CK technique ID or tactic name"
        }

    try:
        techniques = _load_attack_techniques()
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"Failed to load ATT&CK techniques mapping: {exc}"}

    curated_rules = _load_curated_rules()

    normalized_technique = _normalize_technique_id(query)
    if normalized_technique is not None:
        coverage = _technique_coverage(normalized_technique, techniques, curated_rules)
        return {"query": query, "query_type": "technique", **coverage}

    normalized_tactic = _normalize_tactic_name(query)
    if normalized_tactic not in ATTACK_TACTICS:
        return {"error": f"Invalid ATT&CK technique ID or tactic name: {query!r}"}

    tactic_techniques = sorted(
        (t for t in techniques.values() if t.get("tactic") == normalized_tactic),
        key=lambda t: t["id"],
    )
    results = [
        _technique_coverage(t["id"], techniques, curated_rules) for t in tactic_techniques
    ]
    covered_count = sum(1 for r in results if r["coverage_status"] == "covered")

    return {
        "query": query,
        "query_type": "tactic",
        "tactic": normalized_tactic,
        "result_count": len(results),
        "covered_count": covered_count,
        "gap_count": len(results) - covered_count,
        "techniques": results,
    }


# Maps ATT&CK data source names (as they appear in
# mappings/attack_techniques.json) to a suggested Sigma logsource, candidate
# Windows Event IDs, and a short hint for building a detection around them.
# Not exhaustive across all of ATT&CK — covers the data sources actually
# used in our curated mapping file; unmapped data sources fall back to
# _DEFAULT_DATA_SOURCE_HINT.
DATA_SOURCE_HINTS = {
    "Process: OS API Execution": {
        "logsource": {"product": "windows", "category": "process_access"},
        "event_ids": ["Sysmon 10"],
        "hint": "monitor process access/API calls (Sysmon Event ID 10 ProcessAccess) for suspicious cross-process memory access",
    },
    "Process: Process Access": {
        "logsource": {"product": "windows", "category": "process_access"},
        "event_ids": ["Sysmon 10"],
        "hint": "monitor process access events (Sysmon Event ID 10 ProcessAccess) for suspicious handles opened to sensitive processes",
    },
    "Process: Process Creation": {
        "logsource": {"product": "windows", "category": "process_creation"},
        "event_ids": ["Sysmon 1", "Security 4688"],
        "hint": "monitor process creation (Sysmon Event ID 1 or Security 4688) for suspicious binaries or command lines",
    },
    "Command: Command Execution": {
        "logsource": {"product": "windows", "category": "process_creation"},
        "event_ids": ["Sysmon 1", "Security 4688"],
        "hint": "monitor process creation / command-line logging (Sysmon Event ID 1 or Security 4688) for suspicious command-line arguments or tool names",
    },
    "File: File Access": {
        "logsource": {"product": "windows", "category": "file_event"},
        "event_ids": ["Sysmon 11"],
        "hint": "monitor file creation/access events (Sysmon Event ID 11 FileCreate, or Security 4663) for reads/writes to sensitive credential files or paths",
    },
    "Windows Registry: Windows Registry Key Access": {
        "logsource": {"product": "windows", "service": "security"},
        "event_ids": ["Security 4663"],
        "hint": "monitor registry key access (Security Event ID 4663 with object auditing enabled, or Sysmon 13) for reads of sensitive hives like SAM/SECURITY",
    },
    "Windows Registry: Windows Registry Key Modification": {
        "logsource": {"product": "windows", "category": "registry_set"},
        "event_ids": ["Sysmon 13"],
        "hint": "monitor registry value modifications (Sysmon Event ID 13/14) for changes to authentication packages, SSP, or Notification Packages keys (e.g. LSA)",
    },
    "Active Directory: Active Directory Object Access": {
        "logsource": {"product": "windows", "service": "security"},
        "event_ids": ["Security 4662"],
        "hint": "monitor directory service object access (Security Event ID 4662) for access to sensitive AD objects/extended rights",
    },
    "Network Traffic: Network Traffic Content": {
        "logsource": {"category": "network_connection"},
        "event_ids": [],
        "hint": "requires network traffic inspection (packet capture / IDS) since Windows event logs alone don't capture on-the-wire protocol content",
    },
    "Network Traffic: Network Connection Creation": {
        "logsource": {"product": "windows", "category": "network_connection"},
        "event_ids": ["Sysmon 3"],
        "hint": "monitor outbound network connections (Sysmon Event ID 3) for connections to unexpected hosts/ports associated with this technique",
    },
    "Application Log: Application Log Content": {
        "logsource": {"product": "windows"},
        "event_ids": [],
        "hint": "monitor the relevant application's own log channel for content indicating this technique (specific channel depends on the target application)",
    },
    "User Account: User Account Authentication": {
        "logsource": {"product": "windows", "service": "security"},
        "event_ids": ["Security 4624", "Security 4625", "Security 4768"],
        "hint": "monitor authentication events (logon success/failure, Kerberos AS/TGS requests) for anomalous patterns",
    },
    "Logon Session: Logon Session Creation": {
        "logsource": {"product": "windows", "service": "security"},
        "event_ids": ["Security 4624"],
        "hint": "monitor logon session creation (Security Event ID 4624) for logon type and anomalies indicating credential reuse",
    },
}

_DEFAULT_DATA_SOURCE_HINT = {
    "logsource": None,
    "event_ids": [],
    "hint": "no specific Windows Event ID mapping curated for this data source yet — consult the ATT&CK data source definition and available log sources",
}


def _build_suggestion(technique: dict) -> dict:
    data_sources = technique.get("data_sources") or []
    per_source = []
    logsource_candidates = []
    event_ids: list[str] = []
    for data_source in data_sources:
        hint = DATA_SOURCE_HINTS.get(data_source, _DEFAULT_DATA_SOURCE_HINT)
        per_source.append(
            {
                "data_source": data_source,
                "hint": hint["hint"],
                "event_ids": hint["event_ids"],
                "logsource": hint["logsource"],
            }
        )
        if hint["logsource"]:
            logsource_candidates.append(hint["logsource"])
        event_ids.extend(hint["event_ids"])

    primary_logsource = logsource_candidates[0] if logsource_candidates else {"product": "windows"}
    summary = (
        f"No curated rule covers {technique['id']} ({technique['name']}). "
        + " ".join(f"For {h['data_source']}, {h['hint']}." for h in per_source)
    )

    return {
        "data_sources": per_source,
        "primary_logsource": primary_logsource,
        "candidate_event_ids": sorted(set(event_ids)),
        "summary": summary,
    }


def _render_rule_template(technique_id: str, technique: dict, suggestion: dict) -> str:
    logsource_lines = "\n".join(f"  {k}: {v}" for k, v in suggestion["primary_logsource"].items())
    hint_comment_lines = "\n".join(
        f"  #   - {h['data_source']}: {h['hint']}" for h in suggestion["data_sources"]
    )
    event_ids = suggestion["candidate_event_ids"]
    event_id_note = (
        f"candidate Event IDs: {', '.join(event_ids)}" if event_ids else "no candidate Event IDs identified"
    )
    mitre_url_path = technique_id.replace(".", "/")

    return f"""title: "TODO: {technique['name']} Detection"
id: {uuid.uuid4()}
status: experimental
description: >
  TODO: draft detection logic for {technique_id} ({technique['name']}).
  {technique['description']}
references:
  - https://attack.mitre.org/techniques/{mitre_url_path}/
author: Detection Engineering Team
date: {date.today().strftime("%Y/%m/%d")}
tags:
  - attack.{technique.get("tactic", "credential-access")}
  - attack.{technique_id.lower()}
logsource:
{logsource_lines}
detection:
  # Suggested data sources for this technique ({event_id_note}):
{hint_comment_lines}
  selection:
    # TODO: fill in selection fields
    TODO: TODO
  condition: selection
falsepositives:
  - "TODO: identify false positive sources"
level: medium
"""


@mcp.tool()
def suggest_rule(technique_id: str, write_template: bool = False) -> dict:
    """Suggest a detection approach for an ATT&CK technique gap.

    Checks curated-rule coverage for the given technique using the same
    logic as analyze_coverage. If coverage already exists, reports the
    covering rule(s) instead of a suggestion. If it's a gap, suggests a
    detection approach derived from the technique's data_sources in
    mappings/attack_techniques.json.

    Args:
        technique_id: A single ATT&CK technique ID (e.g. "T1003.002").
        write_template: If true and the technique is a coverage gap, write
            a starter Sigma rule template to rules/<technique_id>.yml
            (e.g. rules/t1003_002.yml). Defaults to false. Never overwrites
            an existing file — if one is already there, the template is
            not written and a note explains why.
    """
    if not ATTACK_TECHNIQUES_PATH.is_file():
        return {"error": f"ATT&CK techniques mapping not found: {ATTACK_TECHNIQUES_PATH}"}
    if not CURATED_RULES_DIR.is_dir():
        return {"error": f"Curated rules directory not found: {CURATED_RULES_DIR}"}

    normalized = _normalize_technique_id(technique_id)
    if normalized is None:
        return {"error": f"Invalid ATT&CK technique ID: {technique_id!r}"}

    try:
        techniques = _load_attack_techniques()
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"Failed to load ATT&CK techniques mapping: {exc}"}

    coverage = _technique_coverage(normalized, techniques, _load_curated_rules())
    result = {**coverage, "suggestion": None, "template_written": False, "template_path": None}

    if coverage["coverage_status"] == "unknown_technique":
        result["note"] = (
            f"{normalized} is not in the curated ATT&CK techniques mapping "
            f"({ATTACK_TECHNIQUES_PATH.name}), so no data sources are available to base a "
            "suggestion on."
        )
        return result

    if coverage["coverage_status"] == "covered":
        result["note"] = f"{normalized} already has curated rule coverage; no suggestion needed."
        return result

    # Gap: build a suggestion from the technique's data sources.
    suggestion = _build_suggestion(coverage["technique"])
    result["suggestion"] = suggestion

    if not write_template:
        return result

    template_path = CURATED_RULES_DIR / f"{normalized.lower().replace('.', '_')}.yml"
    if template_path.exists():
        result["note"] = f"Template not written: {template_path.name} already exists."
        return result

    try:
        template_path.write_text(
            _render_rule_template(normalized, coverage["technique"], suggestion), encoding="utf-8"
        )
    except OSError as exc:
        result["note"] = f"Failed to write template: {exc}"
        return result

    global _CURATED_RULE_CACHE
    _CURATED_RULE_CACHE = None  # Invalidate cache so the new template is picked up.
    result["template_written"] = True
    result["template_path"] = str(template_path)
    return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
