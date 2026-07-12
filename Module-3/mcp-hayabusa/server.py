"""MCP server that wraps Hayabusa for EVTX analysis."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")

HAYABUSA_DIR = Path(__file__).parent / "hayabusa"
RULES_DIR = HAYABUSA_DIR / "rules"
SCAN_TIMEOUT_SECONDS = 600

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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
