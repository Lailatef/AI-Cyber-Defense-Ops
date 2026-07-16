#!/usr/bin/env python3
"""Validate a Sigma detection rule against this repo's detection-engineering
standards (see ../SKILL.md). Prints a JSON validation report to stdout.

Usage:
    py validate-rule.py <path-to-rule.yml>

Checks performed:
  1. attack_mapping   - at least one tag matches attack.tXXXX or attack.tXXXX.XXX
  2. severity         - top-level 'level' is one of low/medium/high/critical
  3. falsepositives   - top-level 'falsepositives' is present and non-empty
  4. test_case        - at least one '# test-case: ...' comment line exists

Sigma has no native field for "this was tested against sample X", so check 4
relies on a comment convention specific to this repo:

    # test-case: samples/some_file.evtx
    # test-case: manually verified against inline example event below

Add one such comment per known/attempted test to satisfy the check.

Exit code is 0 if all checks pass, 1 if any check fails, 2 on usage/parse
errors (file not found, invalid YAML, etc).
"""
import json
import re
import sys

try:
    import yaml
except ImportError:
    print(json.dumps({"error": "PyYAML is required (pip install pyyaml)"}))
    sys.exit(2)

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
ATTACK_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TEST_CASE_COMMENT_RE = re.compile(r"^\s*#\s*test-case\s*:\s*(.+)$", re.IGNORECASE)


def check_attack_mapping(rule):
    tags = rule.get("tags") or []
    if not isinstance(tags, list):
        return {"passed": False, "detail": "'tags' is not a list", "matches": []}
    matches = [t for t in tags if isinstance(t, str) and ATTACK_TAG_RE.match(t)]
    if matches:
        return {"passed": True, "detail": f"found {len(matches)} ATT&CK tag(s)", "matches": matches}
    near_misses = [
        t for t in tags
        if isinstance(t, str) and t.lower().startswith("attack.t") and not ATTACK_TAG_RE.match(t)
    ]
    detail = "no tag matches attack.tXXXX / attack.tXXXX.XXX"
    if near_misses:
        detail += f" (found near-miss(es), check case/format: {near_misses})"
    return {"passed": False, "detail": detail, "matches": []}


def check_severity(rule):
    level = rule.get("level")
    if level is None:
        return {"passed": False, "detail": "'level' field is missing", "value": None}
    if not isinstance(level, str) or level not in VALID_SEVERITIES:
        return {
            "passed": False,
            "detail": f"'level: {level}' is not one of {sorted(VALID_SEVERITIES)}",
            "value": level,
        }
    return {"passed": True, "detail": f"level is '{level}'", "value": level}


def check_falsepositives(rule):
    fps = rule.get("falsepositives")
    if fps is None:
        return {"passed": False, "detail": "'falsepositives' field is missing", "count": 0}
    if isinstance(fps, str):
        fps = [fps]
    if not isinstance(fps, list) or len(fps) == 0:
        return {"passed": False, "detail": "'falsepositives' is empty", "count": 0}
    return {"passed": True, "detail": f"{len(fps)} falsepositive entr(y/ies) documented", "count": len(fps)}


def check_test_case(raw_text):
    found = [
        m.group(1).strip()
        for line in raw_text.splitlines()
        for m in [TEST_CASE_COMMENT_RE.match(line)]
        if m
    ]
    if found:
        return {"passed": True, "detail": f"found {len(found)} '# test-case:' comment(s)", "entries": found}
    return {
        "passed": False,
        "detail": "no '# test-case: ...' comment found (see script docstring for convention)",
        "entries": [],
    }


def validate(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_text = f.read()
    except OSError as e:
        return {"file": path, "valid": False, "error": f"could not read file: {e}"}, 2

    try:
        rule = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        return {"file": path, "valid": False, "error": f"invalid YAML: {e}"}, 2

    if not isinstance(rule, dict):
        return {"file": path, "valid": False, "error": "rule did not parse to a YAML mapping"}, 2

    checks = {
        "attack_mapping": check_attack_mapping(rule),
        "severity": check_severity(rule),
        "falsepositives": check_falsepositives(rule),
        "test_case": check_test_case(raw_text),
    }

    issues = [c["detail"] for c in checks.values() if not c["passed"]]
    valid = len(issues) == 0

    result = {
        "file": path,
        "title": rule.get("title"),
        "valid": valid,
        "checks": checks,
        "issues": issues,
    }
    return result, (0 if valid else 1)


def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: validate-rule.py <path-to-rule.yml>"}))
        sys.exit(2)

    result, exit_code = validate(sys.argv[1])
    print(json.dumps(result, indent=2))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
