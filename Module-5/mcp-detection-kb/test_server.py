"""Simple manual test: call scan_evtx directly against a sample EVTX file.

Usage:
    python test_server.py [path/to/file.evtx]

Defaults to the sample in samples/ (a known mimikatz LSASS credential-dumping
attack from https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), useful since
it reliably produces detections to check severity filtering against.
"""

import json
import sys
from pathlib import Path

import server

DEFAULT_SAMPLE = (
    Path(__file__).parent
    / "samples"
    / "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"
)


def test_get_hayabusa_rules() -> None:
    print("\nTesting get_hayabusa_rules(keyword='credential')...")
    filtered = server.get_hayabusa_rules(keyword="credential")
    assert "error" not in filtered, filtered
    assert filtered["result_count"] == filtered["returned_count"] == len(filtered["rules"])
    assert all(server._matches_keyword(r, "credential") for r in filtered["rules"])
    assert filtered["result_count"] > 0
    print(f"total_rules: {filtered['total_rules']}, result_count: {filtered['result_count']}")

    print("\nTesting get_hayabusa_rules() with no keyword...")
    unfiltered = server.get_hayabusa_rules()
    assert "error" not in unfiltered, unfiltered
    assert unfiltered["total_rules"] == unfiltered["result_count"] == unfiltered["returned_count"]
    print(f"total_rules: {unfiltered['total_rules']}")

    print("\nTesting get_hayabusa_rules(keyword='credential', max_results=10)...")
    capped = server.get_hayabusa_rules(keyword="credential", max_results=10)
    assert "error" not in capped, capped
    assert capped["result_count"] == filtered["result_count"]
    assert capped["returned_count"] == 10
    assert len(capped["rules"]) == 10

    print("\nTesting get_hayabusa_rules(max_results=0) for error handling...")
    invalid = server.get_hayabusa_rules(max_results=0)
    assert "error" in invalid, invalid
    print(invalid)

    print("\nTesting get_hayabusa_rules(max_results=-1) for error handling...")
    negative = server.get_hayabusa_rules(max_results=-1)
    assert "error" in negative, negative
    print(negative)


def main() -> int:
    evtx_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SAMPLE

    test_get_hayabusa_rules()

    print(f"Scanning {evtx_path} (no severity filter)...")
    result = server.scan_evtx(str(evtx_path))
    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        return 1
    print(f"result_count: {result['result_count']}")
    print(json.dumps(result["findings"][:3], indent=2))

    print("\nScanning again with severity='high'...")
    filtered = server.scan_evtx(str(evtx_path), severity="high")
    if "error" in filtered:
        print(f"Error: {filtered['error']}", file=sys.stderr)
        return 1
    print(f"result_count (high+): {filtered['result_count']}")

    print("\nScanning a missing file to check error handling...")
    missing = server.scan_evtx("does-not-exist.evtx")
    print(missing)

    return 0


if __name__ == "__main__":
    sys.exit(main())
