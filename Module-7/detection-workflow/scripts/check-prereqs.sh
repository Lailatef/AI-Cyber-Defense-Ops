#!/usr/bin/env bash
set -uo pipefail

missing=()

command -v jq >/dev/null 2>&1 || missing+=("jq")

python_bin=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    python_bin="$candidate"
    break
  fi
done
[ -n "$python_bin" ] || missing+=("python3/python/py")

if [ "${#missing[@]}" -gt 0 ]; then
  echo "WARNING: missing prerequisite(s): ${missing[*]}" >&2
fi

exit 0
