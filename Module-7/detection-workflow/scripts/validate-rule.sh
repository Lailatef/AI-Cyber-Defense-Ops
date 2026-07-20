#!/usr/bin/env bash
set -euo pipefail

input="$(cat)"
file_path="$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty')"

if [[ -z "$file_path" ]]; then
  exit 0
fi

normalized_path="${file_path//\\//}"

if [[ "$normalized_path" != *"/rules/"* && "$normalized_path" != "rules/"* ]]; then
  exit 0
fi

case "$normalized_path" in
  *.yml|*.yaml) ;;
  *) exit 0 ;;
esac

python_bin=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
    python_bin="$candidate"
    break
  fi
done

if [[ -z "$python_bin" ]]; then
  echo "validate-rule: no working python interpreter found" >&2
  exit 2
fi

"$python_bin" - "$file_path" <<'PYEOF'
import sys
import yaml

path = sys.argv[1]
errors = []

try:
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)
except Exception as e:
    print(f"validate-rule: failed to parse YAML in {path}: {e}", file=sys.stderr)
    sys.exit(2)

if not isinstance(doc, dict):
    print(f"validate-rule: {path} is not a valid YAML mapping", file=sys.stderr)
    sys.exit(2)

if not doc.get("title"):
    errors.append("missing 'title' field")

if not doc.get("description"):
    errors.append("missing 'description' field")

tags = doc.get("tags")
if not isinstance(tags, list) or not any(
    isinstance(t, str) and t.startswith("attack.t") for t in tags
):
    errors.append("'tags' must contain at least one 'attack.t' entry")

if errors:
    print(f"validate-rule: {path} is invalid:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(2)

print(f"validate-rule: {path} is valid", file=sys.stderr)
sys.exit(2)
PYEOF
