#!/usr/bin/env bash
set -euo pipefail

input=$(cat)
file_path=$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty')

if [ -z "$file_path" ]; then
  exit 0
fi

file_path=${file_path//\\//}

if printf '%s' "$file_path" | grep -qE '(^|/)\.env(\..+)?$|\.key$|\.pem$|(^|/)secrets/|(^|/)credentials/'; then
  echo "BLOCKED: '$file_path' matches a sensitive file pattern (.env, *.key, *.pem, secrets/, credentials/)" >&2
  exit 2
fi

exit 0
