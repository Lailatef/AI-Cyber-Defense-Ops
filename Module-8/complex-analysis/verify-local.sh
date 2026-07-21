#!/bin/bash
# verify-local.sh — send an analysis/investigation file to the local llama3.2
# model (via the LiteLLM proxy's OpenAI-compatible /v1/chat/completions endpoint)
# for a second-opinion review.
#
# This deliberately bypasses Claude Code's subagent/tool-calling machinery: a 3B
# local model can't reliably drive tool-use, but it handles a plain chat request
# fine. See the module README / investigations notes for context.
#
# Usage: ./verify-local.sh <path-to-analysis-file>
# Env overrides: PROXY_URL (default http://localhost:4000),
#                MODEL (default llama3.2),
#                LITELLM_MASTER_KEY (default sk-litellm-dev-key)
set -euo pipefail

FILE="${1:-}"
if [[ -z "$FILE" ]]; then
  echo "usage: ./verify-local.sh <path-to-analysis-file>" >&2
  exit 2
fi
if [[ ! -f "$FILE" ]]; then
  echo "error: file not found: $FILE" >&2
  exit 2
fi

PROXY_URL="${PROXY_URL:-http://localhost:4000}"
MODEL="${MODEL:-llama3.2}"
AUTH_TOKEN="${LITELLM_MASTER_KEY:-sk-litellm-dev-key}"

SYSTEM_PROMPT="You are a critical reviewer of security analysis writeups. Review the analysis for:
- Unsupported conclusions (claims not backed by the cited evidence)
- Alternative explanations (benign or different readings of the same evidence)
- Logical gaps (missing steps between evidence and conclusion)

For EACH finding/claim in the analysis, output one line:
  <Agrees|Questions|Disagrees>: <short reason>
Respond in plain text only. Do not call tools. Do not emit JSON or function calls."

# Build the request body with jq so the file content is safely JSON-escaped.
# Write it to a temp file rather than a shell variable: on Windows/mingw, passing
# a large body as a curl command-line arg (-d "$BODY") gets truncated crossing the
# process boundary, so the proxy sees a broken request (model=None). --data-binary
# @file avoids the command line entirely.
BODY_FILE=$(mktemp)
trap 'rm -f "$BODY_FILE"' EXIT

jq -n \
  --arg model "$MODEL" \
  --arg sys "$SYSTEM_PROMPT" \
  --arg content "$(cat "$FILE")" \
  '{
     model: $model,
     stream: false,
     temperature: 0.2,
     messages: [
       {role: "system", content: $sys},
       {role: "user",   content: ("Review this analysis:\n\n" + $content)}
     ]
   }' > "$BODY_FILE"

RESP=$(curl -sS "$PROXY_URL/v1/chat/completions" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @"$BODY_FILE")

# Surface proxy/model errors instead of printing an empty result.
CONTENT=$(printf '%s' "$RESP" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)
if [[ -z "$CONTENT" ]]; then
  echo "verify-local: no content returned from $PROXY_URL (model=$MODEL)." >&2
  echo "raw response:" >&2
  printf '%s\n' "$RESP" | jq . >&2 2>/dev/null || printf '%s\n' "$RESP" >&2
  exit 1
fi

echo "===== verify-local review of: $FILE ====="
printf '%s\n' "$CONTENT"
