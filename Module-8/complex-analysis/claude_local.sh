#!/bin/bash
ANTHROPIC_BASE_URL="http://localhost:4000" \
ANTHROPIC_AUTH_TOKEN="sk-litellm-dev-key" \
MAX_THINKING_TOKENS=0 \
claude --model llama3.2 "$@"
