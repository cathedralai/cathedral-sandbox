#!/bin/sh
# llama-server for one baked-in LFM3 GGUF. OpenAI-compatible on :8080.
# Network is deny_all in a sealed sandbox; nothing is downloaded at start.
set -eu

MODEL="${LFM3_MODEL:?LFM3_MODEL is required}"
HOST="${LFM3_HOST:-0.0.0.0}"
PORT="${LFM3_PORT:-8080}"
THREADS="${LFM3_THREADS:-0}"
REASONING="${LFM3_REASONING:-off}"
ALIAS="${LFM3_ALIAS:-lfm3}"
MMPROJ="${LFM3_MMPROJ:-}"

if [ -n "$MMPROJ" ] && [ -f "$MMPROJ" ]; then
  exec llama-server \
    -m "$MODEL" \
    --mmproj "$MMPROJ" \
    --host "$HOST" \
    --port "$PORT" \
    --threads "$THREADS" \
    --temp 0.1 \
    --reasoning "$REASONING" \
    --alias "$ALIAS"
fi

exec llama-server \
  -m "$MODEL" \
  --host "$HOST" \
  --port "$PORT" \
  --threads "$THREADS" \
  --temp 0.1 \
  --reasoning "$REASONING" \
  --alias "$ALIAS"
