#!/usr/bin/env bash
# Prefetch LFM images onto sealed hotels only. This is the ops step that
# avoids a cold GHCR pull during create (the original sealed timeout).
#
# Does not create a sandbox and does not spend sealed compute. Needs a
# broker key that may call POST /v1/images/prefetch.
#
# Usage:
#   BROKER=https://cathedral.computer \
#   CATHEDRAL_API_KEY=... \
#   ./scripts/prepull-sealed-lfm3.sh
#
# Optional IMAGES='["ghcr.io/cathedralai/room-lfm3-1.7b@sha256:..."]'
set -euo pipefail

BROKER="${BROKER:-${CATHEDRAL_API_URL:-https://cathedral.computer}}"
BROKER="${BROKER%/}"
KEY="${CATHEDRAL_API_KEY:?set CATHEDRAL_API_KEY}"

# Live 1.7B pin from broker/catalog.go. Add more digests after each publish.
DEFAULT_IMAGES='["ghcr.io/cathedralai/room-lfm3-1.7b@sha256:b1ba8837ea388c8c98720772b0f41af5813d4cebf214637fde20aae58a1ea761"]'
IMAGES_JSON="${IMAGES:-$DEFAULT_IMAGES}"

body=$(printf '{"images":%s,"sealed":true}' "$IMAGES_JSON")

echo "POST ${BROKER}/v1/images/prefetch (sealed hotels only)"
resp=$(curl -sS -X POST "${BROKER}/v1/images/prefetch" \
  -H "Authorization: Bearer ${KEY}" \
  -H "Content-Type: application/json" \
  -d "$body")
printf '%s\n' "$resp"
id=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("prefetch_id",""))' <<<"$resp")
if [ -z "$id" ]; then
  echo "prefetch did not return prefetch_id" >&2
  exit 1
fi
echo
echo "Poll with:"
echo "  curl -sS -H \"Authorization: Bearer \$CATHEDRAL_API_KEY\" ${BROKER}/v1/images/prefetch/${id}"
