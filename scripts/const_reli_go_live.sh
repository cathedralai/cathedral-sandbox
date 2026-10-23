#!/usr/bin/env bash
# Plug-and-play CONST limit raise + Reliquary guest guards against live broker.
# Requires Fred's operator key. Does NOT edit config.json (do that on the host
# before stage B). Safe to re-run.
#
# Usage:
#   BROKER_OPERATOR_KEY=… CONST_KEY=… RELIQUARY_KEY=… ./scripts/const_reli_go_live.sh
# Optional: BROKER=https://live.cathedral.computer SKIP_SMOKE=1

set -euo pipefail

BROKER="${BROKER:-https://live.cathedral.computer}"

need() {
  local n="$1"
  if [[ -z "${!n:-}" ]]; then
    echo "refusing: set $n (Fred go-live input)" >&2
    exit 2
  fi
}

need BROKER_OPERATOR_KEY
need CONST_KEY

auth() { curl -sS -H "Authorization: Bearer $1" -H "Content-Type: application/json" "${@:2}"; }

echo "== GET /v1/broker/guests =="
GUESTS_RAW="$(auth "$BROKER_OPERATOR_KEY" "$BROKER/v1/broker/guests")"
echo "$GUESTS_RAW" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("guests:", [g["id"] for g in d.get("guests",[])])'

echo "== PATCH /v1/broker/guests/const =="
PATCH_RAW="$(auth "$BROKER_OPERATOR_KEY" -X PATCH "$BROKER/v1/broker/guests/const" \
  -d '{"max_rooms":4000,"max_creates_per_minute":600,"default_sealed":true,"hotels":["green","nc","c46","c48","nc-sealed"]}')"
echo "$PATCH_RAW" | python3 -c 'import json,sys; g=json.load(sys.stdin); assert g.get("max_rooms")==4000, g; print("patched const", g)'

echo "== CONST quota guard =="
auth "$CONST_KEY" "$BROKER/v1/quota" | python3 -c '
import json,sys
g=json.load(sys.stdin)["guest"]
assert g["id"]=="const" and g["max_rooms"]==4000 and g["max_creates_per_minute"]==600, g
print("const ok", g)
'

if [[ -n "${RELIQUARY_KEY:-}" ]]; then
  echo "== Reliquary quota guard =="
  auth "$RELIQUARY_KEY" "$BROKER/v1/quota" | python3 -c '
import json,sys
g=json.load(sys.stdin)["guest"]
assert g["id"]=="reliquary", g
print("reliquary ok", g)
'
else
  echo "skip Reliquary quota (set RELIQUARY_KEY when Fred mints it)"
fi

smoke_one() {
  local name="$1" key="$2"
  local sid
  sid="$(auth "$key" -X POST "$BROKER/v1/sandboxes" \
    -d '{"image":"alpine:3.20","vcpus":1,"memory_mib":256,"network":{"mode":"deny_all"},"labels":{"smoke":"const-reli-go-live"}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
  echo "$name created $sid"
  auth "$key" -X POST "$BROKER/v1/sandboxes/$sid/exec" \
    -d "{\"cmd\":[\"echo\",\"${name}_OK\"]}" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("exit_code")==0, d; print("exec ok")'
  code="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer $key" "$BROKER/v1/sandboxes/$sid")"
  echo "$name delete $code"
  [[ "$code" == "204" || "$code" == "200" ]]
}

if [[ "${SKIP_SMOKE:-0}" != "1" ]]; then
  echo "== smoke CONST =="
  smoke_one const "$CONST_KEY"
  if [[ -n "${RELIQUARY_KEY:-}" ]]; then
    echo "== smoke Reliquary =="
    smoke_one reliquary "$RELIQUARY_KEY"
  fi
fi

echo "GREEN — const limits raised; Reliquary guards ran if key was set."
