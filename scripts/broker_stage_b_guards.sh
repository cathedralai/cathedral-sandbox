#!/usr/bin/env bash
# Post stage-B guards against live.cathedral.computer (no operator key required).
# Usage:
#   CONST_KEY=… OPS_KEY=… ./scripts/broker_stage_b_guards.sh
# Optional: BROKER=https://live.cathedral.computer HOTEL=nc

set -euo pipefail

BROKER="${BROKER:-https://live.cathedral.computer}"
HOTEL="${HOTEL:-nc}"

need() {
  local n="$1"
  if [[ -z "${!n:-}" ]]; then
    echo "refusing: set $n" >&2
    exit 2
  fi
}

need CONST_KEY
need OPS_KEY

auth() { curl -sS -H "Authorization: Bearer $1" -H "Content-Type: application/json" "${@:2}"; }

echo "== CONST quota =="
code="$(curl -sS -o /tmp/const-quota.json -w '%{http_code}' -H "Authorization: Bearer $CONST_KEY" "$BROKER/v1/quota")"
echo "quota $code"
[[ "$code" == "200" ]]

echo "== ops create/exec/delete =="
SID="$(auth "$OPS_KEY" -X POST "$BROKER/v1/sandboxes" \
  -d '{"image":"alpine:3.20","vcpus":1,"memory_mib":256,"network":{"mode":"deny_all"},"sealed":false,"labels":{"smoke":"stage-b-guard"}}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
echo "sid $SID"
auth "$OPS_KEY" -X POST "$BROKER/v1/sandboxes/$SID/exec" \
  -d '{"cmd":["echo","stage_b_ok"]}' | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("exit_code")==0, d'
del="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer $OPS_KEY" "$BROKER/v1/sandboxes/$SID")"
echo "delete $del"

echo "== CONST hotel receipts filtered =="
auth "$CONST_KEY" "$BROKER/v1/hotels/$HOTEL/receipts" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d.get("filtered") is True and "scanned" in d, d
print("filtered ok scanned=", d.get("scanned"))
'

echo "GREEN — stage B guards passed."
