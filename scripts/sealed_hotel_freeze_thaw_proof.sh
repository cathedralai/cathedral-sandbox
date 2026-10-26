#!/usr/bin/env bash
# Live proof: sealed hotel create → freeze → thaw → exec → delete via thin broker.
#
# Fred/Spock model (2026-10-26): polaris-sealed guest takes free sealed capacity
# from the shared pool (today c46-sealed); const stays alone on nc-sealed.
# This script does not pin a hotel id — the broker picks the arena.
#
# Usage:
#   export CATHEDRAL_BROKER_URL=https://live.cathedral.computer
#   export CATHEDRAL_BROKER_BEARER=...   # polaris-sealed guest once minted, or ops temp
#   ./scripts/sealed_hotel_freeze_thaw_proof.sh
#
# Exit 0 only if every step passes. Writes evidence under docs/evidence/.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
URL="${CATHEDRAL_BROKER_URL:?set CATHEDRAL_BROKER_URL}"
KEY="${CATHEDRAL_BROKER_BEARER:?set CATHEDRAL_BROKER_BEARER}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${CATHEDRAL_EVIDENCE_DIR:-$ROOT/docs/evidence}"
OUT="$OUT_DIR/SEALED_FREEZE_THAW_PROOF_${STAMP}.md"
LABEL="freeze-thaw-proof-${STAMP}"

mkdir -p "$OUT_DIR"
auth=(-H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json")

json_get() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d'"$1"')'
}

{
  echo "# Sealed hotel freeze/thaw proof — ${STAMP}"
  echo
  echo "- Broker: \`${URL}\`"
  echo "- Guest: broker-picked sealed hotel (no manual hotel pin)"
  echo "- Expect: create sealed → freeze → thaw → exec → delete"
  echo

  echo "## 0. Hotels"
  hotels="$(curl -sS -m 30 "${auth[@]}" "${URL}/v1/hotels")"
  echo '```json'
  echo "$hotels" | python3 -m json.tool
  echo '```'
  echo

  echo "## 1. Create (sealed)"
  create_body="$(python3 - <<'PY'
import json
print(json.dumps({
  "image": "alpine:3.20",
  "sealed": True,
  "network": {"mode": "deny_all"},
  "labels": {"smoke": "freeze-thaw", "job": "'"${LABEL}"'"},
}))
PY
)"
  create_hdr="$(mktemp)"
  create_code="$(curl -sS -m 180 -D "$create_hdr" -o /tmp/create_body.json -w '%{http_code}' \
    "${auth[@]}" -d "$create_body" "${URL}/v1/sandboxes")"
  echo "- HTTP ${create_code}"
  echo '```json'
  python3 -m json.tool </tmp/create_body.json
  echo '```'
  if [[ "$create_code" != "202" && "$create_code" != "200" ]]; then
    echo "**FAIL** create"
    exit 1
  fi
  sid="$(python3 -c 'import json; print(json.load(open("/tmp/create_body.json"))["id"])')"
  hotel="$(python3 -c 'import json; d=json.load(open("/tmp/create_body.json")); print(d.get("hotel") or d["id"].split(".",1)[0])')"
  echo "- sandbox_id: \`${sid}\`"
  echo "- hotel (broker picked): \`${hotel}\`"
  if [[ "$hotel" == "nc-sealed" ]]; then
    echo "**FAIL** landed on nc-sealed (const fence); polaris-sealed guest must not use nc-sealed"
    curl -sS -m 60 -X DELETE "${auth[@]}" "${URL}/v1/sandboxes/${sid}" >/dev/null || true
    exit 1
  fi
  echo

  # Wait running
  for _ in $(seq 1 60); do
    state="$(curl -sS -m 30 "${auth[@]}" "${URL}/v1/sandboxes/${sid}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))')"
    [[ "$state" == "running" ]] && break
    sleep 2
  done
  echo "## 2. State before freeze: \`${state}\`"
  [[ "$state" == "running" ]] || { echo "**FAIL** not running"; exit 1; }
  echo

  echo "## 3. Freeze"
  freeze_code="$(curl -sS -m 60 -o /tmp/freeze.json -w '%{http_code}' \
    -X POST "${auth[@]}" "${URL}/v1/sandboxes/${sid}/freeze")"
  echo "- HTTP ${freeze_code}"
  echo '```json'
  python3 -m json.tool </tmp/freeze.json || cat /tmp/freeze.json
  echo '```'
  [[ "$freeze_code" == "200" ]] || { echo "**FAIL** freeze"; exit 1; }
  fstate="$(python3 -c 'import json; print(json.load(open("/tmp/freeze.json")).get("state",""))')"
  [[ "$fstate" == "frozen" ]] || { echo "**FAIL** state after freeze: ${fstate}"; exit 1; }
  echo

  echo "## 4. Thaw"
  thaw_code="$(curl -sS -m 60 -o /tmp/thaw.json -w '%{http_code}' \
    -X POST "${auth[@]}" "${URL}/v1/sandboxes/${sid}/thaw")"
  echo "- HTTP ${thaw_code}"
  echo '```json'
  python3 -m json.tool </tmp/thaw.json || cat /tmp/thaw.json
  echo '```'
  [[ "$thaw_code" == "200" ]] || { echo "**FAIL** thaw"; exit 1; }
  tstate="$(python3 -c 'import json; print(json.load(open("/tmp/thaw.json")).get("state",""))')"
  [[ "$tstate" == "running" ]] || { echo "**FAIL** state after thaw: ${tstate}"; exit 1; }
  echo

  echo "## 5. Exec after thaw"
  exec_body='{"cmd":["/bin/sh","-c","echo freeze-thaw-ok && uname -a"],"timeout_seconds":60}'
  exec_code="$(curl -sS -m 90 -o /tmp/exec.json -w '%{http_code}' \
    "${auth[@]}" -d "$exec_body" "${URL}/v1/sandboxes/${sid}/exec")"
  echo "- HTTP ${exec_code}"
  echo '```json'
  python3 -m json.tool </tmp/exec.json || cat /tmp/exec.json
  echo '```'
  [[ "$exec_code" == "200" ]] || { echo "**FAIL** exec"; exit 1; }
  exit_code="$(python3 -c 'import json; print(json.load(open("/tmp/exec.json")).get("exit_code",1))')"
  [[ "$exit_code" == "0" ]] || { echo "**FAIL** exec exit ${exit_code}"; exit 1; }
  echo

  echo "## 6. Delete"
  del_code="$(curl -sS -m 60 -o /tmp/del.json -w '%{http_code}' \
    -X DELETE "${auth[@]}" "${URL}/v1/sandboxes/${sid}")"
  echo "- HTTP ${del_code}"
  [[ "$del_code" == "204" || "$del_code" == "200" ]] || { echo "**FAIL** delete"; exit 1; }
  echo
  echo "## Verdict: **PASS** on hotel \`${hotel}\` sandbox \`${sid}\`"
} | tee "$OUT"

echo "Wrote $OUT" >&2
