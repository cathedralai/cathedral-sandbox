#!/usr/bin/env bash
# Bounded SNP staging canary (Fred 13 Oct spec).
# Does not bake credentials. Requires STAGING_API_KEY in the environment.
# Do not point this at production. Do not run until inventory is qualified.
set -euo pipefail

# Prefer isolated staging when STAGING_BASE_URL is set.
# Default Railway URL stays cold (acaa2961) until SNP join is deployed there.
BASE="${STAGING_BASE_URL:-https://polariscomputer-staging-staging.up.railway.app}"
KEY="${STAGING_API_KEY:?set STAGING_API_KEY (staging cat_sk only; never the prod key)}"
IDEM_CREATE="${IDEM_CREATE:-snp-canary-create-$(date -u +%Y%m%dT%H%M%SZ)}"
IDEM_EXEC="${IDEM_EXEC:-snp-canary-exec-$(date -u +%Y%m%dT%H%M%SZ)}"
IDEM_DELETE="${IDEM_DELETE:-snp-canary-delete-$(date -u +%Y%m%dT%H%M%SZ)}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/tmp/snp-staging-canary}"
mkdir -p "${EVIDENCE_DIR}"

auth() {
  curl -sS -H "Authorization: Bearer ${KEY}" -H "Accept: application/json" "$@"
}

echo "base=${BASE}"
echo "evidence_dir=${EVIDENCE_DIR}"
echo "=== account ==="
auth "${BASE}/v1/account" | tee "${EVIDENCE_DIR}/account.json" | python3 -c 'import sys,json; d=json.load(sys.stdin); print({k:d.get(k) for k in ("id","email","scopes","key_prefix") if k in d})'

echo "=== create amd_sev_snp deny_all 180s max_spend 1 ==="
CREATE_HTTP=$(curl -sS -o "${EVIDENCE_DIR}/create.json" -w '%{http_code}' \
  -H "Authorization: Bearer ${KEY}" -H "Accept: application/json" \
  -H "Content-Type: application/json" -H "Idempotency-Key: ${IDEM_CREATE}" \
  -d '{"required_hardware":"amd_sev_snp","network":"deny_all","lifetime_seconds":180,"max_spend_usd":"1"}' \
  "${BASE}/v1/sandboxes")
echo "http=${CREATE_HTTP}"
python3 -m json.tool "${EVIDENCE_DIR}/create.json" | head -80
SID=$(python3 -c 'import json; print(json.load(open("'"${EVIDENCE_DIR}"'/create.json")).get("id") or "")')
if [ -z "${SID}" ]; then
  echo "CREATE_FAILED: no sandbox id (need SNP adapter modules + qualified worker)"
  exit 1
fi

echo "=== poll ==="
for i in $(seq 1 36); do
  auth "${BASE}/v1/sandboxes/${SID}" > "${EVIDENCE_DIR}/status.json"
  ST=$(python3 -c 'import json; d=json.load(open("'"${EVIDENCE_DIR}"'/status.json")); print(d.get("state") or d.get("status") or "?")')
  echo "t=${i} state=${ST}"
  case "${ST}" in running|ready|active) break ;; failed|error|deleted) cat "${EVIDENCE_DIR}/status.json"; exit 1 ;; esac
  sleep 5
done

echo "=== exec known argv ==="
curl -sS -H "Authorization: Bearer ${KEY}" -H "Accept: application/json" \
  -H "Content-Type: application/json" -H "Idempotency-Key: ${IDEM_EXEC}" \
  -d '{"cmd":["sh","-c","printf cathedral-snp-canary-ok\\n"],"timeout_seconds":10}' \
  "${BASE}/v1/sandboxes/${SID}/execs" | tee "${EVIDENCE_DIR}/exec.json" | python3 -m json.tool | head -60

echo "=== native-evidence ==="
auth "${BASE}/v1/sandboxes/${SID}/native-evidence" | tee "${EVIDENCE_DIR}/native-evidence.json" | python3 -m json.tool | head -80

echo "=== delete ==="
curl -sS -X DELETE -H "Authorization: Bearer ${KEY}" -H "Accept: application/json" \
  -H "Idempotency-Key: ${IDEM_DELETE}" \
  "${BASE}/v1/sandboxes/${SID}" | tee "${EVIDENCE_DIR}/delete.json" | python3 -m json.tool | head -40

echo "DONE sandbox=${SID}"
echo "NEXT: independent central_guest_gone proof + one settlement (see snp-staging-prober-notes-20261013.md)."
echo "Container DELETE is not absence."
