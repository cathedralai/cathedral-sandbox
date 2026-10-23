#!/usr/bin/env bash
# Run the minute staging SNP policy is renewed.
# Flow: roster refresh → bump supply → wait for waiting offer →
#       Join + IDE (+ ditto/reliquary) create→exec→delete → write evidence.
#
# Requires:
#   - CATHEDRAL_STAGING_TEST_API_KEY in .local/staging-var-keys.json
#   - scripts/staging_join_roster_refresh.sh prerequisites (bt wallet + roster bearer)
#   - railway CLI linked to polariscomputer-staging (for supply bump / offer poll)
#
# Usage:
#   bash scripts/staging_sealed_retest_after_policy.sh
#   WAIT_OFFER_SECONDS=600 bash scripts/staging_sealed_retest_after_policy.sh

set -euo pipefail

ROOT="${CATHEDRAL_ROOT:-/Users/user/Documents/Cathedral}"
BASE="${CATHEDRAL_STAGING_API:-https://api-staging.cathedral.computer}"
KEYS="${ROOT}/.local/staging-var-keys.json"
EVIDENCE_DIR="${ROOT}/docs/evidence"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${EVIDENCE_DIR}/STAGING_SEALED_RETEST_${STAMP}.md"
WAIT_OFFER_SECONDS="${WAIT_OFFER_SECONDS:-900}"
POLL_INTERVAL="${POLL_INTERVAL:-10}"
RAILWAY_PROJECT="${RAILWAY_PROJECT:-d55649ed-2cb9-49b3-85b0-0883f03fbf31}"
RAILWAY_ENV="${RAILWAY_ENV:-staging}"
RAILWAY_SERVICE="${RAILWAY_SERVICE:-polariscomputer-staging}"
BAKE="${ROOT}/.local/polariscomputer-main-snp-bake"

need() { command -v "$1" >/dev/null || { echo "refusing: missing $1" >&2; exit 2; }; }
need curl
need python3
need uuidgen || true

if [[ ! -f "$KEYS" ]]; then
  echo "refusing: missing $KEYS" >&2
  exit 2
fi

KEY="$(python3 -c 'import json;print(json.load(open("'"$KEYS"'"))["CATHEDRAL_STAGING_TEST_API_KEY"])')"
AUTH=( -H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json" )

log() { printf '%s\n' "$*" | tee -a "$OUT.tmp"; }

mkdir -p "$EVIDENCE_DIR"
: >"$OUT.tmp"
log "# Staging sealed retest — ${STAMP}"
log ""
log "## Health"
HEALTH="$(curl -sS -m 20 "${BASE}/health")"
log '```json'
log "$HEALTH"
log '```'
TIP="$(python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(d.get("deployment_id",""))' "$HEALTH")"
SHA="$(python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(d.get("deployed_sha",""))' "$HEALTH")"
log ""
log "| tip | \`${TIP}\` |"
log "| sha | \`${SHA}\` |"
log ""

log "## 1. Roster refresh"
if bash "${ROOT}/scripts/staging_join_roster_refresh.sh" | tee -a "$OUT.tmp"; then
  log "roster: OK"
else
  log "roster: FAILED (continue; supply bump may still help)"
fi
log ""

log "## 2. Supply bump + wait for waiting offer"
if [[ -d "$BAKE" ]] && command -v railway >/dev/null; then
  (
    cd "$BAKE"
    railway ssh -p "$RAILWAY_PROJECT" -e "$RAILWAY_ENV" -s "$RAILWAY_SERVICE" -- python3 - <<'PY'
import asyncio, os, asyncpg
async def main():
    url = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://").replace("postgres://", "postgresql://")
    conn = await asyncpg.connect(url)
    await conn.execute("UPDATE cathedral_snp_supply SET listed_at = NOW()")
    n = await conn.fetchval("SELECT count(*) FROM cathedral_snp_guest_offers WHERE state='waiting'")
    print(f"supply_bumped waiting_now={n}")
    await conn.close()
asyncio.run(main())
PY
  ) | tee -a "$OUT.tmp" || log "railway supply bump skipped/failed"
else
  log "railway bake path missing — skip DB bump; rely on discovery after roster"
fi

DEADLINE=$((SECONDS + WAIT_OFFER_SECONDS))
OFFER=""
BOOT=""
while (( SECONDS < DEADLINE )); do
  if [[ -d "$BAKE" ]] && command -v railway >/dev/null; then
    ROW="$(
      cd "$BAKE"
      railway ssh -p "$RAILWAY_PROJECT" -e "$RAILWAY_ENV" -s "$RAILWAY_SERVICE" -- python3 - <<'PY' 2>/dev/null
import asyncio, os, asyncpg
async def main():
    url = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://").replace("postgres://", "postgresql://")
    conn = await asyncpg.connect(url)
    r = await conn.fetchrow("SELECT id::text, boot_id FROM cathedral_snp_guest_offers WHERE state='waiting' ORDER BY updated_at DESC LIMIT 1")
    await conn.close()
    if r:
        print(f"{r['id']}|{r['boot_id']}")
    else:
        print("NONE")
asyncio.run(main())
PY
    )"
    log "poll: $ROW"
    if [[ "$ROW" != NONE && "$ROW" == *"|"* ]]; then
      OFFER="${ROW%%|*}"
      BOOT="${ROW##*|}"
      break
    fi
  else
    log "no railway — will attempt creates without waiting-offer gate"
    OFFER="skipped"
    BOOT="unknown"
    break
  fi
  sleep "$POLL_INTERVAL"
done

if [[ -z "$OFFER" ]]; then
  log ""
  log "## RESULT: BLOCKED — no waiting offer within ${WAIT_OFFER_SECONDS}s"
  log "Likely causes: policy still expired, JoinRejected, guest down."
  mv "$OUT.tmp" "$OUT"
  echo "wrote $OUT"
  exit 3
fi
if [[ "$OFFER" == "skipped" ]]; then
  log "waiting-offer gate skipped (no railway); creates may still 503 if policy expired"
fi

log ""
log "waiting offer \`${OFFER}\` boot \`${BOOT}\`"
log ""

smoke() {
  local label="$1"
  local body="$2"
  local ik="${label}-${STAMP}-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:12])')"
  log "### ${label}"
  local create
  create="$(curl -sS -m 90 -w "\nHTTP=%{http_code}" -X POST "${BASE}/v1/sandboxes" \
    "${AUTH[@]}" -H "Idempotency-Key: ${ik}" -d "$body")"
  local http create_json
  http="$(printf '%s' "$create" | sed -n 's/^HTTP=//p' | tail -1)"
  create_json="$(printf '%s' "$create" | sed '/^HTTP=/d')"
  log "create HTTP=${http}"
  log '```json'
  log "$create_json"
  log '```'
  local sid
  sid="$(python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(d.get("id") or "")' "$create_json")"
  if [[ -z "$sid" ]]; then
    log "**FAIL** ${label}: no sandbox id"
    return 1
  fi
  local state="" i
  for i in $(seq 1 40); do
    sleep 3
    local get
    get="$(curl -sS -m 30 "${AUTH[@]}" "${BASE}/v1/sandboxes/${sid}")"
    state="$(python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(d.get("state",""))' "$get")"
    local hw
    hw="$(python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(d.get("hardware",""))' "$get")"
    log "poll ${i}: state=${state} hardware=${hw}"
    case "$state" in running|failed|ended) break ;; esac
  done
  if [[ "$state" != "running" ]]; then
    log "**FAIL** ${label}: state=${state}"
    return 1
  fi
  local eik="${label}-exec-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:10])')"
  local exec_out
  exec_out="$(curl -sS -m 90 -w "\nHTTP=%{http_code}" -X POST "${BASE}/v1/sandboxes/${sid}/exec" \
    "${AUTH[@]}" -H "Idempotency-Key: ${eik}" \
    -d "{\"command\":[\"/bin/sh\",\"-c\",\"echo ${label}_OK && uname\"]}")"
  local ehttp ejson
  ehttp="$(printf '%s' "$exec_out" | sed -n 's/^HTTP=//p' | tail -1)"
  ejson="$(printf '%s' "$exec_out" | sed '/^HTTP=/d')"
  log "exec HTTP=${ehttp}"
  log '```json'
  log "$ejson"
  log '```'
  local ec
  ec="$(python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(d.get("exit_code"))' "$ejson")"
  if [[ "$ec" != "0" ]]; then
    log "**FAIL** ${label}: exit_code=${ec}"
    curl -sS -m 30 -X DELETE "${BASE}/v1/sandboxes/${sid}" "${AUTH[@]}" \
      -H "Idempotency-Key: ${label}-del-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:8])')" >/dev/null || true
    return 1
  fi
  curl -sS -m 30 -X DELETE "${BASE}/v1/sandboxes/${sid}" "${AUTH[@]}" \
    -H "Idempotency-Key: ${label}-del-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:8])')" >/dev/null || true
  log "**GREEN** ${label} sid=\`${sid}\` exit_code=0"
  log ""
  echo "$sid"
}

FAIL=0
JOIN_BODY='{"required_hardware":"amd_sev_snp","max_spend_usd":"1","lifetime_seconds":180}'
IDE_BODY='{"required_hardware":"amd_sev_snp","resources":{"cpu":1,"memory_gib":1,"disk_gib":5},"network":"deny_all","lifetime_seconds":180,"max_spend_usd":"1","labels":{"customer":"agent_ide","smoke":"post-policy-'"$STAMP"'"}}'
DITTO_BODY='{"required_hardware":"amd_sev_snp","resources":{"cpu":1,"memory_gib":1,"disk_gib":5},"network":"deny_all","lifetime_seconds":180,"max_spend_usd":"1","labels":{"customer":"ditto","smoke":"post-policy-'"$STAMP"'"}}'
RELI_BODY='{"required_hardware":"amd_sev_snp","resources":{"cpu":1,"memory_gib":1,"disk_gib":5},"network":"deny_all","lifetime_seconds":180,"max_spend_usd":"1","labels":{"customer":"reliquary","smoke":"post-policy-'"$STAMP"'"}}'

log "## 3. Smokes"
smoke join "$JOIN_BODY" || FAIL=1
smoke agent_ide "$IDE_BODY" || FAIL=1
smoke ditto "$DITTO_BODY" || FAIL=1
smoke reliquary "$RELI_BODY" || FAIL=1

log "## Verdict"
if [[ "$FAIL" -eq 0 ]]; then
  log "**GREEN** — Join + IDE + ditto + reliquary create→exec→delete on tip \`${TIP}\`."
else
  log "**PARTIAL/FAIL** — see sections above."
fi

mv "$OUT.tmp" "$OUT"
echo "wrote $OUT"
exit "$FAIL"
