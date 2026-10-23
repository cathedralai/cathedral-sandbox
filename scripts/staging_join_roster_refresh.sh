#!/usr/bin/env bash
# Post a fresh Eng-signed UID5 join roster to api-staging.
# Requires:
#   - bt wallet validator/default = 5HNKFe… (Eng)
#   - roster bearer file (0600), default: agent-store eng-credentials-2026-10-18/roster.bearer
#   - polariscomputer .venv with bittensor + cathedral-validator on PYTHONPATH
#
# Durable host (preferred): Cherry 84.32.220.46
#   systemd timer cathedral-staging-join-roster.timer (*/20)
#   CATHEDRAL_SNP_ROSTER_URL + CATHEDRAL_SNP_ROSTER_TOKEN_FILE on the unit
#   Exec: /srv/cathedral-join-roster/bin/post-staging-join-roster
# Laptop fallback only (API max age default 1800s):
#   */20 * * * * .../scripts/staging_join_roster_refresh.sh >>/tmp/roster-refresh.log 2>&1

set -euo pipefail

ROOT="${CATHEDRAL_ROOT:-/Users/user/Documents/Cathedral}"
PY="${ROOT}/polariscomputer/.venv/bin/python"
STORE_DEFAULT="${HOME}/Library/Application Support/Cursor/AgentStores/cursor_agent_stores/31d68d91-72f6-4d5f-b81c-5e20ec0e8abf/files/eng-credentials-2026-10-18/roster.bearer"
BEARER_FILE="${CATHEDRAL_SNP_ROSTER_TOKEN_FILE:-$STORE_DEFAULT}"
API="${CATHEDRAL_STAGING_API:-https://api-staging.cathedral.computer}"
export PYTHONPATH="${ROOT}/cathedral-validator${PYTHONPATH:+:$PYTHONPATH}"

if [[ ! -x "$PY" ]]; then
  echo "refusing: missing $PY" >&2
  exit 2
fi
if [[ ! -f "$BEARER_FILE" ]]; then
  echo "refusing: missing bearer $BEARER_FILE" >&2
  exit 2
fi

exec "$PY" - "$BEARER_FILE" "$API" <<'PY'
import json, sys, time
from datetime import datetime, timezone
from pathlib import Path

import bittensor as bt
from cathedral_thin.independent_runtime.snp_roster import (
    EVIDENCE_KIND_SEV_SNP,
    build_snp_roster,
    post_snp_roster,
    sign_snp_roster,
)

bearer_file, api = sys.argv[1], sys.argv[2]
EXPECTED = "5HNKFeHjvppKyKHTA1SK4rN7L2SZWpJeoNjeLo4DDg2FcRKh"
hk = bt.wallet(name="validator", hotkey="default").hotkey
if str(hk.ss58_address) != EXPECTED:
    raise SystemExit(f"hotkey mismatch: {hk.ss58_address}")

block = max(int(time.time()), 1)
rows = [{
    "tee_kind": EVIDENCE_KIND_SEV_SNP,
    "uid": 5,
    "hotkey": "5CftP3XTpK9FF79xdpAZLCMbBLUwBtm7CVU8h3MZyGU5snzX",
    "endpoint": "https://84.32.220.46:8081",
    "machine_id": "1d7ba6c7db10f27c4b7a656b15821e0255edb416894fe23dffab3bcae7569165",
}]
doc = build_snp_roster(
    healthy_rows=rows,
    network="test",
    netuid=584,
    block_number=block,
    validator_uid=0,
    validator_hotkey=str(hk.ss58_address),
    generated_at=datetime.now(timezone.utc),
)
signed = sign_snp_roster(doc, keypair=hk)
token = Path(bearer_file).read_text().strip()
ack = post_snp_roster(url=f"{api.rstrip('/')}/v1/cathedral/snp/roster", document=signed, token=token)
print(json.dumps({"status": "POSTED", **ack}, sort_keys=True))
PY
