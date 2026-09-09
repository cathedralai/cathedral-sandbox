#!/usr/bin/env bash
# Item-local acceptance for the miner update channel.
#
# Runs the real signer and the real state machine against a fake host tree, so
# it finishes in seconds and needs no confidential guest, no registry and no
# network.
#
# SCOPE, stated plainly: this is LOCAL SYNTHETIC PROOF. It shows the signed
# channel behaves correctly. It does NOT show any real miner updated, does not
# touch SEV-SNP hardware, and does not prove a live customer path. Those are
# separate and are not claimed here.
#
#   bash deploy/miner-update/acceptance.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${ROOT}/.venv/bin/python"
[[ -x "${PY}" ]] || PY="$(command -v python3)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; exit 1; }

OLD="ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:$(printf '1%.0s' {1..64})"
NEW="ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:$(printf '2%.0s' {1..64})"

echo "== 1. offline signing =="
"${PY}" - "${WORK}" <<'PY'
import os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
work = sys.argv[1]
key = Ed25519PrivateKey.generate()
path = os.path.join(work, "key.pem")
with open(path, "wb") as handle:
    handle.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"acceptance"),
    ))
os.chmod(path, 0o600)
public = key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
).hex()
import json
with open(os.path.join(work, "keys.json"), "w") as handle:
    json.dump({"schema": "cathedral_sn39_miner_release_keys_v1",
               "keys": {"sn39-miner-release-1": public}}, handle)
PY
pass "generated an encrypted release key"

export CATHEDRAL_MINER_RELEASE_PASSPHRASE=acceptance
PYTHONPATH="${ROOT}" "${PY}" "${ROOT}/deploy/miner-update/build_signed_miner_release.py" canary \
  --private-key "${WORK}/key.pem" --signing-key-id sn39-miner-release-1 \
  --image "${NEW}" --runtime-contract snp-signed-validator-fleet-v1 \
  --launcher "${ROOT}/scripts/run_sn39_snp_miner.sh" \
  --version 2026.09.09 --sequence 5 --lifetime-seconds 604800 \
  --out "${WORK}/canary.json" >/dev/null
pass "signed a canary"

PYTHONPATH="${ROOT}" "${PY}" "${ROOT}/deploy/miner-update/build_signed_miner_release.py" stable \
  --private-key "${WORK}/key.pem" --signing-key-id sn39-miner-release-1 \
  --promote "${WORK}/canary.json" --sequence 4 --lifetime-seconds 604800 \
  --out "${WORK}/stable.json" >/dev/null
pass "promoted that exact canary to stable"

if PYTHONPATH="${ROOT}" "${PY}" "${ROOT}/deploy/miner-update/build_signed_miner_release.py" stable \
  --private-key "${WORK}/key.pem" --signing-key-id sn39-miner-release-1 \
  --promote "${WORK}/canary.json" --sequence 4 --lifetime-seconds 604800 \
  --out "${WORK}/stable.json" >/dev/null 2>&1; then
  fail "the signer overwrote an existing signed record"
fi
pass "refused to overwrite an existing signed record"

echo "== 2. applying the release =="
cat >"${WORK}/miner.env" <<EOF
# Cathedral SN39 SNP miner
SN39_SNP_MINER_IMAGE=${OLD}
CATHEDRAL_MINER_HOTKEY=5ERBwsMBUrvjCVcXu1B73m7Ne693DwKEi68q2ionAkWtdALT
CATHEDRAL_PUBLIC_ENDPOINT=https://167.150.153.139:8081
EOF

PYTHONPATH="${ROOT}" "${PY}" - "${WORK}" "${NEW}" "${OLD}" <<'PY'
import json, sys
from pathlib import Path
from cathedral.miner_updater import (
    IMAGE_VARIABLE, MinerUpdateError, MinerUpdateHalted, MinerUpdaterHost,
    describe_status, read_env_assignments, read_state, update_once,
)
from cathedral.miner_update_cli import load_trusted_keys

work, new_image, old_image = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
metadata = (work / "stable.json").read_bytes()
trusted = load_trusted_keys(work / "keys.json")

state = {"restarts": 0, "pulled": [], "running": old_image,
         "durable": "before", "follow": True, "safe": True}

def restart():
    state["restarts"] += 1
    if state["follow"]:
        state["running"] = read_env_assignments(env_path()).get(IMAGE_VARIABLE)

current_env = {"path": work / "miner.env"}
def env_path():
    return current_env["path"]

def host():
    return MinerUpdaterHost(
        fetch_metadata=lambda: metadata,
        restart_service=restart,
        running_image=lambda: state["running"],
        durable_digest=lambda: state["durable"],
        prepare_image=lambda r: state["pulled"].append(r.image),
        verify_launcher=lambda r: None,
        safe_to_activate=lambda: state["safe"],
        env_path=env_path(),
        state_path=work / "state" / "state.json",
        pause_path=work / "paused",
        lock_path=work / "state" / "updater.lock",
        trusted_keys=trusted,
        now_unix=lambda: 1_500_000_000,
    )

def check(label, condition):
    print("  " + ("PASS" if condition else "FAIL") + "  " + label)
    if not condition:
        sys.exit(1)

before = read_env_assignments(work / "miner.env")

state["safe"] = False
check("an unsafe moment defers without restarting",
      update_once(host(), channel="stable").action == "deferred" and state["restarts"] == 0)
state["safe"] = True

outcome = update_once(host(), channel="stable")
after = read_env_assignments(work / "miner.env")
check("a valid signed release activates", outcome.action == "activated")
check("the pin moved to the released digest", after[IMAGE_VARIABLE] == new_image)
check("the released image is what is running", state["running"] == new_image)
check("the miner hotkey survived", after["CATHEDRAL_MINER_HOTKEY"] == before["CATHEDRAL_MINER_HOTKEY"])
check("the endpoint survived", after["CATHEDRAL_PUBLIC_ENDPOINT"] == before["CATHEDRAL_PUBLIC_ENDPOINT"])
check("operator comments survived", "# Cathedral SN39 SNP miner" in (work / "miner.env").read_text())
check("the image was pulled before the pin was swapped", state["pulled"] == [new_image])
check("re-running the same release is a no-op",
      update_once(host(), channel="stable").action == "current")

tampered = json.loads(metadata)
tampered["release"]["image"] = "ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:" + "3" * 64
bad = host()
bad.fetch_metadata = lambda: json.dumps(tampered).encode()
try:
    update_once(bad, channel="stable")
    check("a tampered record is refused", False)
except MinerUpdateError as exc:
    check("a tampered record is refused", "refused" in str(exc))
check("the pin is unchanged after a refusal",
      read_env_assignments(work / "miner.env")[IMAGE_VARIABLE] == new_image)

(work / "paused").write_text("x")
check("the operator pause stops the check",
      update_once(host(), channel="stable").action == "paused")
(work / "paused").unlink()

status = json.dumps(describe_status(host()))
check("status reports the version without leaking the hotkey",
      new_image in status and "5ERBws" not in status)

work2 = work / "recovery"
work2.mkdir()
(work2 / "miner.env").write_text(IMAGE_VARIABLE + "=" + old_image + "\nX=1\n")
current_env["path"] = work2 / "miner.env"
state.update(restarts=0, running=old_image, durable="before", follow=True)

def host2():
    h = host()
    h.state_path = work2 / "state.json"
    h.lock_path = work2 / "updater.lock"
    return h

def restart_then_write():
    state["restarts"] += 1
    state["durable"] = "after"
    state["running"] = None

h = host2()
h.restart_service = restart_then_write
try:
    update_once(h, channel="stable")
    check("a release that may have written is never rolled back", False)
except MinerUpdateHalted as exc:
    check("a release that may have written is never rolled back",
          "durable state changed" in str(exc))
check("the halt leaves the latch set for an operator",
      read_state(work2 / "state.json")["stage"] == "may_have_run")
check("status flags that the host needs an operator",
      describe_status(host2())["needs_operator"] is True)
PY

echo "== 3. unit tests =="
PYTHONPATH="${ROOT}" "${PY}" -m pytest \
  "${ROOT}/tests/test_miner_release.py" "${ROOT}/tests/test_miner_updater.py" -q 2>&1 | tail -1

echo
echo "LOCAL SYNTHETIC PROOF ONLY."
echo "Not proven here: a real miner updating, SEV-SNP hardware, any customer path."
