# Toby — commands to finish #274 (copy/paste)

Remote SSH from the agent may be auto-blocked. Run these yourself and paste
output back (or approve Smart Mode when the agent SSHs).

## What your last paste showed

| Result | Meaning |
| --- | --- |
| `A.launch_bind` **FAIL** `No module named 'cryptography'` | You ran `python3` (system). `setup.sh prepare` puts crypto in **`/opt/cathedral-e2e/venv`**. Not a HOST_DATA failure. |
| B.prepare / runsc / B.a / B.c | Still **PASS** |
| B.d | **BLOCKED** (expected on SNP) |
| B.b/e/f/g + C–E | Still **UNTESTED** (need worker) |

## 0) On `:2225` — fix A, re-run clearout

```bash
ssh -p 2225 root@84.32.220.48
cd /opt/cathedral/sandbox
git fetch origin && git reset --hard origin/feat/tee-box-snp-startup-gates
export PYTHONPATH=/opt/cathedral/sandbox TEE=snp
unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX

# harness venv (cryptography lives here after prepare)
PY=/opt/cathedral-e2e/venv/bin/python
test -x "$PY" || TEE=snp bash scripts/tee_box_tdx_e2e/setup.sh prepare
"$PY" -c 'import cryptography; print("cryptography", cryptography.__version__)'

# re-run clearout with venv python (tip after pull prefers this automatically)
"$PY" scripts/tee_box_snp_e2e/run_bf_clear.py | tee /tmp/bf-clear.log
# expect: A.launch_bind PASS, no FAIL, B.d BLOCKED, rest UNTESTED
```

## 1) Start SNP tee-box worker smoke (real HOST_DATA, no inject)

Clearout green is not enough — `serve-snp` needs throwaway signed
validator-access materials. Script builds those and starts the worker:

```bash
# on laptop: commit+push feat/tee-box-snp-startup-gates first, then on guest:
cd /opt/cathedral/sandbox
git fetch origin && git reset --hard origin/feat/tee-box-snp-startup-gates
export PYTHONPATH=/opt/cathedral/sandbox TEE=snp
unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
PY=/opt/cathedral-e2e/venv/bin/python

"$PY" scripts/tee_box_snp_e2e/start_worker_smoke.py
# expect: worker_smoke=PASS … cathedral_effective_startup_v1
# log: /var/lib/cathedral-e2e/snp-worker/worker.log
```

If it fails, paste the tail of `worker.log`.

## 2) B.b / B.e / B.f / B.g — fork (honest)

Tee-box routes require **central-access signatures** from the measured root
private key. That seed is offline with **Fred** (`cathedral-root-1`); it is
not on `:2225`. The TDX harness injects throwaway roots + MRCONFIGID — that
is **not** allowed as a measured SNP PASS.

| Path | What it proves | Claim |
| --- | --- | --- |
| **A. Fred signs** central requests against live `:2225` | Full B matrix on measured image | Can claim measured |
| **B. Inject guest** (`:2224` or harness inject) | Functional B matrix | Dev only — not sealed PASS |
| **C. Honest BLOCKED** on #274 | Document why API cannot be driven without root seed | Closes with BLOCKED |

Do **not** overwrite `/usr/share/cathedral/central-root-keys.json` on `:2225`.

## 3) Close checklist

- Update `docs/TEE_BOX_SNP_E2E_RESULTS.md`
- Comment on #274
- Close only when B.b/e/f/g are PASS or honest BLOCKED; B.d stays BLOCKED

## Agent note

Approve Smart Mode SSH to `84.32.220.48` if you want the agent to drive the guest.
