# Toby — commands to finish #274 (copy/paste)

Remote SSH from the agent may be auto-blocked. Run these yourself on your
machine and paste the output back (or keep running until green).

## Already cleared (do not redo unless regressing)

On `:2225` with tip `73894ba+`: A launch bind, B.prepare, runsc pin, B.a
(no-swap/tmpfs/LUKS), B.c (runsc alpine), B.d BLOCKED. Report:
`docs/evidence/snp-bf-report-20261009T175646Z.json`.

## 0) Sync local + guest

```bash
# laptop
cd /path/to/cathedral-sandbox
git fetch origin && git checkout feat/tee-box-snp-startup-gates && git pull --ff-only

# guest
ssh -p 2225 root@84.32.220.48
cd /opt/cathedral/sandbox
git fetch origin && git reset --hard origin/feat/tee-box-snp-startup-gates
export PYTHONPATH=/opt/cathedral/sandbox TEE=snp
unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
```

## 1) Re-confirm clearout (optional)

```bash
python3 scripts/tee_box_snp_e2e/run_bf_clear.py | tee /tmp/bf-clear.log
# expect SUMMARY with PASS>=9, BLOCKED=1 (B.d), no FAIL
```

## 2) Remaining B — tee-box worker path (main gap)

The TDX harness (`harness.py`) still assumes RTMR3/TDX quotes. On SNP you must
either:

**Option A (preferred short path):** drive the box API manually after starting
the worker with live HOST_DATA (no inject):

```bash
# on :2225 — marker already written by setup prepare
test -f /run/cathedral-tee-e2e/TEST_BOX || sudo bash scripts/tee_box_tdx_e2e/setup.sh prepare

# start worker (SNP). Adjust if your image uses a different entrypoint:
cd /opt/cathedral/sandbox
# If serve_worker is TDX-only, use cathedral CLI tee-box start for snp — see docs/TEE_BOX_SERVICE.md
# Capture: boot_id, lease create, sandbox create/exec/delete, second customer refused, 401s.
```

**Option B:** Port `harness.py` `--tee snp` (skip RTMR3; assert
`fresh_boot_hardware_backed=false`; use snpguest evidence). Bigger change;
do if A cannot exercise B.b/e/f/g.

Paste back: worker start log, `GET /v1/box` JSON, lease/sandbox results,
any FAIL.

## 3) Record + close checklist

```bash
# update docs/TEE_BOX_SNP_E2E_RESULTS.md verdicts
# commit + push feat/tee-box-snp-startup-gates
# gh issue comment 274 --repo cathedralai/cathedral-sandbox --body '...'
```

Close #274 only when B.b/e/f/g are PASS or honestly BLOCKED with linked
reason, and C/D/E marked for scope. B.d stays BLOCKED forever unless
leadership accepts software-lease substitute.

## Agent note

If Cursor blocks `ssh/scp` to `84.32.220.48`, approve the Smart Mode card or
run the commands above and paste logs — same outcome.
