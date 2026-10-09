# TEE box SEV-SNP e2e results (#274)

Status: **Measured official `:2225` — Phase A + B clearout + `serve-snp` worker
smoke PASS** (live HOST_DATA, no inject). B.d **BLOCKED** (honest). B.b/e/f/g
API matrix **BLOCKED** until Fred signs central-access (root private key offline)
or leadership accepts that scope. C–E still **UNTESTED**. #274 not fully closed.

Evidence: `docs/evidence/snp-bf-report-20261009T175646Z.json`,
worker smoke startup at tip **`e622448`**.

## Machines

| Role | Address |
| --- | --- |
| Host | `ssh root@84.32.220.48` |
| Stock guest (untouched) | `:2222` |
| **Measured official (B–F)** | `:2225` |
| Measured dev | `:2224` |

Sandbox tip: **`e622448`** on `feat/tee-box-snp-startup-gates`.

## Phase verdicts (2026-10-09 on :2225)

| Phase | Verdict | Notes |
| --- | --- | --- |
| A. Launch bind / #275 / AMD | **PASS** | `phase_a_launch_bind` via harness venv |
| A′. Measured image | **PASS** | dm-verity + MEASUREMENT `0132f65b…` |
| B.prepare + runsc 20261005.0 | **PASS** | `setup.sh prepare` TEE=snp |
| B.a no-swap / state tmpfs / LUKS2 | **PASS** | scratch LUKS2 integrity |
| B.c pull + runsc exec | **PASS** | alpine by digest under runsc |
| B.d fresh-boot HW | **BLOCKED** | `fresh_boot_hardware_backed=false` (software lease register) |
| Worker smoke `serve-snp` | **PASS** | live HOST_DATA `551df92e…`, egress enforced, pid kept |
| B.b revocation | **BLOCKED** | needs Fred-signed central-access; key not on guest |
| B.e egress matrix | **BLOCKED** | same — API routes need central signatures |
| B.f one-customer / B.g 401s | **BLOCKED** | same |
| C–E | **UNTESTED** | receipts / fork / customer formats |
| F bundle | **PARTIAL** | this file + evidence |

### Worker smoke facts (2026-10-09)

- `posture=snp-production`, `tee=snp`, TLS + signed validator access
- `central_root_digest=sha256:551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e`
- `egress.enforced=true`, runsc systrap, docker on LUKS scratch
- `fresh_boot_hardware_backed=false` (matches B.d)
- Portable CPython 3.13 via uv (guest system Python is 3.14; no sr25519 wheel)

## Re-run

```bash
ssh -p 2225 root@84.32.220.48
cd /opt/cathedral/sandbox
git fetch && git reset --hard origin/feat/tee-box-snp-startup-gates
export PYTHONPATH=$PWD TEE=snp PATH=$HOME/.local/bin:$PATH
unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
PY=/opt/cathedral-e2e/venv313/bin/python   # after uv bootstrap once
"$PY" scripts/tee_box_snp_e2e/run_bf_clear.py
"$PY" scripts/tee_box_snp_e2e/start_worker_smoke.py
```

## Remaining to close #274

1. **Fred** (or root owner): sign central-access against live `:2225` for B.b/e/f/g — **or** mark those honest BLOCKED in the issue if out of scope for this bolt.
2. C receipts + D fork as scoped; E if customer formats agreed.
3. Publish measurement-list entry for `0132f65b…` + `host_data` `551df92e…`.
4. Hold panic-on-corruption until after agreed runs (changes MEASUREMENT).

Do **not** overwrite `/usr/share/cathedral/central-root-keys.json` on `:2225` (breaks launch bind).
