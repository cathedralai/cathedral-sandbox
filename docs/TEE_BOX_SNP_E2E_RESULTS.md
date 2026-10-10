# TEE box SEV-SNP e2e results (#274)

Status: **Measured official `:2225` — Phase A + B clearout + `serve-snp` worker
smoke PASS** (live HOST_DATA, no inject). Remaining items are honest
**SKIP / BLOCKED** (not silent gaps). #274 measured-image + worker-startup
bolt is ready to close once image owner publishes the list entry and
leadership accepts the BLOCKED rows.

Evidence: `docs/evidence/snp-bf-report-20261009T175646Z.json`,
worker smoke tip **`e622448`**, measurement-list draft
`docs/evidence/measurement-list-draft-tee-box-snp-official-2225.json`.

## Machines

| Role | Address |
| --- | --- |
| Host | `ssh root@84.32.220.48` |
| Stock guest (untouched) | `:2222` |
| **Measured official (B–F)** | `:2225` |
| Measured dev | `:2224` |

Sandbox tip: **`feat/tee-box-snp-startup-gates`**.

## Phase verdicts (2026-10-09 on :2225)

| Phase | Verdict | Notes |
| --- | --- | --- |
| A. Launch bind / #275 / AMD | **PASS** | `phase_a_launch_bind` via harness venv |
| A′. Measured image | **PASS** | dm-verity + MEASUREMENT prefix `0132f65b…` (full hex → image owner) |
| B.prepare + runsc 20261005.0 | **PASS** | `setup.sh prepare` TEE=snp |
| B.a no-swap / state tmpfs / LUKS2 | **PASS** | scratch LUKS2 integrity |
| B.c pull + runsc exec | **PASS** | alpine by digest under runsc |
| B.d fresh-boot HW | **BLOCKED** | `fresh_boot_hardware_backed=false` (software lease register) |
| Worker smoke `serve-snp` | **PASS** | live HOST_DATA `551df92e…`, egress enforced |
| B.b revocation | **BLOCKED** | needs Fred-signed central-access; root seed offline |
| B.e egress matrix | **BLOCKED** | same — API routes need central signatures |
| B.f one-customer / B.g 401s | **BLOCKED** | same |
| C. receipts | **BLOCKED** | Polaris/prober capacity receipt path + idle probe/lease; not Toby-solo on `:2225` |
| D. fork density | **SKIP** | Owner decision: no snapshot/fork in v1 (`docs/TEE_BOX.md` decision 5). Not implemented; not a #274 bug. |
| E. customer formats | **BLOCKED** | awaiting agreed customer verifier formats |
| measurement-list | **DRAFT (measurement filled)** | 96-hex MEASUREMENT from live `:2225` snpguest; **@skyrocket2026** publishes signed registry |
| panic-on-corruption | **HOLD** | changes MEASUREMENT; do after list publish / new image rev |
| F bundle | **PARTIAL** | this file + evidence |

### Worker smoke facts

- `posture=snp-production`, `tee=snp`, TLS + signed validator access
- `central_root_digest=sha256:551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e`
- `egress.enforced=true`, runsc systrap, docker on LUKS scratch
- Portable CPython 3.13 via uv (guest system Python is 3.14)

## Honesty pass (C / D / E)

| Item | Verdict | Why |
| --- | --- | --- |
| **C receipts** | **BLOCKED** | Capacity receipts need Polaris/prober + drained-box probe (lease). Same central-access dependency as B.b. Follow-on, not a silent UNTESTED. |
| **D fork** | **SKIP** | `TEE_BOX.md` decision 5: no snapshots/fork/port/DinD in v1. Not a missing test. |
| **E customer formats** | **BLOCKED** | No agreed customer verifier formats for this bolt. Spec first, then re-open. |

## Measurement-list draft → @skyrocket2026

File: `docs/evidence/measurement-list-draft-tee-box-snp-official-2225.json`

- Image id: `tee-box-snp-cherry-official-2026-10-09`
- `host_data`: `551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e` (**confirmed** on `:2225`)
- `measurement`: **filled** `0132f65b23fc8776dcd248b47224301be8d7f66a6c612b00c7b9780c16101291948e5c3df9fac140a0048971fa3ea3db` (live `snpguest display report` on `:2225`, 2026-10-10)
- Host Data in same report matches `551df92e…71c9885e`

Next: **@skyrocket2026** publishes the signed measurement-list registry entry from the draft JSON.

## Re-run clearout / worker smoke

```bash
ssh -p 2225 root@84.32.220.48
cd /opt/cathedral/sandbox
git fetch && git reset --hard origin/feat/tee-box-snp-startup-gates
export PYTHONPATH=$PWD TEE=snp PATH=$HOME/.local/bin:$PATH
unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
PY=/opt/cathedral-e2e/venv313/bin/python
"$PY" scripts/tee_box_snp_e2e/run_bf_clear.py
"$PY" scripts/tee_box_snp_e2e/start_worker_smoke.py
```

## Remaining owners

| Who | Action |
| --- | --- |
| **Fred** | Sign central-access for B.b/e/f/g **or** accept those BLOCKED |
| **@skyrocket2026** | Draft MEASUREMENT filled — publish signed measurement-list entry |
| **Leadership** | Accept C BLOCKED / D SKIP / E BLOCKED for this bolt if closing #274 now |
| **Toby** | Keep evidence current; do **not** enable panic-on-corruption yet |

Do **not** overwrite `/usr/share/cathedral/central-root-keys.json` on `:2225`.
