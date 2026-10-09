# TEE box SEV-SNP e2e results (#274)

Status: **Measured tee-box images live. Phase A + B clearout (storage/runsc)
PASS on official `:2225`.** B.d **BLOCKED** (honest). Full worker path B.b/e/f/g
and C–E still **UNTESTED**. #274 not fully closed.

Evidence JSON: `docs/evidence/snp-bf-report-20261009T175646Z.json`

## Machines

| Role | Address |
| --- | --- |
| Host | `ssh root@84.32.220.48` |
| Stock guest (untouched) | `:2222` |
| **Measured official (B–F)** | `:2225` |
| Measured dev | `:2224` |

Sandbox tip used for clearout: **`73894ba`** (+ setup SNP patches).

## Phase verdicts (2026-10-09 clearout on :2225)

| Phase | Verdict | Notes |
| --- | --- | --- |
| A. Launch bind / #275 / AMD | **PASS** | `phase_a_launch_bind` |
| A′. Measured image | **PASS** | dm-verity + MEASUREMENT `0132f65b…` |
| B.prepare + runsc 20261005.0 | **PASS** | `setup.sh prepare` TEE=snp |
| B.a no-swap / state tmpfs / LUKS2 | **PASS** | scratch on `/tmp` (1G) |
| B.c pull + runsc exec | **PASS** | alpine by digest under runsc |
| B.d fresh-boot HW | **BLOCKED** | no RTMR3-class register |
| B.b revocation | **UNTESTED** | needs tee-box worker + central-access |
| B.e egress | **UNTESTED** | needs worker nft/tc matrix |
| B.f one-customer / B.g 401s | **UNTESTED** | needs `serve_worker` / lease API |
| C–E | **UNTESTED** | receipts / fork / customer formats |
| F bundle | **PARTIAL** | this file + evidence JSON |

## Re-run clearout

```bash
ssh -p 2225 root@84.32.220.48
cd /opt/cathedral/sandbox
git pull --ff-only   # feat/tee-box-snp-startup-gates
export PYTHONPATH=$PWD TEE=snp
unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
python3 scripts/tee_box_snp_e2e/run_bf_clear.py
```

## Remaining to close #274

1. Start tee-box worker on measured guest (`serve_worker` / configure SNP path).
2. Run B.b, B.e, B.f, B.g against that worker (port TDX harness checks).
3. C receipts + D fork as scoped; E if customer formats agreed.
4. Publish measurement-list entry for `0132f65b…` + `host_data` `551df92e…`.
5. Hold panic-on-corruption until after those runs (changes MEASUREMENT).
