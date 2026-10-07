# TEE box SEV-SNP e2e results (#274)

Status: **harness not yet run on cathedral-1/2.** This file records
prerequisites and per-phase verdicts. A missing run is UNTESTED, not PASS.

Hosts (from #274): `cathedral-1` 167.150.153.211, `cathedral-2`
167.150.153.212 (Milan, `/dev/sev-guest`, shared CHIP_ID, no KVM).

## Prerequisites

| Item | Verdict | Notes |
| --- | --- | --- |
| `read_snp_host_data` + measured-root SNP bind | implemented in-repo | Guest reader; needs launch HOST_DATA for real bind |
| SNP configure / SoftwareLeaseRegister | implemented | Guest-local only; `fresh_boot_hardware_backed=false` |
| Real HOST_DATA at launch | **BLOCKED** | External VMM; see `docs/SNP_HOST_DATA_LAUNCH.md` |
| Fresh-boot HW register (B.d) | **BLOCKED** | Written reason: no RTMR3-class field in SNP report (`docs/TEE_BOX_SERVICE.md`) |
| Polaris sealed field fill / #1444 | external | Platform signer today; sealed fields null |
| Miner `PROVEN_ABSENT` | **BLOCKED** | Draft only: `docs/MINER_TEARDOWN_EVIDENCE.md` |

## Phase verdicts

| Phase | Verdict | Evidence |
| --- | --- | --- |
| A. Sealed hardware | UNTESTED | Need live report + real or labeled inject HOST_DATA |
| B.a–c, e–g tee-box | UNTESTED | Harness scaffold: `scripts/tee_box_snp_e2e/` |
| B.d Fresh-boot admission | **BLOCKED** | No HW register; software lease ≠ sealed PASS |
| C. Receipts | UNTESTED / partial in Polaris | #1415 chain; sealed fields null |
| D. Fork / density | UNTESTED | No KVM → no Firecracker; runsc CoW only |
| E. Customer formats | UNTESTED | |
| F. Bundle | UNTESTED | |

## Honest substitutes (not sealed PASS)

- **HOST_DATA inject** via `read_binding` / `E2E_HOST_DATA_HEX`: exercises
  the box; label every result `test_hook`, never launch-bound PASS.
- **SoftwareLeaseRegister**: one customer per boot inside the guest only.
