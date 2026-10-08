# TEE box SEV-SNP e2e results (#274)

Status: **HOST_DATA launch bind + #275 measured-root gate PASS on Genoa bare
metal we control.** Full tee-box B–F harness is still open. Missing rows stay
**UNTESTED** or **BLOCKED**, never silent PASS.

## Machines (current)

| Role | Address | Notes |
| --- | --- | --- |
| SNP host (launch) | `ssh root@84.32.220.48` | Cherry bare metal, AMD EPYC 9124 Genoa, SNP on in BIOS, QEMU `sev-snp-guest` |
| Stamped guest | `ssh -p 2222 root@84.32.220.48` | hostname `snp-guest-official`; code at `/root/sb` |
| Relaunch | `/root/snp-launch/launch-snp-guest.sh <root-keys.json>` | HOST_DATA = sha256(root file) |
| Old Milan guests | cathedral-1/2 | Superseded for this stamp; do not treat as current PASS surface |
| GCP TDX | gone | Tell ops if Intel needed again |

Sandbox commit on guest for this evidence: **`fde596b`**
(`feat/tee-box-snp-startup-gates`).

## Prerequisites

| Item | Verdict | Notes |
| --- | --- | --- |
| `read_snp_host_data` + measured-root SNP bind | **PASS** (in-repo + live) | #275 gate on stamped guest |
| SNP configure / SoftwareLeaseRegister | implemented | Guest-local only; `fresh_boot_hardware_backed=false` |
| Real HOST_DATA at launch | **PASS** | Official root; Inject=NO; see Phase A |
| Fresh-boot HW register (B.d) | **BLOCKED** | Written reason: no RTMR3-class field in SNP report (`docs/TEE_BOX_SERVICE.md`) |
| Official root minted | **PASS** | `cathedral-root-1`; Fred holds seed offline |
| Measured tee-box image (image-owner row) | **BLOCKED** | Guest is stock Ubuntu cloud image, not measured tee-box |
| Polaris sealed field fill / #1444 | external | Platform signer today; sealed fields null |
| Miner `PROVEN_ABSENT` | **BLOCKED** | Draft / issuer scaffolding; not this run |

## Ownership seats (as of 2026-10-08)

| Seat | Name |
| --- | --- |
| Root owner | Fred (`cathedral-root-1`, seed offline) |
| Launch owner | Cathedral (Cherry Servers host `84.32.220.48`) |
| Image owner | **TBD** — blocks measured-image language |

See `docs/CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md`.

## Phase A — Sealed hardware / launch bind (2026-10-08)

| Field | Value |
| --- | --- |
| Root key id | `cathedral-root-1` |
| File / report / QEMU host-data sha256 | `551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e` |
| Inject | **NO** |
| snpguest | 0.10.0 |
| Policy | `0x30000` |
| AMD chain | ARK self-signed → ASK by ARK → VCEK by ASK; VEK signed report |
| #275 official | **STARTED** |
| #275 wrong key | **REFUSED** (`does not match HOST_DATA`) |

**How to re-run (no inject):**

```bash
ssh -p 2222 root@84.32.220.48
cd /root/sb && source .venv/bin/activate && export PYTHONPATH=/root/sb
# unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
python -m scripts.tee_box_snp_e2e.phase_a_launch_bind \
  --root-keys /usr/share/cathedral/central-root-keys.json
```

Evidence links:
- https://github.com/cathedralai/cathedral-sandbox/issues/274#issuecomment-6065495704
- https://github.com/cathedralai/cathedral-sandbox/issues/274#issuecomment-6065599339

## Phase verdicts

| Phase | Verdict | Evidence |
| --- | --- | --- |
| A. Sealed hardware (launch HOST_DATA + AMD verify + #275 gate) | **PASS** | Genoa guest `snp-guest-official`; script above |
| B.a–c, e–g tee-box | **UNTESTED** | Need LUKS/runsc/egress harness day on this guest |
| B.d Fresh-boot admission | **BLOCKED** | No HW register; software lease ≠ sealed PASS |
| C. Receipts | **UNTESTED** / partial in Polaris | #1415 chain; sealed fields null |
| D. Fork / density | **UNTESTED** | Host has KVM; guest path still unrun |
| E. Customer formats | **UNTESTED** | |
| F. Bundle | **PARTIAL** | This file + #274 comments; full harness bundle not yet |

## Honest substitutes (not sealed PASS)

- **HOST_DATA inject** via `read_binding` / `E2E_HOST_DATA_HEX`: exercises
  the box; label every result `test_hook`, never launch-bound PASS.
- **SoftwareLeaseRegister**: one customer per boot inside the guest only.

## What this does *not* close

- Full #274 Done-when (B–F on measured tee-box image)
- Image-owner approval of a measured guest image + measurement-list
- Customer / miner private path (custody + other SN94 blockers)
