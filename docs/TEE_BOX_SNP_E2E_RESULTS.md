# TEE box SEV-SNP e2e results (#274)

Status: **Measured tee-box images (official + dev) are up on Cherry Genoa
metal.** HOST_DATA + MEASUREMENT (kernel-hashes + dm-verity roothash) +
#275 gate + runsc 20261005.0 verified. **B–F harness still UNTESTED** —
Toby can start on the measured guests. Full #274 Done-when is not closed.

## Machines (current)

| Role | Address | Notes |
| --- | --- | --- |
| SNP host | `ssh root@84.32.220.48` | Cherry, EPYC 9124 Genoa |
| Stock stamped guest (untouched) | `ssh -p 2222 root@84.32.220.48` | `snp-guest-official`, OVMF.fd only (firmware MEASUREMENT) |
| **Measured official** | `ssh -p 2225 root@84.32.220.48` | Cathedral OS / tee-box; use for B–F |
| **Measured dev** | `ssh -p 2224 root@84.32.220.48` | Same stack + debug tools |
| Build / launch | `/root/snp-launch/tee-box-image/` | `launch-tee-box.sh`, mkosi project, images/ |

Sandbox on measured guests: `/opt/cathedral/sandbox` @ **`efe7585`**
(`feat/tee-box-snp-startup-gates`). Harness `setup.sh` now pins **runsc
20261005.0** via `gvisor.tar.zstd` (was 20260817 bare binary).

## Official measured image (2026-10-09)

| Field | Value |
| --- | --- |
| Image owner | @skyrocket2026 |
| Boot | `OVMF.amdsev.fd` + direct boot, `kernel-hashes=on` |
| dm-verity roothash (on measured cmdline) | `e1a3ce4f9546926232482a7eeb442c3de0871c856eb0ddb7a0b705c94ff57a6b` |
| MEASUREMENT (live) | `0132f65b23fc8776dcd248b47224301be8d7f66a6c612b00c7b9780c16101291948e5c3df9fac140a0048971fa3ea3db` |
| HOST_DATA | `551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e` (same official root) |
| runsc | `release-20261005.0` sha256 `210b437a9cfae51e8f8c9074ed19b8b5e59477178e2e391a18117d8d6b924f7a` |
| #275 gate | **STARTED** (`cathedral-root-1`) |
| Attack tests | cmdline word flip → MEASUREMENT changes; one-byte root flip → dm-verity corruption |

Dev guest MEASUREMENT: `f4df8ff3…` (roothash `993ad3ff…`).

Draft measurement-list object:

```json
{"id":"cathedral-tee-box-snp_official-20261009",
 "measurement":"0132f65b23fc8776dcd248b47224301be8d7f66a6c612b00c7b9780c16101291948e5c3df9fac140a0048971fa3ea3db",
 "host_data":"551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e"}
```

## Prerequisites

| Item | Verdict | Notes |
| --- | --- | --- |
| `read_snp_host_data` + measured-root SNP bind | **PASS** | Live on measured + stock guests |
| Real HOST_DATA at launch | **PASS** | Official digest; Inject=NO |
| Measured tee-box image + dm-verity | **PASS** (live) | Official 2225 / dev 2224 |
| Image owner seat | **PASS** | @skyrocket2026 |
| Fresh-boot HW register (B.d) | **BLOCKED** | No RTMR3-class field; written reason stands |
| Measurement-list published in policy registry | **UNTESTED** | Draft object above; owner release still needed |
| Miner `PROVEN_ABSENT` | **BLOCKED** | Separate |

## Phase verdicts

| Phase | Verdict | Evidence |
| --- | --- | --- |
| A. Sealed hardware / launch bind | **PASS** | HOST_DATA + AMD chain (earlier) |
| A′. Measured Cathedral OS image | **PASS** | 2225/2224; predicted==live; verity; #275; runsc |
| B.a–c, e–g tee-box | **UNTESTED** | Start on **2225** (or 2224); no `E2E_HOST_DATA_HEX` |
| B.d Fresh-boot admission | **BLOCKED** | Software lease ≠ sealed PASS |
| C. Receipts | **UNTESTED** | |
| D. Fork / density | **UNTESTED** | Host has KVM |
| E. Customer formats | **UNTESTED** | |
| F. Bundle | **PARTIAL** | This file + #274; harness day not done |

## How Toby starts B–F

```bash
# Preferred: measured official
ssh -p 2225 root@84.32.220.48
cd /opt/cathedral/sandbox   # tip efe7585+ after pull
unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
# pull latest feat/tee-box-snp-startup-gates, then:
sudo bash scripts/tee_box_tdx_e2e/setup.sh prepare   # now pins runsc 20261005.0
# then SNP-adapted harness / port of tee_box_tdx_e2e with --tee snp
```

Do **not** use stock 2222 for sealed B–F claims. Do **not** enable
panic-on-corruption verity until after this B–F run (changes MEASUREMENT).

## Ops follow-ups (not Toby blockers for starting B–F)

- Reproducible builds (build twice, compare)
- panic-on-corruption (hold until after B–F)
- Sealed official build without SSH
- Desktop / browser / base sandbox images
