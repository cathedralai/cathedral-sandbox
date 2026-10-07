# SNP HOST_DATA launch contract

Status: guest reader **implemented** (`cathedral/tee_box/measured_root.py`).
Host launch path is **outside this repository** (no QEMU/cloud-hypervisor
launcher ships here). This document is the contract a hypervisor operator
(WildCommunist or Cathedral ops) must satisfy so an SNP tee-box can start
with a real binding — not a test inject.

## Binding

| Field | Value |
| --- | --- |
| Report offset | `0xC0` (32 bytes) — `cathedral.verify.snp.HOST_DATA_OFFSET` |
| Contents | `sha256(bytes of /usr/share/cathedral/central-root-keys.json)` |
| Helper | `cathedral.tee_box.measured_root.host_data_for_root_keys(data)` |
| CLI | `python -m cathedral.tee_box.host_data_cli --root-keys PATH` |

Cathedral TDX uses MRCONFIGID the same way (48 bytes = digest ‖ 16 zero).
SNP `MEASUREMENT` does **not** cover HOST_DATA; admission that cares about
the root must pin HOST_DATA separately (`docs/COMPUTE_POOL_INTEGRITY.md`).

## Operator checklist

1. Install the same root key file the image will serve at
   `/usr/share/cathedral/central-root-keys.json`.
2. Compute HOST_DATA with the CLI (or `host_data_for_root_keys`).
3. Pass those 32 bytes into the SNP launch blob (`host-data` / equivalent
   on the VMM). Do not pad, truncate, or hash twice.
4. Boot the guest; `serve-snp` with tee-box flags must load that root.
5. Confirm a fresh report’s `host_data` matches
   (`parse_snp_report(...).host_data`).

## What this repository does not own

- QEMU SEV-SNP / cloud-hypervisor / firmware flags that set host-data
- Publishing a reference guest image or launch measurement
- Relabeling a test inject (`E2E_HOST_DATA_HEX` / `read_binding`) as a
  sealed HOST_DATA PASS — injects stay labeled test-only (#274 phase A)

## Ask once (external)

When the reader is on main: ask the launch owner to set `host-data` on
cathedral-1/2 (or the production SNP pool) to the Cathedral root digest
and confirm with one report dump. Until then, #274 phase A real-binding
stays **BLOCKED**; harness injects may still exercise the box.
