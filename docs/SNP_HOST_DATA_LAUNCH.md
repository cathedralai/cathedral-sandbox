# SNP HOST_DATA launch contract

Status: guest reader **implemented** (`cathedral/tee_box/measured_root.py`).
Remote admit pin **implemented** (`admission.admit(..., expected_root_digest=)` /
`capacity/tee_honesty.py` — same digest TDX pins via MRCONFIGID; see
`TEE_HONESTY_STACK.md`). Host launch path is **outside this repository**
(no QEMU/cloud-hypervisor launcher ships here). This document is the contract
a hypervisor operator (WildCommunist or Cathedral ops) must satisfy so an SNP
tee-box can start with a real binding — not a test inject.

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

### Paste-ready ask (ops / WildCommunist)

```text
We need one SNP launch with host-data bound to Cathedral's central root.

1) Install the same central-root-keys.json the guest will serve at
   /usr/share/cathedral/central-root-keys.json
2) On a builder with cathedral-sandbox:
   python -m cathedral.tee_box.host_data_cli --root-keys /path/to/central-root-keys.json
3) Pass that exact 32-byte hex as the VMM host-data (SNP report offset 0xC0).
4) Boot cathedral-1 (or -2); return one snpguest/report dump showing host_data
   matches the CLI output.

Until this lands, #274 sealed SNP acceptance stays BLOCKED on real HOST_DATA
(test injects are not a PASS). Guest reader + CLI are already on
feat/tee-box-snp-startup-gates / docs/SNP_HOST_DATA_LAUNCH.md.
```

### Parallel owner ask (Cathedral root)

Who mints the offline Cathedral root and who approves the measured tee-box
image + measurement-list entries? Without that, MRCONFIGID/HOST_DATA bind has
nothing production-trusted to pin. See
`docs/CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md`.

## Evidence pack (post on #274 when W1 completes)

Copy, fill, attach report dump:

```text
HOST_DATA evidence — cathedral-N — YYYY-MM-DD

Root owner: ________
Image owner: ________
Launch owner: ________

central-root-keys.json sha256:
host_data_cli hex:
VMM host-data hex actually launched:
SNP report host_data hex:
Match CLI == report? YES/NO
Image id / measurement-list rev:
Inject used? NO (required)

Attached: snp report dump / snpguest output
```

### Done when (HOST_DATA bolt green)

1. Ceremony seats named in `CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md`.
2. Evidence pack above posted on #274 with **Match = YES** and **Inject = NO**.
3. Optional: sealed SNP e2e on that guest without `E2E_HOST_DATA_HEX`.

**Status 2026-10-08:** items 1–2 **PASS** on Genoa host `84.32.220.48` /
guest `snp-guest-official` (digest `551df92e…71c9885e`, #275 gate STARTED /
wrong key REFUSED). Root+launch seats filled; image owner still TBD. Re-check:
`python scripts/tee_box_snp_e2e/phase_a_launch_bind.py`. Item 3 (full B–F)
remains open — see `docs/TEE_BOX_SNP_E2E_RESULTS.md`.
