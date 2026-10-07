# TEE box SNP e2e harness (#274)

Scaffold only. Prefer extending or mirroring
`scripts/tee_box_tdx_e2e/` rather than claiming a sealed run from this
directory alone.

## Goal

One acceptance day on cathedral-1/2 covering tee-box, sealed evidence,
receipts, and fork/density — recorded in
`docs/TEE_BOX_SNP_E2E_RESULTS.md`.

## Non-goals

- Claiming B.d PASS (hardware fresh-boot): **BLOCKED** — see
  `docs/TEE_BOX_SERVICE.md`
- Treating HOST_DATA inject as launch-bound binding
- Firecracker / E2B (no KVM on the SNP guests)

## Preflight

1. Guest has `/dev/sev-guest` and pinned `snpguest` 0.10.0 on PATH.
2. Root key file at the image path, or harness inject:
   `E2E_HOST_DATA_HEX=$(python -m cathedral.tee_box.host_data_cli --root-keys …)`
   with `read_binding` returning those 32 bytes — **label test_hook**.
3. For a real bind: operator sets launch host-data
   (`docs/SNP_HOST_DATA_LAUNCH.md`) before asking for sealed A PASS.
4. Run unit gates first:

```bash
.venv/bin/python -m pytest -q \
  tests/test_tee_box_measured_root.py \
  tests/test_tee_box_boot.py \
  tests/test_cli_tee_box.py \
  tests/test_tee_admission.py
```

## Next implementation slice

Port `tee_box_tdx_e2e/harness.py` behind `--tee snp`: swap MRCONFIGID inject
for HOST_DATA inject, skip RTMR3 sysfs checks, assert
`fresh_boot_hardware_backed` is false, and record B.d as BLOCKED with the
written reason rather than failing the whole run.
