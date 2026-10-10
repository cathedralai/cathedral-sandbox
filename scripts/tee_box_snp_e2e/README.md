# TEE box SNP e2e harness (#274)

Phase A launch-bind checker is live. Full B–F still mirrors
`scripts/tee_box_tdx_e2e/` and must be recorded in
`docs/TEE_BOX_SNP_E2E_RESULTS.md` — do not claim sealed PASS from phase A alone.

## Goal

One acceptance day on Cathedral-controlled SNP metal covering tee-box, sealed
evidence, receipts, and fork/density.

Current stamp surface: host `84.32.220.48`, guest `ssh -p 2222` →
`snp-guest-official`.

## Non-goals

- Claiming B.d PASS (hardware fresh-boot): **BLOCKED** — see
  `docs/TEE_BOX_SERVICE.md`
- Treating HOST_DATA inject as launch-bound binding
- Claiming measured tee-box image PASS while guest is stock Ubuntu

## Phase A (launch bind) — run on stamped guest

```bash
cd /root/sb && source .venv/bin/activate && export PYTHONPATH=/root/sb
unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
python -m scripts.tee_box_snp_e2e.phase_a_launch_bind \
  --root-keys /usr/share/cathedral/central-root-keys.json
```

Exit 0 = live HOST_DATA matches official root, AMD verify OK, official
STARTED, wrong key REFUSED. Still not full #274.

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
