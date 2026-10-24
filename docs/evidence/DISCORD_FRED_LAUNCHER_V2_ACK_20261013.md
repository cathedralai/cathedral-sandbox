# Discord → Fred (reviewed launcher + launch-inputs v2)

@wallscaler Updated boot preparation to the reviewed launcher + launch-inputs v2. Observer setup not repeated.

**Pinned**
- Launcher source SHA256 `64eed232bff47bb08b6a43ba880493898545e6bed18ef7195aa2fd51cd9a4bdf` (local file hash-checked match)
- Planned host path `/root/snp-launch/cathedral-staging-20261013/launch_diagnostic_20261013.py`
- Owner command as published (env marker + `python3 -I … --launch-approved-diagnostic`)
- Launch-inputs v2 status `DIAGNOSTIC_ARTIFACT_AND_LAUNCHER_SOURCE_VERIFIED_NOT_BOOTED_NOT_CUSTOMER_QUALIFIED`
- Image/APPEND/HOST_DATA unchanged from verified packet (`8296f243…` / `5607dede…` / `VR35Ls6k…`)
- Budget noted: 4 vCPU / 8 GiB guest, **10 GiB host process cap**
- Quarantine shape: **nic none / no hostfwd** (replaced my earlier hostfwd draft — will not use that path)

**Hold**
- Recorded `source_review_grants_boot_permission: false` — Astra GO = source/publication only
- Boot/`--execute` still held until separate owner boot authorization
- Policy accept + customer qualification still outstanding; 900s grant clock not running

Local refs: `polariscomputer/scripts/snp_staging/launch_diagnostic_20261013.py`, `docs/evidence/VERIFIED_DIAGNOSTIC_LAUNCH_INPUTS_v2_20261013.json`, updated `polariscomputer/scripts/snp_staging/boot_new_guest.sh`.
