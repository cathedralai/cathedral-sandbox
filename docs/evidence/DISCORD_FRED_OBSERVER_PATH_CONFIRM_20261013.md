# Discord → Fred (observer path/signer confirm + Sky policy context)

@wallscaler Confirmed — no repeat of launch-input / #1451 work.

**1) Observer inbox (absolute, no tilde, no symlink)**
- Effective path: `/Users/user/.cathedral-snp-staging-qualification/independent_probe_inbox`
- Absolute: yes
- Symlink components: none
- Owner: API/local staging UID `501` (matches process user)
- Mode: `0700`
- Will **not** configure a literal `~/…` path in `CATHEDRAL_SNP_STARTUP_FILE` / `independent_probe.receipt_directory`

**2) Public pin ↔ retained signer**
- `signing_key_id`: `snp-staging-observer-1`
- pubkey b64: `33w8TDt31qA9sNI75SPQYiBKi27sJa1v7CWleal92y8=`
- Re-derived from local seed → **exact match** to configured pin
- Private key stays local only

**3) Boot prep / #1451**
- Still pinned to verified diagnostic inputs in #1449 (`8296f243…` / `images-verity` / APPEND with `5607dede…`)
- #1451 producer kept ready for whole-guest absence → inbox → cleanup closeout
- Boot held until reviewed launcher is released (noted: 4 vCPU / 8 GiB guest + 2 GiB host overhead must be explicit in execution approval; third file-size fix still pending)
- Customer canary held; 900s grant not issued / clock not running — acknowledged
- Diagnostic image stays diagnostic; customer-profile hardening + disk-quota layout are your/Astra track

**4) Sky / policy authority — public records I have (not reusable as acceptance for this candidate)**
- Ownership doc: `cathedral-sandbox/docs/CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md` — image/policy owner named **`skyrocket2026`** (GitHub); root owner Fred / `cathedral-root-1` is a **different** trust root (central-access, not measurement-list)
- Chase note: `docs/evidence/SKYROCKET_MEASUREMENT_LIST_CHASE.md` — asks Sky to publish signed `cathedral_policy_registry_v1` with the **pinned image-owner key**
- Older-guest drafts only (do **not** reuse for this verity candidate):
  - `docs/evidence/measurement-list-draft-tee-box-snp-official-2225.json`
  - `docs/evidence/measurement-list-publish-ready-tee-box-snp-2225.json`
  - image_id `tee-box-snp-cherry-official-2026-10-09` / measurement `0132f65b…` on `:2225`
- I do **not** hold Sky’s policy signing key. I have **no** public `signing_key_id` / trusted-keys bundle / checkpoint for an accepted SN94 release covering the new diagnostic/verity candidate. Qual `policy_release.json` remains empty.

Ready for trust-bootstrap proposal when agents ship it. Target path unchanged: create → exec → native evidence → usage → delete → independent cleanup.
