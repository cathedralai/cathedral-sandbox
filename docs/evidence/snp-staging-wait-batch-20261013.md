# SNP staging — wait-batch (grant / qual / preflight) 2026-10-13

## Shipped this batch

### 1. Grant packet template (unsigned, 900s)
- `docs/evidence/snp-staging-grant-packet.template.json`
- `docs/evidence/snp-staging-grant-packet.README.md`
- Placeholders only; signature fields null until Fred signs on secure channel

### 2. Qualification dir skeleton
- Script: `polariscomputer/scripts/snp_staging/init_qualification_dir.sh`
- Created: `/Users/user/.cathedral-snp-staging-qualification` (mode `700`)
- Placeholders: `binding.json`, `target.json`, empty secret stubs, `FILL_WHEN_READY.txt`
- Do not set `SNP_STAGING_INSTALL=1` until Fred materials fill the stubs

### 3. Canary preflight
- Script: `polariscomputer/scripts/snp_staging/canary_preflight.sh`
- Ran against `http://127.0.0.1:8010`
- Result: **PREFLIGHT_OK** — health healthy, account active, AMD create `503 snp_customer_path_unqualified` `billed:false`
- Artifacts: `/tmp/snp-staging-preflight/{health,account,create}.json`

### 4. Boot hold still enforced
- `boot_new_guest.sh` still refuses draft launch
- Blocked raw SHA: `a7ad573b…` (Fred hold)
- Still need: `POLICY_ACCEPTED`, `HOST_DATA_B64`, `APPEND`, corrected `EXPECTED_RAW_SHA256`

## Staging API
- Local `:8010`, release `local-snp-staging-4f046be1`
- Migration head: `cathedral_snp_journal_20261013`
- Public URL: `http://bore.pub:53871` (file `/tmp/cathedral-snp-staging-url.txt`)
- Public preflight: health OK + AMD create `503 snp_customer_path_unqualified` `billed:false`

## Blocked until Fred
Corrected image ≠ a7ad573b, boot inputs, shared branch if any, HTTPS grant signature, qualification secrets.
