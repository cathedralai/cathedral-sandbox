# SNP staging — parallel work while waiting on Fred (2026-10-13)

## Shipped now

### 1. Fail-closed install scaffold
- `polaris/services/cathedral_snp_staging_install.py`
- Hooked in app lifespan when `ENVIRONMENT=staging`
- Installs `TobySandboxes` **only** when `SNP_STAGING_INSTALL=1` + complete qualification dir + policy/signer loaders
- Otherwise logs uninstalled and leaves `503 snp_customer_path_unqualified`
- Unit tests: `tests/test_cathedral_snp_staging_install.py` (3 passed)

### 2. Boot script (no launch)
- `scripts/snp_staging/boot_new_guest.sh`
- Refuses without `SNP_STAGING_POLICY_ACCEPTED=yes`, `SNP_STAGING_HOST_DATA_B64`, `SNP_STAGING_APPEND`
- Dry-run by default; `--execute` only after Fred inputs
- Ports `:2226`/`:8444` only; blocks reuse of `:2222/:2224/:2225`

### 3. Operator helpers
- `scripts/snp_staging/status.sh` — health, URL, key prefix, install checklist, boot readiness
- `scripts/snp_staging/qualification.example/` — file layout + README for Fred materials

### 4. Canary still ready
```bash
export STAGING_BASE_URL="$(cat /tmp/cathedral-snp-staging-url.txt)"
export STAGING_API_KEY="$(cat /tmp/cathedral-snp-staging-api-key)"
./cathedral-sandbox/scripts/snp_staging_canary.sh
```
(Today: create stays 503 until install + guest + grant.)

### 5. Wait-batch (grant / qual / preflight)
See `snp-staging-wait-batch-20261013.md` — grant template, qual dir init, preflight OK, boot hold.

## Proved after restart
- Startup log: `snp staging path uninstalled` / `installed=False ready=False`
- AMD create still `503 snp_customer_path_unqualified` `billed:false`

## Still waiting on Fred
See `FRED_ASK_LAUNCH_TODAY_20261013.md` + `FRED_REPLY_HOLD_A7AD_20261013.md` (corrected image, policy accept, roothash/host-data, grant, secure secrets).
