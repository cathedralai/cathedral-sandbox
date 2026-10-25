# Isolated SNP staging URL — 2026-10-13

## Staging URL (owned, isolated)

```
http://bore.pub:53871
```

(Ephemeral bore port — re-run `scripts/snp_staging/publish_tunnel.sh` if it drops. Live value: `/tmp/cathedral-snp-staging-url.txt`. Prior: `:7262`, `:10450`.)

- Local API: `http://127.0.0.1:8010`
- Branch: `feat/snp-customer-staging-broker` @ `4f046be1`
- Release label: `local-snp-staging-4f046be1`
- Postgres: `127.0.0.1:55432/cathedral_snp_staging` (docker `cathedral-snp-staging-pg`)
- Redis: `127.0.0.1:56379` (docker `cathedral-snp-staging-redis`)
- Broker: `CATHEDRAL_CAPACITY_BROKER_ENABLED=true`
- Env file (gitignored): `polariscomputer/.env.snp-staging.local`

## Staging key (owned, isolated)

- Prefix: `cat_sk_zLFoi` (live `/tmp/cathedral-snp-staging-api-key`; earlier mint used `cat_sk_xwGye`)
- Scopes: `sandboxes:control`, `billing:read`
- Budget: $5 · wallet: $50 staging credits
- Expires: 2026-10-15T08:47:04Z
- Secret: `/tmp/cathedral-snp-staging-api-key` only (0600) — not in git/chat
- Mint: `polariscomputer/scripts/snp_staging/mint_staging_key.py`
- Proved: `GET /v1/account` → 200 on local and public URL

## Health (proved)

```json
{
  "status": "healthy",
  "release_sha": "local-snp-staging-4f046be1",
  "migration_head": "cathedral_snp_journal_20261013",
  "database": "connected",
  "compute": "disabled"
}
```

`compute: disabled` is expected (no Verda). AMD capacity is via the SQL broker + Cherry SNP guest, not Verda.

## How to run

```bash
cd polariscomputer
./scripts/snp_staging/run_isolated_api.sh
./scripts/snp_staging/publish_tunnel.sh

# Canary (still needs SNP adapters + guest)
export STAGING_BASE_URL="$(cat /tmp/cathedral-snp-staging-url.txt)"
export STAGING_API_KEY="$(cat /tmp/cathedral-snp-staging-api-key)"
../cathedral-sandbox/scripts/snp_staging_canary.sh
```

## Not this URL / key

- Railway `https://polariscomputer-staging-staging.up.railway.app` (`acaa2961`, compute disabled)
- Fred key `b30b7437-…` (secret still missing)
- Prod key `cat_sk_E-j9h…`

## Still blocked for full create→cleanup

1. Six Polaris adapter modules from `acaa2961` / `66deb72e`
2. Policy accept + new guest boot + 15‑min central grant
