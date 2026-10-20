# SNP adapters integrated — 2026-10-13

Source: `toby-source-complete-66deb72e-20261013` (commit `66deb72e`, complete files).

## Copied into `polariscomputer` (feat/snp-customer-staging-broker)

Required six (hashes MATCH package + earlier handoff manifest):

- `polaris/db/snp_runtime.py`
- `polaris/providers/broker_runtime_connector_proposal.py`
- `polaris/providers/snp_customer_adapter_proposal.py`
- `polaris/providers/snp_postgres_journal_proposal.py`
- `polaris/providers/snp_selected_runtime_proposal.py`
- `tests/test_snp_customer_adapter_proposal.py`

Also joined:

- Router/service/e2b SNP path (`cathedral_sandboxes` router+service, `e2b_sandbox_runtime`)
- `polaris/providers/snp_operation_journal_proposal.py`
- Migration `alembic/versions/cathedral_snp_journal_20261013.py` (applied on isolated staging DB)
- Related unit tests + `cathedral/` package from the bundle (for verifier/producer imports)
- OpenAPI `docs/openapi/cathedral.json`

## Proved locally

- Adapter-focused pytest: **74 passed** (`test_snp_customer_adapter_proposal` + `test_cathedral_snp_customer_requirement`)
- Isolated API `/health` healthy
- `/v1/account` 200 with owned staging key
- `POST /v1/sandboxes` with `required_hardware=amd_sev_snp` → **503** `snp_customer_path_unqualified` `billed:false` (correct: `TobySandboxes` not installed yet / no qualified guest)

## Staging DB

- `cathedral_runtime_leases` + `cathedral_runtime_operations` created
- alembic head marked `cathedral_snp_journal_20261013`

## Still required for live canary

1. Image/policy accept + boot new guest (`:2226`/`:8444` draft)
2. `TobySandboxes.from_qualified_workers(...).install(...)` on staging startup with real TLS/policy/prober
3. 15‑min central grant after guest HTTPS is up
4. Run `snp_staging_canary.sh`
