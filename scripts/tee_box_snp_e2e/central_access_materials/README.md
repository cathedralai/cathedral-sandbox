# Central-access materials for measured SNP `:2225`

Drop Fred-signed files here. **Never commit** seeds or signed JSON (gitignored).

## Round 1 (done 2026-10-11) — filenames used by `smoke-bb` / `matrix-efg`

| File | Role |
| --- | --- |
| `delegation-full.json` | A full scopes (seq 1 — **expired**) |
| `revocations-first.json` | Empty list seq 1 (stale after 24h) |

## Corrected Round 2 — `toby-handoff-20261012` (use this README order)

Seven delegations. **Never reorder.** A2 → B3 → Box4 → A5 → Box6 → Sibling7 → A8.

| File | Role |
| --- | --- |
| `delegation-a-full-seq2.json` | A start / release |
| `delegation-b-full-seq3.json` | Customer B → 409 |
| `delegation-box-scope-seq4.json` | Scope-only (NOT revoke target) |
| `delegation-a-full-seq5.json` | A re-lease + push rev3 |
| `delegation-box-revoke-target-seq6.json` | Revoke target (`BOX_DIGEST`) |
| `delegation-sibling-box-seq7.json` | Sibling after revoke → 200 |
| `delegation-a-cleanup-seq8.json` | Cleanup last |
| `revocations-seq2-fresh.json` | Fresh empty list |
| `revocations-seq3-revoke-box-seq6.json` | Revokes seq6 digest only |
| `SIGNING_RECEIPT.json` | Local audit (`BOX_DIGEST`) |

Seeds (laptop only): `.secrets/snp-central-2225/toby-snp-2225-{bf,b,box,sibling}.seed`

```bash
export PYTHONPATH=/opt/cathedral/sandbox
export MATERIALS=/path/to/central_access_materials
export CENTRAL_SEED_A=/path/to/toby-snp-2225-bf.seed
export CENTRAL_SEED_B=/path/to/toby-snp-2225-b.seed
export CENTRAL_SEED_BOX=/path/to/toby-snp-2225-box.seed
export CENTRAL_SEED_SIBLING=/path/to/toby-snp-2225-sibling.seed
export WORKER_HOST=127.0.0.1 WORKER_PORT=8443
PY=/opt/cathedral-e2e/venv313/bin/python
"$PY" scripts/tee_box_snp_e2e/central_bf_client.py matrix-fg-finish
```

Do **not** overwrite `/usr/share/cathedral/central-root-keys.json`.
