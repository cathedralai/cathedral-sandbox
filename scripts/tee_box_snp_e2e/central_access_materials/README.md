# Central-access materials for measured SNP `:2225`

Drop Fred-signed files here. **Never commit** seeds or signed JSON (gitignored).

## Round 1 (done 2026-10-11) — filenames used by `smoke-bb` / `matrix-efg`

| File | Role |
| --- | --- |
| `delegation-full.json` | A full scopes (seq 1 — **expired**) |
| `revocations-first.json` | Empty list seq 1 (stale after 24h) |

## Round 2 — Fred signing batch (`fred-signing-batch-bf-fg-20261012.md`)

Place exactly:

| File | Role |
| --- | --- |
| `delegation-a-full-seq2.json` | A renew |
| `delegation-b-full-seq3.json` | Customer B |
| `delegation-box-only-seq4.json` | Least-privilege (+ revoke target) |
| `delegation-sibling-box-seq5.json` | Unrevoked sibling |
| `delegation-a-full-seq6.json` | A after high-water |
| `revocations-seq2-fresh-empty.json` | Fresh empty list |
| `revocations-seq3-revoke-box-only.json` | Revokes box-only digest |

Seeds (laptop only): `.secrets/snp-central-2225/toby-snp-2225-{bf,b,box,sibling}.seed`

## After Round 2 lands

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
