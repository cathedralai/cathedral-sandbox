# Central-access materials for measured SNP `:2225` (B.b/e/f/g)

Drop Fred-signed files here. **Never commit** seeds, delegations, or rev lists
(see `.gitignore`). Keep the central seed offline on the laptop only.

## Expected files

| File | Source |
| --- | --- |
| `delegation-full.json` | Fred — full `TEE_BOX_CENTRAL_SCOPES` to your central pubkey |
| `revocations-first.json` | Fred — first empty list (`--first-list --allow-empty`) |
| `delegation-box-only.json` | Optional — B.g scope 401s (`tee-box:box` only) |

Central seed (local, not here):  
`Cathedral/.secrets/snp-central-2225/toby-snp-2225-bf.seed`

Public key sent to Fred:  
`wgyQxlR1GNnuVDnextSRonGLkB4geLh3bw4P6DIqoIA=`

## After files land

On the guest (worker already smoking on `:8443`):

```bash
export PYTHONPATH=/opt/cathedral/sandbox
export CENTRAL_SEED=/path/to/toby-snp-2225-bf.seed
export MATERIALS=/path/to/central_access_materials
PY=/opt/cathedral-e2e/venv313/bin/python
"$PY" scripts/tee_box_snp_e2e/central_bf_client.py push-revocations
"$PY" scripts/tee_box_snp_e2e/central_bf_client.py get-box
"$PY" scripts/tee_box_snp_e2e/central_bf_client.py smoke-bb
```

Do **not** overwrite `/usr/share/cathedral/central-root-keys.json`.
