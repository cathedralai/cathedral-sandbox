# testdata

All files are public. They are published on the Cathedral site.

- `attestation.json`, `amd/ark.der`, `amd/ask.der`, `amd/vcek.der`: from `public/proof/4000-agents/sealed/` (and its `amd/` folder) in the cathedral-site repo.
- `receipts-first5.json`: receipts with sequence 1 to 5 from `public/proof/4000-agents/sealed/receipts.json` (3369 receipts, about 4 MB). Each receipt object is copied byte for byte; the wrapper holds only `receipts` (no `head`, no `count`).
- `attestation-library.json`: `public/library/runs/20261022-sealed/attestation.json`.
- `openenv-echo.receipts.json`: `public/library/runs/20261022-sealed/openenv-echo.receipts.json`.
