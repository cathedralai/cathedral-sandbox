# SNP adapter source hunt — 2026-10-13

Attempted to retrieve the 6 missing Polaris SNP customer-adapter modules online.

## Result: NOT FOUND on any reachable remote

| Source | Outcome |
|--------|---------|
| GitHub `bigailabs/polariscomputer` commit `66deb72e…` | HTTP 422 — commit not on origin |
| GitHub commit `acaa2961…` | HTTP 422 — commit not on origin |
| Branch `codex/customer-snp-integration-20261012` | Not listed among origin branches |
| `gh search code` for filenames / `CathedralRuntimeLease` / `systrap-snp-customer-v1` | Empty (org + global) |
| Web search | No public copies of these proposal modules |
| Local ZIP hunt (`Documents`, `Downloads`) | Only tiny deltas in `backend-on-acaa2961.patch` |
| Handoff `vm/backend/` | Evidence only; no polaris source tree |
| Railway CLI | Not installed / no session here |

## Authoritative location (from Fred handoff)

`toby-transfer-20261013 (1)/TOBY_PICKUP.txt`:

- Root on Fred’s machine: `/Users/dreamboat/Documents/Codex.nosync/2026-10-12/task-3`
- Backend: `implementation/backend`
- Branch: `codex/customer-snp-integration-20261012`
- Commit: `66deb72e7fbf90c66c612f608fdfb06e6164d62f` — **local, no push/deploy**

Railway staging still **serves** `acaa2961` (code in the deploy image), but that tree was never pushed to GitHub, so we cannot `git show` it.

## Files still needed (full sources + manifest sha256)

1. `polaris/db/snp_runtime.py` — `fbb6ae13…` (~4370 B)
2. `polaris/providers/broker_runtime_connector_proposal.py` — `947a7e90…` (~6781 B)
3. `polaris/providers/snp_customer_adapter_proposal.py` — `9832f94f…` (~31734 B)
4. `polaris/providers/snp_postgres_journal_proposal.py` — `3d218b2b…` (~19081 B)
5. `polaris/providers/snp_selected_runtime_proposal.py` — `80892420…` (~5919 B)
6. `tests/test_snp_customer_adapter_proposal.py`

## How Fred can deliver (one of)

1. Tar from that local path and send securely  
2. Push `66deb72e` / branch to GitHub (or a private gist/branch Toby can read)  
3. Export the six files from the Railway staging image filesystem  
4. Attach `selected-runtime-increment-20261012.zip` if it still holds the historical full proposals
