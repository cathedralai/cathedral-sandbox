Mr Spock / Fred — Eng cannot re-smoke sealed Join/IDE/Ditto/Reliquary on staging: SNP **policy release 12 expired**.

**Fact:** `/app/cathedral-staging-public/policy.json` has `valid_until=2026-10-23T13:26:07Z` (signing_key_id `cathedral-staging-policy-1`, tool `sign_staging_policy.py`). After that instant, `_accepted_policy` → `registry is outside its validity window` → join discovery `JoinRejected` → create `503 no_verified_supply`. Cherry guest is up (boot `e223e4ac…`, identity fetch OK from Railway).

**Need from Fred (policy key stays with you):** sign a new staging policy (same measurement `a994d7c2…8600` / r12 image is fine) with `valid_until` at least **+7 days**, bump release if your process requires it, drop `policy.json` (+ keys if changed) into the staging public pack and re-accept into `accepted-policy.sqlite`. Eng has no `cathedral-staging-policy-1` private key and no `sign_staging_policy.py` on this laptop.

**After you land it:** Eng will roster-refresh, confirm a `waiting` offer, and re-run Join + IDE (+ ditto/reliquary labels) create→exec→delete. Pay stays false.
