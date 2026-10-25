# Discord → Fred (unblock — observer + #1451 wire)

@wallscaler Unblocking you on observer / cleanup before I step away.

**Observer (public only — private key stays with me)**
- `signing_key_id`: `snp-staging-observer-1`
- Ed25519 pubkey b64 (32-byte): `33w8TDt31qA9sNI75SPQYiBKi27sJa1v7CWleal92y8=`
- pubkey hex: `df7c3c4c3b77d6a03db0d23be523d062204a8b6eec25ad6fec25a579a97ddb2f`

**Inbox / format** (per #1449 comment 6153302746)
- `receipt_directory`: absolute owner-only dir `~/.cathedral-snp-staging-qualification/independent_probe_inbox` (0700)
- file: `<original DELETE Operation.identity>.json` (bare SHA256 identity, not op id / idempotency key)
- envelope exactly `receipt` + `payload`
- receipt: `cathedral_miner_lifecycle_receipt_v1`, signature `{algorithm:ed25519,value_base64}`; verify with pinned key by `signing_key_id`
- payload: `{binding_sha256, operation_id, sandbox_id, state:"absent", source:"independent_runtime_probe"}`

**Wired into pilot (source)**
- PR #1449 tip `f7625052` already compared/integrated (recipe, probe, startup template)
- PR #1451 @ `7de36c09` pulled: `cathedral_pilot_absence_receipts.py` + docs; **34/34** focused tests passed locally
- Pilot composition: `polariscomputer/scripts/snp_staging/wire_pilot_absence_producer.py` (loads my observer seed locally, refuses HostReader until live authenticated reader is injected after real launch fence)
- Startup template `independent_probe` pin set to the key above
- Understood: #1451 is whole-guest teardown seam; does **not** prove container delete while guest stays up

**Still holding (as you asked)**
- Customer canary held until guest HTTPS + accepted policy + your 900s grant
- No guest boot from me until exact launch packet lands
- Grant timing: wait for HTTPS + policy so it doesn’t expire mid-prep — acknowledged

Ready for agents/Astra launch packet. Ping when verity image hashes + APPEND are published.
