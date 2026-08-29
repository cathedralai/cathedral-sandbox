# Qualified validator access and bounded fleet discovery

## Status

The general worker and remote client implement this protocol in merged source.
The reviewed fixed audit image is published at the digest recorded in
[`SN39_AUDIT_MINER_OPERATIONS.md`](SN39_AUDIT_MINER_OPERATIONS.md). Publication
is not deployment or live proof. The two-machine signed-fleet activation and
production deployment remain open gates.

The fixed image always uses permit-only qualification with a local minimum
stake of `0` Rao and always keeps the narrow public evidence and canonical SAT
bridge for the current UID30 collector. Those are reviewed image constants,
not operator-selectable modes. Fleet discovery and nontrivial validation work
stay signed. Customer SAT stays disabled.

Do not describe signed fleet access as deployed or live-proven. The remaining
[activation gates](#activation-gates) stay open.

## Plain-language flow

1. A host-side operator reads one finalized Bittensor metagraph. It keeps only
   validator-permit holders at or above the operator's configured stake floor.
2. The operator signs this bounded snapshot with a dedicated Ed25519 artifact
   key and atomically refreshes a fixed file visible to the worker.
3. A validator connects to the chain axon and signs each HTTP request with its
   existing Bittensor sr25519 hotkey.
4. The worker verifies the exact request, the observed TLS SPKI, freshness,
   replay state, and the caller's current entry in the signed snapshot.
5. After fresh attestation confirms the TLS SPKI, the validator requests the
   bounded fleet candidate list.
6. The validator independently attests and tests every candidate. It derives
   hardware identity from verified evidence and deduplicates it. Endpoint
   count and miner claims never prove distinct compute.

The worker contains no Bittensor RPC client and no wallet. The private
validator hotkey remains on the validator. The private snapshot-artifact key
remains on the operator host.

## HTTP contract

The request header is:

```text
X-Cathedral-Validator-Request: <base64 canonical JSON>
```

The decoded document has this exact schema:

```json
{
  "schema": "cathedral_validator_request_v1",
  "validator_hotkey": "<Bittensor SS58 hotkey>",
  "worker_hotkey": "<miner Bittensor SS58 hotkey>",
  "network": "finney",
  "netuid": 39,
  "method": "POST",
  "path": "/v1/fleet",
  "body_sha256": "sha256:<64 lowercase hex>",
  "channel_binding_type": "tls_spki_sha256",
  "channel_binding_digest_hex": "<64 lowercase hex>",
  "nonce_hex": "<64 lowercase hex>",
  "issued_at": "2026-08-29T07:00:00Z",
  "expires_at": "2026-08-29T07:01:00Z",
  "signature": {
    "algorithm": "sr25519",
    "value_base64": "<64-byte signature>"
  }
}
```

The signature covers canonical JSON with the `signature` member removed.
Canonical JSON uses sorted keys, compact separators, ASCII, and no NaN. A
request is bound to one validator, miner, subnet, method, path, body, TLS key,
nonce, and validity window. The maximum validity window is 120 seconds.

The protected paths are:

| Path | Signed-access behavior |
|---|---|
| `POST /v1/evidence` | Signed by default. It is public with either explicit migration flag. |
| `POST /v1/fleet` | Always signed. The request body is exactly `{}`. |
| `POST /v1/sat-work` | Signed validator request or legacy bearer. The legacy-audit flag also permits only canonical SAT without a credential. Noncanonical customer SAT still requires the bearer. |
| `POST /v1/capabilities` | Signed validator request or legacy bearer. |

`POST /v1/fleet` returns this exact bounded document:

```json
{
  "schema": "cathedral_worker_fleet_v1",
  "worker_hotkey": "<miner Bittensor SS58 hotkey>",
  "endpoints": [
    "https://<primary-public-ip>:8081",
    "https://<second-public-ip>:8081"
  ]
}
```

Production endpoints must be canonical HTTPS origins with a globally routable
IP literal and an explicit port from 1 through 65535. The maximum is 32. The
chain axon endpoint is always first. If no fleet manifest is configured, the
response contains exactly that one endpoint. The worker never invents other
operator capacity. The angle-bracket values above are placeholders, not
runnable reserved example addresses. IPv4-mapped, 6to4, Teredo, NAT64
well-known, NAT64 local-use, and deprecated IPv4-compatible IPv6 transition
forms are always rejected, even when their embedded IPv4 address is public.

The fleet response has no separate miner signature. It arrives over the same
TLS key that the validator freshly attested, in response to an authenticated,
fresh, replay-protected request. The validator rejects a channel-key change and
independently attests each returned candidate. A response received before that
TLS promotion is not trusted.

## Qualification snapshot

The fixed worker input uses this exact shape:

```json
{
  "schema": "cathedral_validator_access_snapshot_v1",
  "network": "finney",
  "netuid": 39,
  "block": 8948557,
  "block_hash": "0x<64 lowercase hex>",
  "block_is_finalized": true,
  "generated_at": "2026-08-29T07:00:00Z",
  "expires_at": "2026-08-29T07:15:00Z",
  "minimum_stake_rao": 1000,
  "validators": [
    {
      "hotkey": "<Bittensor SS58 hotkey>",
      "uid": 30,
      "validator_permit": true,
      "stake_rao": 2000
    }
  ],
  "signing_key_id": "cathedral-validator-access-1",
  "signature": {
    "algorithm": "ed25519",
    "value_base64": "<64-byte signature>"
  }
}
```

The worker's configured minimum stake is authoritative. The signed document
must state the same value. A snapshot cannot lower the local policy. Validator
hotkeys and UIDs must both be unique, and rows must be sorted by hotkey.

The worker checks the file identity, size, owner, permissions, Ed25519
signature, network, subnet, finalized block, validity, age, permit, exact Rao
stake, and uniqueness. It pays the signature-verification cost only after the
file identity changes. A missing or malformed replacement does not evict the
last verified snapshot while it is still fresh. Expiry always fails closed.

The trusted public-key JSON is pinned by its exact SHA-256 digest. Never load an
unpinned adjacent key file. Snapshot block high-water state is durable, so a
restart does not permit a lower finalized block or same-height equivocation.

## Durable replay boundary

Every accepted `(validator_hotkey, nonce)` is written to an owner-only SQLite
file before work is served. Expired rows are pruned, the table is capped at
4,096 live rows, and a full or unavailable store fails closed. The state also
holds the accepted snapshot high-water mark and a maximum observed request
time. A backward wall-clock step fails closed, so pruning an expired nonce can
never make a captured request reusable after clock rollback. Use a persistent,
integrity protected path. Do not place it on a container tmpfs if worker
restarts retain the same TLS key.

Authorization has two phases. Before any class-pool admission or body read, the
worker verifies the canonical signed envelope, signer, snapshot qualification,
method, path, miner, subnet, TLS channel, nonce shape, and validity window. Only
then does the verified hotkey allocate a per-validator limiter entry. An
unverified claimed hotkey cannot allocate an entry. Each qualified validator
gets one concurrent signed request and 120 verified envelopes per 60-second
window. The table is capped at 256 verified validator hotkeys. A caller over
either limit receives HTTP 429 before its body is read.

After admission, the worker reads the bounded body, checks its exact signed
SHA-256 digest, rechecks snapshot qualification and expiry, and durably consumes
the `(validator_hotkey, nonce)` replay key before serving work. The concurrency
lease stays held through handling and is released in a `finally` block. Global
connection and class pools remain separate process-wide ceilings. After headers
are parsed and authenticated, verified validator control requests use a
reserved signed pool. Public evidence and canonical SAT enabled by a migration
flag cannot consume those signed request-class slots. This ordering prevents
either one qualified validator with stalled bodies or public bridge traffic
from consuming every signed-work class slot while another qualified validator
is ready.

Before headers are parsed, every TLS client shares the finite connection gate.
A raw TCP or TLS client that stalls before sending complete headers can consume
that gate until its deadline. The source-level class pools do not prove signed
validator availability during a connection flood. Enabling this image in live
testing therefore requires reviewed network-edge connection and handshake
limits, monitoring, and a tested rollback path.

Snapshot refresh does not restart the worker and does not rotate its TLS SPKI.
The producer writes a complete temporary file, fsyncs it, and atomically
replaces the fixed snapshot path.

## Host-side setup

Run the chain reader outside the measured guest in its own environment. The
operator role intentionally stays separate from the worker role.

```bash
python3.12 -m venv .venv-validator-access-producer
. .venv-validator-access-producer/bin/activate
python -m pip install -e '.[enrollment-operator]'

install -d -m 0700 /secure/cathedral-validator-access

python scripts/cathedral_validator_access.py init-key \
  --signing-key-id cathedral-validator-access-1 \
  --signing-key-out /secure/cathedral-validator-access/snapshot.seed \
  --keys-out /secure/cathedral-validator-access/snapshot-keys.json
```

`init-key` refuses to overwrite either output. It creates the private seed at
mode `0600`, creates the public-key JSON at mode `0644`, prints the public-key
file's `sha256:` pin, and never prints the seed.

Capture and atomically publish a short-lived finalized view. The capture command
refuses to publish when the expected UID30 hotkey is absent. This catches an
operator mistake. It is not protection from the operator who controls the
artifact signing seed.

```bash
python scripts/cathedral_validator_access.py capture \
  --network finney \
  --netuid 39 \
  --minimum-stake-rao <operator-policy-floor-in-exact-rao> \
  --signing-key-id cathedral-validator-access-1 \
  --signing-key-file /secure/cathedral-validator-access/snapshot.seed \
  --out /srv/cathedral/validator-access.json \
  --valid-seconds 900 \
  --require-hotkey <uid30-validator-hotkey>
```

Refresh well before the 15-minute expiry. Every run reads one finalized head,
filters exact `total_stake.rao`, signs, verifies, and atomically replaces the
output. If the chain read, signer, required hotkey, or verification fails, the
existing file remains in place.

Verify the deployed artifact against the pinned key file:

```bash
python scripts/cathedral_validator_access.py verify \
  --snapshot /srv/cathedral/validator-access.json \
  --keys /srv/cathedral/snapshot-keys.json \
  --keys-digest sha256:<digest-printed-by-init-key> \
  --network finney \
  --netuid 39 \
  --minimum-stake-rao <same-operator-policy-floor-in-exact-rao> \
  --require-hotkey <uid30-validator-hotkey>
```

The private artifact seed stays outside the guest. The guest receives only the
public snapshot, public key JSON, immutable digest pin, and persistent replay
state path.

## Worker setup in the general image

Install the explicit worker role:

```bash
python -m pip install -e '.[validator-access-worker]'
```

The optional fleet manifest is owner-controlled JSON:

```json
{
  "schema": "cathedral_worker_fleet_v1",
  "worker_hotkey": "<miner-hotkey>",
  "endpoints": [
    "https://<second-public-ip>:8081"
  ]
}
```

The primary chain axon does not need to be repeated. The worker adds it first.
Omit the manifest for exact one-machine compatibility.

```bash
cathedral worker migrate \
  --hotkey <miner-hotkey> \
  --host 0.0.0.0 \
  --port 8081 \
  --tls-certificate /run/cathedral/worker.crt \
  --tls-private-key /run/cathedral/worker.key \
  --channel-binding-type tls_spki_sha256 \
  --channel-binding-digest <certificate-spki-sha256-hex> \
  --validator-access-snapshot /srv/cathedral/validator-access.json \
  --validator-access-keys /srv/cathedral/snapshot-keys.json \
  --validator-access-keys-digest sha256:<pinned-public-key-json-digest> \
  --validator-access-state /var/lib/cathedral/validator-access.sqlite \
  --validator-minimum-stake-rao <same-operator-policy-floor-in-exact-rao> \
  --validator-network finney \
  --validator-netuid 39 \
  --public-endpoint https://<primary-public-ip>:8081 \
  --fleet-manifest /srv/cathedral/fleet.json \
  --migration-mode public-legacy-audit
```

Signed-only audit serving does not require a bearer. Keep the enrollment bearer
configured during migration if a legacy validator still uses it. The explicit
`worker migrate --migration-mode public-bootstrap-evidence` posture opens only
evidence. `public-legacy-audit` is the bounded UID30 bridge. It keeps evidence
and canonical audit SAT public while fleet discovery, capabilities, and
noncanonical customer SAT remain protected. Neither migration mode is accepted
by production `worker serve` or development `worker develop`. Remove the bridge
after the signed validator path is live and rollback-tested.
After headers are parsed and authenticated, public bridge traffic has its own
bounded pools and cannot occupy the reserved signed-validator request pool. It
still shares the pre-header connection gate described above.

## Trust and scoring boundaries

- Qualification permits access. It does not admit hardware, prove work, assign
  weight, or promise emissions.
- A fleet endpoint is only a candidate. Verified vendor evidence, policy,
  same-SPKI binding, work result, and hardware uniqueness remain validator
  decisions.
- One UID can advertise several candidates. The validator counts only distinct
  endpoints with distinct attested hardware identities and distinct attested
  TLS SPKIs. Repeating one machine at several IPs produces one machine of
  verified compute. Reusing one TLS private key across machines also fails the
  distinct-compute gate because work could collapse onto one channel. Generate
  each TLS key inside its own guest and never copy a TLS private key between
  machines.
- A UID advertises at most 32 endpoints. Fleet overflow zeros the UID. The
  validator never silently truncates it.
- Each verified machine receives one canonical SAT per scoring window, capped
  at 20 raw work units. `raw_uid_units` is the sum across distinct verified
  machines and is capped at 640 raw units per UID per window.
- A verified duplicate endpoint, stable hardware identity, or TLS SPKI and
  channel identity zeros every verified claimant in that collision. The
  validator never chooses a winner. An unverified manifest claim does not
  poison a verified claim.
- Declared machine count, vCPU, RAM, capacity, idle uptime, and attestation
  alone earn zero. Every counted machine needs fresh evidence, assigned-hotkey
  binding, QVL-derived stable hardware identity, TLS SPKI binding, global
  uniqueness, and replayed canonical SAT.
- The transport is TEE-profile neutral. `--tee snp` exists only under the
  explicit `worker develop` posture. Live multi-machine scoring remains Intel
  TDX-only. AMD SEV-SNP must complete
  the friend-hardware probe and prove stable `CHIP_ID` deduplication before SNP
  fleet rewards are enabled.
- The miner or host operator is trusted for access-policy accuracy. An operator
  who controls the artifact seed can allow or deny any caller, including by
  signing a fabricated higher-block row after bypassing the capture command.
  The signature and pinned public key stop parties without that seed from
  changing the access view. Durable high-water state detects rollback and
  same-height equivocation relative to artifacts the worker already accepted.
  None of these controls proves chain truth or grants score. Validators still
  independently verify hardware, channel binding, uniqueness, and work.

## Migration compatibility

- `worker serve` is the signed/bearer-protected production surface and exposes
  no public-route compatibility controls.
- `worker migrate` requires the complete signed-access bundle and exactly one
  explicit migration mode.
- Signed access plus no fleet manifest returns exactly the current chain axon.
- SAT and capabilities accept either a qualified signed validator request or
  the existing valid bearer.
- `public-bootstrap-evidence` preserves the old public evidence route while
  validators migrate.
- `public-legacy-audit` preserves public evidence and canonical SAT for the
  current UID30 collector. It never opens noncanonical customer work.
- Fleet discovery never accepts a bearer and never becomes public.
- Bearer removal requires a later measured-image change after all active
  validators have moved and rollback evidence exists.

## Activation gates

Image review, merge, immutable publication, provenance inspection, anonymous
manifest access, runtime-label verification, and the UID124 rollback exercise
are complete for the digest in `SN39_AUDIT_MINER_OPERATIONS.md`. Publication is
not deployment. These activation gates remain:

1. Configure the validator signer and fleet traversal. Prove UID30
   signs with its existing hotkey and no private key enters the worker guest.
2. Complete a two-endpoint Intel TDX test with fresh QVL, same-SPKI work on
   each endpoint, distinct endpoint, distinct TLS SPKI, stable distinct-hardware
   deduplication, and deterministic scoring.
3. Keep AMD SEV-SNP fleet scoring disabled until the friend-owned hardware test
   proves stable `CHIP_ID` behavior.

## Replacement image is published in fixed migration posture

The reviewed replacement was built from source merge
`78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8` and published as
`ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99`.
Its fixed command uses `worker migrate --migration-mode public-legacy-audit`
and emits `cathedral_effective_startup_v1`. The preserved legacy rollback image
was built from source merge `8ad7f6e127ad7dcc4dd150f0e1eb47ce72c5ab22`.
It uses `worker serve --tee tdx --allow-public-legacy-audit` and must not be
substituted into the new launcher. Promotion to signed-only `worker serve`
requires a later reviewed image change. Do not treat publication as evidence
the artifact is deployed or serving live traffic.

The fixed host paths and exact startup are documented in
[SN39_AUDIT_MINER_IMAGE.md](SN39_AUDIT_MINER_IMAGE.md). The config directory is
read-only inside the container. Replay state is persistent. The narrow
configfs TSM report bind is read-write because quote collection creates and
writes report entries. No wallet, chain RPC, private validator key, snapshot
signing seed, shared bearer, or broader TDX device mount enters the guest.
