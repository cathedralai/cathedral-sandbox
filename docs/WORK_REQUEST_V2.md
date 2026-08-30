# Validator access and fleet protocol

This document defines the machine-facing contract between a Cathedral miner
worker and a direct SN39 validator.

It is not a weight relay. The access snapshot only tells the worker which
validator hotkeys may call protected routes. The validator verifies machines,
derives its own weights, and writes them directly to Bittensor. The current
validator uses zero burn.

## Request flow

1. Outside the guest, the miner operator reads one finalized Finney metagraph,
   keeps validator-permit holders, signs the bounded result with a dedicated
   Ed25519 key, and atomically refreshes the worker's access snapshot.
2. A validator connects to the miner axon over HTTPS and signs each protected
   request with its Bittensor sr25519 hotkey.
3. The worker checks the request signature, access snapshot, exact body, TLS
   SPKI, freshness, and durable replay state.
4. The validator verifies fresh hardware evidence before trusting the channel
   or requesting the fleet.
5. The validator independently verifies and tests every advertised machine.

The worker contains no Bittensor wallet or chain client. The validator hotkey
stays on the validator. The access-snapshot signing seed stays on the miner
operator host.

## Signed request

Every protected validator request carries:

```text
X-Cathedral-Validator-Request: <base64 canonical JSON>
```

The decoded JSON has this exact schema:

```json
{
  "schema": "cathedral_validator_request_v1",
  "validator_hotkey": "<validator SS58 hotkey>",
  "worker_hotkey": "<miner SS58 hotkey>",
  "network": "finney",
  "netuid": 39,
  "method": "POST",
  "path": "/v1/fleet",
  "body_sha256": "sha256:<64 lowercase hex>",
  "channel_binding_type": "tls_spki_sha256",
  "channel_binding_digest_hex": "<64 lowercase hex>",
  "nonce_hex": "<64 lowercase hex>",
  "issued_at": "<UTC time without fractional seconds>",
  "expires_at": "<UTC time without fractional seconds>",
  "signature": {
    "algorithm": "sr25519",
    "value_base64": "<64-byte signature>"
  }
}
```

The signature covers canonical JSON with `signature` removed. Canonical JSON
uses sorted keys, compact separators, ASCII, and no NaN. The validity window is
at most 120 seconds. The worker also limits future clock skew to 15 seconds.

The signature binds the validator, miner, subnet, method, path, body bytes, TLS
key, nonce, and validity window. A nonce is accepted once and recorded before
work is served.

## Protected routes

For the validator path, signed requests protect all four routes:

| Route | Request body | Purpose |
|---|---|---|
| `POST /v1/evidence` | Fresh evidence challenge | Bind fresh TEE evidence to the miner hotkey and observed TLS SPKI. |
| `POST /v1/capabilities` | `{}` | Confirm signed validator access and supported work. |
| `POST /v1/fleet` | `{}` | Return bounded machine candidates. This route never accepts a bearer. |
| `POST /v1/sat-work` | Canonical SAT challenge | Run the validator's existing proof-of-work check. |

An optional bearer remains separate customer-work authentication. In signed
access production, a bearer does not bypass the signed evidence route.

## Fleet response

`POST /v1/fleet` returns:

```json
{
  "schema": "cathedral_worker_fleet_v1",
  "worker_hotkey": "<miner SS58 hotkey>",
  "endpoints": [
    "https://<primary-public-ip>:8081",
    "https://<second-public-ip>:8081"
  ]
}
```

Rules:

- The chain axon is always first.
- Omitting a fleet manifest returns only the chain axon.
- The full response has at most 32 endpoints.
- Each endpoint is a canonical HTTPS origin with a globally routable IP
  literal and explicit port.
- Credentials, DNS names, paths, queries, fragments, duplicate endpoints, and
  IPv6 transition addresses are rejected.

The fleet response has no separate miner signature. It travels over the TLS
key freshly bound into verified evidence and in response to an authenticated,
replay-protected request. The validator rejects a channel-key change and
independently attests every candidate.

An operator-controlled fleet manifest contains only additional candidates:

```json
{
  "schema": "cathedral_worker_fleet_v1",
  "worker_hotkey": "<miner SS58 hotkey>",
  "endpoints": [
    "https://<second-public-ip>:8081"
  ]
}
```

The worker adds the primary chain axon itself. The manifest must be a regular,
non-symlink file owned by the worker user and not group or world writable.

## Validator-access snapshot

The worker consumes this exact signed document:

```json
{
  "schema": "cathedral_validator_access_snapshot_v1",
  "network": "finney",
  "netuid": 39,
  "block": 12345678,
  "block_hash": "0x<64 lowercase hex>",
  "block_is_finalized": true,
  "generated_at": "<UTC time without fractional seconds>",
  "expires_at": "<UTC time without fractional seconds>",
  "minimum_stake_rao": 0,
  "validators": [
    {
      "hotkey": "<validator SS58 hotkey>",
      "uid": 17,
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

The local minimum stake is authoritative and must match the signed document.
Use `0` to admit every validator-permit holder. Validator hotkeys and UIDs must
be unique, and validator rows must be sorted by hotkey.

The worker verifies the file identity, owner, permissions, size, Ed25519
signature, network, subnet, finalized marker, age, validity, permit, exact Rao
stake, and uniqueness. The public-key file is pinned by SHA-256. A malformed
replacement does not evict the last verified snapshot while it remains fresh.
Expiry fails closed.

The artifact signer is trusted for access policy. The worker does not prove the
snapshot against Bittensor itself. This trust grants request access only. It
does not prove hardware, work, score, weight, or emissions.

## Create and refresh the snapshot

Run the producer on a separate miner-controlled host, not in the TDX VM:

```bash
python3.12 -m venv .venv-validator-access
. .venv-validator-access/bin/activate
python -m pip install -e '.[enrollment-operator]'

install -d -m 0700 ../cathedral-validator-access-state

python scripts/cathedral_validator_access.py init-key \
  --signing-key-id cathedral-validator-access-1 \
  --signing-key-out ../cathedral-validator-access-state/snapshot.seed \
  --keys-out ../cathedral-validator-access-state/snapshot-keys.json
```

The state directory is outside the Git checkout. `init-key` refuses to
overwrite either file. Keep the printed key-file digest.
Only the public-key file and signed snapshot belong in the guest. Do not copy
the private seed.

Capture and atomically publish a 15-minute finalized view:

```bash
python scripts/cathedral_validator_access.py capture \
  --network finney \
  --netuid 39 \
  --minimum-stake-rao 0 \
  --signing-key-id cathedral-validator-access-1 \
  --signing-key-file ../cathedral-validator-access-state/snapshot.seed \
  --out ../cathedral-validator-access-state/validator-access.json \
  --valid-seconds 900
```

Verify the generated files before transfer:

```bash
KEYS_DIGEST='sha256:<64 hex characters printed after keys_digest>'
python scripts/cathedral_validator_access.py verify \
  --snapshot ../cathedral-validator-access-state/validator-access.json \
  --keys ../cathedral-validator-access-state/snapshot-keys.json \
  --keys-digest "$KEYS_DIGEST" \
  --network finney \
  --netuid 39 \
  --minimum-stake-rao 0
```

Transfer only those two public files through the miner's secure provisioning
channel. On each TDX VM, install the key file once and replace the snapshot
atomically:

```bash
sudo install -d -o root -g root -m 0700 \
  /etc/cathedral/validator-access \
  /var/lib/cathedral/validator-access
sudo install -o root -g root -m 0644 \
  /path/to/staging/snapshot-keys.json \
  /etc/cathedral/validator-access/snapshot-keys.json
sudo install -o root -g root -m 0644 \
  /path/to/staging/validator-access.json \
  /etc/cathedral/validator-access/.validator-access.json.new
sudo mv \
  /etc/cathedral/validator-access/.validator-access.json.new \
  /etc/cathedral/validator-access/validator-access.json
```

Refresh, verify, transfer, and atomically install the snapshot well before
expiry. A failed chain read, signature, transfer, or verification must leave
the last valid file in place.

## Signed-only worker target

This is the command contract for the next reviewed image. It is not an
instruction to run an editable checkout as a production service.

Use one TLS key generated inside each guest. Never copy a TLS private key
between machines.

```bash
cathedral worker serve \
  --hotkey <miner-hotkey> \
  --host 0.0.0.0 \
  --port 8081 \
  --tls-certificate /run/cathedral/worker.crt \
  --tls-private-key /run/cathedral/worker.key \
  --validator-access-snapshot /srv/cathedral/validator-access.json \
  --validator-access-keys /srv/cathedral/snapshot-keys.json \
  --validator-access-keys-digest sha256:<pinned-public-key-file-digest> \
  --validator-access-state /var/lib/cathedral/validator-access.sqlite \
  --validator-minimum-stake-rao 0 \
  --validator-network finney \
  --validator-netuid 39 \
  --public-endpoint https://<primary-public-ip>:8081 \
  --fleet-manifest /srv/cathedral/fleet.json
```

Omit `--fleet-manifest` for one machine. The replay database must be an
owner-only persistent file. Do not put it on tmpfs when restarts retain the
same TLS key.

Startup emits `cathedral_effective_startup_v1`. The intended posture reports
`posture: "production"`, `signed_validator_access: true`,
`public_legacy_audit: false`, and the expected fleet-candidate count.

## Current image exception

The currently published image is:

```text
ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99
```

Its fixed entrypoint still runs
`worker migrate --migration-mode public-legacy-audit`. This is a temporary
compatibility bridge, not the desired steady state. It leaves evidence and the
canonical SAT route public while fleet discovery and other protected work stay
signed. Do not copy this mode into a new image or general operator setup. The
replacement target is the signed-only `worker serve` command above.

The image digest proves publication, not deployment or live service.

## Security and scoring boundaries

- Signed access grants permission to ask. It does not grant score.
- The direct validator counts only machines that pass fresh vendor evidence,
  same-SPKI binding, canonical SAT, and global endpoint, channel, and hardware
  deduplication. Intel TDX uses the pinned QVL verifier. AMD SEV-SNP uses its
  released measurement and TCB policy plus the pinned SNP verifier.
- Repeating one machine at several addresses zeroes every verified claimant in
  that hardware collision for the round.
- Reusing a TLS private key across machines zeroes every verified claimant in
  that channel collision for the round.
- The current direct validator normalizes positive verified-machine counts by
  UID into a zero-burn vector. Uptime, declared capacity, and attestation alone
  earn zero.
- Signed validator requests are limited to one concurrent request and 120
  verified envelopes per 60 seconds for each qualified hotkey. Replay state is
  capped at 4,096 live entries and fails closed.
- Every TLS client shares the finite pre-header connection gate. A deployment
  still needs edge connection limits and monitoring.
- AMD SEV-SNP is eligible only after the validator policy accepts the exact
  measurement and TCB. A local hardware test does not prove a registered miner
  or a finalized weight row. See
  [AMD_SEV_SNP_FRIEND_TEST.md](AMD_SEV_SNP_FRIEND_TEST.md).
