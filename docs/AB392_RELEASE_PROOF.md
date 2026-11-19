# Guest release proof (AB#392)

This implements the guest proof from API [design PR1920](https://github.com/bigailabs/polariscomputer/pull/1920),
section 5.3. It is one part of the separate vault release service. It does not
release a key, validate an AWS policy, or enable attested vault secrets.

The new route is `POST /room/release-proof` on the authenticated receipts front.
On a miner hotel it is served through the existing attested HTTPS listener;
the public HTTP listener still serves attestation only. Sealed mode and the
existing sealed-secrets key must both be enabled, and startup room scanning
must have finished.

The request is exactly `{sandbox_id, challenge}`. The outer `sandbox_id` is the
guest's room ID. `challenge` has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | `cathedral_vault_release_challenge_v1` |
| `nonce_b64` | Canonical standard base64 of 32 random bytes |
| `issued_at` | Integer Unix seconds, no future time, at most 60 seconds old |
| `secret_id` | Canonical lowercase UUID of the secret |
| `sandbox_id` | Cathedral sandbox UUID from the signed create or pool claim |
| `binding_sha256` | Current guest boot binding digest |
| `room_create_receipt_sha256` | Current room incarnation, its create receipt digest |
| `hmac_b64` | Canonical standard base64 of the release service's 32-byte MAC |

This specifies the wire details left open in the design. Binding and incarnation
are included in the challenge so a challenge issued for one boot cannot be used
for another. The service must MAC the UTF-8 canonical JSON of all challenge
fields except `hmac_b64`, prefixed with `cathedral.vault-release.challenge.v1`
and a zero byte, using HMAC-SHA256 and its private challenge key. Canonical JSON
uses sorted keys and no whitespace. Every accepted field is ASCII or an integer.

The guest **does not know the challenge key**. It checks the strict shape and
time, but cannot authenticate the MAC, authorize the secret or decide its
policy. A well-formed invented MAC can get a proof; the release service must
reject it. The service must independently check its MAC, challenge expiry,
AMD chain, approved post-fix measurement, TCB, debug/migration policy, receipt
key, create/claim and any dedicated-owner signature before decrypting.

The guest checks the binding, current incarnation and customer ID from its own
signed create or claim, then reads the guest-local room API with a three-second
total deadline. Only a successful response naming that room qualifies. It
rechecks the challenge and room state under the ledger lock before signing.
Ended, replaced, unclaimed, broken or uncertain rooms refuse. A pending bulk
delete or another in-flight room request also refuses. Serial rooms retain
their usual exclusive turn. These checks prove the observed state at signing,
not that the sandbox will remain alive after the response.

The response is `{receipt}`. Its ordinary sealed receipt statement contains the
existing chain fields (`schema`, `binding_sha256`, `hotel`, `operation_id`,
`sequence`, `previous_receipt_sha256`, `issued_at`, `room_sequence`,
`room_previous_receipt_sha256`) plus exactly:

- `action: release_proof`, fixed by the guest;
- `purpose: cathedral.vault-release.v1`, fixed by the guest;
- `challenge_sha256`, the digest of canonical JSON of the **whole** challenge,
  including its MAC;
- `sandbox_id`, the guest room ID;
- `room_create_receipt_sha256`, the current incarnation;
- `status: 200`.

The proof is signed with the receipt key named by the boot binding and appended
to the existing chain. No caller-selected action, signature preimage, secret
value or raw challenge is appended. A signing failure returns no proof. The
request is capped at 4 KiB before reading; duplicate JSON fields and extra
fields refuse. Repeating a valid challenge creates another proof in the chain;
it does not execute a command or release a secret. Release-side replay policy
is still part of the separate service.

Deployment requires independent review, green CI and a new guest image/roll by
the release owner. Coordinate with sandbox597 and API1939; this does not modify
their branches or authorize a rollout. Future release-service allowlists must
require a build containing both the reserved-report-data guard and this route.
No API relay, release service, AWS provisioning or live hardware acceptance is
included. The tests use synthetic SNP evidence and real receipt signatures.
