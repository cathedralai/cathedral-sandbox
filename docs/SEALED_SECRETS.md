# Customer-sealed secrets at /run/secrets (AB#417, slice 1)

**Status:** behind `ROOM_SEALED_SECRETS=1` (default 0). No hotel runs it. This is Mode B of AB#415: the customer seals the value, so our API and broker relay only ciphertext and only the attested guest opens it. Commands are still visible (see section 7). Client: `ctcli sandbox secret seal` (cathedral-pool).

## 1. Key binding, and why it is compatible

- At start the receipts front (`room-kit/room_receipts.py`, `SealedSecrets`) makes an X25519 key in process memory. One per boot. Never written to disk.
- On a sealed guest with the flag on, the binding gains one key:
  `"sealed_secrets": {"schema": "cathedral_sealed_secret_v1", "algorithm": "x25519-hkdf-sha256-aes256gcm-v1", "x25519_public_b64": <32 bytes>, "path": "/run/secrets"}`
- REPORT_DATA keeps its rule: `sha256(canonical(binding)) || 32 zero bytes`. The AMD-signed report commits to the receipt key and the secrets key together. Miner hotels already add keys this way (`tls_spki_sha256`, `hotel_key_install_x25519_b64`).
- **Compatible:** every verifier hashes the binding whole and reads only the fields it checks, so `verify_receipts.py` is unchanged (byte for byte main, sha256 `ae585ab6...`, the copy cathedral-pool #92 vendors). The broker's `verifyAttestation` is unchanged too (Go test added). The spare 32 bytes stay zero because every verifier requires that. Flag off: the binding is byte for byte what it was, so every current receipt verifies as before.
- Level 1 hotels never offer the key: no SNP report binds it.

## 2. Envelope

- One construction in the guest. It is the one the Escape plant and the miner hotel-key install already use, here with its own HKDF info and AAD: ephemeral X25519 to the bound key, HKDF-SHA256 (salt = AAD, info = `"cathedral.sealed-secret.v1" || eph_pub || recipient_pub`), AES-256-GCM (random 12-byte nonce, same AAD). pyca/cryptography only. AB#417 asks for this envelope because WebCrypto does every step (deriveBits X25519, HKDF, AES-GCM), so the browser slice needs no crypto code of its own.
- `POST /v1/sandboxes/<room>/sealed-secrets`, body with exactly these fields:

| Field | Value |
|---|---|
| `schema`, `algorithm` | `cathedral_sealed_secret_v1`, `x25519-hkdf-sha256-aes256gcm-v1` |
| `binding_sha256` | the binding the client verified |
| `sandbox_id` | the hotel room id (the guest create receipt's `sandbox_id`) |
| `name` | file name, `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` |
| `version` | integer 1 to 2^53 - 1; must rise per room and name (ctcli: milliseconds now) |
| `ephemeral_public_b64`, `nonce_b64`, `ciphertext_b64` | the envelope; the value is at most 64 KiB |

- AAD = `"cathedral.sealed-secret.v1\n" || canonical(the six header fields)`. Any change to the binding, room, name or version fails the open.

## 3. What the client checks before sealing (ctcli)

1. Input is the evidence bundle from `ctcli sandbox evidence` (AB#557): the hotel attestation and the room's guest receipts.
2. The vendored `verify_receipts.py` runs on the attestation and the room's guest create receipt, with `--require-sealed` and a **required** `--expected-measurement` (without a pin any SNP guest passes, including one built to leak). AMD chain: always checked. Certificates from the bundle are used only with `--ark-sha256`; otherwise the verifier fetches AMD KDS itself.
3. That create receipt names this room and verifies under the binding's receipt key, so the room is on this boot of this guest.
4. The key sealed to is read from that same verified binding object, never from a separate answer.
5. With `--send`, the guest's answer must name this envelope's sha256, and its `X-Room-Receipt` is checked against the binding's receipt key when present.
6. `409 sealed_secret_wrong_binding` means the guest restarted: fetch the evidence again and reseal.

## 4. What the API and broker relay

- **Broker:** the existing room passthrough (`/v1/sandboxes/<hotel>.<room>/<tail>` and the UUID compat path) carries the route as-is. No broker change.
- **Customer API (polariscomputer):** no relay route yet. Slice 2 adds the passthrough and stores the `X-Room-Receipt`.
- Relays see ciphertext, name, version, room and size. Never the value. The receipt signs the envelope sha256, never a digest of the value (secrets are often guessable).

## 5. In the guest

- The front checks, in order: flag, hotel key, size, exact fields, algorithm, this boot's binding, room in path equals body, name, version, room directory (`O_NOFOLLOW`), version order, then the open. The envelope never reaches the room API.
- It writes `/run/room-secrets/<room>/<name>` as a new file (temp, then rename), mode 0444. `/run/room-secrets` is tmpfs (guest memory, which SNP encrypts), 0700, made at every boot.
- The room API (`CATHEDRAL_SEALED_SECRETS_DIR`) makes an empty directory per room at create and bind-mounts it **read-only** at `/run/secrets`. It drops it on retire (delete, bulk delete, expiry), on a failed start, and in reconcile for any room with no record.

## 6. Replay and rollback

- **Another boot or guest:** the binding is in the AAD and the key is per boot: 409, or it does not open.
- **Another room:** the room id is in the AAD and must match the path.
- **Rollback in a boot:** a version at or below the last accepted for (room, name) gets `409 sealed_secret_replayed`. An exact retry of the current envelope answers `unchanged`, only while its file is in place. State lives for the whole boot, so a room made again under the same id refuses old envelopes. Bounds: 64 names per room, 65,536 per boot.
- **Across boots:** a restart loses the key, the values and the state. Every old envelope is for a dead binding. Fail closed; the client reseals.
- **Withholding:** a relay can drop an envelope. The client sees it: no `written` answer, no receipt with its envelope sha256, no entry in `GET .../sealed-secrets`.

## 7. What this does NOT protect

- **Commands, outputs and files** still pass through the API and broker in clear (and the host on config hotels until AB#378).
- **Exec reads the file.** Whoever can send an exec to the room (our API and broker can) can `cat /run/secrets/<name>`. The exec lands in the guest-signed chain (`command_sha256`), so it can be seen, not stopped. Stopping it needs customer-signed commands or the encrypted link below.
- **Room identity on shared hotels.** The client learns its room from our API. A dishonest operator could point it at a room it made on the same attested guest. Dedicated machines close this with the owner gate (`--owner-pubkey`).
- **Measurement trust** is the customer's pin until a signed approved-build list (AB#382); builds are not yet reproducible (AB#380).
- **Room to room** inside one guest is gVisor only. **Mode A** (AB#416, vault release) is a different path where our control plane handles plaintext.

## 8. Convergence with M-H's encrypted link (AB#353, spike AB#361)

- The spike binds one key: REPORT_DATA = `sha256(box TLS SPKI) || 32 zero bytes`. The binding is the same idea for several keys, and miner hotels already name `tls_spki_sha256` in it (`verify_receipts.py --tls-spki-sha256` checks the peer). One rule, one verifier.
- Proposal for the combined box: boxd names its TLS SPKI as `tls_spki_sha256` and this key as `sealed_secrets` in one binding, instead of raw `sha256(SPKI)`. No second scheme.
- The two do different jobs. The link (slice 3) carries commands and files into the guest, which closes the gap in section 7. The envelope stays end to end through any relay, queue or store, and Mode A's attested release (AB#392) wraps vault secrets to the same key.

## 9. Rollout (Toby's go-live)

1. Merge with the flag off. Nothing changes at runtime. Hotels pick it up only when a guest is rebuilt.
2. Bump the guest API tarball (`room-kit/make-dist.sh <commit>`, then `CATHEDRAL_COMMIT`, `CATHEDRAL_TARBALL` and its sha256 in `room-kit/versions.lock`). Without it the `/run/secrets` mount is absent and the front answers 404 for every room.
3. Build a guest with `SEALED_ROOM_SEALED_SECRETS=1`. The flag is in the measured `room.env`: **a new measurement**. Record it and add it to the broker's `sealed_measurements`.
4. Test on the isolated fleet (AB#379; coordinate machine 3 with mission #353): seal with ctcli, read the file in the room, confirm the mount is read-only, confirm a file written after the room started is visible under gVisor (runsc bind-mount file access mode, not yet checked), restart and confirm 409 and an empty directory, verify the chain.
5. Ship in the combined guest release, one restart per sealed hotel (a restart destroys rooms, so drain and notify first). Then turn on the API relay (slice 2).
