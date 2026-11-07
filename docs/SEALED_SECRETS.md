# Customer-sealed secrets at /run/secrets (AB#417, slice 1)

**Status:** behind `ROOM_SEALED_SECRETS=1` (default 0). No hotel runs it. This is Mode B of AB#415: the customer seals the value, so our API and broker relay only ciphertext and only the attested guest opens it. Commands are still visible (see section 7). Client: `ctcli sandbox secret seal` (cathedral-pool).

## 1. Key binding, and why it is compatible

- At start the receipts front (`room-kit/room_receipts.py`, `SealedSecrets`) makes an X25519 key in process memory. One per boot. Never written to disk.
- On a sealed guest with the flag on, the binding gains one key:
  `"sealed_secrets": {"schema": "cathedral_sealed_secret_v2", "algorithm": "x25519-hkdf-sha256-aes256gcm-v1", "x25519_public_b64": <32 bytes>, "path": "/run/secrets"}`
- Schema v2 is the envelope with the room incarnation (section 2). v1 had no incarnation and never shipped, so no guest or client speaks it. The algorithm name is unchanged because the cryptography is unchanged.
- REPORT_DATA keeps its rule: `sha256(canonical(binding)) || 32 zero bytes`. The AMD-signed report commits to the receipt key and the secrets key together. Miner hotels already add keys this way (`tls_spki_sha256`, `hotel_key_install_x25519_b64`).
- **Compatible:** every verifier hashes the binding whole and reads only the fields it checks, so `verify_receipts.py` is unchanged (byte for byte main, sha256 `ae585ab6...`, the copy cathedral-pool #92 vendors). The broker's `verifyAttestation` is unchanged too (Go test added). The spare 32 bytes stay zero because every verifier requires that. Flag off: the binding is byte for byte what it was, so every current receipt verifies as before.
- Level 1 hotels never offer the key: no SNP report binds it.

## 2. Envelope

- One construction in the guest. It is the one the Escape plant and the miner hotel-key install already use, here with its own HKDF info and AAD: ephemeral X25519 to the bound key, HKDF-SHA256 (salt = AAD, info = `"cathedral.sealed-secret.v2" || eph_pub || recipient_pub`), AES-256-GCM (random 12-byte nonce, same AAD). Every seal draws a new ephemeral key and nonce; tests on both sides fail when either is constant, and the guest refuses an ephemeral key it has already accepted in that room (`400 sealed_secret_ephemeral_reused`). pyca/cryptography only. AB#417 asks for this envelope because WebCrypto does every step (deriveBits X25519, HKDF, AES-GCM), so the browser slice needs no crypto code of its own.
- `POST /v1/sandboxes/<room>/sealed-secrets`, body with exactly these fields:

| Field | Value |
|---|---|
| `schema`, `algorithm` | `cathedral_sealed_secret_v2`, `x25519-hkdf-sha256-aes256gcm-v1` |
| `binding_sha256` | the binding the client verified |
| `sandbox_id` | the hotel room id (the guest create receipt's `sandbox_id`) |
| `room_create_receipt_sha256` | the room's incarnation: `receipt_sha256` of its latest successful guest create receipt in this boot's chain (64 lowercase hex) |
| `name` | file name, `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` |
| `version` | integer 1 to 2^53 - 1; must rise per room and name (ctcli: milliseconds now) |
| `ephemeral_public_b64`, `nonce_b64`, `ciphertext_b64` | the envelope; the value is at most 64 KiB |

- AAD = `"cathedral.sealed-secret.v2\n" || canonical(the seven header fields)`. Any change to the binding, room, incarnation, name or version fails the open.
- The guest accepts an envelope only for the room's current incarnation: the last successful create receipt it signed for that id, with no successful delete of the room signed after it. Otherwise `404 sealed_secret_room_not_found` (no create, or deleted) or `409 sealed_secret_wrong_incarnation` (made again, including an idempotent create replay, which signs a new create receipt: read the evidence again and reseal). A batch create signs no per-room create receipt, so its rooms take no sealed secrets.

## 3. What the client checks before sealing (ctcli)

1. Input is the evidence bundle from `ctcli sandbox evidence` (AB#557): the hotel attestation and the room's guest receipts.
2. The vendored `verify_receipts.py` runs on the attestation and the room's guest create receipt, with `--require-sealed` and a **required** `--expected-measurement` (without a pin any SNP guest passes, including one built to leak). AMD chain: always checked. Certificates from the bundle are used only with `--ark-sha256`; otherwise the verifier fetches AMD KDS itself.
3. That create receipt names this room and verifies under the binding's receipt key, so the room is on this boot of this guest. Its sha256, computed from the verified statement, is the envelope's `room_create_receipt_sha256`. Which create receipt is the room's (and which room is the customer's) is still our API's word: it serves the bundle.
4. The key sealed to is read from that same verified binding object, never from a separate answer.
5. With `--send`, the answer must be 200, name this envelope's sha256, and carry an `X-Room-Receipt` that verifies with the binding's receipt key and names this envelope, room, incarnation, name and version. That holds for `written` and for `unchanged` (the guest returns the original write's receipt). Anything else is "the guest did not confirm this write": ctcli exits 3 with `sealed_secret_unconfirmed`.
6. `409 sealed_secret_wrong_binding` means the guest restarted, and `409 sealed_secret_wrong_incarnation` means the room was made again: fetch the evidence again and reseal.

## 4. What the API and broker relay

- **Broker:** the existing room passthrough (`/v1/sandboxes/<hotel>.<room>/<tail>` and the UUID compat path) carries the route as-is. No broker change.
- **Customer API (polariscomputer):** no relay route yet. Slice 2 adds the passthrough and stores the `X-Room-Receipt`.
- Relays see ciphertext, name, version, room and size. Never the value. The receipt signs the envelope sha256, never a digest of the value (secrets are often guessable).

## 5. In the guest

- The front checks, in order: flag, hotel key, size, exact fields, envelope fields are ASCII strings (a lone surrogate escape is `400`, not a dropped connection), algorithm, this boot's binding, room in path equals body, name, version, incarnation, room directory (`O_NOFOLLOW`), version order, a fresh ephemeral key, then the open. The envelope never reaches the room API.
- It writes `/run/room-secrets/<room>/<name>` as a new file (temp, then rename), mode 0444. `/run/room-secrets` is tmpfs (guest memory, which SNP encrypts), 0700, made at every boot.
- The room API (`CATHEDRAL_SEALED_SECRETS_DIR`) makes an empty directory per room at create and bind-mounts it **read-only** at `/run/secrets`. It drops it on retire (delete, bulk delete, expiry), on a failed start, and in reconcile for any room with no record.
- **A write racing a retire.** The front can rename a file into the directory while the API's rmtree runs, and then rmtree's rmdir fails (ENOTEMPTY). Two closures: the API tries the rmtree again until the directory is gone (5 tries), and when a delete passes the front, the front signs the delete receipt (which ends the incarnation), then, under the lock every write holds until its file is in place, drops the room's entries and removes the directory. No write can land after that. A delete the front does not see (expiry, bulk delete) relies on the retries, then on reconcile. A write whose directory is gone answers `404`, never `500`.

## 6. Replay and rollback

- **Another boot or guest:** the binding is in the AAD and the key is per boot: 409, or it does not open.
- **Another room:** the room id is in the AAD and must match the path.
- **Rollback in a boot:** a version at or below the last accepted for (room incarnation, name) gets `409 sealed_secret_replayed`. An exact retry of the current envelope answers `unchanged` with the receipt of the write that put it in place, only while its file is in place.
- **A room made again under the same id:** it has a new create receipt, so every older envelope names a dead incarnation and is refused (`409`), and a rewritten incarnation field fails the open. That is why the state can go with the room.
- **Bounds and state:** the front keeps (version, envelope sha256, ephemeral key, write receipt) per (room incarnation, name). A room's entries go when a delete passes the front, when the room is made again, or (swept when the table is full, at most once a second) when its directory is gone. A directory is made only by a create, which signs a new create receipt, so a swept room never takes a write under its old incarnation. Bounds: 64 secrets per room directory, 65,536 entries of live rooms per boot (1,000 slots x 64). Only live rooms can fill the table, and a full table answers `503 sealed_secrets_full`.
- **Across boots:** a restart loses the key, the values and the state. Every old envelope is for a dead binding. Fail closed; the client reseals.
- **Withholding:** a relay can drop an envelope. The client sees it: no signed receipt naming its envelope sha256, for `written` or `unchanged`. `GET .../sealed-secrets` is not signed, so it is a hint, not proof.

## 7. What this does NOT protect

- **Commands, outputs and files** still pass through the API and broker in clear (and the host on config hotels until AB#378).
- **Exec reads the file.** Whoever can send an exec to the room (our API and broker can) can `cat /run/secrets/<name>`. The exec lands in the guest-signed chain (`command_sha256`), so it can be seen, not stopped. Stopping it needs customer-signed commands or the encrypted link below.
- **Room identity on shared hotels.** The client learns its room, and which create receipt is the room's, from our API. A dishonest operator could point it at a room it made on the same attested guest. Dedicated machines close this with the owner gate (`--owner-pubkey`): the create receipt then carries the owner's signature over the create.
- **No sender authentication (slice 1 limitation).** The guest checks only that an envelope is sealed to its key for a live room incarnation. Anyone who reads the public attestation and holds the hotel bearer (our API and broker) can seal their own value at a higher version, or burn a name's version space with `2^53 - 1`. This adds nothing in slice 1, because the same relay can exec in the room. It must close before slice 3 closes exec: a customer key named in the create request (so the create receipt commits to it) that signs each envelope. So the rule in section 6 stops rollback by replay only: it does not stop a relay sealing an old value again at a new version.
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
