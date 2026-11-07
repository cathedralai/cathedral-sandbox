# Customer-sealed commands (AB#417)

**Status:** behind `ROOM_SEALED_EXEC=1` (default 0). No hotel runs it. Line 3 of the security table ("our API can read commands and secrets before they reach the machine"): with this, our API, the cathedral.computer Worker and the broker carry only ciphertext for a command and its output. Same pattern as sealed secrets (`docs/SEALED_SECRETS.md`, slice 1). Client: `ctcli sandbox exec --sealed` (cathedral-pool). API relay: polariscomputer `POST /v1/sandboxes/{id}/exec` with a `sealed` body.

## 1. Key binding

- At start the receipts front (`room-kit/room_receipts.py`, `SealedExec`) makes an X25519 key in memory, one per boot, and names it in the binding: `"sealed_exec": {"schema": "cathedral_sealed_exec_v1", "algorithm": "x25519-hkdf-sha256-aes256gcm-v1", "x25519_public_b64": ...}`.
- REPORT_DATA is unchanged in rule (`sha256(canonical(binding)) || 32 zero bytes`), so the AMD report commits to the key. `verify_receipts.py` is unchanged (sha256 `ae585ab6...`); it hashes the binding whole. Flag off: the binding is byte for byte what it was. Level 1 never offers the key.
- Its own key, not the sealed secrets key: three X25519 keys, three HKDF infos, three AAD labels (plant, secrets, exec), no cross-use.

## 2. Wire format

Request (`POST /v1/sandboxes/<room>/sealed-exec` at the front; the customer sends it as `{"sealed": <doc>}` to the API's `/exec`):

| Field | Value |
|---|---|
| `schema`, `algorithm` | `cathedral_sealed_exec_v1`, `x25519-hkdf-sha256-aes256gcm-v1` |
| `binding_sha256` | the binding the client verified |
| `sandbox_id` | the guest's room id (its create receipt's `sandbox_id`) |
| `room_create_receipt_sha256` | the room incarnation, as for sealed secrets |
| `issued_at` | unix seconds; the guest takes 120 s back to 30 s ahead |
| `timeout_seconds` | 1 to 14,400; the one the room enforces |
| `response_public_b64` | X25519 key the client made for this exec; the answer is sealed to it |
| `ephemeral_public_b64`, `nonce_b64`, `ciphertext_b64` | the envelope |

- Plaintext: canonical JSON `{"cmd", "env", "stdin", "cwd", "user"}` (cmd required; at most 6 MiB).
- AAD = `"cathedral.sealed-exec.v1\n" || canonical(the eight header fields)`; HKDF info `"cathedral.sealed-exec.v1" || eph || recipient`. A relay can read the header but cannot change it: a longer timeout, a fresh `issued_at`, its own answer key or another room all fail the open (tested per field).
- Answer: HTTP 200 `{"sealed_response": {"schema": "cathedral_sealed_exec_response_v1", "algorithm", "request_sha256", "ephemeral_public_b64", "nonce_b64", "ciphertext_b64"}}`, plus `room_alive: false` and `oom_killed` only when the room died. The plaintext is `{"status": <room API status>, "answer": <room API JSON>}` (or `answer_b64`). AAD = `"cathedral.sealed-exec-response.v1\n" || canonical({schema, algorithm, binding_sha256, sandbox_id, room_create_receipt_sha256, request_sha256, response_public_b64})`, so an answer opens only as the answer to its own request.
- WebCrypto has every step, as for sealed secrets.

## 3. In the guest

- Checks, in order: flag, bearer, size, exact fields, ASCII envelope fields, algorithm, this boot's binding, room in path equals body, formats, freshness, a usable answer key, the room's current incarnation, a replay, then the open, then the exec shape. Nothing reaches the room API before all pass.
- **Runs once.** An envelope's ephemeral key is its identity (it is in the ECDH and the HKDF info, so a relay cannot change it). The front keeps each accepted one per room incarnation while its `issued_at` is in the window; outside the window the envelope is refused anyway. Two racing copies: one runs (tested with 8 threads). Bounds: 4,096 per room per window (429), 131,072 per boot (503, after a sweep of rooms that are gone).
- **Kept out of the room API's records.** The front sends the opened exec to the room API's own route `POST /v1/sandboxes/<id>/exec-sealed`, which runs it as `/exec` does but writes no exec history and no container log (`GET .../logs` serves both to whoever holds the hotel key). The front refuses that route to every caller, in every spelling. A guest built with an older API tarball answers 404 there: the command does not run (fail closed), it does not leak into the log.
- **Receipt.** One exec receipt per sealed exec: `action: "exec"`, `command_sha256` = sha256 of the plaintext command (as today), `status: 200` (the front's answer), `result_sha256` of the answer bytes, plus `sealed: true`, `room_create_receipt_sha256`, `sealed_request_sha256` and `sealed_response_sha256` (canonical sha256 of each envelope, so they survive re-encoding by relays). The client accepts an answer only with this receipt, signed by the attested receipt key and naming its own request and this answer: anyone holding the public answer key could seal a fake answer, only the guest can sign it.

## 4. What the relays see, and what still leaks

| Leak | Why it stays |
|---|---|
| Sizes: request about plaintext + 16 bytes, answer about output size | No padding yet. Bucketed padding is cheap to add (both sides); not in this slice. |
| Timing: when an exec starts and how long it runs | The relay carries the request and waits for the answer. |
| `timeout_seconds`, `issued_at` in the clear (authenticated) | The API refuses sync execs over 45 s and the broker sizes its wait from the timeout; `issued_at` bounds the replay table. |
| `room_alive: false`, `oom_killed` in the clear, only when the room died | The API ends a dead room's billing on them (billing unchanged). |
| `command_sha256` in the guest receipt, readable by the relay and stored by our API | Required: receipts keep signing sha256 of the plaintext command as today. A guessable command (`["ls"]`) can be confirmed by hashing guesses. Fix later: a salted digest with the salt inside the envelope. |
| Who, which room, when, how often | Metadata the relay needs to route. |
| **Not leaked:** command, env, stdin, cwd, user, exit code, room API status and errors, stdout, stderr | Inside the envelopes. |

## 5. What this does NOT protect

- **The relay can still run its own commands.** Plaintext exec, files, processes and terminals stay open to whoever holds the hotel bearer (our API, broker), so they can read what a sealed exec wrote to disk or `/run/secrets`. Every such exec is in the guest-signed chain: seen, not stopped. Closing it needs a sealed-only room mode plus a customer key named in the create receipt that signs each request (the slice 1 section 7 gap).
- **No sender authentication.** Anyone with the attestation can seal an exec to the guest key, as for sealed secrets. This adds confidentiality for the customer's own commands, not authorization.
- **Sync only.** Background execs (`/execs`), process starts and terminals are plaintext. Through cathedral.computer that limits a sealed exec to 45 s.
- **Withholding and delay.** A relay can drop an exec or hold it up to the 120 s window. The client sees a missing or unsigned answer (exit 3), never a fake one.
- **Room identity on shared hotels** and **measurement trust**: as for sealed secrets (our API serves the bundle; the customer pins the measurement).
- **Inside the guest** the plaintext exists in memory (front, room API, the `docker exec` argv and env), which SNP encrypts. Room to room is gVisor only.

## 6. Rollout (Toby's go-live)

1. Merge with the flag off. No runtime change.
2. Bump the guest API tarball (`room-kit/make-dist.sh`, `CATHEDRAL_COMMIT`, `CATHEDRAL_TARBALL` and sha256 in `versions.lock`): the `exec-sealed` route lives in the API. Without it every sealed exec answers a sealed 404 and runs nothing.
3. Build with `SEALED_ROOM_SEALED_EXEC=1`: **a new measurement**; add it to the broker's `sealed_measurements`.
4. Isolated fleet (AB#379): `ctcli sandbox exec --sealed` end to end; `GET .../logs` shows nothing of it; the receipt verifies; a replayed envelope gets 409.
5. Ship in the combined guest release with sealed secrets; then turn on the API relay flag (`CATHEDRAL_SEALED_EXEC_RELAY`).
