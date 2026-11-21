# Config hotel key installer (AB#817, AB#378 "Still open")

Status: spec, not built. Blocks the guest TLS re-seal of const's hotels
(nc-sealed, chi-sealed) and with it const's Docker Hub login (AB#817).

## The gap

- The guest side of guest TLS is built (`SEALED_MINER=1`, room-kit/sealed/README.md
  "Miner hotel"): an attested TLS key, an install key, `POST /room/hotel-key`.
- The broker side is built (#522): `"guest_tls": true` pins the attested key
  (`syncGuestPin`, broker/miner_tls.go) and sends no hotel key until it is pinned.
- Nothing installs the hotel key in a config hotel's guest.
  - The control plane installer (`RoomKitKeyInstaller`, polariscomputer
    cathedral_hotel_reconciler.py) acts only on `miner-*` hotels and never sees config hotels.
  - So after a guest TLS re-seal, and again after every reboot or receipts
    restart, the hotel answers 401 to every keyed call. For const that means a
    hotel down until someone hand-runs an install.

## Proposal: the broker installs it

The broker already holds the hotel key (`key_file`) and already verifies and
pins the guest's attested TLS key. Installing from there adds no new party that
learns the key.

1. Config: per hotel `"hotel_key_install_signing_key_file"` (Ed25519 seed,
   base64, mode 600, beside `key_file`). Allowed only with `"guest_tls": true`.
2. Trigger: right after `syncGuestPin` stores a new pin (a reboot or a
   receipts restart makes a new TLS key, so both land here), and when a keyed
   call on the current pin answers 401 (an install whose answer was lost).
3. Over the pinned client:
   - `GET /room/hotel-key-install-key`. Check `purpose`, `algorithm`,
     `binding_sha256` = sha256(canonical(binding)) of the attestation just
     verified, `x25519_public_b64` = `binding.hotel_key_install_x25519_b64`,
     and the signature by the binding's receipt key.
   - Seal the `key_file` key: X25519 + HKDF-SHA256 (salt = AAD, info =
     `cathedral.hotel-key-install.v1` || ephemeral || recipient) + AES-256-GCM,
     AAD = `hotel-key-install:<binding_sha256>` (same as `seal_hotel_key`).
   - `POST /room/hotel-key` with `cathedral_hotel_key_install_v1`, `hotel_id` =
     broker hotel id, `key_sha256`, `issued_at` = max(now, last + 1), signed
     with the seed over the room-kit canonical form.
   - 200 `installed` or `unchanged` = done. Any refusal code is logged (code
     only) and retried on the pin recheck interval; the hotel stays unadmitted.
4. Admission starts only after a successful install, so the scheduler never
   places on a 401 hotel.
5. Never log the key, the seed or the envelope. Log `key_sha256[:12]` and the code.

## Signer

- One ops Ed25519 key per broker host, separate from the control plane's miner
  install key, so a leak of one does not install keys into the other's hotels.
- Its public key goes into `SEALED_HOTEL_KEY_INSTALL_SIGNERS` of each config
  hotel build. That is measured: decide it before the kit is built.
- Decision for Toby: this (recommended) or the control plane signing for
  config hotels too.

## Also needed before the const re-seal

- release_run.py guest step: no handling for `SEALED_MINER=1` builds.
  `install-sealed.sh` cannot count rooms in a guest TLS guest, so the step must
  drain, wait for 0 rooms through the broker, and pass `SEALED_RESTART_WITH_ROOMS=1`;
  it must also stop passing `SEALED_API_KEY_FILE` for these hotels.
- chi-sealed: the Frankfurt broker reaches it over a tunnel to plain :18090
  (`http://127.0.0.1:39093`). It needs a tunnel to `SEALED_MINER_PUBLIC_PORT`
  so `api`/`health` can be `https://`.
- nc-sealed: the broker is on the same host; `host-net.sh` nat OUTPUT DNAT
  (AB#822) covers `https://<host>:9443`.
- Note: on Frankfurt the broker's `key_file` for nc-sealed is on the same host
  as the guest, so guest TLS does not take the key off that host. It does give
  what const needs: `registry_auth` crosses only attested TLS into the guest.

## Tests

- Go: fake guest built from the test_room_kit_miner_tls.py vectors; install on
  first pin, re-install after a re-pin, retry after 401, refusal codes keep the
  hotel unadmitted, no secret in logs.
- Live: chi-escape test guest rebuilt with `SEALED_MINER=1` and the ops signer,
  `guest_tls` entry, create with `registry_auth` from a test guest (not const),
  pull by digest through mirror-chi.

## Then

The AB#817 + AB#854 combined re-seal runs as briefed (one kit: `SEALED_MINER=1`
+ ops signer + `SEALED_ROOM_REGISTRY_MIRRORS`), with the patch in
`release_queue/hold/AB817-const-guest-tls.json` applied per const hotel.
