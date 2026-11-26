# In-room SNP report call for dedicated hotels

Status: spec r2 for review (26 Nov 2026; r1 reviewed by Astra, 6 blockers taken). Owner: Mr Spock. Reviewer: SpockChaser, Astra.
Decision: Toby, Core 26 Nov: "Build the hotel-side report call for dedicated rooms (room
supplies report_data_hex; hotel does SNP_GET_REPORT + VCEK). No gVisor ioctl proxy, no runc.
After that lands + reseal, drop the #758 sev-guest bind/prefer-emulated."

## Problem (measured)

- chi-ur-2, 26 Nov 16:47Z, fresh dedicated room (runsc 4.19.0-gvisor), after #758:
  `/dev/sev-guest` exists (char 10:263), `os.open(O_RDWR)` succeeds, `SNP_GET_REPORT`
  ioctl (0xC0205300) fails with ENOTTY. gVisor's gofer opens the host device but does not
  pass its ioctls. A room cannot get a chip report today.
- The hotel attest route works: broker `POST /v1/hotels/chi-ur-2/attest` with a fresh
  64-byte nonce gave a v5 report, REPORT_DATA equal to the nonce, measurement 91ae30c0.
  That route needs the hotel key, which room code must not hold.

## Facts that bound the change

- The receipts front (`room-kit/room_receipts.py`) already makes fresh reports:
  `Ledger.attest()` reads configfs-tsm (`fresh_report`), checks the measurement against the
  boot binding and returns `report_b64`, `cert_chain` (null when the host supplied no
  certificates), `binding_sha256`, `measurement`, `generated_at`. `POST /room/attest` wraps
  it with the bearer check, the reserved binding shape refusal (`binding_shaped`, AB#392),
  the per-guest rate limit (`attest_slot`) and an optional room create receipt.
- Rooms are made by the room API (`cathedral/sandbox_guest.py`) with `docker run` under
  runsc. Without the hotel egress daemon, `deny_all` and `allowlist` rooms run
  `--network none`; with it, they get a bridge interface. A network path cannot serve the
  no-interface case.
- The room API runs from a pinned tarball (`install.sh`, `CATHEDRAL_TARBALL_SHA256`), so an
  API change ships only with a repin. The room bridge INPUT chain admits only the egress daemon ports
  (`room-kit/lib/room-net.sh`).
- Precedent for a per-room host directory: AB#417 secrets. The API makes
  `$CATHEDRAL_SEALED_SECRETS_DIR/<room id>` before `docker run`, binds it at `/run/secrets`
  read-only, drops it on retire, and sweeps strays on reconcile. The front writes into it.
- Tenancy is hotel config only (`CATHEDRAL_HOTEL_TENANCY=dedicated`, `_dedicated_room`).
  A request label never decides it.
- Dedicated hotels already run different runsc flags (`build-guest.sh`, `ROOM_RUNSC_FLAGS`
  with `--character-device-policy=prefer-emulated`). Shared hotels stay `emulated-only`.
- gVisor connects to a host Unix socket on a bind mount only with `--host-uds=open`
  (default `none`). Only paths that are mounted into the room are reachable.

## Goals and invariants

1. Code in a dedicated room gets a fresh, chip-signed SNP report over data it chooses,
   with no key, in every network mode.
2. Shared hotels expose nothing new: no socket, no mount, no runsc flag change.
3. A room report can never be mistaken for a hotel statement (boot binding, broker fresh
   check, Escape claims) or for another room's report.
4. One room cannot starve the chip for others or for the broker's fresh check.
5. A room learns nothing it could not learn before, except its own report.

## Design (r2, after Astra round 1)

### Provenance: a receipt-key signature, not the hash alone

Any broker guest can ask any hotel for a report over any 64 bytes
(`broker/main.go` handleHotelAttest: hotel lists do not gate it). So a REPORT_DATA formula
alone cannot prove a report came from inside a room: an outsider can compute it and ask
the attest route. Provenance comes from the guest's receipt key, which never leaves the
guest and is named in the attested boot binding.

For each in-room request the front builds a statement and signs it with the receipt key:

```
statement = {"schema": "cathedral.room.report/v1", "hotel": ..., "binding_sha256": ...,
             "sandbox_id": ..., "incarnation": <receipt_sha256 of the room's create receipt>,
             "caller_report_data_hex": <the room's 64 bytes>, "requested_at": <unix s>}
REPORT_DATA = SHA-512(b"cathedral.room.report/v1\0" || canonical(statement))
```

The answer carries: the signed statement, the fresh report and `cert_chain` (or `chip_id`
and `reported_tcb` when null), the room's create receipt, and the boot attestation
document (binding plus boot report, as `GET /room/attestation` gives it).

Only the socket handler signs this schema. The front's other signing paths refuse a
statement with this schema.

### Transport: one Unix socket per room

- Env `CATHEDRAL_ROOM_ATTEST_DIR`, set on dedicated sealed images only, a tmpfs path
  (`/run/cathedral-room-attest`) made at boot by tmpfiles, owned by the API user
  (`poolroom`) with the front's group able to write sockets. Unset means off.
- The room API, on a dedicated hotel with the dir set, makes `<dir>/<room id>/` before
  `docker run` with the secrets-dir lifecycle (make, drop on failed start and retire, sweep
  strays on reconcile), and binds it read-only at `/run/cathedral`.
- The front creates `<dir>/<room id>/attest.sock` (mode 0666; the directory is mounted
  into that one room only) when it signs the room's create receipt.
- Dedicated runsc flags gain `--host-uds=open`. Shared hotels: no env, no dir, no mount,
  no flag.

### Liveness on every request, not on the listener

Closing a listener does not end accepted connections. So each request, not each
connection, is checked:

1. Snapshot `(create receipt, incarnation)` for the room under the ledger lock.
2. Refuse 410 if the room is not current: no incarnation, in `reaping` or `broken`, or a
   delete receipt signed. Ask the room API (loopback `GET /v1/sandboxes/<id>`) and refuse
   410 unless it answers running. That catches a retire the API did on its own
   (`room_end`, idle GC, reconcile) that the front never signed.
3. Make the report (chip work, no ledger lock held).
4. Re-check the incarnation. If a replayed create rotated it, answer 409 `retry`.

On a delete receipt or a 410, the front closes every tracked connection of that room and
unlinks the socket.

### Restarts

- Front restart: new binding and receipt key, empty incarnation table. Rooms made before
  it get no socket back. At start the front unlinks every `attest.sock` under the dir. A
  room that needs reports after a front restart is recreated. Answer for an old connection:
  none (the process is gone).
- API restart: reconcile sweeps dirs of rooms with no record; the front's per-request API
  check refuses those rooms.
- Reboot: tmpfs, nothing survives.

### Chip fairness and resource bounds

- Kernel serializes SNP guest requests (sev-guest driver mutex). In-room reports go
  through one in-room gate: at most 1 in-room report in flight per hotel, at most 1 waiting
  per room, others 429 with Retry-After. The broker's fresh check and the hotel attest
  route (`POST /room/attest`) bypass the gate, so they queue behind at most one in-room
  report. Measure the report time on chi-ur-2 before choosing the per-minute limit.
- Per-room listener: at most 4 open connections, 5 s header and body deadline, 1 KiB body,
  rate limit bucket `_room:<id>` through `attest_slot`.
- If the TSM read takes over 5 s, answer 503 and log it; do not retry inside the handler.

### Verifier

`room-kit/verify_receipts.py --room-report <file> --nonce <hex>`:
boot report chain and signature (AMD), measurement in the signed approved list, binding
matches the boot report, receipt key from the binding, statement signature, create receipt
signature and `receipt_sha256 == incarnation`, statement `sandbox_id` and nonce as expected,
fresh report chain and signature, its measurement equals the binding's, its REPORT_DATA
equals the formula, its chip_id equals the boot report's.

## Work packages (r2)

1. Room API (`cathedral/sandbox_guest.py`): attest dir make, bind (read-only), drop, sweep,
   dedicated only. Tests: shared adds nothing; dedicated adds the bind; dir dropped on
   failed start, retire and reconcile.
2. Front (`room-kit/room_receipts.py`): socket per room from the create receipt; request
   path with snapshot, liveness (ledger and API), report, re-check; statement signing;
   connection tracking and close on delete or 410; unlink all at start; in-room gate and
   bounds. Tests with fake `fresh_report` and fake API: formula and signature; two rooms
   get different statements; forgery test (an outsider's `/room/attest` report over the
   same REPORT_DATA has no valid statement signature and fails the verifier); keep-alive
   connection after delete gets 410 then close; API says retired, front gets 410; replay
   during a report gives 409; front restart unlinks old sockets; gate gives 429 at cap
   while `/room/attest` still answers; slow reader hits the deadline.
3. Install wiring: `room-kit/install.sh` and `room-kit/profiles/v1.sh` pass
   `CATHEDRAL_ROOM_ATTEST_DIR` into the API env and the receipts unit; tmpfiles entry;
   `room-kit/sealed/build-guest.sh` dedicated env and `--host-uds=open`; repin the API
   tarball and its sha256. Tests on the generated unit and env files.
4. Verifier: `--room-report`, with fixtures for good, wrong key, wrong room, other launch,
   tampered statement, and the outsider forgery.
5. Live, after reseal and a signed release: a non-root probe in a fresh chi-ur-2 room with
   real `--network none` (Docker config checked), and one with `internet`; the verifier
   passes on both. Then a follow-up PR drops the #758 bind and `prefer-emulated`.

Stop conditions: if `--host-uds=open` cannot connect through a read-only bind for a
non-root room user under the pinned runsc, stop and report before resealing.

## Options not taken

- gVisor ioctl proxy for sev-guest: a gVisor fork to keep. Toby: no.
- runc for dedicated rooms: Toby: no.
- One shared socket for all rooms: no caller identity, so no per-room binding or limit.
- A network endpoint on the room bridge gateway: misses `--network none` rooms and opens an
  INPUT port on the bridge.
- Caller bytes verbatim in REPORT_DATA: any broker guest can already get a report over any
  64 bytes, so verbatim bytes say nothing about a room. The signed statement does.

Fallback if host UDS fails: the room asks through the API with its own short-lived room
token. Larger change; only if the stop condition fires.

## How to verify

- `pytest tests/test_room_kit_attest.py tests/test_room_attest_dir.py tests/test_sandbox_guest_tun_gate.py tests/test_verify_receipts_room_report.py`.
- Live, after reseal: work package 5.

## Questions for the reviewer

1. Is the per-request loopback API check affordable, or should the API push retire events?
2. Is "recreate the room after a front restart" acceptable for a dedicated customer?
3. Is 1 in flight per hotel too tight for a dedicated customer that attests often? It
   depends on the measured report time.
