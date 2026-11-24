# AB#683 one-room fresh slot: escape-destroy route and host retire

Status: built in this PR (code and tests). No live change: no broker roll, no
host install, no drain, no Railway write, no release queue entry. Planned by
Mr Spock job ab683-slot-20261124, built by ab683-destroy-build-20261124
(24 Nov 2026). Host channel decision: leader on Toby's delegation, card 683
comment 33000587: extend the existing net-check host unit (no new agent, no
new port); the #496 supervisor self-retire stays on as the backstop; the
broker route is the primary trigger.

## What this PR adds

Broker (`broker/escape_destroy.go`):
- `POST /v1/broker/hotels/{slot}/escape-destroy`, operator key (enroller 403,
  other keys 401). Body is exactly the `cathedral.escape.destroy_original/v1`
  fence of `fresh_destroy.py`; anything else is 400.
- Fence: the hotel must be sealed, `escape=true` and `max_slots` 1; the
  report_id, binding_sha256 and measurement must be a launch this broker
  admitted on that slot; while the broker remembers the fresh create it sent
  there, attempt_id and request_sha256 must be that create's. One destroy
  request per launch and per attempt. Anything else is 409.
- Before any non-refusal answer the request is recorded and the launch
  retired in `state_dir/escape-slots.json` (synced write and rename). A
  retired launch is not admitted (no create is placed on it) and its
  REPORT_ID never passes the gate again, across restarts. No `state_dir`, or
  a failed write: 503 `escape_destroy_unsaved`, nothing changed.
- `200 {"schema": "cathedral.escape.destroy_result/v1", ...fence, "slot",
  "state": "destroyed"}` only after the slot's host confirmed the launch
  stopped. The route waits up to 2 s for that confirm, then answers 503
  `escape_destroy_pending` (Retry-After 5); the API retries the same request.
  The 200 body is stored and replayed byte for byte for the same
  destroy_request_sha256 and fence, also after a restart.
- Host channel, slot hotel key only: `GET .../escape-retire` lists retired
  launches not yet stopped (`cathedral.escape.retire_request/v1`);
  `POST .../escape-retire` with `cathedral.escape.retire_confirm/v1`
  records the stop. A stop nobody requested is 409.

Host (`scripts/escape_slots/`):
- `write-escape-units.sh sealed.env` (needs `SEALED_ESCAPE_SLOT=1` and an
  https `SEALED_BROKER_URL`) writes a drop-in for the existing
  `room-sealed-<slot>-net.service`: an `ExecStartPre=-` that runs
  `supervise_escape_slot.py --retire-channel` each minute, plus the
  `room-sealed-<slot>-escape.service` supervisor unit. It only writes files
  and daemon-reloads; it never starts, stops or enables anything. The
  measured guest kit (`room-kit/`) is untouched, so the guest measurement
  (fed85a0f) is unchanged.
- The channel pulls retires from the broker with the slot's hotel key, drops
  one request file per launch in `run/escape-retire/`, waits up to 150 s for
  the supervisor, and posts each stop back.
- The supervisor learns each launch's REPORT_ID from its attestation. On a
  request for the running launch it retires it (stop, confirm inactive and
  MainPID 0, delete scratch, start a new launch on a new REPORT_ID) and writes
  `<report_id>.stopped` after the stop and scratch delete. A requested launch
  that is not the running one is recorded stopped at once (one unit, one
  guest); while the running launch is unknown it waits. Its own retire
  (attempt ended, 0 rooms on 2 polls) also writes the record, so a destroy
  that arrives after the backstop is confirmed on the next timer run.

Staged, not queued: `max_slots: 1` for chi-escape as a release queue entry
in the job directory (`INBOX/ab683-destroy-build-20261124/staged/`).

## Roll order (for the release, not done here)

1. Drain chi-escape, wait for 0 rooms.
2. On the host: add `SEALED_ESCAPE_SLOT=1` and `SEALED_BROKER_URL` to
   sealed.env, run `write-escape-units.sh`, enable
   `room-sealed-chi-escape-escape.service`.
3. One broker roll with this PR and the staged `max_slots: 1` patch.
4. Read back `max_slots 1 / free_rooms 1 / rooms_in_use 0`, admitted; undrain.
5. Then the API flags and the attempt proof.

## Original plan (kept for reference)

## The API gates (polariscomputer main 8267cd3)

- Create, `fresh_admission.py` `_parse`: the slot hotel document must show
  `max_slots == 1`, `free_rooms == 1`, `rooms_in_use == 0`, up, not draining,
  admitted with AMD chain, no `sealed_admission`, approved measurement.
- Cleanup, `fresh_destroy.py`: `POST /v1/broker/hotels/{slot}/escape-destroy`
  with the fence `{schema: cathedral.escape.destroy_original/v1,
  destroy_request_sha256, attempt_id, report_id, binding_sha256, measurement,
  request_sha256}`. Only 200 with that exact object, `schema` set to
  `cathedral.escape.destroy_result/v1`, plus `slot` and `state: "destroyed"`.
  Then `_gone`: the slot readback must be admitted on a different REPORT_ID and
  binding, attested strictly after the cleanup intent.

## What main has (5255c28)

- `max_slots` is a hotel config field and runtime PATCH. `max_slots: 1` caps
  `slots` and `free_rooms` to 1 (main.go hotel tick, capacity.go
  `admissibleFreeIn`). The create gate can pass on config alone.
- No `escape-destroy` route anywhere in `broker/`. Every cleanup call is 404,
  the worker never confirms, and the API keeps the attempt held (quota and
  slot), so the slot serves exactly one attempt and then nothing.
- `scripts/escape_slots/supervise_escape_slot.py` (#496) retires a used launch
  (stop, confirm QEMU gone, delete scratch, start), but it is not wired into any
  unit. On the chi-escape host only `room-sealed-chi-escape.service` runs.
- The broker has no channel to the host. A sealed hotel's API is inside the
  guest, so the broker cannot stop the VM that answers it.

## Why config alone is not enough

Setting `max_slots: 1` now would:
- pass the create gate once, then hold the only slot forever (no destroy);
- cut chi-escape from 480 to 1 room for the legacy escape pool while the API
  flags are off.
So the slot shape and the destroy route must land together.

## Work to ship (one broker roll, one host change)

1. Broker route `POST /v1/broker/hotels/{id}/escape-destroy` (operator key):
   - refuse 409 unless the hotel is an `escape_fresh_guest` slot and the
     fence's report_id, binding_sha256 and measurement equal the live admitted
     launch, or a recorded result exists for the same
     `destroy_request_sha256` (replay that result byte for byte);
   - before answering, durably record the destroy (claims journal) and mark the
     launch retired: admission of that REPORT_ID is refused from then on and no
     create is placed on the hotel until a different REPORT_ID is admitted;
   - answer `state: "destroyed"` only after the host confirms the original VM
     stopped (see 2). Otherwise 503, the API retries the same request.
2. Host retire channel: wire the #496 supervisor as a unit beside
   `room-sealed-<slot>.service`, plus a host-local retire request it accepts
   from the broker (mTLS or the hotel key over the host link, not the guest).
   It stops the unit, confirms `MainPID=0`, deletes scratch, starts a new launch
   and reports the stop. The new launch attests on a new REPORT_ID and binding.
3. Config, in the same release queue entry as the roll: hotel chi-escape
   `max_slots: 1`. Drain first, swap, read back `max_slots 1 / free_rooms 1 /
   rooms_in_use 0`, undrain.
4. Then the API flags (`CATHEDRAL_ESCAPE_FRESH_GUESTS`,
   `CATHEDRAL_ESCAPE_FRESH_CLEANUP_WORKER`), fed85a0f in
   `CATHEDRAL_ESCAPE_APPROVED_MEASUREMENTS`, and the tester attempt proof.

## Open questions for review

- Host channel shape for step 2 (new host agent vs. extending the net check
  unit). This is the decision that blocks code.
- Whether the supervisor's own retire (attempt ended, no rooms on 2 polls)
  stays on once the broker route exists, or the broker route is the only
  trigger.
