# AB#385: guest-signed routes

Goal: every customer-facing mutation through `room-kit/room_receipts.py` leaves an
`X-Room-Receipt`, and `room-kit/verify_receipts.py` verifies it. A changed receipts
front is part of the sealed guest MEASUREMENT: it reaches a hotel only with a re-seal.

Slices:

| Slice | What | PR |
|-------|------|----|
| 1 | file GET/PUT | cathedral-sandbox#452 |
| 2 | tar GET/PUT, process stop, snapshot, freeze, thaw, expose | cathedral-sandbox#495 |
| 3 | every other mutating route of the room API, plus a guard test | this table |
| reaper | TTL deletes through the front, signed with reason `ttl` | see "TTL reaper" |
| WebSocket | terminal sockets through the front, signed open and close | see "Terminal WebSocket" |

## Guard

`tests/test_room_kit_signed_routes.py` walks the room API's own route table
(`cathedral/sandbox_server.py` `SandboxApplication._register`). It fails when a
route is neither a row of `SIGNED` nor on its `UNSIGNED` table with a reason,
when a route is on both, when `UNSIGNED` names a route the API no longer has,
and when a `SIGNED` row matches no API route. A new route therefore cannot land
unsigned by accident: it is signed, or it is listed with a reason.

## Inventory: room API routes (via the receipts front)

Re-derived from cathedral-sandbox main 4d0610d (`SandboxApplication._register`,
69 method/path rows) and `SIGNED` in `room-kit/room_receipts.py`.

### Signed

| Method | Path | Receipt action | Slice |
|--------|------|----------------|-------|
| POST | `/v1/sandboxes` | `create` | before 385 |
| DELETE | `/v1/sandboxes` | `bulk_delete` | before 385 |
| DELETE | `/v1/sandboxes/{id}` | `delete` | before 385 |
| POST | `/v1/sandboxes/{id}/exec` | `exec` | before 385 |
| POST | `/v1/sandboxes/{id}/exec/cancel` | `exec_cancel` | AB#406 |
| POST | `/v1/sandboxes/{id}/processes` | `process_start` | before 385 |
| PUT, POST, PATCH | `/v1/sandboxes/{id}/network` | `network_set` | before 385 |
| PUT | `/v1/sandboxes/{id}/files` | `file_put` | 1 |
| GET | `/v1/sandboxes/{id}/files` | `file_get` | 1 |
| PUT | `/v1/sandboxes/{id}/tar` | `tar_put` | 2 |
| GET | `/v1/sandboxes/{id}/tar` | `tar_get` | 2 |
| DELETE | `/v1/sandboxes/{id}/processes/{pid}` | `process_stop` | 2 |
| POST | `/v1/sandboxes/{id}/snapshot` | `snapshot` | 2 |
| POST | `/v1/sandboxes/{id}/freeze` | `freeze` | 2 |
| POST | `/v1/sandboxes/{id}/thaw` | `thaw` | 2 |
| POST | `/v1/sandboxes/{id}/expose` | `expose` | 2 |
| PUT | `/v1/sandboxes/{id}/directories` | `mkdir` | 3 |
| DELETE | `/v1/sandboxes/{id}/entries` | `entry_delete` | 3 |
| POST | `/v1/sandboxes/{id}/ports/{port}/http` | `port_http` | 3 |
| POST | `/v1/sandboxes/{id}/access-tickets` | `access_ticket` | 3 |
| POST | `/v1/sandboxes/{id}/terminals` | `terminal_create` | 3 |
| DELETE | `/v1/sandboxes/{id}/terminals/{tid}` | `terminal_delete` | 3 |
| POST | `/v1/sandboxes/{id}/terminals/{tid}/connect` | `terminal_connect` | 3 |
| POST | `/v1/sandboxes/{id}/terminals/{tid}/input` | `terminal_input` | 3 |
| POST | `/v1/sandboxes/{id}/terminals/{tid}/resize` | `terminal_resize` | 3 |
| POST | `/v1/sandboxes/{id}/publish` | `publish` | 3 |
| DELETE | `/v1/snapshots/{id}` | `snapshot_delete` (carries `snapshot_id`) | 3 |
| POST | `/v1/snapshots/{id}/push` | `snapshot_push` | 3 |
| POST | `/v1/workspaces` | `workspace_create` | 3 |
| DELETE | `/v1/workspaces/{name}` | `workspace_delete` | 3 |
| POST | `/v1/workspaces/{name}/versions` | `workspace_version` | 3 |
| POST | `/v1/workspaces/{name}/rollback` | `workspace_rollback` | 3 |
| PUT | `/v1/secrets/{name}` | `secret_put` (request hash withheld) | 3 |
| DELETE | `/v1/secrets/{name}` | `secret_delete` | 3 |
| POST | `/v1/images/prefetch` | `image_prefetch` | 3 |
| POST | `/v1/images/build` | `image_build` (still owner-gated on a dedicated machine) | 3 |
| POST | `/v1/affline/validate-rerun` | `affline_rerun` | 3 |

Served by the front itself, signed there: `POST /v1/sandboxes/{id}/sealed-secrets`
(`sealed_secret_write`), `POST /v1/sandboxes/{id}/sealed-exec` (`exec`),
`POST /v1/sandboxes/{id}/sealed-env` (`sealed_env_set`), `POST /v1/sandboxes/{id}/claim`
(claim receipt), `POST /room/escape-nonce` (`escape_nonce_plant`), `POST /room/hotel-key`
(`hotel_key_install`).

### Unsigned, with the reason (the guard test's `UNSIGNED` table)

| Method | Path | Reason |
|--------|------|--------|
| GET | `/v1/sandboxes`, `/v1/sandboxes/{id}` | read |
| POST | `/v1/sandboxes/{id}/wait` | read: long poll |
| PATCH | `/v1/sandboxes/{id}` | keepalive (heartbeat); a receipt per keepalive would stay on the chain |
| POST | `/v1/sandboxes/{id}/heartbeat`, `/lifetime`; PATCH `/lifetime` | keepalive, as above |
| POST | `/v1/sandboxes/{id}/exec-sealed` | internal: the front's own route; refused 404 to callers |
| PUT | `/v1/sandboxes/{id}/env-sealed` | internal: the front's own route; refused 404 to callers |
| GET | `/v1/sandboxes/{id}/processes/{pid}/logs` | read |
| POST | `/v1/sandboxes/{id}/processes/{pid}/attach` | unsupported: always 501 |
| GET | `/v1/sandboxes/{id}/entries`, `/stat`, `/terminals`, `/desktop`, `/logs` | read |
| GET | `/v1/sandboxes/{id}/terminals/{tid}/output` | drains only the reader's buffer and is polled; what goes into a terminal is signed |
| GET | `/v1/snapshots`, `/v1/workspaces`, `/v1/workspaces/{name}`, `/v1/workspaces/{name}/versions` | read |
| GET | `/v1/secrets` | read: names, never values |
| GET | `/v1/sandbox-templates`, `/v1/sandbox-templates/{uid}`, `/v1/images/{ref}` | read |
| GET | `/v1/quota`, `/v1/usage`, `/v1/status`, `/v1/operations/{id}`, `/openapi.json` | read |

Front-only routes that stay unsigned: `GET /room/attestation`, `POST /room/attest`,
`POST /room/release-proof` (signs its own fixed statement), `GET /room/receipts`,
`GET /v1/sandboxes/{id}/receipts`, `GET /room/health`, `GET /room/escape-plant-key`,
`GET /room/hotel-key-install-key`, `GET /v1/sandboxes/{id}/sealed-secrets`,
`GET` and `DELETE /v1/sandboxes/{id}/exec/result` (the front's own kept answer).

## Receipt fields

Every receipt carries `action`, `target` (method, path as the API routes on it, and
query), `sandbox_id` (null for a route that names no room), `customer_request_sha256`
(the request body bytes), `command_sha256`, `status` and `result_sha256` (the answer
bytes). Non-2xx answers and a lost answer (502 `hotel_api_no_answer`) are signed too.

- Request bodies of file, tar and slice 3 routes are never parsed: a JSON file with a
  lone surrogate escape or a `cmd` key is signed as bytes (`command_sha256` null),
  not refused or read as an exec.
- `secret_put`: `customer_request_sha256` is null and `customer_request_withheld` is
  `"secret_value"`. A short secret would fall to a guess from its hash, and anyone with
  the hotel key reads the chain. The secret's name is in `target`.
- `snapshot_delete`: `snapshot_id` from the path and `sandbox_id` null, as
  `verify_receipts.py` check 13 reads it.
- Serial rooms: terminal routes and access tickets are signed but still refused with
  409 `room_serial_unsigned`; `mkdir`, `entry_delete`, `port_http` and the other slice 3
  room routes run one at a time like every signed route.

Cost: each signed call adds one chain entry. Port traffic (`port_http`) and terminal
input are signed per request, as exec and file reads are.

## Path matching

The front matches `SIGNED` on `urlparse(path).path`, the path the room API routes on,
so `PUT .../files;x` does not reach the API unsigned. `target` records that path.

The broker's cloud-API compat tar routes (`broker/compat.go` `compatPutTar` /
`compatGetTar`) run `tar` through an exec, so those calls carry an `exec` receipt,
not `tar_put` / `tar_get`.

## TTL reaper

Not in slice 3. The room TTL reaper (`<ROOM_ID>-reaper.timer` in `room-kit/install.sh`)
calls `GET http://127.0.0.1:$ROOM_API_PORT/v1/sandboxes` with the internal API key,
not through the receipts front, and the API also sweeps in-process. Expiry deletes
produce no delete receipt; a room the API removed gets a `room_end` at the front's
next look.

## Terminal WebSocket

Not in slice 3. The front strips `Upgrade` from what it forwards, so
`GET /v1/sandboxes/{id}/terminals/{tid}/ws` through the front reaches the API as a
plain GET (404). `GET /v1/sandboxes/{id}/desktop/ws` is refused by the broker
(403 `desktop_disabled`, AB#121).
