# AB#385 — guest-signed mutating routes (slice 1)

Goal: every customer-facing mutation through `room_receipts.py` leaves an
`X-Room-Receipt` on success. Slice 1 adds **file GET/PUT** (`/v1/sandboxes/{id}/files`).
A changed receipts front is part of the sealed guest **MEASUREMENT** — re-seal and
re-publish the guest image after merge.

## Inventory (room API, via receipts front)

Routes the broker and customers reach on a hotel. Status is what `SIGNED` in
`room-kit/room_receipts.py` records today unless noted.

| Method | Path pattern | Receipt action | Notes |
|--------|--------------|----------------|-------|
| POST | `/v1/sandboxes` | `create` | Owner-gated on dedicated machines |
| POST | `/v1/sandboxes/{id}/exec` | `exec` | |
| POST | `/v1/sandboxes/{id}/processes` | `process_start` | |
| DELETE | `/v1/sandboxes/{id}` | `delete` | |
| PUT/PATCH/POST | `/v1/sandboxes/{id}/network` | `network_set` | |
| DELETE | `/v1/sandboxes` | `bulk_delete` | |
| **PUT** | `/v1/sandboxes/{id}/files` | **`file_put`** | **This slice** |
| **GET** | `/v1/sandboxes/{id}/files` | **`file_get`** | **This slice** |
| PUT/GET | `/v1/sandboxes/{id}/tar` | — | Follow-up |
| GET | `/v1/sandboxes/{id}/stat` | — | Follow-up |
| POST | `/v1/sandboxes/{id}/snapshot` | — | Follow-up |
| POST/PATCH | `/v1/sandboxes/{id}/…` (heartbeat, lifetime, wait, freeze, thaw, expose, ports, …) | — | Follow-up |
| DELETE | `/v1/sandboxes/{id}/processes/{pid}` | — | Follow-up |
| POST/GET/DELETE | `/v1/sandboxes/{id}/terminals/…` | — | Follow-up (incl. WebSocket attach) |
| POST | `/v1/sandboxes/{id}/terminals/{id}/input` | — | Follow-up |
| GET | `/v1/sandboxes/{id}/terminals/{id}/output` | — | Follow-up |
| PUT | `/v1/secrets/{name}` | `sealed_secret_write` | Signed on receipts front, not in `SIGNED` table |
| POST | `/v1/sandboxes/{id}/exec-sealed` | — | Refused at front (404) |
| POST | `/v1/sandboxes/{id}/sealed-env` | `sealed_env_set` | Signed on receipts front (AB#414), not in `SIGNED` table |
| any | `/v1/sandboxes/{id}/env-sealed` | none | Refused at front (404); the front's own route to the room API (AB#414) |
| POST | `/v1/images/build` | — | Owner-gated; not in `SIGNED` |
| GET | `/v1/sandboxes`, `/v1/sandboxes/{id}`, logs, workspaces, … | none | Read-only broker paths; unsigned |
| GET | `/v1/sandboxes/{id}/desktop`, `/v1/sandboxes/{id}/desktop/ws` | none | Refused by the broker (403 `desktop_disabled`, AB#121) |

## TTL reaper (follow-up)

The room TTL reaper (`<ROOM_ID>-reaper.timer` in `room-kit/install.sh`) calls
`GET http://127.0.0.1:$ROOM_API_PORT/v1/sandboxes` with the internal API key —
**not** through the receipts front. Expiry deletes therefore still produce no
delete receipt (see `room-kit/sealed/README.md` “Not covered yet”). Routing the
reaper through the receipts proxy (or an internal signed sweep) is a separate
change.

## Receipt fields for files

Same statement shape as other `SIGNED` routes: `action`, `target` (method + full
path including query), `sandbox_id`, `customer_request_sha256` (PUT body bytes;
empty for GET), `status`, `result_sha256`. No extra path field; the `path`
query parameter is covered by `target`.
