# AB#819: const load test fixes (broker hotel connection wait, Caddy access log)

Card AB#819 (parent AB#525). Room-kit part (image store size, image cleanup) is its own PR.
Nothing here is live until Toby gives the go. const is live on nc-sealed: never change const's hotel list.

## Problem (const load test, 18 Nov 2026)
- `newHotel` capped one hotel at `concurrency + 64` data connections (nc-sealed: 104). Every room call holds one for its whole run (an exec: its timeout + 60 s).
- Past the cap a call waited inside the HTTP transport: no log, no limit of its own. A 900 s command could wait 900 s and never reach the hotel.
- Live at 425 const rooms (19 Nov 05:41:52Z): 105 broker connections to nc-sealed, 309 requests in flight from Caddy.
- Caddy kept no access log, so the 23:15Z stalls left no per-request evidence.

## Broker change (broker/hotelconns.go)
- Hotel config fields:
  - `data_conns`: pool size. 0 or absent = `concurrency + 64` (unchanged). Max 4096.
  - `data_conn_wait_seconds`: longest wait for a free connection. 0 or absent = 10 s. -1 = until the call's own deadline (the old behaviour). Max 600.
  - Checked at config load and at join. A miner enroller cannot set them.
- Every `/v1/...` room call takes a slot before it is sent and gives it back after the answer is read. `/room/...` calls (attestation, receipts, escape nonce) go to the Health port and are not gated, so a full pool never costs a hotel its admission.
- A call with no free slot is counted and logged at most once per 10 s per hotel:
  `hotel <id>: waiting for hotel connection (pool N, in use N, waiting N, waits N, refused N)`.
- After the bound it answers **503 `sold_out` with `Retry-After: 5`**. Nothing reached the hotel, so a retry is safe.
  - Native exec, room proxy, files, snapshots, workspaces: 503 `sold_out` (was 502 `hotel_unreachable` or a silent wait).
  - Compat exec and file calls: 503 `{"detail": {"error": "sold_out", "retry_after_s": 5}}`. Not cached under an idempotency key.
  - Create: busy is a refusal. Not lost, nothing reaped, the hotel is not rested; the create tries the next hotel, else 503 `sold_out` + Retry-After.
  - Background exec (native and compat): state `lost`, reason `sold_out`, "the command did not start". Start it again with a new idempotency key.
- Unchanged: exec and create deadlines (the wait is inside them); room deletes (guest, bulk, reap, orphan, probe) still wait until their deadline, because a delete that gave up would leave a room running.
- `/v1/broker/stats`, per hotel `conns`: `data_conns`, `conns_in_use`, `conns_waiting`, `conn_waits`, `conn_refused` (POST reset zeroes the two totals).
- A changed `data_conns` takes effect at broker start (no hot reload).

## Roll (needs Toby's go)
1. Quiet window: const's rooms on nc-sealed idle, or const told. Check `GET /v1/broker/stats` (ops key) for nc-sealed `broker_running`.
2. Build the broker at the merged sha; back up the running binary and the config.
3. Optional, same restart: `"data_conns": <n>` on nc-sealed in the broker config. A larger pool lets more execs reach a guest that is already about 10:1 oversubscribed (F2), so pick n with the room cap decision. Default keeps 104. **Do not edit const's guest entry or its hotel list.**
4. Restart the broker unit. Check: `journalctl -u <broker unit>` has no config error; `/v1/broker/stats` shows `conns` per hotel; one const-free test room create + exec + delete on a non-const hotel.
5. Rollback: previous binary, restart. An older broker refuses unknown config fields, so first remove `data_conns` and `data_conn_wait_seconds` from the config.

## Caddy access log (prepared, not applied)
Proposed file: `deploy/thin-broker-caddy/Caddyfile.access-log` (the live `Caddyfile` plus one `log` block). Validated with `caddy validate` 2.6.2.
- JSON lines with `duration` (s), `status`, `size`, method, uri, remote IP.
- Request and response headers and TLS fields deleted; the `token` and `share` query values deleted.
- Rolled: 100 MiB, 10 files, 14 days (about 1 GiB at most).

Runbook (Frankfurt, needs Toby's go; reload only, no restart, no dropped connections):
1. `cp /etc/thin-broker-caddy/Caddyfile /etc/thin-broker-caddy/Caddyfile.bak-$(date -u +%Y%m%dT%H%M%SZ)`
2. `install -d -o <caddy user> -m 0750 /var/log/thin-broker-caddy` (the unit's `User=`; check `systemctl cat thin-broker-caddy`).
3. Copy the proposed file over `/etc/thin-broker-caddy/Caddyfile` (drop the 3 PROPOSED comment lines).
4. `caddy validate --config /etc/thin-broker-caddy/Caddyfile --adapter caddyfile` must print `Valid configuration`.
5. The Caddyfile has `admin off`, so `caddy reload` cannot reach it: check the unit's `ExecReload`. With none, a `systemctl restart thin-broker-caddy` is needed, which drops open exec requests: do it in the same quiet window as the broker roll.
6. Check: `tail -1 /var/log/thin-broker-caddy/access.log | jq '{status, duration, uri: .request.uri}'` after one request; `grep -c Authorization` on the file is 0.
7. Rollback: restore the backup, same reload or restart.
8. After it is live: move the `log` block into `deploy/thin-broker-caddy/Caddyfile` (the live record) and delete `Caddyfile.access-log`.
