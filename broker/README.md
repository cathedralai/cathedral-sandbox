# Central booking (thin broker)

Central booking is one small Go service in front of several room hosts.
A room host ("hotel") is one machine with the room kit (`../room-kit`).
A room is one sandbox. A guest is one customer. The chain is all hotels.

The broker does four things:

| Function | Routes | What it does |
|---|---|---|
| Scatter | `POST /v1/sandboxes` (also `count` up to 10,000) | Picks a hotel at random, with weight = free rooms. Each hotel has a fixed number of creates in flight (`concurrency`). If a hotel answers 429, the broker tries another hotel. If no hotel has a free room, it answers 429 `no_free_rooms`. If all matching hotels are down or draining, it answers 503 `hotels_unavailable`. |
| Gather | `GET /v1/sandboxes`, `GET /v1/quota`, `GET /v1/usage`, `DELETE /v1/sandboxes?label=` | Asks all hotels in parallel and merges the answers. A guest sees only its own rooms. |
| Route | `/v1/sandboxes/<hotel>.<id>/...` | Sends exec, files, tar, heartbeat, delete and the other room calls to the hotel that has the room. |
| Show | `/<guest>/live` | Live view: one tile per hotel, one square per room, live counters. |

Room ids are `<hotel id>.<hotel room id>`. The broker adds the label
`broker_guest=<guest>` to each room it creates, and filters on it.

## Placement

- The broker picks a hotel at random. The weight is free rooms x CPU
  headroom / (create time x (1 + expected queue wait)). CPU is the hotel
  health value `host_cpu_pct`. Create time is a moving average of the hotel
  create call. Expected queue wait is creates queued and running at the
  broker / creates in flight allowed x create time. Before the first data,
  the weight is free rooms.
- A create that waits longer than `max_queue_wait_seconds` (config, default
  10; -1 turns it off) for a create slot moves to another eligible hotel
  with a free room. If there is none, it keeps waiting.
- A hotel whose host memory use is at or above `mem_full_pct` (config,
  default 90; -1 turns it off) takes no new rooms. The value is the hotel
  health value `host_mem_used_pct` (MemTotal minus MemAvailable, so page
  cache does not count). Hotel slots come from an install-time sizing with
  memory overcommit, so free slots alone cannot see rooms that use their
  full memory limit. Such a hotel shows 0 free rooms, and the operator stats
  show `mem_full: true`. When every eligible hotel is full this way, a
  create gets 429 `no_free_rooms`.

## Hotel choice

A create can limit the hotels it may use. The broker removes these fields
before it calls the hotel.

| Field | Meaning |
|---|---|
| `"hotels": ["a", "b"]` | Only these hotels. An unknown id gives 409 `unknown_hotel`. |
| `"hotel_labels": {"sealed": "true"}` | Only hotels with every pair. |
| `"exclude_hotel_labels": {"sealed": "true"}` | No hotel with any pair. |

Hotel labels come from the `labels` object of each hotel in the config.
`GET /v1/broker/hotels` lists hotel ids, labels and free rooms. When no
hotel matches, the broker answers 409 `no_matching_hotel`. When the
matching hotels are full, it answers 429 `no_free_rooms`. If matching hotels
are down or draining (not full), it answers 503 `hotels_unavailable` instead of
claiming they are full. It never uses
a hotel outside the choice.

## Guest limits

Each guest in the config can have limits (`guests.go`):

| Field | Meaning |
|---|---|
| `max_rooms` | Rooms running or starting at one time. Absent or 0: 1,000. Over the limit, a create gets 429 `room_limit`. A batch that does not fit is refused as a whole. |
| `max_creates_per_minute` | Rooms the guest may ask for in any 60 s. Absent or 0: no limit. Over the limit, a create gets 429 `create_rate_limit` with `Retry-After`. |
| `default_sealed` | `true`: a create with no hotel choice goes to sealed hotels only. The guest gets an unsealed room only when the create says `"sealed": false`, names hotels with `"hotels"`, or excludes sealed hotels with `"exclude_hotel_labels"`. A fork goes to the hotel of its snapshot. |
| `hotels` | The hotel ids the guest may use. Absent: all hotels. Other hotels are not in the guest's hotel list, and a create that names one gets 409 `unknown_hotel`. |
| `ops` | `true`: the guest may run `POST /v1/broker/probe` and reset the counters with `POST /v1/broker/stats`. Other guests get 403. |

The limits apply to the native routes and to the client (Harbor, ctcli)
routes. `GET /v1/quota` shows the guest its limits.

With `operator_key_sha256` in the config, an operator reads and changes
limits without a restart:

| Route (operator key) | What it does |
|---|---|
| `GET /v1/broker/guests` | Every guest with its limits and active rooms. No key hashes. |
| `PATCH /v1/broker/guests/<id>` | Sets `max_rooms`, `max_creates_per_minute`, `default_sealed` and `hotels`. `max_rooms: 0` and `hotels: []` get 400: in config they mean 1,000 rooms and every hotel. |

A runtime change stays in memory. A restart goes back to the config file.

Guests are apart: the broker labels each room with its guest, lists with
that label only, and answers 404 `sandbox_not_found` to a call on a room of
another guest. The hotel still signs one receipt chain per boot.
`GET /v1/hotels/<id>/receipts` returns that chain to an ops key. Any other
guest receives only the receipts for rooms that guest has owned on that
hotel, including rooms already deleted. A receipt left out can still be the
`previous_receipt_sha256` of a receipt that is returned; the response does
not include the other guest's room id, image name, or target path. Receipts
still omit commands, files, and outputs. One room's own receipts are
`GET /v1/sandboxes/<id>/receipts`.

Only sealed hotels answer these two routes. On a shared (unsealed) hotel
both answer 404. The broker sends a shared hotel's writes straight to its
API port, so the room kit's receipt service (127.0.0.1:18092) never sees a
broker room. The broker reads `/room/receipts` from the hotel's `health`
base, and on a shared hotel that is room_health, which does not serve the
chain. Routing reads alone through 18092 would return an empty chain; a
fix must send writes there too. Until then, signed receipts come from
sealed hotels only.

## Room network policy

A create takes `"network": {"mode": "internet" | "deny_all" | "allowlist", "allow": [...]}`.
`PUT /v1/sandboxes/{id}/network` with the same object switches the policy of a
live room. The broker passes both to the room's hotel. The hotel applies the
policy outside the room (see `room-kit/README.md`, "Room egress policy") and
answers with the canonical policy and its sha256. A sealed hotel also signs a
receipt for the switch (`X-Room-Receipt`).

Clients (Harbor plugin, ctcli) send `"network": "allowlist"` with
`"network_allow": [...]`, and the same PUT with `{"mode", "allow"}`. The
catalog shows `dynamic_network_policy: true` and the entry types in
`network_allowlist`. Client `deny_all` and `none` both become hotel
`deny_all`: the room keeps an interface, so it can switch later. A client
create that names no network fails closed to `deny_all`; egress is asked
for with `"network": "internet"` (or an allowlist), never granted by an
omitted field. A live change must always name its mode (400 otherwise).

## What a room answer says about isolation

Every room document the broker returns (create, get, list, on the native
and the client routes) carries an `isolation` object:

```json
"isolation": {
  "hotel_sealed": true,
  "hotel_tee": "amd_sev_snp",
  "room_runtime": "runsc",
  "attested_per_room": false,
  "network_mode": "deny_all",
  "attestation_of_host": "/v1/hotels/nc-sealed/attestation"
}
```

`hotel_sealed` is true when the room's hotel is a sealed (SEV-SNP) guest;
`hotel_tee` is the TEE kind, or null on an unsealed hotel. `room_runtime` is
what the hotel reports (`runsc`, `docker`, `kata`). `attested_per_room` is
always false: a TEE covers the hotel VM, rooms on it are separated by the
room runtime, and the hotel's attestation is at `attestation_of_host`. A
guest reads the level from this object, never from the hotel id.

## Snapshots and forks

A snapshot stays on the hotel that made it.

| Route | What it does |
|---|---|
| `POST /v1/sandboxes/<room>/snapshot` | Snapshots the room on its hotel. The answer gives `snapshot_id` = `<hotel>.<hotel snapshot id>`. |
| `POST /v1/sandboxes` with `snapshot_id` | Forks. The broker sends every room of the fork to the hotel in the id, and to no other hotel. A bare snapshot name also works when one hotel has it. |
| `GET /v1/snapshots` | The guest's snapshots on all hotels. |
| `DELETE /v1/snapshots/<id>` | Deletes the snapshot and its image on the hotel. |
| `POST /v1/snapshots/<id>/push` | Pushes the snapshot image to a registry: `{"image": "<ref>", "registry_auth": {"username": "...", "password": "..."}}` (login optional). A create with that `image` can then go to any hotel. The image has the root file system only, not `/work`. |

A guest sees, forks, pushes and deletes only its own snapshots (the broker
labels each snapshot with the guest). An unknown or foreign snapshot gives
404 `snapshot_not_found`. A fork whose hotel is full, draining or down gives
503 `snapshot_hotel_unavailable`. A fork whose hotel is outside the hotel
choice gives 409 `snapshot_hotel_excluded`.

## Image prefetch

`POST /v1/images/prefetch` with `{"images": [...]}` pulls the images on
every hotel, or on the hotels that the hotel choice fields select. An
optional `registry_auth` goes to the hotels for that pull only. The broker
does not keep it and does not show it. The answer (202) gives a
`prefetch_id`. `GET /v1/images/prefetch/<id>` gives the state on each
hotel (`pulling`, `done` with image sizes, or `failed` with the error).
The broker keeps a job for 24 hours, in memory.

`GET /v1/broker/stats` gives per-hotel counts and latency percentiles
(hotel call, wait in the broker queue, broker overhead). `POST` resets them.
Each create answer has `X-Broker-Hotel`, `X-Broker-Queue-Ms`,
`X-Broker-Hotel-Ms` and `X-Broker-Overhead-Ms`.

## Client limits and state

- Exec: the longest exec is `max_exec_seconds` in the config (default
  14,400). Keep it at or below the hotel limit
  `CATHEDRAL_SANDBOX_EXEC_TIMEOUT_MAX` (default 14,400).
  On the Harbor/ctcli path the exec body field is `cmd` (a non-empty JSON
  **array** of strings) or the alias `command`; a string value gives 400
  `invalid_exec`. The native `/v1` route reads `cmd` only and runs a string
  through `sh -c`. Exec output is capped by the hotel at 16 MiB per stream;
  the response includes `"truncated": true` when that happens.
- Image build (client path): `POST /v1/images/build` takes the Dockerfile
  and the build context. The broker asks each hotel that takes new rooms
  to build it. The image is `ready` when one hotel has it, and a create
  with it goes only to hotels that have it. A failed build gives state
  `failed` with error `image_build_failed`.
- With `state_dir` set, the broker keeps client room ids, Idempotency-Key
  answers (48 hours), deleted-room tombstones, images, and guest→hotel→room
  mappings in `state_dir/client-state.json` (mode 0600), and build contexts
  in `state_dir/build-contexts/`. After a restart, a repeated create with
  the same key returns the first answer, a room keeps its client id, and
  `GET /v1/hotels/<id>/receipts` still filters correctly for each guest
  (the room→guest mapping is persisted, so a reload does not expose another
  guest's receipts).

## Hotels at runtime

With `operator_key_sha256` (SHA-256 of the operator key) and `state_dir` in
the config, an operator adds and removes hotels without a restart:

| Route (operator key) | What it does |
|---|---|
| `POST /v1/broker/hotels` | Adds a hotel: `{"id", "api", "key", "health"?, "name"?, "concurrency"?, "labels"?, "sealed"?, "threads"?, "ram_gib"?}`. `"sealed": true` is what makes a hotel sealed; a `sealed` label alone leaves it taking unsealed creates. The broker first calls `GET /v1/status` on the hotel with the key (`"verify": false` skips it). |
| `PATCH /v1/broker/hotels/<id>` | Sets `drain` and `labels`. |
| `DELETE /v1/broker/hotels/<id>` | Removes a runtime hotel that has no rooms. Drain it first. |

The broker keeps runtime hotels in `state_dir/hotels.json` and their keys in
`state_dir/hotel-keys/<id>.key` (mode 0600). A hotel from the config file
cannot be removed at runtime. `GET /v1/broker/hotels` (guest key) lists all
hotels with labels and free rooms.

## Secrets

- The config file is private (not in git). It holds hotel addresses, the
  path of each hotel key file, and per guest the SHA-256 of its API key and
  of its view token. The broker never stores a guest key or a view token.
- Hotel keys stay on the broker host. Guests never see them.
- The broker logs no request data.

## Live view

`/<guest>/live` without the cookie shows a sign-in form. The form posts
the view token to `/<guest>/live/sign-in`, so the token does not stay in
the browser history. A good token sets an HttpOnly, Secure, SameSite=Lax
cookie for that guest path and redirects to `/<guest>/live`. The older link
`/<guest>/live?token=<view token>` still works the same way. Every request
to the page and to its data stream (`/<guest>/live/events`, server-sent
events, 1 per second) needs that cookie. A wrong token and an unknown guest
both get 401. The page shows hotel names, threads and RAM from the config,
never addresses. Squares of other guests are grey.

## Run

```
go build -o thin-broker .
./thin-broker -config /etc/thin-broker/config.json
```

Put a TLS proxy (for example Caddy) in front of `listen`. Reach hotel APIs
on a private path (an SSH tunnel per hotel, or a private network). Hotel
APIs must not be public.

## Load test

`blast/` sends N creates at once through the broker, holds the rooms with
heartbeats and a light exec on a sample, stops the heartbeats, and watches the
hotels clean up. It writes `results.json`, `creates.json` and `timeline.csv`.
It stops and deletes its rooms if a hotel's RAM goes above `-memstop` or if
the `-stopfile` exists.

```
go build -o blast ./blast
./blast -url http://127.0.0.1:18100 -keyfile guest.key -n 4000 -ttl 600 -hold 6m -out run1
```
