# Central booking (thin broker)

Central booking is one small Go service in front of several room hosts.
A room host ("hotel") is one machine with the room kit (`../room-kit`).
A room is one sandbox. A guest is one customer. The chain is all hotels.

The broker does four things:

| Function | Routes | What it does |
|---|---|---|
| Scatter | `POST /v1/sandboxes` (also `count` up to 10,000) | Picks a hotel at random, with weight = free rooms. Each hotel has a fixed number of creates in flight (`concurrency`). If a hotel answers 429, the broker tries another hotel. If no hotel has a free room, it answers 429 with `Retry-After`. |
| Gather | `GET /v1/sandboxes`, `GET /v1/quota`, `GET /v1/usage`, `DELETE /v1/sandboxes?label=` | Asks all hotels in parallel and merges the answers. A guest sees only its own rooms. |
| Route | `/v1/sandboxes/<hotel>.<id>/...` | Sends exec, files, tar, heartbeat, delete and the other room calls to the hotel that has the room. |
| Show | `/<guest>/live` | Live view: one tile per hotel, one square per room, live counters. |

Room ids are `<hotel id>.<hotel room id>`. The broker adds the label
`broker_guest=<guest>` to each room it creates, and filters on it.

## Hotel choice

A create can limit the hotels it may use. The broker removes these fields
before it calls the hotel.

| Field | Meaning |
|---|---|
| `"hotels": ["a", "b"]` | Only these hotels. An unknown id gives 400 `unknown_hotel`. |
| `"hotel_labels": {"sealed": "true"}` | Only hotels with every pair. |
| `"exclude_hotel_labels": {"sealed": "true"}` | No hotel with any pair. |

Hotel labels come from the `labels` object of each hotel in the config.
`GET /v1/broker/hotels` lists hotel ids, labels and free rooms. When no
hotel matches, the broker answers 409 `no_matching_hotel`. When the
matching hotels are full, it answers 429 `no_free_rooms`. It never uses
a hotel outside the choice.

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

## Secrets

- The config file is private (not in git). It holds hotel addresses, the
  path of each hotel key file, and per guest the SHA-256 of its API key and
  of its view token. The broker never stores a guest key or a view token.
- Hotel keys stay on the broker host. Guests never see them.
- The broker logs no request data.

## Live view

`/<guest>/live?token=<view token>` sets an HttpOnly, Secure, SameSite=Lax
cookie for that guest path and redirects to `/<guest>/live`. Every request
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
