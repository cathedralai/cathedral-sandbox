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
