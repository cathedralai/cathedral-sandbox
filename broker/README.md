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

Creates in flight:

- A guest that cancels a create, or goes away, gets no room. The hotel does
  not see the cancel and finishes the room. The broker keeps the hotel call
  open and deletes the room when the hotel answers.
- `DELETE /v1/sandboxes?label=` also catches creates of the same guest that
  the broker received before the delete and that match every label. A
  queued create does not start. A create that a hotel already runs is
  deleted when the hotel answers. Such a create answers 409
  `deleted_during_create`. A create received after the delete runs as usual.
  The broker keeps each delete filter for 15 minutes.

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
| `"placement": "require"` | The default. A create that names hotels uses only those hotels. |
| `"placement": "prefer"` | Try the named hotels first. If all of them are down, full or fail the create, use another hotel of the same class: sealed for sealed, unsealed for unsealed. The other label rules and the guest's hotel list still apply. A sealed create falls back only when the guest has its own hotel list. A fork and a mix of sealed and unsealed hotels never fall back. The answer has `"placement_fallback": true` and the header `X-Broker-Fallback: true`. |

Hotel labels come from the `labels` object of each hotel in the config.
`GET /v1/broker/hotels` lists hotel ids, labels and free rooms. When no
hotel matches, the broker answers 409 `no_matching_hotel`. When the
matching hotels are full, it answers 429 `no_free_rooms`. If matching hotels
are down or draining (not full), it answers 503 `hotels_unavailable` instead of
claiming they are full. It never uses
a hotel outside the choice, except a `"prefer"` fallback inside the same class.
Each hotel in `GET /v1/broker/hotels` has `down_since`: the time the broker last
saw it go down, or null while it is up. The broker logs each change between
down and up.

## Guest limits

Each guest in the config can have limits (`guests.go`):

| Field | Meaning |
|---|---|
| `max_rooms` | Rooms running or starting at one time. Absent or 0: 1,000. Over the limit, a create gets 429 `room_limit`. A batch that does not fit is refused as a whole. |
| `max_creates_per_minute` | Rooms the guest may ask for in any 60 s. Absent or 0: no limit. Over the limit, a create gets 429 `create_rate_limit` with `Retry-After`. |
| `default_sealed` | `true`: a create with no hotel choice goes to sealed hotels only. The guest gets an unsealed room only when the create says `"sealed": false`, names hotels with `"hotels"`, or excludes sealed hotels with `"exclude_hotel_labels"`. A fork goes to the hotel of its snapshot. |
| `hotels` | The hotel ids the guest may use. Absent: all hotels. Other hotels are not in the guest's hotel list, and a create that names one gets 409 `unknown_hotel`. |
| `policy` | Hotels by selector, in order: `prefer`, `allow`, `deny`. Replaces `hotels` and `default_sealed`. See "Guest policy and capacity catalog". |
| `ops` | `true`: the guest may run `POST /v1/broker/probe` and reset the counters with `POST /v1/broker/stats`. Other guests get 403. |

The limits apply to the native routes and to the client (Harbor, ctcli)
routes. `GET /v1/quota` shows the guest its limits.

With `operator_key_sha256` in the config, an operator reads and changes
limits without a restart:

| Route (operator key) | What it does |
|---|---|
| `GET /v1/broker/guests` | Every guest with its limits and active rooms. No key hashes. |
| `PATCH /v1/broker/guests/<id>` | Sets `max_rooms`, `max_creates_per_minute`, `default_sealed`, `hotels` and `policy` (`"policy": null` removes it). `max_rooms: 0` and `hotels: []` get 400: in config they mean 1,000 rooms and every non-miner hotel. A bad policy gets 400 `invalid_policy`. |

A runtime change stays in memory. A restart goes back to the config file.

## Guest policy and capacity catalog

A guest `policy` chooses hotels by selector, not by a fixed id list
(`capacity.go`). A hotel that joins at runtime is matched by class and label
with no config edit.

```json
"policy": {
  "prefer": [{"class": "sealed"}],
  "allow":  [{"class": "unsealed"}],
  "deny":   [{"hotel": "nc-sealed"}]
}
```

| Part | Meaning |
|---|---|
| Selector | Exactly one of `{"class": "sealed"\|"unsealed"}`, `{"hotel": "<id>"}` or `{"label": {"k": "v"}}` (every pair). Class is `sealed` when the hotel has the label `sealed=true` (every `"sealed": true` hotel has it). A hotel id need not exist yet. |
| `prefer` | Tried first. |
| `allow` | Tried only when no preferred hotel has a free room. |
| `deny` | Never used. Wins over `prefer`, `allow` and named `hotels`. |

- A create with no hotel choice goes to a preferred hotel while one has a
  free room, else to an allowed hotel. Inside a tier the pick is the usual
  weighted random pick. The answer has `"placement_tier": "prefer"|"allow"`
  and the header `X-Broker-Placement-Tier` (client routes too).
- The policy is the class choice: a plain create may land on a sealed or an
  unsealed hotel only when the policy reaches that class. `"sealed": true`
  still stays on sealed hotels (429 `no_free_rooms` when they are full, never
  an unsealed room), and `"sealed": false` stays on unsealed hotels.
- Named `hotels` must be in the policy's reach (prefer or allow, minus deny),
  else 409 `unknown_hotel`. Tiers still apply among them.
- `max_rooms` is still the cap: at the cap a create gets 429 `room_limit`.
- A miner hotel is denied unless the guest policy explicitly selects
  `{"label": {"miner": "true"}}` in `prefer` or `allow`. A broad sealed
  selector, a named hotel, and a guest with no policy cannot opt in. This
  protects existing customer and Escape guests from newly joined miners.
  Do not opt a customer guest in until the miner-host data isolation and
  attested guest TLS path are proven.
- A guest with no policy keeps `hotels` and `default_sealed` for non-miner hotels.

Example: `polaris-sealed` gets sealed rooms first, unsealed rooms when sealed
is full, never `nc-sealed`, at most 10 rooms:

```json
{"id": "polaris-sealed", "max_rooms": 10,
 "policy": {"prefer": [{"class": "sealed"}], "allow": [{"class": "unsealed"}],
            "deny": [{"hotel": "nc-sealed"}]}}
```

### Reserved hotels

A hotel can be dedicated to one guest with `"reserved_for": "<guest id>"`
(hotel config, join body, or `PATCH /v1/broker/hotels/<id>`). Every other
guest treats it as denied: no create, no named create (409 `unknown_hotel`),
and it is missing from their catalog. The owner reaches it through its own
policy or hotel list, as before. `PATCH {"reserved_for": null}` releases it:
from then on every policy matches it by class and label, with no guest
config edit. A guest `deny` still wins after a release. An unknown guest id
gets 409 `unknown_guest`.

`nc-sealed` (const today) is the first candidate: the operator sets
`reserved_for: "const"` on it. This change does not do that.

### Capacity catalog

`GET /v1/broker/capacity`:

- Operator key: every hotel with `id`, `class`, `labels`, `up`, `drain`,
  `free_rooms`, `slots`, `reserved_for`, `down_since`, `source` and
  `admission`, plus `classes`: per class (`sealed`, `unsealed`) the totals
  `hotels`, `joined`, `up`, `placeable`, `pending_admission`, `draining`,
  `slots` and `free_rooms`.
- Guest key: only the hotels the guest can reach, each with `tier`
  (`prefer`, `allow`, or `hotels` for a guest with no policy), preferred
  first, plus `guest` with `max_rooms` and `active_rooms`, and `classes`
  over those hotels only.

`free_rooms` comes from the function the placer uses (`admissibleFree`: 0
when the hotel is down, draining, resting after a failure, at
`mem_full_pct` or not admitted, else its free slots). A hotel listed with
free rooms takes the create. `source` is `broker` for a config hotel and
`join` for a hotel that joined at runtime.

When nothing fits, the error carries `reason` with the count of matching
hotels per state (`matching`, `down`, `draining`, `resting`,
`pending_admission`, `full`). Status codes are as before (409
`no_matching_hotel`, 429 `no_free_rooms` when every matching hotel is full,
503 `hotels_unavailable` otherwise), plus 503 `hotels_not_admitted` when the
only matching hotels with room are waiting for admission.

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

| Route (guest key) | What it does |
|---|---|
| `POST /v1/hotels/<id>/attest` `{"report_data_hex": "<128 hex>"}` | Passes the body to the hotel's `POST /room/attest` and returns the hotel's status, JSON and `Retry-After` unchanged: a fresh SEV-SNP report whose REPORT_DATA is those 64 bytes verbatim (see room-kit README). A hotel outside the guest's hotel list answers 404, as for receipts. Body cap 4096 bytes (413). An optional `"sandbox_id"` must name a room of this guest on that hotel (404 `room_not_found` otherwise) and goes to the hotel as the hotel's room id. |

A hotel signs receipts only for calls that pass through its receipt front
(room kit, `127.0.0.1:18092` on a shared hotel; `:18090` in a sealed
guest). So point both `api` and `health` of every hotel in the broker
config at that front: it passes every call to the room API, signs each
create, exec, process start and delete, and serves `/room/health`,
`/room/receipts` and `/v1/sandboxes/<id>/receipts`. With `api` on 18090
and `health` on 18091 instead, broker writes skip the front, both receipt
routes answer 404, and no receipt is signed.

A shared hotel signs at level 1: an Ed25519 key held in memory, with no
hardware binding. Its receipts prove that the hotel process signed the
action, not which machine ran it. Only a sealed hotel binds its key to an
SEV-SNP report.

For a hotel behind an SSH tunnel, forward 18092 as well: a fourth port in
`/etc/thin-broker/tunnels.env` (`TUN_<id>="<dest> <api> <health> <receipts>"`),
and `permitopen="127.0.0.1:18092"` on the tunnel key in the hotel's
`authorized_keys`. Live since 2026-10-24 00:06Z: nc on 18092, c46 on 38092
and c48 on 48092.

## Per-room tunables

A create's `"tunables"` goes to the hotel that starts the room, unchanged, in
that create's own body; the broker never reads or rewrites it, and no other
create carries it. A hotel must answer with `"tunables": {"status": "applied",
"sha256": ...}` (room kit README, "Per-room tunables"). A hotel that starts the
room without that (a room kit before per-room tunables ignores the field) does
not keep it: the broker deletes the room and tries the next eligible hotel,
without resting the first. With none left the answer is 409
`tunables_unavailable`.

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

## Workspaces

A workspace is a named directory on one hotel that outlives rooms (#305).
The hotel needs `ROOM_WORKSPACES=1` (see `room-kit/README.md`).

| Route | What it does |
|---|---|
| `POST /v1/workspaces` `{"name"}` | Makes a workspace on one hotel. Takes the hotel choice fields. The answer gives `id` = `<hotel>.<name>`. |
| `GET /v1/workspaces` | The guest's workspaces on all hotels. |
| `GET` or `DELETE /v1/workspaces/<id>` | One workspace. |
| `POST` or `GET /v1/workspaces/<id>/versions` | Makes or lists versions. |
| `POST /v1/workspaces/<id>/rollback` `{"version": n}` | Replaces the files with version n. |
| `POST /v1/sandboxes` with `"workspace": "<id>"` | The room goes to the hotel that holds the workspace and mounts it. |

A bare name works when one hotel has it. A name is unique for each guest.
The broker sends the guest id to the hotel in `X-Cathedral-Guest` and copies
no guest header, so a guest cannot act as another guest. A workspace of
another guest answers 404 `workspace_not_found`. A create whose hotel choice
excludes the workspace hotel gets 409 `workspace_hotel_excluded`. A fork and
a workspace on different hotels get 409 `workspace_snapshot_conflict`. A
full workspace hotel gets 503 `workspace_hotel_unavailable`.
## Guest secrets (egress credentials)

A secret is a named value that the hotel egress proxy adds as a header to
plain HTTP requests from a room to one allowed host (#304). The room never
holds the value. See `room-kit/README.md`, "Egress credentials".

| Route | What it does |
|---|---|
| `PUT /v1/secrets/<NAME>` `{"value": "..."}` | Stores the value on every hotel the guest may use. The answer gives the state on each hotel, never the value. |
| `GET /v1/secrets` | Names and the hotels that hold them. |
| `DELETE /v1/secrets/<NAME>` | Deletes it on every hotel. |

The broker keeps no value and logs no request data. A secret of another
guest answers 404 `secret_not_found`. A hotel that joins later does not have
the secret: put it again.

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

`miner_enroll_key_sha256` is a separate control-plane key for the miner
reconciler. It can read miner hotel documents and a miner-only capacity view,
request sealed miner hotel
joins with HTTPS API and health endpoints, set `drain=true` on a miner hotel,
and leave an empty miner hotel. It cannot read or change operator hotels,
change guest policy, plant Escape nonces, opt out of join verification, set
custom labels or reservations, or undo a drain. The digest must differ from
the operator key and every guest key or view token. The approved hotkey cap
still applies. Scoped joins require guest HTTPS and keyless SNP attestation.
The observed TLS key must match the AMD-verified binding before the broker
sends the hotel key. Miner calls pin the guest key on both data and control
connections. Plain HTTP, a client-supplied pin, and `verify=false` are refused.
The guest must install its hotel key inside the attested room before join.
A miner guest keeps its rooms in memory, so a dead or rebooted guest takes
them with it, but the broker cannot see that: its pinned calls fail, and a
new attested guest at the same origin does not prove the old one stopped (a
host can run both on one chip). So the broker never forgets rooms on its own.
A person with the operator key does, with `forget_rooms=true` on the leave of
a drained miner hotel that has been down for 10 minutes. This also frees the
hotkey cap slot of a machine that is gone for good.
The operator and miner-only capacity views report `admission_policy` with the
configured measurement allowlist and hotkey caps. `miner_tls_pin` is `true`
for this broker build; customer guests never
receive this policy document.

| Route (operator key) | What it does |
|---|---|
| `GET /v1/broker/hotels/<id>` | The hotel with `class`, `up`, `slots`, `max_slots`, `free_rooms`, `miner_hotkey` and `admission`. |
| `POST /v1/broker/hotels` | Adds a hotel: `{"id", "api", "key", "health"?, "name"?, "concurrency"?, "labels"?, "sealed"?, "threads"?, "ram_gib"?, "max_slots"?, "reserved_for"?, "miner_hotkey"?}`. A miner hotel must set `"sealed": true` and use HTTPS with attested guest TLS; the broker pins that key before its first keyed call. `"verify": false` is refused for miners. For operator hotels, the broker calls `GET /v1/status` with the key and checks attestation for sealed hotels; `"verify": false` skips both and joins pending. An unsealed join cannot claim `labels.sealed=true`. `miner_hotkey` (SS58) adds `miner=true` and `miner_hotkey` labels, which a PATCH cannot remove. |
| `PATCH /v1/broker/hotels/<id>` | Sets `drain`, `labels`, `max_slots` (a per-hotel room cap; a lower cap applies at once) and `reserved_for` (a guest id, or null to release the hotel to the pool). An unsealed runtime hotel cannot gain the sealed label. |
| `DELETE /v1/broker/hotels/<id>` | Removes a runtime hotel that has no rooms. Drain it first. `?forget_rooms=true` (operator key only, miner hotels only): when the hotel is drained and has been down for 10 minutes, forgets its rooms first, then leaves. Each forgotten room is tombstoned, so its client sees `deleted`. Otherwise 409 `forget_refused` with the reason. |

The broker keeps runtime hotels in `state_dir/hotels.json` and their keys in
`state_dir/hotel-keys/<id>.key` (mode 0600). A hotel from the config file
cannot be removed at runtime. Runtime join, PATCH and leave return
`state_write_failed` if `hotels.json` cannot be saved. A failed join cannot
take rooms; a failed PATCH restores the previous values, and a failed leave
keeps the hotel and its key.

### Admission of joined hotels

A joined hotel takes rooms only after it passes admission (`admission.go`);
miner hotels are gated even when loaded from the config file. Other config
hotels are not gated.

- Health: a good `/room/health` answer. A hotel that goes down leaves
  placement and must pass again (attestation too, for a sealed hotel).
- Attestation, for a hotel of class sealed: `GET <health>/room/attestation`
  must give an SEV-SNP binding and report that agree: `binding_sha256` is
  the SHA-256 of the binding as served, REPORT_DATA commits to it,
  measurement, chip id, TCB, policy and HOST_DATA equal the binding, debug
  is off (policy bit and `cathedral.debug=1`).
- AMD chain (VCEK, ASK, ARK, report signature): with `amd_verifier` set, the
  broker runs the repository's own `room-kit/verify_receipts.py` on the
  attestation as served (`--require-sealed --ark-sha256 <pin>`, one flag per
  pin); its verdict
  decides. It runs once per binding. Required for a miner hotel
  (`miner_hotkey`): without `amd_verifier` a miner sealed hotel is refused.
- One hotel per chip: a hotel whose CHIP_ID is already an admitted hotel's is
  refused (join: 409 `chip_in_use`; sync loop: `refused` with the other
  hotel's id). It is admitted once the other hotel leaves placement.
- A pass is good for `attest_ttl_seconds` (default 600); the sync loop checks
  again every `attest_every_seconds` (default 60), every 5 s while failing.

Config (all optional):

| Field | Meaning |
|---|---|
| `sealed_measurements` | A joined sealed hotel's measurement must be in this list. A miner hotel requires a nonempty list and is refused if it is empty. |
| `miner_hotkey_caps` | Operator-approved map from miner SS58 hotkey to maximum joined hotels. Missing hotkeys are refused. The broker counts all joined hotels for a hotkey, including pending or draining ones, and refuses the next join at the cap. Changing a cap requires a config restart; the broker has no cap hot reload yet. |
| `miner_max_hotels` | Operator-approved maximum joined miner hotels across all hotkeys. Zero refuses miner joins. Pending and draining hotels count; the next join is refused with `miner_global_cap_reached`. The approved founding cut is 64; configure it explicitly before enabling enrollment. Changing it requires a restart. |
| `sealed_host_data` | Its HOST_DATA must be in this list. |
| `attest_ttl_seconds`, `attest_every_seconds` | As above. |
| `sealed_admission` | `"off"` turns the attestation gate off for joined operator hotels only. Miner hotels always require the SEV-SNP and AMD chain checks. |
| `amd_verifier` | `{"command": ["python3", "/opt/room-kit/verify_receipts.py"], "ark_sha256": "<AMD ARK DER sha256>", "kds_cache"?: "<dir>", "timeout_seconds"?: 120}`. `ark_sha256` is one pin or a list (one per product: Milan, Genoa, Turin; values in `amd_chain.go`); the verifier passes if the report's product chain has any listed ARK, in one run. The host needs Python with `cryptography` and HTTPS to `kdsintf.amd.com` (or a filled KDS cache). |

`admission.state` in the hotel document and the catalog is `admitted`,
`pending` or `refused` (with `reason`). `GET /v1/broker/hotels` (guest key) lists all
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
