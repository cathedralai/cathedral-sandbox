# Room kit

The room kit makes one Linux machine into a room host. A room host runs
sandboxes for one customer. Each sandbox runs under gVisor (runsc). The
customer API is on port 443 with a real TLS certificate.

## What the kit does

1. **Assess** (`assess.py`). It reads the machine and writes `machine.json`.
   It changes nothing. It finds CPU, RAM, disk, file system, KVM, SEV-SNP or
   TDX, kernel, cgroup v2, open ports, and workloads that already run (host
   Docker containers and VMs).
2. **Size** (`size.py`). It reads `machine.json` and calculates the number of
   sandbox slots for one shape (default 1 vCPU, 4 GiB, 10 GiB). It subtracts
   a host reserve and the workloads that already run. It writes `size.json`
   with the slots, the limiting resource, and the API quota.
3. **Deploy** (`install.sh`). It installs and starts the room.
4. **Health** (`room_health.py`). The front desk polls
   `GET https://<host>/room/health` with the room API key. The endpoint gives
   the room id, runtime, kernel isolation proof, machine summary, slots, used
   slots and free slots.

## Requirements for a machine

- Ubuntu 24.04 or 26.04, x86-64, root access, cgroup v2.
- systemd, Docker Engine and containerd. If `dockerd` is missing, the kit
  installs the `docker.io` package.
- Disk: a spare block device (the kit formats it as xfs), or free space on
  the root file system for a sparse loop image. Keep the root file system
  below 70 % full.
- Network: inbound TCP 443 from the internet. Outbound HTTPS to Docker Hub
  (or `ROOM_REGISTRY_MIRRORS`, default mirror.gcr.io), Let's Encrypt, GitHub
  (uv, Caddy, Python), storage.googleapis.com (gVisor) and PyPI (the pinned
  wheel set). Port 80 is not used.
- DNS: an A record for `ROOM_HOSTNAME` to the machine IP, DNS only, before
  you run the installer.
- A free private /22 or larger for the guest bridge (one address per sandbox).
  One Linux bridge takes at most 1,024 ports, so one bridge serves at most
  1,023 rooms with a network. With `ROOM_NETS` unset or `ROOM_NETS=auto` (the
  default) the kit adds room networks when the host can hold more rooms (see
  "Room networks"). Rooms with network `none` use no bridge port.

## Room networks

One Linux bridge takes at most 1,024 ports. A host that can hold more than
1,023 rooms with a network needs more bridges ("room networks").

With `ROOM_NETS` unset or `ROOM_NETS=auto` (the default on a new install), the installer does this:

1. It sizes the host by CPU, memory and disk, with no bridge limit.
2. If the main bridge holds that many rooms (`ROOM_BRIDGE_PORT_CAP`), it
   adds no room network.
3. Otherwise it makes one room network for each `ROOM_NET_SIZE` rooms
   (default 1,000). It cuts the CIDRs from `ROOM_NETS_POOL` (default
   10.214.0.0/16) and skips CIDRs that other host networks use.
4. It writes the CIDRs to the resolved `/etc/pool-room/room.env` and sizes
   the host again with the room networks.

To choose the CIDRs yourself, set `ROOM_NETS` to a space-separated list.
`ROOM_NETS=none` or `ROOM_NETS=off` keeps every room on the main bridge. An
empty `ROOM_NETS` does the same. `ROOM_NETS=auto` still means the sized plan.

For every room network the kit adds the same firewall rules as for the main
bridge (`room-net.sh`, by bridge name `${ROOM_NET_BRIDGE_PREFIX}N`). The
same script refuses a room-network CIDR that another host route already uses.
Guests
use `ROOM_DNS`. The kit sets these API settings (`/etc/pool-room/api.env`)
when the resolved `ROOM_NETS` list is not empty:

| Setting | Value from the kit | Meaning |
|---|---|---|
| `CATHEDRAL_ROOM_NETWORKS` | count of `ROOM_NETS` | Number of room networks. Unset or 0: no room networks. |
| `CATHEDRAL_ROOM_NETWORK_SUBNETS` | `ROOM_NETS`, comma separated | One subnet per network. |
| `CATHEDRAL_ROOM_NETWORK_SIZE` | `ROOM_NET_SIZE` | Rooms per network (max 1,023). |
| `CATHEDRAL_ROOM_NETWORK_PREFIX` | `$ROOM_ID-net` | Docker network name prefix. |
| `CATHEDRAL_ROOM_NETWORK_BRIDGE_PREFIX` | `ROOM_NET_BRIDGE_PREFIX` | Linux bridge name prefix: bridge N is `<prefix>N`. |
| `CATHEDRAL_ROOM_NETWORK_DNS` | `ROOM_DNS` | Name servers for guests on room networks. |

`GET /v1/quota` shows `room_networks`, with the use of each network.

`CATHEDRAL_ROOM_NETWORK_DNS` is set from `ROOM_DNS` in `profiles/v1.sh` whenever
`ROOM_NETS` resolved to one or more CIDRs. The other `CATHEDRAL_ROOM_NETWORK_*`
settings in the table come from the same place.

## Receipts

`ROOM_RECEIPTS=1` is the default for a new install. `ROOM_RECEIPTS=0` turns
receipts off. The installer starts `<ROOM_ID>-receipts.service`
(`room_receipts.py`).

What it turns on: an Ed25519 receipt chain for create, exec, background
process start, delete and network policy changes. The process listens on
`ROOM_RECEIPTS_LISTEN` (default `127.0.0.1:18092`). That port is not
`ROOM_API_PORT` and not `ROOM_HEALTH_PORT`. It proxies those calls to the
room API on `127.0.0.1:ROOM_API_PORT`. When receipts are on, Caddy sends
every request except `/room/health` to that listener. `/room/health` stays
on the health port, so health still answers on
`https://<host>/room/health`. With `ROOM_TLS=off` there is no Caddy; the
receipt listener is the signing front and health stays on
`127.0.0.1:ROOM_HEALTH_PORT`.

On a normal host the binding says `level` `hotel` (schema
`cathedral_hotel_binding_v1`). It does not read
`/sys/kernel/config/tsm/report`, it does not invent an SNP measurement, and
health does not say `sealed`. Verify a chain offline with
`verify_receipts.py`: signature, link to the previous receipt, and head. A
level 1 chain has no SNP report.

Sealed SNP receipts are a separate path and stay opt-in. `install.sh --sealed`
builds a guest that sets `ROOM_RECEIPTS=1` and its own listen address. Inside
that guest, when the TSM provider is `sev_guest`, the same process keeps the
sealed binding (`cathedral_sealed_hotel_binding_v1`), the SNP report, and
`sealed` true on the receipt listener's health document. A new unsealed host
does not enter that path.

`ROOM_HOTEL_NAME` empty means the installer uses `ROOM_ID`.

### Receipt numbers per room

Every statement that names a room carries `room_sequence` (1, 2, 3 for that
room id under this boot's key) and `room_previous_receipt_sha256` (null for the
first). A room id used again continues its numbers. A bulk delete names no room
and takes no number. A retried sealed secret returns its stored receipt and
takes no new number.

`GET /v1/sandboxes/<id>/receipts` answers with `count` (how many receipts the
room holds) and `room_head` (the `receipt_sha256` of the last one, null when
there are none) beside the receipts. A list numbered 1 to `count`, linked, with
that head, holds every receipt the room had when it was read. An action still
running, or signed after the read, is not in it.

A create that asks for more than one room (`count` other than the integer 1)
is refused with 400 `create_count_refused`, unsent and unsigned, so each room's
list holds its own create.

### Serial rooms

A create whose labels carry `cathedral_serial` = `"1"` makes a serial room: one
signed request at a time, so the order of its receipts is the order things ran.

- The label value must be the string `1`, and not set together with
  `cathedral_pool`: 400 `reserved_label_invalid`. A serial create carries no
  `Idempotency-Key` header (an empty one counts): 400 `idempotency_key_refused`.
- The create receipt carries `serial: true` when it is the room's receipt 1, no
  request for that room id was in flight when it was signed, and no non-read
  request for that room's id was in flight at any moment between the create
  being sent and its receipt being signed (an unsigned write counts, and so
  does a request the API refused). Otherwise the room is an ordinary room. The
  front remembers such ids only while a create is pending; the set holds at
  most 4,096 ids, and a further id that has to be remembered withholds every
  flag until the pending creates end.
- A second signed request while one runs is refused at once with 409
  `room_busy` and is not sent on. The turn ends after the receipt is signed and
  before the answer is written.
- Reads (GET of the room, `/wait`, `/logs`, `/stat`, `/tar`, `/desktop`,
  `/terminals`, a process's `/logs`, `sealed-secrets`, `sealed-env`, `/entries`)
  pass without a token and leave no receipt. Every other route that is not a
  signed route or a delete, the front's own sealed secrets and sealed exec
  included, is refused with 409 `room_serial_unsigned`.
- On a serial room each request is sent to the API once, a read or a signed
  GET included (an ordinary room retries a GET whose answer was lost). A read
  whose answer is lost answers 502, signs nothing and does not break the room
  (a read holds no token). A signed request or a delete that reached the API
  and was not answered is signed as a 502, and a signed request whose receipt
  could not be signed leaves none: either breaks the room.
- Once a room is broken, every request that names it, a read included, gets
  409 `room_broken` and is not sent on, except a delete. The room's receipt
  list (`GET /v1/sandboxes/<id>/receipts`) is answered before that and can
  still be read. A 2xx delete ends the room and every mark kept for it.
- Limit: a bulk delete by label (`DELETE /v1/sandboxes?label=...`) names no
  room and is not held back by a busy serial room, so clean-up by label keeps
  working. A room it removes gets no receipt of its own, and any create whose
  pending time it overlaps gets no flag.
- Limit: routes that name no room are not room requests. They are not held
  back by a serial room and are not in its list. That covers secrets (`PUT`
  and `DELETE /v1/secrets/<name>` change what the later outbound requests of
  a room whose network policy references that secret carry), workspaces (a
  room that mounts a shared workspace can be changed through another room of
  the same owner that mounts it), and listing calls (`GET /v1/sandboxes` and
  `GET /v1/quota` run the API's own expiry collection). A serial room that
  needs its list to be everything that could change it mounts no shared
  workspace and references no hotel secret.

An ordinary room runs requests side by side, as before.

### Receipts when a room ends without a request

The front keeps a table of live rooms (a room enters with its 2xx create and
leaves with a 2xx delete or a `room_end`). Every `ROOM_LOOK_SECONDS` (default
15, 0 turns it off) it copies the table, asks the room API for its list, and
for each copied room the list lacks asks for that one room. Only 404
`sandbox_not_found` and 409 `sandbox_deleting` end a room: one `room_end`
receipt with `status`, `reason` (the API's code), `result_sha256` and
`room_create_receipt_sha256`, which ends the room's incarnation as a delete
does. A room with a request in flight, a room made after the copy, a failed
list and any other answer end nothing. A read of one room's receipts first
looks at that room, with one GET.

Limits: only rooms the front signed a create for; after a front restart the
table is empty and no end is signed for earlier rooms.

### Fresh report over caller data (sealed only)

`POST /room/attest` on the receipt front asks the processor for a new SNP
report whose REPORT_DATA is the caller's 64 bytes. Auth is the hotel API key
(`Authorization: Bearer <key>`), as for `/room/receipts`.

Request: `{"report_data_hex": "<128 hex characters>"}`. The hotel puts those
64 bytes in REPORT_DATA verbatim. It does not hash them. So the caller must
send a digest of what it binds (for example sha512 of its own statement)
and check REPORT_DATA against the same digest.

Answer 200:

```json
{"report_b64": "...", "cert_chain": {"vcek": "...", "ask": "...", "ark": "..."},
 "binding_sha256": "<this boot's binding sha256>", "measurement": "<hex>", "generated_at": 1761400000}
```

- `binding_sha256` is the same value as in `GET /room/attestation`. The
  report comes from the same guest: the hotel refuses (500
  `attest_failed`) when its measurement differs from the binding.
- `cert_chain` comes from the host certificate table (configfs-tsm
  `auxblob`). It is `null` unless VCEK, ASK and ARK are all there; then
  fetch them from AMD KDS.
- 400: `report_data_hex` missing, not hex, or not exactly 128 characters.
- 401: no key or a wrong key.
- 503 `{"error":"not_sealed"}`: a level 1 hotel. It has no SNP report.
- 429 `attest_rate_limit` with `Retry-After`: more than
  `ROOM_ATTEST_PER_MINUTE` reports in 60 s for that guest (default 30;
  set it in the receipts unit environment). The broker sends
  `X-Cathedral-Guest`; a direct hotel-key call shares a `_direct` bucket.
  Bad requests do not use a slot.
- Optional `"sandbox_id"`: the answer also has `"room": {"sandbox_id",
  "create_receipt"}`, that room's signed create receipt from this boot
  (`null` when there is none). Through the broker only the guest's own
  rooms are accepted (404 `room_not_found` otherwise).

## Per-room tunables

A create may carry `"tunables"`: the start-up tunables document of the TEE box
and the Escape challenge (`{"schema": 1, ...}`, `cathedral/tee_box/tunables.py`:
same keys, bounds and sha256). They act on that room only
(`cathedral/room_tunables.py`):

| key | how the room gets it |
|---|---|
| `runsc.directfs`, `runsc.overlay2`, `runsc.net_channels` | the room starts under `--runtime runsc-tun-<d1\|d0>-<root\|all>-n<1..4>` |
| `docker.log_driver` | `docker run --log-driver` of that container |
| `image.prime` | `page_cache`: `docker save` of the room's image to /dev/null before it starts |
| `pool.*`, `boot.create_concurrency` | hotel-wide: any value but the default is 400 `tunables_not_per_room` |

- The installer registers the 16 runsc variants in the room daemon
  (`lib/tunable_runtimes.py`): the hotel's `ROOM_RUNSC_FLAGS` without
  `--directfs`, `--overlay2` and `--num-network-channels`, then those three
  set explicitly. The default runtime stays `runsc`; a room without
  `tunables` starts as before. The API reads the daemon's runtimes and
  refuses (409 `tunables_unavailable`) a variant that is missing or is not
  that rule, so the room never claims flags it does not run.
- 400 `invalid_tunables`: unknown or pinned key, wrong type, out of range,
  float, wrong schema. 400 `tunables_unsupported`: a DinD image.
- The create answer and `GET /v1/sandboxes/<id>` carry `"tunables"`:
  `{"schema": "cathedral_room_tunables_v1", "status": "applied", "sha256",
  "values", "runtime", "runtime_args", "log_driver", "image_prime"}`.
  `sha256` is the document's sha256 as the challenge computes it.
- The create receipt signs `tunables`, `tunables_sha256` (computed by the
  receipt front from the values), `tunables_runtime` and
  `tunables_runtime_args`. On a sealed hotel the receipt key is in the
  binding that the boot SNP report covers, and `POST /room/attest` with
  `sandbox_id` returns that receipt beside a fresh report.
  `verify_receipts.py` checks the sha256 and lists each room's
  `room_tunables`.
- `overlay2` `root:self` and `all:self` keep writes in the room's own
  storage, but a snapshot of such a room does not see its root file
  system writes (the hotel default is `--overlay2=none` for that reason).

## Room egress policy

Each room has one policy: `internet`, `deny_all` or `allowlist`. The hotel
applies it outside the room. The room cannot change it.

`room_egress.py` (unit `<ROOM_ID>-egress.service`, root) does the work:

- **nftables.** One table per hotel (`ip` and `bridge` family). A room address
  that has no policy has no egress (deny by default). Sets hold the rooms with
  internet, the rooms with hostnames, and the pairs (room address, allowed
  IPv4 address or CIDR). A change is one nftables transaction.
- **DNS.** All DNS from a fenced room goes to the hotel resolver on the bridge
  gateway, whatever server the room asks. It answers allowed names only
  (NXDOMAIN for other names, REFUSED for `deny_all`).
- **Egress proxy for hostnames.** TCP 443 and 80 from a room with hostnames
  go to the proxy on the gateway. The proxy reads the TLS SNI or the HTTP
  Host, checks it against the room's list, resolves the name itself and
  connects to that answer only (public IPv4 only). A connection with no name
  or another name closes.
- **Port binding.** Frames from a room's bridge port must carry the room's
  MAC and address, so a room with raw sockets cannot take another room's
  address and policy.

Why a proxy and not DNS answers in an address set: many allowed names share
CDN addresses with names that are not allowed. The proxy connects to the
address of the allowed name, so an allowed address does not open other names.

Allowlist entries: hostnames, `*.suffix` wildcards (subdomains only, not the
suffix), IPv4 addresses and IPv4 CIDRs, at most 256. Hostnames and wildcards
work on TCP 80 and 443 only (`host:443` opens TLS alone; a bare hostname
opens both). Addresses and CIDRs work on every port.
`room-net.sh` still drops private and link-local ranges, so an allowlist
cannot open them. IPv6 is not supported.

The API sends the policy to the daemon over `/run/pool-room-egress/control.sock`
after each start and on each `PUT /v1/sandboxes/{id}/network`. A live switch
also closes open proxy connections the new policy does not allow and deletes
the room's conntrack entries. A room created with network `none` has no
interface and cannot switch (409 `network_not_switchable`). Set
`ROOM_EGRESS=0` to turn the daemon off; then `allowlist` and `deny_all` fail
closed to network `none`, as before.

Every create waits for the daemon. The daemon asks the room Docker daemon
(Engine API on its socket, one call) for the room address. In a create storm
that answer can take many seconds, so the API waits up to 120 s
(`CATHEDRAL_ROOM_EGRESS_TIMEOUT`, 5 to 600) and tries a connect again for 5 s
while the daemon restarts. The Docker daemon, the API, the egress daemon,
health and receipts run with `CPUWeight=1000`. Each room scope has the
default weight, so the control units stay ahead of the rooms.

## Workspaces

`ROOM_WORKSPACES=1` turns on persistent workspaces (#305). The default is 0.
A workspace is a named directory that outlives rooms. A room mounts it
read-write when its create has `"workspace": "<name>"` (or
`{"name", "path", "version_on_delete"}`; the default path is `/workspace`).

- Storage: `$ROOM_DATA_DIR/workspaces`. `room-data.sh` makes it a bind mount
  of itself with `nosuid,nodev,noexec`. The API turns workspaces off (503
  `workspaces_unavailable`) when the mount does not have these options.
- Owner: a hash of the hotel API key plus the broker guest id (header
  `X-Cathedral-Guest`, or the `broker_guest` label on a create). A workspace
  of another owner answers 404 `workspace_not_found`.
- Names: 1 to 63 of `a-z 0-9 - _`. No dots and no slashes.
- Routes: `POST/GET /v1/workspaces`, `GET/DELETE /v1/workspaces/<name>`,
  `POST/GET /v1/workspaces/<name>/versions`,
  `POST /v1/workspaces/<name>/rollback` `{"version": n}`.
- A room delete never deletes the workspace. Delete and rollback answer 409
  `workspace_in_use` while a room mounts it.
- Copies, rollback and delete run in a helper container
  (`CATHEDRAL_WORKSPACE_HELPER_IMAGE`, default `alpine:3.20`) under the room
  runtime, with no network. The API never follows a path inside a workspace.
- Limits: `CATHEDRAL_WORKSPACE_MAX_PER_OWNER` (default 10) and
  `CATHEDRAL_WORKSPACE_MAX_VERSIONS` (default 20). There is no byte quota yet.
- Sealed hotels: off by default. `SEALED_ROOM_WORKSPACES=1` in `sealed.env`
  turns them on. Without a data disk the workspaces are on the dm-crypt
  scratch whose key is made at boot in guest memory, so a workspace lives
  until the guest restarts. With `SEALED_DATA_GIB` > 0 they are on the
  sealed data volume (LUKS2, a key only that build on that chip can make):
  a workspace outlives a restart of the same build, not yet a new build
  (`sealed/README.md` "Data volume"). Both switches are in the measured
  room.env, so turning one on gives the hotel a new measurement.
- `ROOM_WORKSPACES_SOURCE`: a directory on a volume of its own that
  `room-data.sh` binds at `$ROOM_DATA_DIR/workspaces` instead. When it is
  missing or on the root file system, workspaces stay on the data volume.
## Egress credentials

A room can use a secret without holding its value (#304). The egress
daemon keeps the values and adds them to requests outside the room.

1. Put the value: `PUT /v1/secrets/<NAME>` with `{"value": "Bearer ..."}`.
   Names are `A-Z 0-9 _`, starting with a letter. The value is the full
   header value: 1 to 8,192 visible ASCII characters. No route returns a
   value. `GET /v1/secrets` lists names; `DELETE /v1/secrets/<NAME>` deletes.
2. Reference it in the room policy (create or `PUT .../network`):
   `{"mode": "allowlist", "allow": ["pypi.example"], "credentials": [{"host": "pypi.example", "header": "Authorization", "secret": "PIP_TOKEN"}]}`.
   The host is an exact hostname that the allowlist allows. One entry per
   host, at most 16.
3. In the room, call `http://pypi.example/...` (plain HTTP, port 80). The
   proxy removes any header of that name from the request, adds the value,
   and sends the request over TLS to port 443 with certificate and hostname
   checks (system CA store). It sends `Connection: close`, so there is one
   request for each connection.

- The proxy reads the value for each request: a new value takes effect at
  once, with no room restart. A missing value gives 502 with the secret name.
- Port 443 from the room stays a TLS pass-through with no credential.
- The answer of the host goes to the room unchanged. A host that echoes
  request headers shows the value to the room. Give a credential only to a
  host you trust.
- Owner: a hash of the hotel API key plus the broker guest id. A secret of
  another owner is never used and answers 404.
- Storage: memory, and with `ROOM_SECRETS_PERSIST=1` (default) also
  `/var/lib/pool-room-egress/secrets.json` (AES-256-GCM; key file
  `secrets.key`, root only, mode 0600). Sealed hotels set
  `ROOM_SECRETS_PERSIST=0`: values stay in SNP guest memory and a reboot
  loses them.
- Receipts sign the policy with the credential references (host, header
  name, secret name). No log line, answer or receipt has a value.

## Build the API tarball

The kit installs a pinned commit of this repository. Run
`./make-dist.sh <commit>` in a clone. It writes `dist/cathedral-<commit>.tar.gz`
and prints the sha256. Put both values in `versions.lock`.

## Install

1. Copy the kit to the machine.
2. Put the API key in a file on the machine, for example `/root/room-api-key`,
   mode 600. Use 32 or more characters from `A-Z a-z 0-9 _ -`. The kit does not
   make keys and does not print keys.
3. Copy `room.env.example` to `room.env` and set the values.
4. Run `sudo ./install.sh room.env`.
5. Keep the key file from step 2 (mode 0600, root): a re-run reads it
   again and stops at once without it. The kit keeps its own copy in
   `/etc/pool-room/` (root only, and the service group for health).

Run `install.sh` again to apply a changed `room.env`. The installer is
idempotent.

The installer stops before it changes anything when the key file is
unreadable, when `ROOM_CUSTOMER` is not 1 to 64 characters of
`A-Z a-z 0-9 . _ -`, when rooms are live on the room daemon (stop them or
wait; a restart would end them), or when a pinned download's checksum differs
from `versions.lock`. It fails at the end unless the API answers
`GET /v1/status` with 200 for its own key; "done" is never printed over a
hotel that answers nobody.

## What the kit installs

| Item | Location |
|---|---|
| Room Docker daemon (runsc default runtime, own socket, data root, containerd namespace, bridge, iptables off) | `<ROOM_ID>-docker.service`, `/etc/pool-room/daemon.json`, `/run/pool-room/docker.sock` |
| Data volume (xfs, prjquota, no nodev) | `<ROOM_ID>-data.service`, `ROOM_DATA_DIR`, `ROOM_DATA_IMG` or `ROOM_DATA_DEVICE` |
| Guest network rules (own chains only) | `/opt/pool-room/bin/room-net.sh` |
| gVisor runsc (pinned, sha512) | `/opt/pool-room/gvisor` |
| Python 3.12 (uv, pinned) and the cathedral package (pinned commit, sha256) | `/opt/pool-room/python`, `/opt/pool-room/venv`, `/opt/pool-room/src` |
| API (profile) on 127.0.0.1 | `<ROOM_ID>.service` |
| Health endpoint on 127.0.0.1 | `<ROOM_ID>-health.service` |
| Signed receipts (level 1 by default; listener `ROOM_RECEIPTS_LISTEN`) | `<ROOM_ID>-receipts.service` when `ROOM_RECEIPTS=1` |
| TTL reaper (every 60 s) | `<ROOM_ID>-reaper.timer` |
| Caddy (pinned, sha512) on 443. With receipts on, API calls go to the receipt listener; `/room/health` stays on the health port | `<ROOM_ID>-caddy.service`, `/etc/pool-room/Caddyfile` |
| Service user | `poolroom` |

The kit does not edit `/etc/docker/daemon.json` and does not restart the host
Docker daemon. Containers that already run on the host are not touched.

## API profiles

`API_PROFILE` selects the customer API. A profile is `profiles/<name>.sh`.
It defines the API start command, its environment, and how the API key is
passed. The API must listen on `127.0.0.1:ROOM_API_PORT` and must start guests
through `DOCKER_HOST` (the room daemon). Then every guest runs under runsc,
and so do image builds: the API uses the classic builder, because BuildKit
runs `RUN` steps in its own runc worker and ignores the daemon's default
runtime.

- `v1`: the `/v1` sandbox API from cathedral-sandbox
  (`cathedral.cli sandbox serve --runtime docker`, started through
  `room_api.py`, which applies `ROOM_CREATES_PER_MINUTE`).

To add a profile, add `profiles/<name>.sh` with the same four items.

The API refuses to start with an empty key store (`CATHEDRAL_SANDBOX_KEYS`),
a malformed key entry (the shape is `key:project[:slots]`) or a malformed
quota (`CATHEDRAL_SANDBOX_QUOTA` is `rooms:vcpu:memory_gib`). The installer
writes both from `room.env` and the sizing step, so a refusal there points
at `room.env`.

## Remove

Run `sudo ./uninstall.sh`. Options:

- `--keep-runtime` keeps runsc in `/opt/pool-room/gvisor`.
- `--keep-data` keeps the loop image file.

The uninstaller stops and removes the room units, the room containers, the
bridge and its iptables rules, the data volume, Caddy, Python, the service
user and `/etc/pool-room`. It does not touch the host Docker daemon. It does
not remove apt packages. Delete the DNS record yourself.

## Limits

- One room per machine (one Caddy on 443).
- The API keeps sandbox state in memory. A restart of `<ROOM_ID>.service`
  forgets the sandboxes, and its first reconcile pass (about 30 s later)
  removes their containers. `install.sh` stops when rooms are live; wait until
  no room is open, or set `ROOM_RESTART_WITH_ROOMS=1` to end them on purpose.
  A sealed hotel is rebuilt as a new guest, so an update there always ends its
  rooms.
- `GET /v1/status` says `runtime: docker` and `kernel_isolation: true` when
  the room daemon's default runtime is runsc (it asks the daemon). Use
  `/room/health` for the runtime the probe saw.
