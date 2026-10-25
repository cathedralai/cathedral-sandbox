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
- Sealed hotels: off. A sealed workspace needs a key that only the guest
  holds (#305 design).

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
