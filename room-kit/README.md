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
- Network: inbound TCP 443 from the internet. Outbound HTTPS to Docker Hub,
  Let's Encrypt, GitHub (uv, Caddy, Python) and storage.googleapis.com (gVisor).
  Port 80 is not used.
- DNS: an A record for `ROOM_HOSTNAME` to the machine IP, DNS only, before
  you run the installer.
- A free private /22 or larger for the guest bridge (one address per sandbox).
  One Linux bridge takes at most 1,024 ports, so one bridge serves at most
  1,023 rooms with a network. With `ROOM_NETS=auto` (the default) the kit
  adds room networks when the host can hold more rooms (see "Room networks").
  Rooms with network `none` use no bridge port.

## Room networks

One Linux bridge takes at most 1,024 ports. A host that can hold more than
1,023 rooms with a network needs more bridges ("room networks").

With `ROOM_NETS=auto` (the default), the installer does this:

1. It sizes the host by CPU, memory and disk, with no bridge limit.
2. If the main bridge holds that many rooms (`ROOM_BRIDGE_PORT_CAP`), it
   adds no room network.
3. Otherwise it makes one room network for each `ROOM_NET_SIZE` rooms
   (default 1,000). It cuts the CIDRs from `ROOM_NETS_POOL` (default
   10.214.0.0/16) and skips CIDRs that other host networks use.
4. It writes the CIDRs to the resolved `/etc/pool-room/room.env` and sizes
   the host again with the room networks.

To choose the CIDRs yourself, set `ROOM_NETS` to a space-separated list.
`ROOM_NETS=""` keeps every room on the main bridge.

For every room network the kit adds the same firewall rules as for the main
bridge (`room-net.sh`, by bridge name `${ROOM_NET_BRIDGE_PREFIX}N`). Guests
use `ROOM_DNS`. The kit sets these API settings (`/etc/pool-room/api.env`):

| Setting | Value from the kit | Meaning |
|---|---|---|
| `CATHEDRAL_ROOM_NETWORKS` | count of `ROOM_NETS` | Number of room networks. Unset or 0: no room networks. |
| `CATHEDRAL_ROOM_NETWORK_SUBNETS` | `ROOM_NETS`, comma separated | One subnet per network. |
| `CATHEDRAL_ROOM_NETWORK_SIZE` | `ROOM_NET_SIZE` | Rooms per network (max 1,023). |
| `CATHEDRAL_ROOM_NETWORK_PREFIX` | `$ROOM_ID-net` | Docker network name prefix. |
| `CATHEDRAL_ROOM_NETWORK_BRIDGE_PREFIX` | `ROOM_NET_BRIDGE_PREFIX` | Linux bridge name prefix: bridge N is `<prefix>N`. |
| `CATHEDRAL_ROOM_NETWORK_DNS` | `ROOM_DNS` | Name servers for guests on room networks. |

`GET /v1/quota` shows `room_networks`, with the use of each network.

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
work on TCP 80 and 443 only. Addresses and CIDRs work on every port.
`room-net.sh` still drops private and link-local ranges, so an allowlist
cannot open them. IPv6 is not supported.

The API sends the policy to the daemon over `/run/pool-room-egress/control.sock`
after each start and on each `PUT /v1/sandboxes/{id}/network`. A live switch
also closes open proxy connections the new policy does not allow and deletes
the room's conntrack entries. A room created with network `none` has no
interface and cannot switch (409 `network_not_switchable`). Set
`ROOM_EGRESS=0` to turn the daemon off; then `allowlist` and `deny_all` fail
closed to network `none`, as before.

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
5. Delete the key file from step 2. The kit keeps its own copy in
   `/etc/pool-room/` (root only, and the service group for health).

Run `install.sh` again to apply a changed `room.env`. The installer is
idempotent.

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
| TTL reaper (every 60 s) | `<ROOM_ID>-reaper.timer` |
| Caddy (pinned, sha512) on 443 | `<ROOM_ID>-caddy.service`, `/etc/pool-room/Caddyfile` |
| Service user | `poolroom` |

The kit does not edit `/etc/docker/daemon.json` and does not restart the host
Docker daemon. Containers that already run on the host are not touched.

## API profiles

`API_PROFILE` selects the customer API. A profile is `profiles/<name>.sh`.
It defines the API start command, its environment, and how the API key is
passed. The API must listen on `127.0.0.1:ROOM_API_PORT` and must start guests
through `DOCKER_HOST` (the room daemon). Then every guest runs under runsc.

- `v1`: the `/v1` sandbox API from cathedral-sandbox
  (`cathedral.cli sandbox serve --runtime docker`, started through
  `room_api.py`, which applies `ROOM_CREATES_PER_MINUTE`).

To add a profile, add `profiles/<name>.sh` with the same four items.

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
  forgets the sandboxes. Their containers keep running until you remove them.
- `GET /v1/status` says `runtime: docker` and `kernel_isolation: false`. The
  API does not know that the room daemon uses runsc. Use `/room/health` for
  the true runtime.
