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
