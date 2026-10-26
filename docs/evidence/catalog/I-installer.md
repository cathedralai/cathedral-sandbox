# Catalog I: room kit installer (review round 6)

Artifact: cathedral-sandbox 22e7824 (PR #311 head), frozen at /private/tmp/claude-501/r6.
Files: room-kit/install.sh, lib/room-data.sh, lib/room_nets_mode.sh, lib/receipts_mode.sh,
profiles/v1.sh, uninstall.sh, make-dist.sh, versions.lock, files/requirements.lock,
assess.py, size.py, room.env.example, .gitignore. Context read: README.md, lib/room-net.sh,
lib/net_plan.py, lib/net_capacity.py, room_api.py, room_health.py, room_receipts.py (main,
Ledger, store), room_egress.py (main, read_env, Rules.base), sealed/guest-boot.sh,
sealed/build-guest.sh (room.env it renders), sealed/install-sealed.sh,
tests/test_room_kit_restart_guard.py, tests/test_room_kit_nets_mode.py,
tests/test_room_kit_size_sealed.py, cathedral/sandbox_guest.py (labels, docker run argv),
cathedral/sandbox_provider.py (work dir root).

Format per item: name, lines, purpose, trusts, side effects, locks, callers, invariant.
No lock is held anywhere in these files unless stated. "none" means none.

## install.sh (498 lines, bash, set -euo pipefail, umask 022, root only)

### Preamble, lines 1 to 27
- Purpose: paths, `--sealed` hand-off (line 12 exec sealed/install-sealed.sh), source
  the operator room.env (line 15) and versions.lock (line 17), root check (18), profile
  file check (19 to 20), create /etc/pool-room, /opt/pool-room/{cache,bin} (27).
- Trusts: room.env and versions.lock are shell, sourced as root. Any code in them runs.
  `API_PROFILE` names a file under profiles/ (path join, no validation).
- Side effects: disk (mkdir). No network.
- Callers: operator (`sudo ./install.sh room.env`), sealed guest at every boot
  (sealed/guest-boot.sh line 26 with the measured /opt/room-kit/room.env).
- Invariant: ROOM_ETC=/etc/pool-room, ROOM_OPT=/opt/pool-room, ROOM_RUN=/run/pool-room,
  SOCK=/run/pool-room/docker.sock are fixed. One room per host.

### log(), line 28. mark(), line 29
- mark appends a line to /etc/pool-room/install-state once (grep -qxF then echo >>).
- Trusts: STATE path. Side effects: disk. Callers: steps 0, 2, 7, 10, 11, 12.
- Invariant: install-state lists what the kit added so uninstall.sh can undo only that
  (`apt:`, `masked:docker`, `file:<img>`, `unit:`, `user:poolroom`, `ufw:`, `iptables:`).

### refuse_restart_with_rooms(), lines 34 to 48, called once at line 49 (new in #311)
- Purpose: stop before any restart when live rooms exist (B24 phase 1).
- Logic: no socket, return 0. `ROOM_RESTART_WITH_ROOMS=1`, return 0. Else count
  `docker ps -q --filter label=cathedral.sandbox.owner` (running containers only);
  docker failure (pipefail) exits 1 with a message (B34 fix); count > 0 exits 1.
- Trusts: the label name matches cathedral/sandbox_guest.py LABEL_OWNER (verified, line 87,
  set on every create at line 1393). `ROOM_RESTART_WITH_ROOMS` from the environment OR
  from room.env (sourced at line 15, before the guard).
- Side effects: one docker CLI call. Network: none.
- Callers: line 49 only. The restarts it protects are at lines 280 and 489 to 493.
- Invariant assumed: no room is created between line 49 and the restarts. Nothing enforces
  it (no broker drain, no second check). See hazards.

### fetch(), lines 51 to 57
- Purpose: download a URL to /opt/pool-room/cache with a sha256 or sha512 pin.
- Logic: cached file with a matching sum, return. Else curl -fsSL --retry 3 to `$out.part`,
  check the sum, mv into place; mismatch removes `.part` and exits 1.
- Trusts: versions.lock sums; cache dir is root-only (0755 root under umask 022).
- Side effects: network (https; curl follows redirects, GitHub to objects.githubusercontent.com),
  disk in the cache. The downloaded bytes are never used before the sum matches.
- Callers: lines 148 (gvisor, sha512), 157 (uv, sha256), 177 (caddy, sha512).
- Invariant: `${algo}sum` exists (coreutils).

### Step 0, host packages, lines 59 to 86
- Purpose: apt install of docker.io, xfsprogs, curl, bzip2, iptables, nftables, conntrack
  when missing. A fresh docker.io install writes /usr/sbin/policy-rc.d (exit 101) first so
  the host Docker daemon does not start, then masks docker.service and docker.socket.
  Ensures containerd runs (line 86).
- Trusts: apt (distro signatures); `command -v` on the installer's PATH.
- Side effects: network (apt), disk, systemd (mask, enable --now containerd). Host wide:
  policy-rc.d while apt runs; masked host docker units if this install added docker.io.
- Invariant: policy-rc.d is removed at line 80, on the happy path only. A failing apt-get
  exits under set -e and leaves it (probe_installer_policy_rcd.py fails today).
- Network before any pin is checked: yes, apt. Also containerd start.

### Step 1, assess, lines 88 to 90
- Runs `python3 assess.py --data-dir $ROOM_DATA_DIR --room-socket $SOCK --out machine.json`
  with the system python3, as root. Read-only on the host.
- Trusts: ROOM_DATA_DIR. The data volume is NOT mounted yet on a first install (step 8 mounts
  it), so machine.json describes the parent file system of ROOM_DATA_DIR on run one and the
  xfs volume on re-runs. size.py gets a different disk leg each time (see size.py).
- Side effects: writes /etc/pool-room/machine.json (0644 root, holds hostname, listening
  ports, workloads). Runs host docker CLI, ps, ss, findmnt.

### ROOM_KEYS and write_room_env(), lines 93 to 97
- Purpose: write the resolved config /etc/pool-room/room.env (0644) as `K="v"` lines for
  the keys in ROOM_KEYS. ROOM_API_KEY_FILE and ROOM_DATA_DEVICE_WIPE are not in the list,
  so neither is persisted. No quoting or escaping of values.
- Readers of room.env: room-data.sh and room-net.sh (bash source, as root), room_egress.py
  read_env (regex, strips quotes), room_health.py _parse_env (mtime cache, live), uninstall.sh
  (source). A value with `"` or `$` breaks the shell readers; operator input only.
- Callers: lines 114, 117, 268.

### Receipts and room network defaults, lines 100 to 118
- `receipts_apply_defaults` (lib) then `resolve_room_nets` (lib). In auto mode with an
  existing room.env.applied, room.env keeps the APPLIED ROOM_NETS until step 8 plans the new
  list (B35 fix, tested by test_auto_room_nets_keep_the_applied_list_until_step_8). ROOM_NETS
  is then reset to empty for the planner.
- Trusts: room.env.applied line format `ROOM_NETS="..."` (sed at line 113).

### Step 2, data volume, lines 120 to 145
- Installs /opt/pool-room/bin/room-data.sh (0755). Device path: if `blkid` does not say xfs,
  requires ROOM_DATA_DEVICE_WIPE=yes then `mkfs.xfs -f`. Image path: if the file is missing,
  `truncate -s ${ROOM_DATA_SIZE_GB}G` (GiB) and mkfs, mark `file:`.
- Writes unit `$ROOM_ID-data.service` (lines 133 to 144):
  Type=oneshot, RemainAfterExit=yes, Before=$ROOM_ID-docker.service,
  ExecStart=room-data.sh up room.env, ExecStop=room-data.sh down room.env,
  WantedBy=multi-user.target. No User (root), no hardening. Root needed for mount/losetup.
- Trusts: ROOM_DATA_DEVICE names the right disk at every run (kernel names such as
  /dev/nvme2n1 can renumber across reboots; WIPE=yes stays in room.env; the sealed guest uses
  the stable /dev/mapper/sealed-scratch). `blkid` output is authoritative.
- Side effects: mkfs (destructive, gated), disk, unit file. Not started here.

### Step 3, gVisor, lines 147 to 154
- fetch gvisor tarball (sha512), extract once into /opt/pool-room/gvisor-<release>,
  symlink /opt/pool-room/gvisor. RUNSC=/opt/pool-room/gvisor/runsc.
- Extraction: `tar -xjf` as root, default --same-owner. The pinned archive stores uid 0,
  gid 0 (verified), so runsc is root owned today.
- Side effects: disk. Network: via fetch only.

### Step 4, Python and the API package, lines 156 to 174
- fetch uv (sha256); `tar -xzf --strip-components=1` into /opt/pool-room/bin (uv, uvx),
  as root with default --same-owner. The pinned uv 0.12.24 archive stores uid 1001 gid 117,
  names runner:docker (verified). On a hotel without a `runner` user the files become
  uid 1001. See hazards and the finding.
- `uv python install 3.12` (network to GitHub python-build-standalone; verified by uv's own
  built-in sha256 list; the patch release floats with the uv pin, not with versions.lock).
  UV_PYTHON_INSTALL_DIR=/opt/pool-room/python, UV_CACHE_DIR=/opt/pool-room/cache/uv,
  UV_NO_CONFIG=1, then UV_PYTHON_PREFERENCE=only-managed.
- venv at /opt/pool-room/venv (created once). `uv pip install --require-hashes
  --only-binary :all: -r files/requirements.lock` (network to PyPI, hash enforced).
- Cathedral tarball: `sha256sum -c` against versions.lock (line 164; missing file or
  mismatch exits), extract into src.new, `rm -rf src`, mv (lines 165 to 167). The running
  API has already imported its modules; a lazy import in the sub-second window between rm
  and mv fails. COMMIT file written (read by room_receipts.py for the binding).
- Installs room_health.py, room_api.py, assess.py, size.py, room_receipts.py,
  room_egress.py into /opt/pool-room/bin (0755 root). `install` unlinks first, so running
  processes keep their old inode.
- Invariant: the API's only non stdlib dependency is cryptography (pyproject.toml), which the
  lock provides with cffi and pycparser. The API runs from PYTHONPATH=/opt/pool-room/src,
  it is not pip installed.

### Step 5, Caddy, lines 176 to 178
- fetch caddy (sha512); `tar -xzf ... caddy` into /opt/pool-room/bin as root, default
  --same-owner. The pinned archive stores uid 1001 gid 1001 runner:runner (verified).

### Step 6, service user, lines 180 to 181
- `useradd --system --home-dir /var/lib/pool-room --shell /usr/sbin/nologin poolroom`, marked.

### Step 7, room Docker daemon, lines 183 to 239
- net_settings() line 186: greps ROOM_BRIDGE, ROOM_BRIDGE_CIDR, ROOM_NETS,
  ROOM_NET_BRIDGE_PREFIX from room.env.applied (ROOM_NETS_POOL does not match).
- ROOM_DAEMON_HASH_BEFORE line 187: sha256 of installed daemon.json + installed room-net.sh +
  net_settings, taken BEFORE line 188 installs the new room-net.sh. On a fresh install the
  input is empty and the hash is of "" (still non empty text).
- daemon.json (lines 192 to 216), 0644 root. Every key:
  hosts [unix:///run/pool-room/docker.sock]; group poolroom (socket 0660 root:poolroom);
  data-root $ROOM_DATA_DIR/docker; exec-root /run/pool-room/exec; pidfile
  /run/pool-room/docker.pid; containerd /run/containerd/containerd.sock (shared with the host
  daemon); containerd-namespace pool-room-$ROOM_ID; containerd-plugins-namespace
  pool-room-$ROOM_ID-plugins; features.containerd-snapshotter false (overlay2 graphdriver,
  needed for --storage-opt size); storage-driver overlay2; bridge $ROOM_BRIDGE (pre made by
  room-net.sh, address from the bridge, no bip or fixed-cidr); iptables false; ip6tables
  false; ip-masq false (room-net.sh masquerades); userland-proxy false; dns from ROOM_DNS;
  registry-mirrors from ROOM_REGISTRY_MIRRORS; default-runtime runsc; runtimes.runsc
  {path $RUNSC, runtimeArgs from ROOM_RUNSC_FLAGS}; log-driver json-file; log-opts
  max-size 20m, max-file 2 (logs live under data-root, on the volume).
  Absent: live-restore (every daemon restart stops all rooms; also Restart=on-failure after
  a dockerd crash), no-new-privileges, icc (moot with iptables false; room-net.sh drops
  bridged frames with an nft bridge rule), ip-forward (default true, also set by
  room-net.sh), default-ulimits, seccomp-profile (runsc ignores it), storage-opts default
  size (the API passes --storage-opt size per room, sandbox_guest.py 577), userns-remap,
  default-address-pools (the API passes subnets), cgroup-parent (rooms are scopes beside
  the kit's units; see hazards), shutdown-timeout, default-cgroupns-mode.
  The built-in runc runtime stays registered; default-runtime only picks the default.
- Unit `$ROOM_ID-docker.service` (lines 217 to 238): Requires=$DATA_UNIT,
  After=$DATA_UNIT containerd.service network-online.target, Type=notify,
  RuntimeDirectory=pool-room (0755 root, so /run/pool-room), RuntimeDirectoryPreserve=yes,
  ExecStartPre=room-net.sh up room.env, ExecStart=/usr/bin/dockerd --config-file daemon.json,
  ExecStopPost=room-net.sh down room.env, ExecReload=kill -HUP, TimeoutStartSec=120,
  Restart=on-failure, LimitNOFILE=1048576, TasksMax=infinity, Delegate=yes, KillMode=process,
  WantedBy=multi-user.target. Root. No hardening (dockerd needs it all).
- Trusts: ROOM_DNS, ROOM_RUNSC_FLAGS, ROOM_REGISTRY_MIRRORS split on whitespace into JSON
  arrays by python (safe quoting); $SOCK, $RUNSC paths are literal in JSON (no quoting issue
  for sane paths).
- Invariant: the daemon never touches host iptables (iptables false); room-net.sh owns the
  rules. Rooms get runsc unless a client passes --runtime (the API passes none unless
  CATHEDRAL_DOCKER_RUNTIME or CATHEDRAL_DIND_RUNTIME is set; the profile sets neither).

### Step 8, size and daemon start, lines 241 to 284
- daemon-reload; `enable --now $DATA_UNIT` (no-op when already active, so a changed
  ROOM_DATA_DIR or image path is not remounted; line 244 then fails "did not mount");
  mountpoint, xfs_info, prjquota check; mkdir work and docker under the volume; chown
  poolroom:poolroom work (0755); ROOM_DISK_BYTES from df.
- size_room() lines 250 to 255: runs size.py with the shape, overcommits, reserves,
  --room-disk-bytes, --max-slots, --bridge-addresses, writes a json.
- Auto room networks (lines 256 to 269): size with no bridge limit, RAW_SLOTS, ROUTED =
  prefixed routes in the main table whose dev is not the main bridge or an rmnetN bridge
  (awk), net_plan.py gives the CIDR list, write_room_env (room.env now has the NEW list,
  before the 0-slot check at line 273 and before the daemon restart).
- Final size (line 270) with net_capacity.py bridge addresses; SIZE_SLOTS, SIZE_QUOTA;
  0 slots exits 1 (line 273). On a live hotel this exit leaves room.env with the new plan
  (possibly empty) while the units run the applied one until a successful run.
- `enable --now $ROOM_ID-docker.service` (276; a running daemon is not restarted here),
  `cp room.env room.env.applied` (277; before the restart below and before step 9),
  hash compare (278): if daemon.json, room-net.sh or the net settings changed, and
  `[ -n "${ROOM_DAEMON_HASH_BEFORE// -/}" ]` (always true), restart the daemon (280).
  Without live-restore this stops every room; the guard at line 49 is the only protection.
  A fresh install always takes this restart (hash of "" differs), harmless.
- Wait up to 60 s for `docker info` (282); default runtime must be runsc (283);
  `docker pull -q $PROBE_IMAGE` (284; mutable tag, through the mirror, unverified; a failure
  here exits after the daemon restart and before step 9).
- Trusts: `ip -o route show` output; machine.json from step 1 (stale for the data dir);
  size.py arithmetic.

### Step 9, API key, lines 286 to 299
- xtrace off; KEY = key file contents without spaces and newlines (line 288: a missing
  ROOM_API_KEY_FILE fails the redirect, set -e exits with only bash's error line); must match
  ^[A-Za-z0-9_-]{32,}$.
- /etc/pool-room/api.key: `install -m 0640 -o root -g poolroom /dev/null` then printf
  (0640 root:poolroom; read by health as poolroom and by receipts as root).
- Sources the profile (line 293). /etc/pool-room/secret.env 0600 root:root from
  profile_keys_env (CATHEDRAL_SANDBOX_KEYS=<key>:<customer>:<slots>; systemd reads it as
  root for the poolroom API unit, so the key is in the API's environment).
  /etc/pool-room/reaper.headers 0600 root:root (`Authorization: Bearer <key>`, read by
  curl in the root reaper unit). unset KEY; xtrace restored.
- The key never appears in a process argument (builtins and shell functions only).
- Rotation path: change the key file and re-run install.sh. There is no separate rotate
  command. A re-run restarts the API (needs no live rooms or the override), so key rotation
  ends rooms. The broker must switch its hotel key at step 13 time; before line 491 the API
  still holds the old key in its environment while api.key on disk is new.
- README step 5 tells the operator to delete the key file; a later re-run therefore dies
  here, after the room daemon restart and the room.env.applied copy. probe_installer_key_preflight.py
  shows the preamble lets it through.

### Step 10, API, health, reaper, egress, receipts units, lines 301 to 422
- /etc/pool-room/api.env (0644): DOCKER_HOST=unix:///run/pool-room/docker.sock,
  HOME=/var/lib/pool-room, TMPDIR=$ROOM_DATA_DIR/work, plus profile_env lines (no secrets).
- `$ROOM_ID.service` (308 to 329): Requires=$ROOM_ID-docker.service, After= same,
  User=poolroom, Group=poolroom, StateDirectory=pool-room (/var/lib/pool-room, poolroom),
  EnvironmentFile api.env and secret.env, ExecStart from profile_exec
  (venv python room_api.py sandbox serve --host 127.0.0.1 --port $ROOM_API_PORT --runtime
  docker), Restart=on-failure, LimitNOFILE=1048576, TasksMax=infinity, NoNewPrivileges=yes,
  ProtectSystem=full, PrivateTmp=yes, ReadWritePaths=$ROOM_DATA_DIR/work /var/lib/pool-room.
  No CapabilityBoundingSet, no ProtectHome, no CPUWeight (default 100).
  Hardening is cosmetic: poolroom holds the room daemon socket (0660 root:poolroom) and the
  daemon keeps runc registered, so `docker run --privileged --runtime runc -v /:/host` from
  this user is host root. The API also runs dind rooms with --privileged (under runsc).
  Its work tree: TMPDIR/cathedral-sandbox-<rand> is a mkdtemp (0700), per room
  <root>/work beneath it, bind mounted as /work. Other local users cannot traverse it.
- `$ROOM_ID-health.service` (332 to 348): After=$ROOM_ID-docker.service only,
  User/Group poolroom, Environment ROOM_ETC, ROOM_DOCKER_SOCK, ROOM_HEALTH_PORT,
  ROOM_PROBE_IMAGE, HOME; ExecStart venv python room_health.py; Restart=on-failure;
  Nice=-5; CPUWeight=1000; NoNewPrivileges=yes. Reads api.key (group), room.env,
  machine.json, size.json. Runs `docker run --rm --network none $PROBE_IMAGE` every 10 min.
  Same socket, same root equivalence.
- `$ROOM_ID-reaper.service` (353 to 359): Type=oneshot, root, ExecStart=curl -fsS
  -H @/etc/pool-room/reaper.headers http://127.0.0.1:$ROOM_API_PORT/v1/sandboxes (GET as the
  hotel key, straight to the API, not through the receipts front; lists are not receipted).
  `$ROOM_ID-reaper.timer` (360 to 369): OnBootSec=120, OnUnitActiveSec=60, AccuracySec=5,
  WantedBy=timers.target. Root only because the header file is 0600 root.
- `$ROOM_ID-egress.service` (376 to 397, when ROOM_EGRESS=1, the default):
  Requires=$ROOM_ID-docker.service, After= same, Before=$ROOM_ID.service,
  PartOf=$ROOM_ID-docker.service; Environment ROOM_ENV=/etc/pool-room/room.env,
  ROOM_DOCKER_SOCK, ROOM_EGRESS_SOCKET=/run/pool-room-egress/control.sock,
  ROOM_EGRESS_GROUP=poolroom; ExecStart venv python room_egress.py; Restart=always;
  RestartSec=1; Nice=-5; CPUWeight=1000; LimitNOFILE. Root (nft, conntrack, chown of the
  control socket to root:poolroom 0660, run dir 0750). No hardening; it also uses the docker
  socket. The API does not Wants/Requires it: if egress is down the API still starts.
  State: /run/pool-room-egress/state.json (tmpfs; reloaded on restart; lost at reboot).
- `$ROOM_ID-receipts.service` (403 to 422, when ROOM_RECEIPTS=1, the default):
  Requires=$ROOM_ID.service, After=$ROOM_ID.service $ROOM_ID-health.service; Environment
  ROOM_RECEIPTS_LISTEN, ROOM_HOTEL_NAME, ROOM_API_PORT, ROOM_HEALTH_PORT, ROOM_DOCKER_SOCK,
  ROOM_API_KEY_PATH=/etc/pool-room/api.key, ROOM_RECEIPTS_DIR=/run/room-receipts;
  ExecStart venv python room_receipts.py; Restart=on-failure; RestartSec=2; Nice=-5;
  CPUWeight=1000; LimitNOFILE. Root, no User, no hardening. On an unsealed host nothing it
  does needs root (key is group readable, socket is group writable, the store could be a
  RuntimeDirectory); root is needed only for the TSM configfs in the sealed guest. It is
  the customer facing HTTP front for every call except /room/health. The store
  (chain-<boot_id>.jsonl, 0700 dir) is on tmpfs and the whole chain is also kept in memory;
  neither is pruned. Requires= on the API means `systemctl restart $ROOM_ID.service`
  restarts receipts too (new chain key), so step 13 re-keys the chain twice.
- Dependency graph: data <- docker <- {API, egress (PartOf)}; API <- receipts; health and
  caddy have ordering only. An explicit stop of data stops docker, the API, egress and
  receipts; an explicit restart of docker restarts them all.

### Step 11, Caddy, lines 424 to 473 (ROOM_TLS=on, the default; off in the sealed guest)
- ROOM_API_UPSTREAM from receipts_api_upstream (receipts listener, or the API).
- /etc/pool-room/Caddyfile (0644): global auto_https disable_redirects, admin off, optional
  email; site https://$ROOM_HOSTNAME:$ROOM_PUBLIC_PORT, tls issuer acme with
  disable_http_challenge (TLS-ALPN on 443 only, no port 80); handle /room/health to
  127.0.0.1:$ROOM_HEALTH_PORT; handle everything else to the upstream with flush_interval -1,
  read and write timeouts 15m. No body limit, no header hardening.
- `$ROOM_ID-caddy.service` (457 to 470): After=network-online.target $ROOM_ID.service
  [$ROOM_ID-receipts.service]; DynamicUser=yes (implies NoNewPrivileges, PrivateTmp,
  ProtectSystem=strict, ProtectHome=read-only, RemoveIPC); StateDirectory=pool-room-caddy
  (/var/lib/private/pool-room-caddy, symlink /var/lib/pool-room-caddy; /var/lib/private is
  0700 root); Environment XDG_DATA_HOME and XDG_CONFIG_HOME there (certificates, ACME
  account key, 0600 by Caddy); AmbientCapabilities=CAP_NET_BIND_SERVICE; ExecStart
  /opt/pool-room/bin/caddy run --config Caddyfile --adapter caddyfile; Restart=on-failure.
  The strongest unit in the kit. It executes a binary that is uid 1001 owned on disk (step 5).
- TLS material survives re-runs (state dir kept); uninstall removes it, so a reinstall
  re-issues (Let's Encrypt duplicate limits apply).

### Step 12, host firewall, lines 475 to 485
- ROOM_TLS=off: log lines only. ufw active: `ufw allow $ROOM_PUBLIC_PORT/tcp`, marked.
  Else, only when INPUT policy is DROP and the rule is absent: `iptables -I INPUT` accept
  443 with the pool-room comment, marked. Side effects: host firewall, world facing 443.

### Step 13, start, lines 487 to 498
- daemon-reload; egress enable + restart (always); API, health, reaper.timer enable; API and
  health restart (always; the API restart propagates to receipts); receipts enable + restart
  (second re-key); caddy enable + restart (TLS blip); timer start; wait up to 30 s for the API
  status code; print versions. Every restart here ends live rooms (API memory) and cuts
  open proxy connections (egress). Only the line 49 guard stands between a room created
  during steps 0 to 12 and this.
- Network: curl to loopback; Caddy starts ACME.

## lib/room-data.sh, lines 1 to 26 (bash, root, set -euo pipefail)
- up (9 to 19): mkdir ROOM_DATA_DIR; already a mountpoint, exit 0; SRC = device, or the loop
  device already attached to the image, or a new `losetup --direct-io=on -f`; `mount -o
  prjquota,noatime` (no nodev by design, also no nosuid or noexec).
- down (20 to 25): umount if mounted; detach every loop device of the image.
- Trusts: room.env values (sourced as root); ROOM_DATA_DEVICE is the intended disk at boot.
- Callers: the data unit ExecStart and ExecStop; uninstall.sh indirectly via disable --now.
- Invariant: ROOM_DATA_DIR is an xfs with prjquota before dockerd starts (install.sh line 246
  checks once at install; the unit does not re-check).

## lib/room_nets_mode.sh, resolve_room_nets(), lines 9 to 22
- Unset or `auto`: ROOM_NETS_AUTO=1, ROOM_NETS="". `none`, `off`, empty: AUTO=0, "".
  A CIDR list: AUTO=0, unchanged (no CIDR validation; room-net.sh and the API validate).
- Callers: install.sh line 108. Tested by tests/test_room_kit_nets_mode.py.

## lib/receipts_mode.sh
- receipts_apply_defaults (12 to 41): ROOM_RECEIPTS unset or empty becomes 1; 0 returns;
  anything else is an error (return 1, caught by set -e at the call site with the message).
  Defaults ROOM_RECEIPTS_LISTEN=127.0.0.1:18092, ROOM_HOTEL_NAME=$ROOM_ID. A loopback or
  all-interfaces listener may not use the API or health port. A specific address may (the
  sealed guest binds <guest ip>:18090).
- receipts_api_upstream (47 to 59): receipts off, 127.0.0.1:$ROOM_API_PORT; on, the listener
  with an all-interfaces host rewritten to 127.0.0.1.
- Callers: install.sh lines 102 and 427. The split `${X%:*}` and `${X##*:}` is wrong for a
  bare IPv6 literal with a port, operator input only.

## profiles/v1.sh (sourced at install.sh line 293, after the key is read)
- PROFILE_DESC (9). profile_exec (13 to 15): venv python room_api.py sandbox serve on
  127.0.0.1:$ROOM_API_PORT, runtime docker. profile_env (17 to 48): PYTHONPATH=src,
  CATHEDRAL_SANDBOX_RUNTIME=docker, CATHEDRAL_SANDBOX_QUOTA=$SIZE_QUOTA,
  CATHEDRAL_SANDBOX_REGION, CATHEDRAL_ALLOW_PRIVILEGED_DIND from ROOM_ALLOW_DIND (default 0,
  example and sealed set 1), CATHEDRAL_API_URL, CATHEDRAL_SANDBOX_OWNER=$ROOM_ID (the label the
  guard counts), PULL_POLICY=missing, GC_PARALLELISM, ROOM_CREATES_PER_MINUTE,
  CATHEDRAL_DIND_DOCKERD_ARGS, CATHEDRAL_DIND_ENV, CATHEDRAL_ROOM_EGRESS_SOCKET when egress
  is on, and the CATHEDRAL_ROOM_NETWORK_* set when ROOM_NETS is non empty (count, subnets
  comma joined, size, prefix $ROOM_ID-net, bridge prefix, DNS). profile_keys_env (51 to 53):
  CATHEDRAL_SANDBOX_KEYS=<key>:$ROOM_CUSTOMER:$SIZE_SLOTS.
- Trusts: SIZE_SLOTS and SIZE_QUOTA from step 8; ROOM_NETS resolved; the API honours
  these names (cathedral/sandbox_provider.py parse_sandbox_keys, sandbox_guest.py).
- Invariant: the API listens on loopback only and uses DOCKER_HOST, so every room is on the
  runsc daemon. The API passes no --runtime (CATHEDRAL_DOCKER_RUNTIME and
  CATHEDRAL_DIND_RUNTIME unset), so the daemon default runsc applies to normal and dind rooms.

## uninstall.sh, lines 1 to 69 (bash, root, set -uo pipefail, no -e by design)
- Flags --keep-runtime, --keep-data (9 to 10). Needs /etc/pool-room/room.env (12), sources it.
- Stops and disables, one at a time: receipts, reaper.timer, caddy, health, API, egress (19
  to 21). Removes every container on the room daemon (22 to 26). Disables the daemon (27;
  ExecStopPost runs room-net.sh down), runs room-net.sh down again (28), deletes the egress
  nft tables and /run/pool-room-egress (29 to 31), empties and removes the two containerd
  namespaces best effort (33 to 41), disables the data unit, unmounts, detaches loops,
  deletes the image only if the install created it (`file:` mark) and --keep-data is absent
  (42 to 48), removes the nine unit files, daemon-reload, reset-failed (49 to 53), reverts
  ufw or iptables rule, unmasks host docker and deletes poolroom only when marked (54 to
  57), unmounts leftovers under /run/pool-room, removes /var/lib/pool-room, the caddy state
  dirs, /run/pool-room (59 to 60), /opt/pool-room (gvisor kept with --keep-runtime), then
  /etc/pool-room (67).
- Not removed: /run/room-receipts (tmpfs), net.ipv4.ip_forward=1, apt packages (listed),
  data on a real device, the DNS record, /usr/sbin/policy-rc.d if a failed install left it.
- Trusts: install-state marks; room.env present. Side effects: everything above, host wide
  only for the marked items.

## make-dist.sh, lines 1 to 12 (bash, set -euo pipefail)
- `git archive --format=tar.gz --prefix=cathedral-<short>/ <short> pyproject.toml cathedral`
  into room-kit/dist (gitignored), prints CATHEDRAL_COMMIT, CATHEDRAL_TARBALL,
  CATHEDRAL_TARBALL_SHA256 (shasum -a 256, macOS friendly).
- Determinism: tar entries use git's fixed modes (0775 dirs, 0664 or 0775 files), uid 0,
  mtime = commit time, a pax header with the commit id; umask has no effect. The gzip layer
  is git's internal zlib stream since git 2.38 (external `gzip -cn` before), so the sha
  depends on the git and zlib build. Reproduced here: git 2.54 (Apple) gives
  033e8807a51f... for 6701dda, equal to versions.lock. .gitattributes has no export-ignore
  or export-subst, so content is the commit's.
- Callers: a human; the sealed build copies the kit dir including dist/ when present.

## versions.lock, lines 1 to 21 (shell, sourced as root by install.sh line 17)
- GVISOR_RELEASE (dir name), GVISOR_URL, GVISOR_SHA512 (fetch); UV_VERSION (cache name),
  UV_URL, UV_SHA256 (fetch); PYTHON_VERSION (uv python install and uv venv, minor only);
  CADDY_VERSION (cache name, unit Description), CADDY_URL, CADDY_SHA512 (fetch);
  CATHEDRAL_COMMIT (COMMIT file, receipts binding software.cathedral), CATHEDRAL_TARBALL
  (path under the kit dir), CATHEDRAL_TARBALL_SHA256 (line 164 check); PROBE_IMAGE (pull at
  line 284, health probe image; a tag, not a digest).
- Readers: install.sh only (the sealed README cites it). All three download pins verified
  against the live upstream files on 2026-10-23 (sha512, sha256, sha512 all OK).

## files/requirements.lock, lines 1 to 167
- cffi==2.1.1 (100 hashes), cryptography==50.0.2 (59 hashes), pycparser==3.11 (2 hashes).
  Enforced by `--require-hashes --only-binary :all:` at install.sh line 163. Wheels only, no
  sdist builds on the host. Produced from a `req.in` that is not in the repo.

## assess.py (read-only probe of the host; system python3 as root)
- sh (23 to 28): subprocess with timeout, returns rc and stdout; failures become 127.
- read (31 to 35): file text or "".
- meminfo (38 to 45): /proc/meminfo in bytes.
- cpu (48 to 56): model, os.cpu_count threads, a subset of flags.
- tee (59 to 68): kvm, sev_snp host and guest, tdx host and guest, hypervisor flag.
- mount_of (71 to 89): walks UP to the nearest existing path, findmnt of that path, xfs
  pquota and nodev flags, disk_usage of the probe path. For a not yet created or not yet
  mounted ROOM_DATA_DIR it describes the parent file system (probe_path says which).
- docker_workloads (92 to 128): per daemon running count, committed cpu and memory limits,
  unlimited counts, live memory from /sys/fs/cgroup/system.slice/docker-<id>*.scope (systemd
  cgroup driver assumed), runtimes.
- vms (131 to 152): qemu, firecracker, cloud-hypervisor processes; vcpus from -smp, memory
  from -m (M default, G), name; sealed_hotel when the name starts with sealed-.
- ports (155 to 164): ss -ltn, int(port) after rpartition.
- main (167 to 201): writes machine.json (indent, sorted) 0644.
- Trusts: /proc, docker CLI output JSON, ps and ss formats. Point in time; the quota it
  feeds is not updated when host workloads change later.

## size.py, main (37 to 109)
- Inputs: machine.json plus flags. threads, ram total, host docker commitments, VMs, sealed
  guest reserve, hugepages.
- used_cpu = docker cpu limits + unlimited containers (1 each) + VM vcpus - sealed vcpus.
  used_ram = docker memory limits + VM memory - sealed memory + hugepages
  (+ live memory of unlimited containers when any).
- cpu_pool = max((threads - reserve_threads - sealed_cpu) * cpu_overcommit - used_cpu, 0).
  ram_pool = max((ram * (1 - reserve_pct/100) - sealed_ram) * mem_overcommit - used_ram, 0).
  fs = root_fs when data_dir.mount == root_fs.mount else data_dir;
  disk_pool = max(fs.total * fill_pct/100 - fs.used, 0); with --room-disk-bytes,
  min(disk_pool, room_disk * 0.95).
- slots_by_resource: cpu floor(cpu_pool / vcpu), memory floor(ram_pool / (mem_gib GiB)),
  disk floor(disk_pool * disk_overcommit / (disk_gib GiB)), operator_cap, bridge_ips.
  slots = min; limiting = its key; quota = "slots:floor(slots*vcpu):floor(slots*mem_gib)"
  (CATHEDRAL_SANDBOX_QUOTA running:vcpu:memory_gib). Units: GiB = 2^30 throughout; df -B1 and
  truncate G are binary too.
- Wrong answers: too many slots means committed cpu quota and memory limits exceed the host
  (the kernel OOM killer picks a room sentry or the API); 0 slots stops the install at
  line 273. Example config uses overcommit 1.0; the sealed room.env sets CPU 16, memory 20,
  disk 1000 and fill 80, so there ROOM_MAX_SLOTS decides and the quota declares 1000 vCPU
  and 4000 GiB on a 96 vCPU, 384 GiB guest by choice.
- The disk leg is unstable (first run vs re-run), see hazards and probe_installer_sizing.py.

## room.env.example (66 lines)
- Every key the installer reads, with defaults: TLS on, receipts on at 127.0.0.1:18092,
  loop image 800 GiB at /var/lib/room-a-data.img, bridge pqbr0 10.213.0.1/22, port cap 1023,
  ROOM_NETS=auto from 10.214.0.0/16, 1000 per network, DNS 1.1.1.1 8.8.8.8, runsc flags
  systrap, overlay2=none, net-raw; dind on; shape 1 vCPU 4 GiB 10 GiB; reserves 12 percent
  RAM and 2 threads; fill 70 percent; overcommit 1.0; creates 100 per minute.
- Comment says ROOM_DATA_DEVICE "e.g. /dev/nvme2n1", a name that can renumber.

## .gitignore: `dist/`
- The pinned API tarball is not versioned; it travels beside the kit. A checkout without
  dist/ fails at install.sh line 164 (after gvisor, uv, python and the wheels are installed,
  before any unit is started).

## Hazards (trusted but not checked)

1. install.sh 158 and 178: tar as root with the archive's owner. uv, uvx and caddy end up
   uid 1001 (GitHub runner) on any host without a `runner` user. A local uid 1001 account
   can replace the TLS front and the tool the next install runs as root. runsc is 0:0 by
   luck of its archive.
2. install.sh 49 vs 280 and 489 to 493: the live-rooms guard is a point check minutes before
   the restarts; no broker drain is required or documented; a room placed in between is
   ended with no receipt (B21).
3. install.sh 89 vs 243: assess runs before the volume is mounted. First run with a device:
   sized by the root fs (0 slots or undersized). Re-runs with a loop image: sized by the
   sparse image, not by the disk it lives on.
4. install.sh 288: the key file is required on every re-run and is checked only after the
   daemon restart and the applied copy; README tells the operator to delete it.
5. install.sh 76 to 80: policy-rc.d removal has no trap; a failed apt leaves the host unable
   to start services from packages.
6. install.sh 278: `${ROOM_DAEMON_HASH_BEFORE// -/}` is never empty; the first-install
   skip it suggests does not exist (harmless double start).
7. install.sh 268 and 273: in auto mode the new plan is written to room.env before the 0-slot
   exit and before the daemon restart; a failure there leaves room.env ahead of the units
   (B35 window moved, not closed). Shrunk lists plus a failed run between 280 and 489 leave
   bridges beyond the new list with no room-net.sh guard; FORWARD policy decides for them.
8. install.sh 284: PROBE_IMAGE by mutable tag through the mirror; no digest.
9. Receipts unit as root, customer facing, no hardening; store on tmpfs and in memory,
   unbounded; API restart re-keys it through Requires= (twice per install).
10. API and health hardening is cosmetic: the poolroom docker socket plus the registered
    runc runtime is host root.
11. room-data.sh and step 2: kernel device names with a persistent WIPE=yes in room.env.
12. No lock file; two installers interleave.
13. daemon.json: no live-restore (any dockerd restart ends rooms), no cgroup-parent (rooms
    are siblings of the kit's units; with the systemd cgroup driver the API at weight 100
    competes with every room scope at weight 100; Nice has no effect across cgroups).
14. The resolved room.env is unescaped shell; health and egress parse it with a different
    grammar than bash does.
15. machine.json is a snapshot; host workloads started after the install are not charged.
16. `uv python install 3.12` floats the patch release with the uv pin; verified by uv, not
    by versions.lock.
