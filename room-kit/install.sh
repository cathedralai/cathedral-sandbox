#!/bin/bash
# Room kit installer. Run as root: ./install.sh room.env
# Steps: assess -> size -> deploy. Idempotent: run it again to apply changes.
# It never edits the host Docker daemon (/etc/docker/daemon.json) and never
# restarts it. The room runs its own dockerd (default runtime runsc) on its own
# socket, data root, containerd namespace and bridge.
set -euo pipefail
umask 022
KIT=$(cd "$(dirname "$0")" && pwd)
# Sealed hotel: build and boot one AMD SEV-SNP guest on this host. The guest
# then runs this same installer inside itself (see sealed/README.md).
if [ "${1:-}" = --sealed ]; then exec "$KIT/sealed/install-sealed.sh" "${2:?usage: install.sh --sealed sealed.env}"; fi
ENV_FILE=$(readlink -f "${1:?usage: install.sh room.env}")
# shellcheck disable=SC1090
source "$ENV_FILE"
# shellcheck disable=SC1091
source "$KIT/versions.lock"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
PROFILE_FILE="$KIT/profiles/${API_PROFILE}.sh"
[ -f "$PROFILE_FILE" ] || { echo "unknown API_PROFILE $API_PROFILE" >&2; exit 1; }
# The key is read at step 9. Checking it here keeps a re-run from rewriting
# config and restarting the room daemon before it fails on a missing file.
[ -r "${ROOM_API_KEY_FILE:-}" ] || { echo "ROOM_API_KEY_FILE (${ROOM_API_KEY_FILE:-unset}) must be a readable file; keep it for re-runs" >&2; exit 1; }
# ROOM_CUSTOMER names the key's project in CATHEDRAL_SANDBOX_KEYS (key:project:slots).
# Empty closed the API for its own key; a comma or colon minted a second key.
[[ "${ROOM_CUSTOMER:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "ROOM_CUSTOMER must be 1 to 64 of [A-Za-z0-9._-] (got '${ROOM_CUSTOMER:-}')" >&2; exit 1; }
# Miner hotel settings are checked here too, before anything on the host changes.
# shellcheck disable=SC1091
source "$KIT/lib/receipts_mode.sh"
receipts_miner_check

# ROOM_DESTDIR prefixes every host path the installer writes. It is empty on a
# hotel; the behaviour tests set it to a temporary directory and fake the host.
ROOM_ETC=${ROOM_DESTDIR:-}/etc/pool-room
ROOM_OPT=${ROOM_DESTDIR:-}/opt/pool-room
ROOM_RUN=${ROOM_DESTDIR:-}/run/pool-room
UNIT_DIR=${ROOM_DESTDIR:-}/etc/systemd/system
SOCK=$ROOM_RUN/docker.sock
STATE=$ROOM_ETC/install-state
mkdir -p "$ROOM_ETC" "$ROOM_OPT/cache" "$ROOM_OPT/bin"
log() { echo "[room-kit] $*"; }
mark() { grep -qxF "$1" "$STATE" 2>/dev/null || echo "$1" >> "$STATE"; }

# The API keeps sandboxes in memory. A restart forgets them and its first
# reconcile pass removes their containers, so an update during live rooms ends
# a customer's work. Stop before any restart unless the operator says so.
refuse_restart_with_rooms() {
  [ -S "$SOCK" ] || return 0
  [ "${ROOM_RESTART_WITH_ROOMS:-0}" = 1 ] && return 0
  local live
  live=$(docker -H "unix://$SOCK" ps -q --filter label=cathedral.sandbox.owner 2>/dev/null | wc -l | tr -d ' ') || {
    echo "room-kit: the room daemon on $SOCK does not answer, so live rooms cannot be counted." >&2
    echo "Fix the daemon, or set ROOM_RESTART_WITH_ROOMS=1 to go on." >&2
    exit 1
  }
  if [ "${live:-0}" -gt 0 ]; then
    echo "room-kit: $live live room(s); an update restarts the API and removes them." >&2
    echo "Wait until no room is open, or set ROOM_RESTART_WITH_ROOMS=1." >&2
    exit 1
  fi
}
refuse_restart_with_rooms

fetch() { # url sha-algo sha out
  local url=$1 algo=$2 sum=$3 out=$4
  if [ -f "$out" ] && echo "$sum  $out" | "${algo}sum" -c --quiet - 2>/dev/null; then return 0; fi
  curl -fsSL --retry 3 -o "$out.part" "$url"
  echo "$sum  $out.part" | "${algo}sum" -c --quiet - || { echo "checksum mismatch: $url" >&2; rm -f "$out.part"; exit 1; }
  mv "$out.part" "$out"
}

# ---------------------------------------------------------------- 0. host packages
need=()
command -v dockerd >/dev/null || need+=(docker.io)
command -v mkfs.xfs >/dev/null || need+=(xfsprogs)
command -v curl >/dev/null || need+=(curl)
command -v bzip2 >/dev/null || need+=(bzip2)
command -v iptables >/dev/null || need+=(iptables)
command -v nft >/dev/null || need+=(nftables)
command -v conntrack >/dev/null || need+=(conntrack)
if [ ${#need[@]} -gt 0 ]; then
  log "apt install ${need[*]}"
  # A fresh docker.io install starts the host Docker daemon. That daemon sets
  # the FORWARD policy to DROP, which can cut off VMs that already run here.
  # The room does not need it: block service starts during the install and
  # mask the host daemon units if this install added them.
  NEW_DOCKER=0; [[ " ${need[*]} " == *" docker.io "* ]] && NEW_DOCKER=1
  if [ $NEW_DOCKER = 1 ] && [ ! -e /usr/sbin/policy-rc.d ]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 0755 /usr/sbin/policy-rc.d; RM_POLICY=1
    trap 'rm -f /usr/sbin/policy-rc.d' EXIT  # a failed apt must not leave every later package start blocked
  fi
  DEBIAN_FRONTEND=noninteractive apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${need[@]}"
  [ "${RM_POLICY:-0}" = 1 ] && { rm -f /usr/sbin/policy-rc.d; trap - EXIT; }
  for p in "${need[@]}"; do mark "apt:$p"; done
  if [ $NEW_DOCKER = 1 ]; then
    systemctl mask docker.service docker.socket >/dev/null 2>&1 && mark "masked:docker"
  fi
fi
[ -S /run/containerd/containerd.sock ] || systemctl enable --now containerd

# ---------------------------------------------------------------- 1. assess (read-only)
python3 "$KIT/assess.py" --data-dir "$ROOM_DATA_DIR" --room-socket "$SOCK" --out "$ROOM_ETC/machine.json"
log "assess: $ROOM_ETC/machine.json"

# Resolved copy of the config (values only, no comments) for units and health.
ROOM_KEYS="ROOM_TLS ROOM_REGISTRY_MIRRORS ROOM_ID ROOM_HOSTNAME ROOM_ACME_EMAIL ROOM_CUSTOMER ROOM_REGION API_PROFILE ROOM_API_PORT ROOM_HEALTH_PORT ROOM_PUBLIC_PORT ROOM_DATA_DIR ROOM_DATA_DEVICE ROOM_DATA_IMG ROOM_DATA_SIZE_GB ROOM_BRIDGE ROOM_BRIDGE_CIDR ROOM_DNS ROOM_RUNSC_FLAGS ROOM_ALLOW_DIND ROOM_CREATES_PER_MINUTE ROOM_GC_PARALLELISM ROOM_DIND_DOCKERD_ARGS ROOM_DIND_ENV ROOM_BRIDGE_PORT_CAP ROOM_NETS ROOM_NETS_POOL ROOM_NET_SIZE ROOM_NET_BRIDGE_PREFIX SHAPE_VCPU SHAPE_MEM_GIB SHAPE_DISK_GIB RESERVE_RAM_PCT RESERVE_THREADS DISK_MAX_FILL_PCT CPU_OVERCOMMIT MEM_OVERCOMMIT DISK_OVERCOMMIT ROOM_MAX_SLOTS ROOM_RECEIPTS ROOM_RECEIPTS_LISTEN ROOM_HOTEL_NAME ROOM_EGRESS ROOM_WORKSPACES ROOM_SECRETS_PERSIST ROOM_ESCAPE ROOM_ESCAPE_ALLOW_PLAINTEXT"
write_room_env() {
  for k in $ROOM_KEYS; do printf '%s="%s"\n' "$k" "${!k:-}"; done > "$ROOM_ETC/room.env"
  chmod 0644 "$ROOM_ETC/room.env"
}
# Level 1 receipts default on. ROOM_RECEIPTS=0 is the off switch. A sealed
# guest sets ROOM_RECEIPTS and ROOM_RECEIPTS_LISTEN itself; those values stay.
# shellcheck disable=SC1091
source "$KIT/lib/receipts_mode.sh"
receipts_apply_defaults
# Unset ROOM_NETS is auto: one room network per ROOM_NET_SIZE rooms, from the
# host size in step 8. Until then the resolved file has no room networks.
# ROOM_NETS=auto is the same. none, off, or empty keeps the main bridge.
# shellcheck disable=SC1091
source "$KIT/lib/room_nets_mode.sh"
resolve_room_nets
if [ "$ROOM_NETS_AUTO" = 1 ] && [ -f "$ROOM_ETC/room.env.applied" ]; then
  # The running units read room.env. Until step 8 plans the new list, keep
  # the applied one, so a re-run that fails before step 8 leaves no live room
  # network without its egress rules.
  ROOM_NETS=$(sed -n 's/^ROOM_NETS="\(.*\)"$/\1/p' "$ROOM_ETC/room.env.applied")
  write_room_env
  ROOM_NETS=""
else
  write_room_env
fi

# ---------------------------------------------------------------- 2. data volume (xfs, prjquota, no nodev)
DATA_UNIT=$ROOM_ID-data.service
install -m 0755 "$KIT/lib/room-data.sh" "$ROOM_OPT/bin/room-data.sh"
if [ -n "${ROOM_DATA_DEVICE:-}" ]; then
  if [ "$(blkid -o value -s TYPE "$ROOM_DATA_DEVICE" 2>/dev/null || true)" != xfs ]; then
    [ "${ROOM_DATA_DEVICE_WIPE:-no}" = yes ] || { echo "$ROOM_DATA_DEVICE is not xfs; set ROOM_DATA_DEVICE_WIPE=yes to format it" >&2; exit 1; }
    mkfs.xfs -f -q "$ROOM_DATA_DEVICE"
  fi
elif [ ! -f "$ROOM_DATA_IMG" ]; then
  truncate -s "${ROOM_DATA_SIZE_GB}G" "$ROOM_DATA_IMG"
  mkfs.xfs -f -q "$ROOM_DATA_IMG"
  mark "file:$ROOM_DATA_IMG"
fi
cat > "$UNIT_DIR/$DATA_UNIT" <<EOF
[Unit]
Description=Pool room $ROOM_ID data volume (xfs prjquota)
Before=$ROOM_ID-docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ROOM_OPT/bin/room-data.sh up $ROOM_ETC/room.env
ExecStop=$ROOM_OPT/bin/room-data.sh down $ROOM_ETC/room.env
[Install]
WantedBy=multi-user.target
EOF
mark "unit:$DATA_UNIT"

# ---------------------------------------------------------------- 3. gVisor runsc (pinned, sha512)
fetch "$GVISOR_URL" sha512 "$GVISOR_SHA512" "$ROOM_OPT/cache/gvisor-$GVISOR_RELEASE.tar.bz2"
if [ ! -x "$ROOM_OPT/gvisor-$GVISOR_RELEASE/runsc" ]; then
  mkdir -p "$ROOM_OPT/gvisor-$GVISOR_RELEASE"
  tar --no-same-owner -xjf "$ROOM_OPT/cache/gvisor-$GVISOR_RELEASE.tar.bz2" -C "$ROOM_OPT/gvisor-$GVISOR_RELEASE"
fi
ln -sfn "gvisor-$GVISOR_RELEASE" "$ROOM_OPT/gvisor"
RUNSC=$ROOM_OPT/gvisor/runsc

# ---------------------------------------------------------------- 4. Python 3.12 + cathedral (pinned)
fetch "$UV_URL" sha256 "$UV_SHA256" "$ROOM_OPT/cache/uv-$UV_VERSION.tar.gz"
# --no-same-owner: these archives carry their builder's uid (1001). A host with
# a second user would own code that runs as root and the TLS front.
tar --no-same-owner -xzf "$ROOM_OPT/cache/uv-$UV_VERSION.tar.gz" -C "$ROOM_OPT/bin" --strip-components=1
export UV_PYTHON_INSTALL_DIR=$ROOM_OPT/python UV_CACHE_DIR=$ROOM_OPT/cache/uv UV_NO_CONFIG=1
"$ROOM_OPT/bin/uv" python install -q "$PYTHON_VERSION"
export UV_PYTHON_PREFERENCE=only-managed
[ -x "$ROOM_OPT/venv/bin/python" ] || "$ROOM_OPT/bin/uv" venv -q --python "$PYTHON_VERSION" "$ROOM_OPT/venv"
"$ROOM_OPT/bin/uv" pip install -q --python "$ROOM_OPT/venv/bin/python" --require-hashes --only-binary :all: -r "$KIT/files/requirements.lock"
echo "$CATHEDRAL_TARBALL_SHA256  $KIT/$CATHEDRAL_TARBALL" | sha256sum -c --quiet -
rm -rf "$ROOM_OPT/src.new" && mkdir -p "$ROOM_OPT/src.new"
tar --no-same-owner -xzf "$KIT/$CATHEDRAL_TARBALL" -C "$ROOM_OPT/src.new" --strip-components=1
rm -rf "$ROOM_OPT/src" && mv "$ROOM_OPT/src.new" "$ROOM_OPT/src"
echo "$CATHEDRAL_COMMIT" > "$ROOM_OPT/src/COMMIT"
install -m 0755 "$KIT/room_health.py" "$ROOM_OPT/bin/room_health.py"
install -m 0755 "$KIT/room_api.py" "$ROOM_OPT/bin/room_api.py"
install -m 0755 "$KIT/assess.py" "$ROOM_OPT/bin/assess.py"
install -m 0755 "$KIT/size.py" "$ROOM_OPT/bin/size.py"
install -m 0755 "$KIT/room_receipts.py" "$ROOM_OPT/bin/room_receipts.py"
install -m 0755 "$KIT/room_egress.py" "$ROOM_OPT/bin/room_egress.py"

# ---------------------------------------------------------------- 5. Caddy (pinned, sha512)
fetch "$CADDY_URL" sha512 "$CADDY_SHA512" "$ROOM_OPT/cache/caddy-$CADDY_VERSION.tar.gz"
tar --no-same-owner -xzf "$ROOM_OPT/cache/caddy-$CADDY_VERSION.tar.gz" -C "$ROOM_OPT/bin" caddy
chown -R root:root "$ROOM_OPT/bin" "$ROOM_OPT/src" "$ROOM_OPT/gvisor-$GVISOR_RELEASE"

# ---------------------------------------------------------------- 6. service user
id poolroom >/dev/null 2>&1 || { useradd --system --home-dir /var/lib/pool-room --shell /usr/sbin/nologin poolroom; mark "user:poolroom"; }

# ---------------------------------------------------------------- 7. room Docker daemon (runsc default)
# The firewall for room bridges comes from room-net.sh and the bridge settings;
# a change in any of them restarts the room daemon (room guests only).
# The bridge settings the room daemon runs with come from the applied env;
# the ones it must run with next come from room.env. The two hashes below
# decide the restart. ROOM_DAEMON_HAD_CONFIG is empty on a first install,
# where `enable --now` already starts the daemon with the new config.
net_settings_of() { grep -E '^(ROOM_BRIDGE|ROOM_BRIDGE_CIDR|ROOM_NETS|ROOM_NET_BRIDGE_PREFIX)=' "$1" 2>/dev/null || true; }
ROOM_DAEMON_HAD_CONFIG=$([ -f "$ROOM_ETC/daemon.json" ] && echo 1 || true)
ROOM_DAEMON_HASH_BEFORE=$({ cat "$ROOM_ETC/daemon.json" "$ROOM_OPT/bin/room-net.sh" 2>/dev/null; net_settings_of "$ROOM_ETC/room.env.applied"; } | sha256sum)
install -m 0755 "$KIT/lib/room-net.sh" "$ROOM_OPT/bin/room-net.sh"
DNS_JSON=$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1].split()))' "$ROOM_DNS")
MIRRORS_JSON=$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1].split()))' "${ROOM_REGISTRY_MIRRORS:-}")
# runsc plus the 16 per-room tunable variants (lib/tunable_runtimes.py). The
# default runtime stays runsc: a room without tunables starts as before.
RUNTIMES_JSON=$(python3 "$KIT/lib/tunable_runtimes.py" "$RUNSC" "$ROOM_RUNSC_FLAGS")
cat > "$ROOM_ETC/daemon.json" <<EOF
{
  "hosts": ["unix://$SOCK"],
  "group": "poolroom",
  "data-root": "$ROOM_DATA_DIR/docker",
  "exec-root": "$ROOM_RUN/exec",
  "pidfile": "$ROOM_RUN/docker.pid",
  "containerd": "/run/containerd/containerd.sock",
  "containerd-namespace": "pool-room-$ROOM_ID",
  "containerd-plugins-namespace": "pool-room-$ROOM_ID-plugins",
  "features": {"containerd-snapshotter": false},
  "storage-driver": "overlay2",
  "bridge": "$ROOM_BRIDGE",
  "iptables": false,
  "ip6tables": false,
  "ip-masq": false,
  "userland-proxy": false,
  "dns": $DNS_JSON,
  "registry-mirrors": $MIRRORS_JSON,
  "default-runtime": "runsc",
  "runtimes": $RUNTIMES_JSON,
  "log-driver": "json-file",
  "log-opts": {"max-size": "20m", "max-file": "2"}
}
EOF
cat > "$UNIT_DIR/$ROOM_ID-docker.service" <<EOF
[Unit]
Description=Pool room $ROOM_ID Docker daemon (runsc)
Requires=$DATA_UNIT
After=$DATA_UNIT containerd.service network-online.target
[Service]
Type=notify
RuntimeDirectory=pool-room
RuntimeDirectoryPreserve=yes
ExecStartPre=$ROOM_OPT/bin/room-net.sh up $ROOM_ETC/room.env
ExecStart=/usr/bin/dockerd --config-file $ROOM_ETC/daemon.json
ExecStopPost=$ROOM_OPT/bin/room-net.sh down $ROOM_ETC/room.env
ExecReload=/bin/kill -s HUP \$MAINPID
TimeoutStartSec=120
Restart=on-failure
LimitNOFILE=1048576
TasksMax=infinity
Delegate=yes
KillMode=process
# Each room is a scope next to this unit with the default weight (100). At
# 300 rooms the daemon got about 1/300 of the CPU in a create storm, and every
# create waits on it (#298). The rooms run in their own scopes, so this weight
# covers the daemon only.
CPUWeight=1000
[Install]
WantedBy=multi-user.target
EOF
mark "unit:$ROOM_ID-docker.service"

# ---------------------------------------------------------------- 8. size (after the volume exists)
systemctl daemon-reload
systemctl enable --now "$DATA_UNIT"
mountpoint -q "$ROOM_DATA_DIR" || { echo "data volume did not mount" >&2; exit 1; }
xfs_info "$ROOM_DATA_DIR" >/dev/null
grep -E " $ROOM_DATA_DIR " /proc/mounts | grep -q prjquota || { echo "prjquota missing on $ROOM_DATA_DIR" >&2; exit 1; }
mkdir -p "$ROOM_DATA_DIR/work" "$ROOM_DATA_DIR/docker"
chown poolroom:poolroom "$ROOM_DATA_DIR/work"
if [ "${ROOM_WORKSPACES:-0}" = 1 ]; then
  # On a re-run that turns workspaces on, the data unit is already active, so
  # enable --now did not run it again. Its "up" is idempotent: run it to make
  # the nosuid,nodev,noexec bind mount. The API owns the root.
  "$ROOM_OPT/bin/room-data.sh" up "$ROOM_ETC/room.env"
  mountpoint -q "$ROOM_DATA_DIR/workspaces" || { echo "workspaces mount missing" >&2; exit 1; }
  chown poolroom:poolroom "$ROOM_DATA_DIR/workspaces"
  chmod 0700 "$ROOM_DATA_DIR/workspaces"
fi
# Assess again now that the volume is mounted: the first pass saw the parent
# file system, and the disk leg of the sizing differed between a first
# install and a re-run.
python3 "$KIT/assess.py" --data-dir "$ROOM_DATA_DIR" --room-socket "$SOCK" --out "$ROOM_ETC/machine.json"
ROOM_DISK_BYTES=$(df -B1 --output=size "$ROOM_DATA_DIR" | tail -1)
size_room() { # size_room <bridge addresses (0 = no bridge limit)> <out>
  python3 "$KIT/size.py" "$ROOM_ETC/machine.json" --vcpu "$SHAPE_VCPU" --mem-gib "$SHAPE_MEM_GIB" --disk-gib "$SHAPE_DISK_GIB" \
    --cpu-overcommit "$CPU_OVERCOMMIT" --mem-overcommit "$MEM_OVERCOMMIT" --disk-overcommit "$DISK_OVERCOMMIT" \
    --reserve-ram-pct "$RESERVE_RAM_PCT" --reserve-threads "$RESERVE_THREADS" --disk-max-fill-pct "$DISK_MAX_FILL_PCT" \
    --room-disk-bytes "$ROOM_DISK_BYTES" --max-slots "${ROOM_MAX_SLOTS:-0}" --bridge-addresses "$1" --out "$2"
}
if [ "$ROOM_NETS_AUTO" = 1 ]; then
  # One room network for each ROOM_NET_SIZE rooms that CPU, memory and disk
  # allow, cut from ROOM_NETS_POOL. Skip CIDRs that other host networks use
  # (this room's own bridges do not count, so a second install keeps them).
  size_room 0 "$ROOM_ETC/size-unbridged.json"
  RAW_SLOTS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["slots"])' "$ROOM_ETC/size-unbridged.json")
  ROUTED=$(ip -o route show | awk -v main="$ROOM_BRIDGE" -v pre="${ROOM_NET_BRIDGE_PREFIX:-rmnet}" '
    { dev=""; for (i=1;i<NF;i++) if ($i=="dev") dev=$(i+1) }
    $1 ~ /\// && dev != main && dev !~ ("^" pre "[0-9]+$") { print $1 }')
  ROOM_NETS=$(python3 "$KIT/lib/net_plan.py" "$RAW_SLOTS" "${ROOM_BRIDGE_PORT_CAP:-1023}" "${ROOM_NET_SIZE:-1000}" \
    "${ROOM_NETS_POOL:-10.214.0.0/16}" "$ROOM_BRIDGE_CIDR" $ROUTED)
  log "room networks (auto, $RAW_SLOTS rooms by resources): ${ROOM_NETS:-none, the main bridge holds them}"
  write_room_env
fi
size_room "$(python3 "$KIT/lib/net_capacity.py" "$ROOM_BRIDGE_CIDR" "${ROOM_BRIDGE_PORT_CAP:-1023}" "${ROOM_NET_SIZE:-1000}" ${ROOM_NETS:-})" "$ROOM_ETC/size.json"
SIZE_SLOTS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["slots"])' "$ROOM_ETC/size.json")
SIZE_QUOTA=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["quota"])' "$ROOM_ETC/size.json")
[ "$SIZE_SLOTS" -gt 0 ] || { echo "size: 0 slots on this machine; see $ROOM_ETC/size.json" >&2; exit 1; }
log "size: $SIZE_SLOTS slots, quota $SIZE_QUOTA"

systemctl enable --now "$ROOM_ID-docker.service"
if [ "$({ cat "$ROOM_ETC/daemon.json" "$ROOM_OPT/bin/room-net.sh"; net_settings_of "$ROOM_ETC/room.env"; } | sha256sum)" != "$ROOM_DAEMON_HASH_BEFORE" ] && [ -n "$ROOM_DAEMON_HAD_CONFIG" ]; then
  log "room daemon config changed: restarting the room daemon (room guests only)"
  refuse_restart_with_rooms  # rooms may have started since the first check
  systemctl restart "$ROOM_ID-docker.service"
fi
# Applied only once the daemon runs with these settings: a refused restart
# above leaves room.env.applied at the old values, so the next run restarts.
cp "$ROOM_ETC/room.env" "$ROOM_ETC/room.env.applied"
for _ in $(seq 60); do docker -H "unix://$SOCK" info >/dev/null 2>&1 && break; sleep 1; done
[ "$(docker -H "unix://$SOCK" info --format '{{.DefaultRuntime}}')" = runsc ] || { echo "room daemon default runtime is not runsc" >&2; exit 1; }
docker -H "unix://$SOCK" pull -q "$PROBE_IMAGE" >/dev/null

# ---------------------------------------------------------------- 9. key (from a file; never printed)
{ XTRACE=$(set +o | grep xtrace); set +x; } 2>/dev/null
KEY=$(tr -d ' \r\n' < "$ROOM_API_KEY_FILE")
[[ "$KEY" =~ ^[A-Za-z0-9_-]{32,}$ ]] || { echo "key file must hold one key of 32+ chars [A-Za-z0-9_-]" >&2; exit 1; }
install -m 0640 -o root -g poolroom /dev/null "$ROOM_ETC/api.key"
printf '%s\n' "$KEY" > "$ROOM_ETC/api.key"
# shellcheck disable=SC1090
source "$PROFILE_FILE"
install -m 0600 -o root -g root /dev/null "$ROOM_ETC/secret.env"
profile_keys_env "$KEY" > "$ROOM_ETC/secret.env"
install -m 0600 -o root -g root /dev/null "$ROOM_ETC/reaper.headers"
printf 'Authorization: Bearer %s\n' "$KEY" > "$ROOM_ETC/reaper.headers"
unset KEY
eval "$XTRACE"

# ---------------------------------------------------------------- 10. API unit (profile)
{
  echo "DOCKER_HOST=unix://$SOCK"
  echo "HOME=/var/lib/pool-room"
  echo "TMPDIR=$ROOM_DATA_DIR/work"
  profile_env
} > "$ROOM_ETC/api.env"
cat > "$UNIT_DIR/$ROOM_ID.service" <<EOF
[Unit]
Description=Pool room $ROOM_ID API (profile $API_PROFILE)
Requires=$ROOM_ID-docker.service
After=$ROOM_ID-docker.service
[Service]
User=poolroom
Group=poolroom
StateDirectory=pool-room
EnvironmentFile=$ROOM_ETC/api.env
EnvironmentFile=$ROOM_ETC/secret.env
ExecStart=$(profile_exec)
Restart=on-failure
# The API is on every create path: keep it ahead of the rooms (#298).
CPUWeight=1000
# A stop removes every room's container and work directory; on a full hotel
# that takes minutes, and the default 90 s ended in SIGKILL mid-pass.
TimeoutStopSec=600
KillMode=mixed
LimitNOFILE=1048576
TasksMax=infinity
NoNewPrivileges=yes
ProtectSystem=full
PrivateTmp=yes
ReadWritePaths=$ROOM_DATA_DIR/work /var/lib/pool-room
[Install]
WantedBy=multi-user.target
EOF
mark "unit:$ROOM_ID.service"

cat > "$UNIT_DIR/$ROOM_ID-health.service" <<EOF
[Unit]
Description=Pool room $ROOM_ID health endpoint
After=$ROOM_ID-docker.service
[Service]
User=poolroom
Group=poolroom
Environment=ROOM_ETC=$ROOM_ETC ROOM_DOCKER_SOCK=$SOCK ROOM_HEALTH_PORT=$ROOM_HEALTH_PORT ROOM_PROBE_IMAGE=$PROBE_IMAGE HOME=/var/lib/pool-room
ExecStart=$ROOM_OPT/venv/bin/python $ROOM_OPT/bin/room_health.py
Restart=on-failure
# Health must answer when the rooms use every CPU.
Nice=-5
CPUWeight=1000
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
EOF
mark "unit:$ROOM_ID-health.service"

# The API collects past-TTL sandboxes only when it handles a list/get.
# This timer makes collection happen even when no client is calling.
cat > "$UNIT_DIR/$ROOM_ID-reaper.service" <<EOF
[Unit]
Description=Pool room $ROOM_ID TTL reaper tick
[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsS -o /dev/null -H @$ROOM_ETC/reaper.headers http://127.0.0.1:$ROOM_API_PORT/v1/sandboxes
EOF
cat > "$UNIT_DIR/$ROOM_ID-reaper.timer" <<EOF
[Unit]
Description=Pool room $ROOM_ID TTL reaper (every 60 s)
[Timer]
OnBootSec=120
OnUnitActiveSec=60
AccuracySec=5
[Install]
WantedBy=timers.target
EOF
mark "unit:$ROOM_ID-reaper.timer"; mark "unit:$ROOM_ID-reaper.service"

# Egress policy per room (ROOM_EGRESS=1, the default): room_egress.py runs as
# root outside the rooms. It owns the nftables rules per room, the hotel DNS
# resolver and the SNI/HTTP egress proxy. A room address with no policy has no
# egress, so it starts before the API and goes down with the room daemon.
if [ "${ROOM_EGRESS:-1}" = 1 ]; then
cat > "$UNIT_DIR/$ROOM_ID-egress.service" <<EOF
[Unit]
Description=Pool room $ROOM_ID egress policy (nftables per room, DNS, egress proxy)
Requires=$ROOM_ID-docker.service
After=$ROOM_ID-docker.service
Before=$ROOM_ID.service
PartOf=$ROOM_ID-docker.service
[Service]
Environment=ROOM_ENV=$ROOM_ETC/room.env ROOM_DOCKER_SOCK=$SOCK ROOM_EGRESS_SOCKET=/run/pool-room-egress/control.sock ROOM_EGRESS_GROUP=poolroom
ExecStart=$ROOM_OPT/venv/bin/python $ROOM_OPT/bin/room_egress.py
Restart=always
RestartSec=1
# Fenced rooms need DNS and the proxy: keep them ahead of the rooms.
Nice=-5
CPUWeight=1000
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
mark "unit:$ROOM_ID-egress.service"
fi

# Signed receipts (ROOM_RECEIPTS=1, the default). Level 1 is an Ed25519 hotel
# chain and does not read the SNP report. When the TSM provider is sev_guest
# the same unit keeps the sealed SNP binding. The listener proxies create,
# exec and delete to the API.
if [ "$ROOM_RECEIPTS" = 1 ]; then
cat > "$UNIT_DIR/$ROOM_ID-receipts.service" <<EOF
[Unit]
Description=Pool room $ROOM_ID signed receipts and attestation
Requires=$ROOM_ID.service
After=$ROOM_ID.service $ROOM_ID-health.service
[Service]
Environment=ROOM_RECEIPTS_LISTEN=$ROOM_RECEIPTS_LISTEN ROOM_HOTEL_NAME=$ROOM_HOTEL_NAME ROOM_API_PORT=$ROOM_API_PORT ROOM_HEALTH_PORT=$ROOM_HEALTH_PORT ROOM_DOCKER_SOCK=$SOCK ROOM_API_KEY_PATH=$ROOM_ETC/api.key ROOM_RECEIPTS_DIR=/run/room-receipts ROOM_ESCAPE=${ROOM_ESCAPE:-0} ROOM_ESCAPE_ALLOW_PLAINTEXT=${ROOM_ESCAPE_ALLOW_PLAINTEXT:-0}
EOF
if [ "${ROOM_MINER:-0}" = 1 ]; then
# Miner hotel: HTTPS on a key the front makes; api.key is the guest-internal key;
# the hotel key comes only through POST /room/hotel-key signed by one of these.
cat >> "$UNIT_DIR/$ROOM_ID-receipts.service" <<EOF
Environment=ROOM_MINER=1 ROOM_RECEIPTS_TLS_LISTEN=$ROOM_RECEIPTS_TLS_LISTEN
Environment="ROOM_HOTEL_KEY_INSTALL_SIGNERS=$ROOM_HOTEL_KEY_INSTALL_SIGNERS"
EOF
fi
cat >> "$UNIT_DIR/$ROOM_ID-receipts.service" <<EOF
ExecStart=$ROOM_OPT/venv/bin/python $ROOM_OPT/bin/room_receipts.py
Restart=on-failure
# The receipts front serves health and every room call: keep it ahead of the rooms.
Nice=-5
CPUWeight=1000
RestartSec=2
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
mark "unit:$ROOM_ID-receipts.service"
fi

# ---------------------------------------------------------------- 11. Caddy on 443 (TLS-ALPN only, no port 80)
# Receipts on: create, exec and delete go to the receipt proxy. /room/health
# stays on the health port. Receipts off: the API port, as before.
ROOM_API_UPSTREAM=$(receipts_api_upstream)
if [ "${ROOM_TLS:-on}" = on ]; then
CADDY_AFTER="network-online.target $ROOM_ID.service"
if [ "$ROOM_RECEIPTS" = 1 ]; then CADDY_AFTER="$CADDY_AFTER $ROOM_ID-receipts.service"; fi
cat > "$ROOM_ETC/Caddyfile" <<EOF
{
	auto_https disable_redirects
	admin off
	${ROOM_ACME_EMAIL:+email $ROOM_ACME_EMAIL}
}
https://$ROOM_HOSTNAME:$ROOM_PUBLIC_PORT {
	tls {
		issuer acme {
			disable_http_challenge
		}
	}
	handle /room/health {
		reverse_proxy 127.0.0.1:$ROOM_HEALTH_PORT
	}
	handle {
		reverse_proxy $ROOM_API_UPSTREAM {
			flush_interval -1
			transport http {
				read_timeout 15m
				write_timeout 15m
			}
		}
	}
}
EOF
cat > "$UNIT_DIR/$ROOM_ID-caddy.service" <<EOF
[Unit]
Description=Pool room $ROOM_ID TLS front (Caddy $CADDY_VERSION)
After=$CADDY_AFTER
[Service]
DynamicUser=yes
StateDirectory=pool-room-caddy
Environment=XDG_DATA_HOME=/var/lib/pool-room-caddy XDG_CONFIG_HOME=/var/lib/pool-room-caddy
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=$ROOM_OPT/bin/caddy run --config $ROOM_ETC/Caddyfile --adapter caddyfile
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$ROOM_ETC/Caddyfile"
mark "unit:$ROOM_ID-caddy.service"
fi

# ---------------------------------------------------------------- 12. host firewall (only if it blocks 443)
if [ "${ROOM_TLS:-on}" != on ]; then
  log "ROOM_TLS=off: no Caddy, no port $ROOM_PUBLIC_PORT; the API stays on 127.0.0.1 (front desk or SSH tunnel)"
  if [ "$ROOM_RECEIPTS" = 1 ]; then
    log "receipts: create, exec and delete through $ROOM_RECEIPTS_LISTEN (proxies to the API); /room/health stays on 127.0.0.1:$ROOM_HEALTH_PORT"
  fi
  if [ "${ROOM_MINER:-0}" = 1 ]; then
    log "miner hotel: HTTPS on $ROOM_RECEIPTS_TLS_LISTEN (attested key); $ROOM_RECEIPTS_LISTEN serves /room/attestation only; no hotel key until the control plane installs one"
  fi
elif command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "$ROOM_PUBLIC_PORT/tcp" comment "pool-room:$ROOM_ID" >/dev/null && mark "ufw:$ROOM_PUBLIC_PORT/tcp"
elif [ "$(iptables -S INPUT | head -1)" = "-P INPUT DROP" ] && ! iptables -C INPUT -p tcp --dport "$ROOM_PUBLIC_PORT" -j ACCEPT -m comment --comment "pool-room:$ROOM_ID" 2>/dev/null; then
  iptables -I INPUT -p tcp --dport "$ROOM_PUBLIC_PORT" -j ACCEPT -m comment --comment "pool-room:$ROOM_ID" && mark "iptables:$ROOM_PUBLIC_PORT"
fi

# ---------------------------------------------------------------- 13. start
refuse_restart_with_rooms  # the guard at the top is minutes old by now
systemctl daemon-reload
if [ "${ROOM_EGRESS:-1}" = 1 ]; then systemctl enable -q "$ROOM_ID-egress.service"; systemctl restart "$ROOM_ID-egress.service"; fi
systemctl enable -q "$ROOM_ID.service" "$ROOM_ID-health.service" "$ROOM_ID-reaper.timer"
systemctl restart "$ROOM_ID.service" "$ROOM_ID-health.service"
if [ "$ROOM_RECEIPTS" = 1 ]; then systemctl enable -q "$ROOM_ID-receipts.service"; systemctl restart "$ROOM_ID-receipts.service"; fi
if [ "${ROOM_TLS:-on}" = on ]; then systemctl enable -q "$ROOM_ID-caddy.service"; systemctl restart "$ROOM_ID-caddy.service"; fi
systemctl start "$ROOM_ID-reaper.timer"
# With the key: 200 means the API is up and the key store took this key. A
# bare 401 or 000 used to print "done" over a hotel that answered nobody.
API_CODE=000
for _ in $(seq 60); do
  # curl exits 7 while the API still starts; under set -e that ended the
  # install here instead of trying again (2026-10-23, every live hotel).
  API_CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "@$ROOM_ETC/reaper.headers" "http://127.0.0.1:$ROOM_API_PORT/v1/status" || true)
  [ "$API_CODE" = 200 ] && break; sleep 1
done
[ "$API_CODE" = 200 ] || { echo "API did not answer 200 on /v1/status with its own key (got $API_CODE); see journalctl -u $ROOM_ID.service" >&2; exit 1; }
log "API status: $API_CODE"
log "python: $("$ROOM_OPT/venv/bin/python" -V) runsc: $("$RUNSC" --version | head -1) caddy: $("$ROOM_OPT/bin/caddy" version | cut -d' ' -f1)"
log "done. health: curl -H 'Authorization: Bearer <key>' https://$ROOM_HOSTNAME/room/health"
