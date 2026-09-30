#!/usr/bin/env bash
# TEE box guest setup for the end-to-end harness. Run as root on the TD (run.sh
# ships it and runs it with sudo; see README.md).
#
#   setup.sh prepare   the test-box marker, packages, pinned runsc registered
#                      with docker (systrap), classic image store, tmpfs for the
#                      central state, no swap, the harness venv. Docker's data
#                      root is NOT moved yet, so the harness can show the storage
#                      refusal on plain ext4.
#   setup.sh luks      a LUKS2 integrity scratch device (aes-xts-plain64 +
#                      hmac-sha256, random key kept only in ramfs during setup),
#                      ext4 on it, docker's data root moved onto it, docker
#                      restarted, the test image pulled by digest.
#   setup.sh all       prepare, then luks.
#   setup.sh status    print what is in place.
#
# Every phase is idempotent: a second run keeps what is already correct (the
# tmpfs and its contents, an open scratch mapping, an installed runsc).
set -euo pipefail
umask 022

RUNSC_VERSION=20260817.0
RUNSC_SHA256=048b89aada69dc3333422e139d6e9d02f8ab06bda52398060e0fbdacca00074c
RUNSC_URL="https://storage.googleapis.com/gvisor/releases/release/${RUNSC_VERSION}/x86_64/runsc"
RUNSC_PATH=/usr/local/bin/runsc
DAEMON_JSON=${DAEMON_JSON:-/etc/docker/daemon.json}
STATE_DIR=${STATE_DIR:-/run/cathedral-tee-box}
SCRATCH_IMG=${SCRATCH_IMG:-/var/lib/cathedral-scratch.img}
SCRATCH_GIB=${SCRATCH_GIB:-2}
SCRATCH_NAME=${SCRATCH_NAME:-cathedral-scratch}
SCRATCH_MNT=${SCRATCH_MNT:-/var/lib/cathedral-scratch}
DOCKER_ROOT="$SCRATCH_MNT/docker"
IMAGE_REF=${IMAGE_REF:-docker.io/library/alpine}
IMAGE_DIGEST=${IMAGE_DIGEST:-sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc}
VENV=${VENV:-/opt/cathedral-e2e/venv}
# harness.py and serve_worker.py refuse to run without this marker. It sits on
# tmpfs, so it goes away at the next boot. Keep in step with serve_worker.py.
MARKER_DIR=/run/cathedral-tee-e2e
MARKER=$MARKER_DIR/TEST_BOX
# The LUKS key lives in a ramfs under here, only while the scratch is formatted.
KEY_PARENT=${KEY_PARENT:-/run}
# Global, not local: the EXIT trap reads it after the function has returned,
# and under set -u a local would be unbound there.
KEY_DIR=
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

log() { printf '[setup %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf '[setup] ERROR: %s\n' "$*" >&2; exit 1; }

wait_docker() {
  for _ in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  die "docker did not come back"
}

restart_docker() {
  log "restarting docker"
  systemctl restart docker
  wait_docker
}

# Merge keys into daemon.json with python (jq may be absent). Prints "changed"
# when the file changed.
merge_daemon_json() {
  local mode=$1
  mkdir -p "$(dirname "$DAEMON_JSON")"
  python3 - "$DAEMON_JSON" "$mode" "$RUNSC_PATH" "$DOCKER_ROOT" <<'PY'
import json, os, sys
path, mode, runsc, root = sys.argv[1:5]
try:
    with open(path) as handle:
        text = handle.read()
    current = json.loads(text) if text.strip() else {}
except FileNotFoundError:
    current = {}
wanted = json.loads(json.dumps(current))
runtimes = wanted.setdefault("runtimes", {})
runtimes["runsc"] = {"path": runsc, "runtimeArgs": ["--platform=systrap", "--network=sandbox"]}
wanted.setdefault("features", {})["containerd-snapshotter"] = False
if mode == "luks":
    wanted["data-root"] = root
if wanted != current:
    tmp = path + ".e2e-tmp"
    with open(tmp, "w") as handle:
        json.dump(wanted, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)
    print("changed")
PY
}

need_packages() {
  local missing=() pkg
  for pkg in "$@"; do
    dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    log "installing ${missing[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=600 update -qq
    apt-get -o DPkg::Lock::Timeout=600 install -y -qq "${missing[@]}" >/dev/null
  fi
}

check_tdx() {
  [ -e /dev/tdx_guest ] || die "/dev/tdx_guest is missing: not an Intel TDX guest"
  [ -e /sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384 ] \
    || die "the RTMR3 sysfs register is missing (needs Linux 6.16+)"
  if [ ! -d /sys/kernel/config/tsm/report ]; then
    mountpoint -q /sys/kernel/config || mount -t configfs configfs /sys/kernel/config || true
  fi
  [ -d /sys/kernel/config/tsm/report ] || die "configfs-tsm report root is missing"
  log "TDX guest: /dev/tdx_guest, RTMR3 sysfs and configfs-tsm present"
}

no_swap() {
  if [ "$(grep -vc '^Filename' /proc/swaps || true)" != 0 ]; then
    log "turning swap off"
    swapoff -a
  fi
  [ "$(grep -vc '^Filename' /proc/swaps || true)" = 0 ] || die "swap is still on"
  log "no swap"
}

install_runsc() {
  if [ -x "$RUNSC_PATH" ] && echo "$RUNSC_SHA256  $RUNSC_PATH" | sha256sum --check --status -; then
    log "runsc $RUNSC_VERSION already installed (sha256 ok)"
    return
  fi
  local tmp
  tmp=$(mktemp /tmp/runsc.XXXXXX)
  if [ -f "$HERE/bin/runsc" ]; then
    cp "$HERE/bin/runsc" "$tmp"
  else
    log "downloading runsc $RUNSC_VERSION"
    curl --fail --silent --show-error --location --proto '=https' --retry 3 -o "$tmp" "$RUNSC_URL"
  fi
  echo "$RUNSC_SHA256  $tmp" | sha256sum --check --status - \
    || { rm -f "$tmp"; die "runsc sha256 mismatch"; }
  install -o root -g root -m 0755 "$tmp" "$RUNSC_PATH"
  rm -f "$tmp"
  log "runsc installed at $RUNSC_PATH (sha256 $RUNSC_SHA256)"
}

state_tmpfs() {
  if mountpoint -q "$STATE_DIR"; then
    [ "$(findmnt -no FSTYPE "$STATE_DIR")" = tmpfs ] || die "$STATE_DIR is mounted but not tmpfs"
    log "central state tmpfs already mounted at $STATE_DIR (contents kept)"
  else
    mkdir -p "$STATE_DIR"
    mount -t tmpfs -o mode=0700,size=64m,nosuid,nodev tmpfs "$STATE_DIR"
    log "mounted tmpfs at $STATE_DIR"
  fi
  chmod 0700 "$STATE_DIR"
}

harness_venv() {
  if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import cryptography, sys; sys.exit(int(cryptography.__version__.split(".")[0]) < 42)' 2>/dev/null; then
    log "harness venv ready at $VENV"
    return
  fi
  mkdir -p "$(dirname "$VENV")"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q 'cryptography>=42'
  log "harness venv created at $VENV"
}

# The marker says: this TD is a disposable test box, set up by this script, in
# this boot. harness.py and serve_worker.py check it before they touch anything.
write_marker() {
  mkdir -p "$MARKER_DIR"
  chmod 0755 "$MARKER_DIR"
  [ "$(findmnt -no FSTYPE --target "$MARKER_DIR")" = tmpfs ] \
    || die "$MARKER_DIR is not on tmpfs; the test-box marker must vanish at reboot"
  printf 'cathedral TEE box e2e TEST BOX, disposable; boot_id %s\n' \
    "$(cat /proc/sys/kernel/random/boot_id)" > "$MARKER"
  chmod 0644 "$MARKER"
  log "test-box marker written at $MARKER (tmpfs; gone at the next boot)"
}

phase_prepare() {
  check_tdx
  write_marker
  need_packages python3-venv python3-pip cryptsetup-bin nftables iproute2 util-linux dmsetup e2fsprogs curl git
  command -v docker >/dev/null || die "docker is not installed"
  [ -x /usr/bin/docker ] || die "the worker expects the docker CLI at /usr/bin/docker"
  for tool in /usr/sbin/nft /usr/sbin/tc /usr/sbin/ip /usr/bin/nsenter /usr/sbin/dmsetup; do
    [ -x "$tool" ] || die "missing $tool"
  done
  no_swap
  install_runsc
  if [ "$(merge_daemon_json prepare)" = changed ]; then
    restart_docker
  else
    wait_docker
  fi
  docker info --format '{{json .Runtimes.runsc}}' | grep -q -- '--platform=systrap' \
    || die "docker did not register runsc with --platform=systrap"
  state_tmpfs
  harness_venv
  log "prepare done; docker root: $(docker info --format '{{.DockerRootDir}}')"
}

# Shred the key and unmount its ramfs. Runs from the EXIT trap too, so it only
# uses globals and never fails.
cleanup_key() {
  [ -n "$KEY_DIR" ] || return 0
  shred -u "$KEY_DIR/key" 2>/dev/null || rm -f "$KEY_DIR/key" 2>/dev/null
  if mountpoint -q "$KEY_DIR" 2>/dev/null; then umount "$KEY_DIR" 2>/dev/null; fi
  rmdir "$KEY_DIR" 2>/dev/null
  if [ -e "$KEY_DIR" ]; then
    printf '[setup] ERROR: could not remove the key directory %s; remove it by hand\n' "$KEY_DIR" >&2
  fi
  KEY_DIR=
  return 0
}

# format_and_open DEVICE NAME: LUKS2 with integrity under a random 64-byte key
# that exists only in a ramfs, then open it as /dev/mapper/NAME. The key is
# shredded and the ramfs unmounted whether this succeeds or fails.
format_and_open() {
  local device=$1 name=$2
  KEY_DIR=$(mktemp -d "$KEY_PARENT/cathedral-key.XXXXXX")
  trap cleanup_key EXIT
  trap 'exit 130' INT TERM HUP   # so the EXIT trap runs on a signal too
  mount -t ramfs -o mode=0700 ramfs "$KEY_DIR"   # never swapped
  head -c 64 /dev/urandom > "$KEY_DIR/key"
  log "luksFormat: LUKS2, aes-xts-plain64, 512-bit key, integrity hmac-sha256, pbkdf2 1000 iterations"
  cryptsetup luksFormat --batch-mode --type luks2 \
    --cipher aes-xts-plain64 --key-size 512 --integrity hmac-sha256 \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-file "$KEY_DIR/key" "$device"
  cryptsetup open --type luks2 --key-file "$KEY_DIR/key" "$device" "$name"
  cleanup_key
  trap - EXIT INT TERM HUP
}

phase_luks() {
  need_packages cryptsetup-bin e2fsprogs
  if mountpoint -q "$SCRATCH_MNT" && [ -e "/dev/mapper/$SCRATCH_NAME" ]; then
    log "scratch already open and mounted at $SCRATCH_MNT"
  else
    if [ -e "/dev/mapper/$SCRATCH_NAME" ]; then
      # Open but not mounted (an interrupted run). The key is gone; format again.
      log "closing a stale $SCRATCH_NAME mapping"
      umount "$SCRATCH_MNT" 2>/dev/null || true
      cryptsetup close "$SCRATCH_NAME"
    fi
    for loop in $(losetup -j "$SCRATCH_IMG" -O NAME -n 2>/dev/null); do losetup -d "$loop"; done
    rm -f "$SCRATCH_IMG"
    fallocate -l "${SCRATCH_GIB}G" "$SCRATCH_IMG"
    chmod 0600 "$SCRATCH_IMG"
    local loopdev started
    loopdev=$(losetup --find --show "$SCRATCH_IMG")
    log "backing file $SCRATCH_IMG (${SCRATCH_GIB} GiB) on $loopdev"
    started=$(date +%s)
    format_and_open "$loopdev" "$SCRATCH_NAME"
    log "luksFormat + open took $(( $(date +%s) - started )) s; key shredded, ramfs unmounted"
    mkfs.ext4 -q -F -L cathedral-scratch "/dev/mapper/$SCRATCH_NAME"
    mkdir -p "$SCRATCH_MNT"
    mount -o nodev "/dev/mapper/$SCRATCH_NAME" "$SCRATCH_MNT"
    log "ext4 mounted at $SCRATCH_MNT"
  fi
  mkdir -p "$DOCKER_ROOT"
  chmod 0710 "$DOCKER_ROOT"
  if [ "$(merge_daemon_json luks)" = changed ] || [ "$(docker info --format '{{.DockerRootDir}}')" != "$DOCKER_ROOT" ]; then
    restart_docker
  fi
  [ "$(docker info --format '{{.DockerRootDir}}')" = "$DOCKER_ROOT" ] \
    || die "docker did not move its data root to $DOCKER_ROOT"
  log "docker data root: $DOCKER_ROOT"
  local ok=
  for _ in 1 2 3; do
    if docker pull -q "$IMAGE_REF@$IMAGE_DIGEST" >/dev/null; then ok=1; break; fi
    sleep 5
  done
  [ -n "$ok" ] || die "could not pull $IMAGE_REF@$IMAGE_DIGEST"
  log "pulled $IMAGE_REF@$IMAGE_DIGEST"
  status_luks
}

status_luks() {
  local dev uuid
  dev=$(findmnt -no MAJ:MIN "$SCRATCH_MNT" 2>/dev/null | tr -d '[:space:]' || true)
  uuid=$(cat "/sys/dev/block/$dev/dm/uuid" 2>/dev/null || true)
  log "scratch device $dev dm uuid ${uuid:-?}"
  # Never print a key: mask the key field of every crypt segment.
  dmsetup table "$SCRATCH_NAME" 2>/dev/null | awk '{ if ($3 == "crypt") $5 = "<key>"; print "  table: " $0 }' || true
  cryptsetup status "$SCRATCH_NAME" 2>/dev/null | sed -n 's/^ *\(type\|cipher\|keysize\|integrity\|integrity keysize\|device\|sector size\):/  \1:/p' || true
}

phase_status() {
  echo "marker: $(cat "$MARKER" 2>/dev/null || echo "none at $MARKER")"
  echo "runsc: $(sha256sum "$RUNSC_PATH" 2>/dev/null | cut -d' ' -f1)"
  echo "docker root: $(docker info --format '{{.DockerRootDir}} {{.Driver}} {{json .DriverStatus}}' 2>/dev/null)"
  echo "docker runsc: $(docker info --format '{{json .Runtimes.runsc}}' 2>/dev/null)"
  echo "state tmpfs: $(findmnt -no FSTYPE,OPTIONS "$STATE_DIR" 2>/dev/null)"
  echo "swaps: $(grep -vc '^Filename' /proc/swaps || true)"
  status_luks
}

main() {
  [ "$(id -u)" = 0 ] || die "run as root (sudo)"
  case "${1:-all}" in
    prepare) phase_prepare ;;
    luks) phase_luks ;;
    all) phase_prepare; phase_luks ;;
    status) phase_status ;;
    *) die "usage: setup.sh prepare|luks|all|status" ;;
  esac
}

# Sourcing defines the functions only (for tests).
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
