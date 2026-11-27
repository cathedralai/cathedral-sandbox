#!/bin/bash
# Synthetic mount handoff only. No SNP, verity or customer resources are used.
# Requires Linux root, unshare/mount/chroot, and Go 1.26 on PATH.
set -eu
if [ "${1:-}" = "--inside" ]; then
    shift
    if [ "$$" != 1 ]; then
        echo "Internal probe must run as PID1 in a new namespace." >&2
        exit 1
    fi
    base="$1/ram"
mount -t tmpfs -o nosuid,nodev,mode=0700,size=32m tmpfs "$base"
mkdir -p "$base"/{dev,proc,sys,newroot}
mount -t tmpfs -o nosuid,nodev,size=16m tmpfs "$base/newroot"
mkdir -p "$base/newroot"/{dev,proc,sys,run,sbin}
cp "$1/bootstate.test" "$base/init"
cp "$1/owner-init" "$base/newroot/sbin/init"
printf 'synthetic fixture\n' > "$base/old-root-only"
mount -t tmpfs -o nosuid,noexec,size=1m tmpfs "$base/dev"
mount -t tmpfs -o nosuid,nodev,noexec,size=1m tmpfs "$base/sys"
mount -t proc -o nosuid,nodev,noexec proc "$base/proc"
printf 'synthetic fixture\n' > "$base/dev/handoff-dev"
printf 'synthetic fixture\n' > "$base/sys/handoff-sys"
mount -o remount,ro,nosuid,nodev "$base/newroot"
mount -t tmpfs -o nosuid,nodev,noexec,size=1m tmpfs "$base/newroot/run"
printf 'synthetic fixture\n' > "$base/newroot/run/handoff-run"
export GUEST_RUNTIME_HANDOFF_PROBE=1
exec chroot "$base" /init -test.run '^TestRuntimeIsolatedHandoff$' -test.v

fi
if [ "$(id -u)" != 0 ]; then
    echo 'Run as root in a disposable test environment.' >&2
    exit 1
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d /tmp/guest-handoff-test.XXXXXXXX)
mkdir "$work/ram"
cd "$repo/room-kit/custom-guest"
CGO_ENABLED=0 go test -c -o "$work/bootstate.test" ./internal/bootstate
CGO_ENABLED=0 go build -o "$work/owner-init" ./testdata/handoff-init
unshare --mount --pid --fork --kill-child --propagation private bash "$repo/scripts/test_custom_guest_handoff.sh" --inside "$work"
printf 'Synthetic fixture build files retained at %s\n' "$work"
