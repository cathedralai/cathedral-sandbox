#!/bin/bash
# Scratch tmpfs capacity only. No VM, host device or systemd instance is started.
# Requires Linux root, unshare/mount, and Go 1.26 on PATH.
set -eu
if [ "$(id -u)" != 0 ]; then
    echo 'Run as root in a disposable test environment.' >&2
    exit 1
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d /tmp/guest-runtime-test.XXXXXXXX)
cd "$repo/room-kit/custom-guest"
CGO_ENABLED=0 go test -c -o "$work/bootstate.test" ./internal/bootstate
GUEST_RUNTIME_MOUNT_TEST_DIR="$work" unshare --mount --propagation private \
    "$work/bootstate.test" -test.run '^TestRuntimeMountCapacity$' -test.v
printf 'Scratch test binary retained at %s\n' "$work"
