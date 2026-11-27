#!/bin/bash
# Build the REHEARSAL-ONLY test image of the dedicated custom SNP guest (AB#1008,
# spec-r9 14.3 rehearsal B): a module-free initrd for the #776 reference kernel,
# a small verity root.raw, the cmdline and the expected launch measurements.
# Never offered to customers. It stands in for the Cathedral test image until the
# reference PID1 exists, so that a rehearsal can go through the real operator path:
# the intake validator accepts the reference kernel (IKCONFIG, drivers built in),
# while it refuses a distribution kernel that loads its drivers as modules.
#
# Usage: build.sh KERNEL_DIR OVMF OUT_DIR
#   KERNEL_DIR  output of scripts/build_custom_guest_kernel.sh (vmlinuz, kernel.config, SHA256SUMS)
#   OVMF        the host's OVMF.amdsev.fd (the sha256 below), the firmware the launch measures
#   OUT_DIR     a new or empty directory for the outputs
# Env: CG_WORK (work dir, kept), CG_OWNER_PUB (32 raw bytes, the owner's Ed25519 public key; required),
#      CG_VCPUS (default 4), CG_KIT_DIR (optional measurement positive control: a dir with a kit's
#      OVMF.amdsev.fd, vmlinuz, initrd.cpio.zst and cmdline) and CG_KIT_MEASUREMENT (its live value).
# Runs on any Docker host; the Go helpers come from this checkout's committed HEAD (git archive).
set -euo pipefail
KDIR=$(cd "${1:?KERNEL_DIR}" && pwd)
OVMF=$(cd "$(dirname "${2:?OVMF}")" && pwd)/$(basename "$2")
mkdir -p "${3:?OUT_DIR}"
OUT=$(cd "$3" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)

GO_IMAGE=golang:1.26.11-bookworm                  # #776 pins go1.26.11
ALPINE_IMAGE=alpine:3.22                          # linux/amd64 userland: busybox-static, OpenSSH
PY_IMAGE=python:3.12-slim
SNP_MEASURE=0.0.12                                # spec-r9 9; the operator's measure phase pins 0.0.12
OVMF_SHA256=ac27e626b097cf6f9eae09b79fc87fc2d3fb6e99c8d97b27f0603993c06a28bb  # edk2 2025.11 AmdSev build
VCPUS=${CG_VCPUS:-4}
CPU_MODEL=EPYC-v4
EPOCH=1795737600                                  # 2026-11-27T00:00:00Z: fixed mtimes
OWNER_PUB=${CG_OWNER_PUB:?CG_OWNER_PUB: the owner public key file (32 raw bytes)}
NOTE=rehearsal-test-image-v1

log() { echo "[rehearsal-build] $*"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
[ "$(sha "$OVMF")" = "$OVMF_SHA256" ] || { echo "$OVMF is not the pinned OVMF.amdsev.fd" >&2; exit 1; }
[ "$(wc -c < "$OWNER_PUB" | tr -d ' ')" = 32 ] || { echo "$OWNER_PUB must hold 32 raw bytes" >&2; exit 1; }
for f in vmlinuz kernel.config SHA256SUMS; do [ -f "$KDIR/$f" ] || { echo "$KDIR/$f missing" >&2; exit 1; }; done
[ "$(awk '/vmlinuz$/ {print $1}' "$KDIR/SHA256SUMS")" = "$(sha "$KDIR/vmlinuz")" ] || { echo "vmlinuz differs from its SHA256SUMS" >&2; exit 1; }
for o in IKCONFIG SEV_GUEST TSM_REPORTS FW_CFG_SYSFS VIRTIO_NET VIRTIO_BLK CONFIGFS_FS DEVTMPFS; do
  grep -qx "CONFIG_$o=y" "$KDIR/kernel.config" || { echo "kernel lacks built-in CONFIG_$o" >&2; exit 1; }
done
! grep -qx 'CONFIG_MODULES=y' "$KDIR/kernel.config" || { echo "the reference kernel must not load modules" >&2; exit 1; }
WORK=${CG_WORK:-$(mktemp -d)}
rm -rf "$WORK" && mkdir -p "$WORK/src" "$WORK/in" "$WORK/out"
log "work $WORK, source $(git -C "$REPO" rev-parse --short HEAD)"

# ---------------------------------------------------------------- 1. Go helpers (this checkout's #776 source)
# The bootcheck main is room-kit/custom-guest/testdata/smoke-bootcheck: outside ./..., built by path.
git -C "$REPO" archive HEAD room-kit/custom-guest tests/fixtures/custom_guest_v1.json | tar -x -C "$WORK/src"
log "go: test bootstrap, build cathedral-attest and cathedral-rehearsal-bootcheck"
docker run --rm -v "$WORK/src:/src" -w /src/room-kit/custom-guest "$GO_IMAGE" sh -euc '
  export GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS= GOPROXY=off GOSUMDB=off CGO_ENABLED=0
  go version
  go test ./internal/bootstrap/
  GOOS=linux GOARCH=amd64 go vet ./testdata/smoke-bootcheck/ ./cmd/cathedral-attest/
  b() { GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "/src/out/$1" "$2"; }
  b cathedral-attest ./cmd/cathedral-attest
  b cathedral-rehearsal-bootcheck ./testdata/smoke-bootcheck
  GOOS=linux GOARCH=amd64 go test -c -o /src/test/snp.test ./internal/snp/
  GOOS=linux GOARCH=amd64 go test -c -o /src/test/attest.test ./cmd/cathedral-attest/'
# The Go toolchain crashes under amd64 emulation on an arm64 Mac, so the test binaries
# are cross-compiled above and only they run as linux/amd64.
docker run --rm --platform linux/amd64 -v "$WORK/src:/src" -w /src/room-kit/custom-guest/internal/snp "$ALPINE_IMAGE" /src/test/snp.test
docker run --rm --platform linux/amd64 -v "$WORK/src:/src" -w /src/room-kit/custom-guest/cmd/cathedral-attest "$ALPINE_IMAGE" /src/test/attest.test

# ---------------------------------------------------------------- 2. initrd tree, pack, root.raw
cp "$HERE/init.sh" "$HERE/sshd_config" "$HERE/stage-initrd.sh" "$WORK/"
log "initrd tree, pack, verity root ($ALPINE_IMAGE linux/amd64)"
docker run --rm --platform linux/amd64 -e EPOCH="$EPOCH" -v "$WORK:/w" "$ALPINE_IMAGE" sh -euc '
  apk add -q --no-cache bash busybox-static openssh-server openssh-keygen cpio zstd cryptsetup coreutils findutils file
  exec bash /w/stage-initrd.sh'
ROOT_HASH=$(cat "$WORK/out/root.verity")
[[ "$ROOT_HASH" =~ ^[0-9a-f]{64}$ ]] || { echo "no verity root hash" >&2; exit 1; }
OWNER_B64URL=$(python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(open(sys.argv[1],"rb").read()).rstrip(b"=").decode())' "$OWNER_PUB")
CMDLINE="console=ttyS0 loglevel=7 panic=-1 systemd.import_credentials=no cathedral.owner=$OWNER_B64URL cathedral.root_verity=$ROOT_HASH cathedral.root_data_bytes=1048576 cathedral.note=$NOTE"
printf '%s' "$CMDLINE" > "$WORK/out/cmdline"

# ---------------------------------------------------------------- 3. expected measurements
cp "$OVMF" "$WORK/in/OVMF.amdsev.fd"
cp "$KDIR/vmlinuz" "$WORK/in/vmlinuz"
CONTROL=0
if [ -n "${CG_KIT_DIR:-}" ]; then
  mkdir -p "$WORK/kit" && cp "$CG_KIT_DIR/OVMF.amdsev.fd" "$CG_KIT_DIR/vmlinuz" "$CG_KIT_DIR/initrd.cpio.zst" "$WORK/kit/"
  cp "$CG_KIT_DIR/cmdline" "$WORK/kit/cmdline.kit"
  CONTROL=1
fi
log "sev-snp-measure $SNP_MEASURE (positive control: $CONTROL)"
docker run --rm -e SNP_MEASURE="$SNP_MEASURE" -e VCPUS="$VCPUS" -e CPU_MODEL="$CPU_MODEL" -e CONTROL="$CONTROL" \
  -e KIT_MEASUREMENT="${CG_KIT_MEASUREMENT:-}" -v "$WORK:/w" "$PY_IMAGE" bash -euo pipefail -c '
  python3 -m venv /tmp/v >/dev/null
  /tmp/v/bin/pip install -q --disable-pip-version-check "sev-snp-measure==$SNP_MEASURE"
  /tmp/v/bin/pip freeze > /w/out/measure-tool-versions.txt
  m() { /tmp/v/bin/sev-snp-measure --mode snp --vcpus "$1" --vcpu-type "$CPU_MODEL" --ovmf "$2" \
          --kernel "$3" --initrd "$4" --append "$(cat "$5")"; }
  if [ "$CONTROL" = 1 ]; then
    got=$(m 56 /w/kit/OVMF.amdsev.fd /w/kit/vmlinuz /w/kit/initrd.cpio.zst /w/kit/cmdline.kit)
    [ "$got" = "$KIT_MEASUREMENT" ] || { echo "positive control failed: $got" >&2; exit 1; }
    echo "positive control ok: the kit inputs at 56 vCPUs give $got, its live report value" > /w/out/measure-control.txt
  fi
  m "$VCPUS" /w/in/OVMF.amdsev.fd /w/in/vmlinuz /w/out/initrd.cpio.zst /w/out/cmdline > /w/out/expected-measurement
  m 56 /w/in/OVMF.amdsev.fd /w/in/vmlinuz /w/out/initrd.cpio.zst /w/out/cmdline > /w/out/expected-measurement-56'

for f in initrd.cpio.zst root.raw cmdline expected-measurement expected-measurement-56 apk-versions.txt \
         initrd-files.txt initrd-root-entry.txt file-types.txt sshd-check.txt measure-tool-versions.txt; do
  cp "$WORK/out/$f" "$OUT/"
done
[ "$CONTROL" = 0 ] || cp "$WORK/out/measure-control.txt" "$OUT/"
cp "$WORK/src/out/cathedral-attest" "$WORK/src/out/cathedral-rehearsal-bootcheck" "$KDIR/vmlinuz" "$KDIR/kernel.config" "$OUT/"
( cd "$OUT" && shasum -a 256 vmlinuz kernel.config initrd.cpio.zst root.raw cmdline cathedral-attest \
    cathedral-rehearsal-bootcheck > SHA256SUMS )
log "done: $OUT"
cat "$OUT/SHA256SUMS"
log "cmdline: $CMDLINE"
log "expected measurement ($VCPUS vCPUs, $CPU_MODEL): $(cat "$OUT/expected-measurement")"
