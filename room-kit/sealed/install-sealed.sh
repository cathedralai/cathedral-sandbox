#!/bin/bash
# Room kit, sealed mode: make this host run ONE sealed hotel (an AMD SEV-SNP
# guest with the room kit inside). Called as: install.sh --sealed sealed.env
#   1. assess: SEV-SNP on, free SNP ASIDs, free disk after the scratch disk
#   2. host packages: QEMU (SNP), OVMF AmdSev, mmdebstrap, zstd, cpio
#   3. build the measured guest (build-guest.sh) and compute the expected
#      launch measurement (sev-snp-measure, pinned, in a venv)
#   4. unit room-sealed-<name>.service: host link (host-net.sh) + QEMU
#   5. start, wait for the guest's attestation, save it, compare measurements
# The host Docker daemon and other guests are not touched.
set -euo pipefail
umask 022
KIT=$(cd "$(dirname "$0")/.." && pwd)
ENV_FILE=$(readlink -f "${1:?usage: install-sealed.sh sealed.env}")
# shellcheck disable=SC1090
source "$ENV_FILE"
log() { echo "[sealed] $*"; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
UNIT=room-sealed-$SEALED_NAME.service
SNP_MEASURE_VERSION=0.0.12

# ---------------------------------------------------------------- 1. assess
[ "$(cat /sys/module/kvm_amd/parameters/sev_snp 2>/dev/null)" = Y ] || { echo "SEV-SNP is not enabled in kvm_amd" >&2; exit 1; }
[ -c /dev/sev ] || { echo "/dev/sev missing" >&2; exit 1; }
[ -r "$SEALED_API_KEY_FILE" ] || { echo "hotel key file $SEALED_API_KEY_FILE missing (the kit does not make keys)" >&2; exit 1; }
mkdir -p "$SEALED_DIR/images" "$SEALED_DIR/run"
FREE_GIB=$(( $(df -B1 --output=avail "$SEALED_DIR" | tail -1) / 1073741824 ))
HAVE_GIB=0; [ -f "$SEALED_DIR/scratch.raw" ] && HAVE_GIB=$(( $(du -B1 "$SEALED_DIR/scratch.raw" | cut -f1) / 1073741824 ))
LEFT=$(( FREE_GIB - (SEALED_SCRATCH_GIB - HAVE_GIB) ))
log "free ${FREE_GIB} GiB; after a full ${SEALED_SCRATCH_GIB} GiB scratch: ${LEFT} GiB (minimum ${SEALED_MIN_HOST_FREE_GIB})"
[ "$LEFT" -ge "$SEALED_MIN_HOST_FREE_GIB" ] || { echo "not enough disk: lower SEALED_SCRATCH_GIB" >&2; exit 1; }
MEM_FREE_GIB=$(( $(awk '/MemAvailable/ {print $2}' /proc/meminfo) / 1048576 ))
systemctl is-active -q "$UNIT" || [ "$MEM_FREE_GIB" -gt $(( SEALED_MEM_GIB + 32 )) ] || { echo "only ${MEM_FREE_GIB} GiB RAM available" >&2; exit 1; }

# ---------------------------------------------------------------- 2. host packages
need=()
command -v qemu-system-x86_64 >/dev/null || need+=(qemu-system-x86)
[ -f "$SEALED_OVMF" ] || need+=(ovmf)
command -v mmdebstrap >/dev/null || need+=(mmdebstrap)
command -v zstd >/dev/null || need+=(zstd)
command -v cpio >/dev/null || need+=(cpio)
python3 -c 'import venv' 2>/dev/null && python3 -c 'import ensurepip' 2>/dev/null || need+=(python3-venv)
if [ ${#need[@]} -gt 0 ]; then
  log "apt install ${need[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${need[@]}"
fi
qemu-system-x86_64 -object help | grep -qx '  sev-snp-guest' || { echo "this QEMU has no sev-snp-guest" >&2; exit 1; }

# ---------------------------------------------------------------- 3. build + expected measurement
if [ "${SEALED_SKIP_BUILD:-0}" != 1 ] || [ ! -e "$SEALED_DIR/images/current" ]; then
  "$KIT/sealed/build-guest.sh" "$ENV_FILE"
fi
IMG=$(readlink -f "$SEALED_DIR/images/current")
[ -x "$SEALED_DIR/venv/bin/sev-snp-measure" ] || {
  python3 -m venv "$SEALED_DIR/venv"
  "$SEALED_DIR/venv/bin/pip" install -q "sev-snp-measure==$SNP_MEASURE_VERSION"
}
EXPECTED=$("$SEALED_DIR/venv/bin/sev-snp-measure" --mode snp --vcpus "$SEALED_VCPUS" --vcpu-type "$SEALED_CPU_MODEL" \
  --ovmf "$IMG/OVMF.amdsev.fd" --kernel "$IMG/vmlinuz" --initrd "$IMG/initrd.cpio.zst" --append "$(cat "$IMG/cmdline")")
echo "$EXPECTED" > "$IMG/expected-measurement"
log "expected measurement $EXPECTED"

# ---------------------------------------------------------------- 4. unit
install -m 0755 "$KIT/sealed/host-net.sh" "$KIT/sealed/launch-guest.sh" -t "$SEALED_DIR/"
# A rerun may pass the installed copy itself.
[ "$ENV_FILE" -ef "$SEALED_DIR/sealed.env" ] || install -m 0600 "$ENV_FILE" "$SEALED_DIR/sealed.env"
cat > /etc/systemd/system/$UNIT <<EOF
[Unit]
Description=Sealed hotel $SEALED_NAME (AMD SEV-SNP guest with the room kit)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStartPre=$SEALED_DIR/host-net.sh up $SEALED_DIR/sealed.env
ExecStart=$SEALED_DIR/launch-guest.sh $SEALED_DIR/sealed.env
ExecStopPost=$SEALED_DIR/host-net.sh down $SEALED_DIR/sealed.env
KillSignal=SIGTERM
TimeoutStopSec=60
Restart=no
LimitMEMLOCK=infinity
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# ---------------------------------------------------------------- 5. start and check
systemctl restart "$UNIT"
log "guest starting; serial log $SEALED_DIR/run/serial.log"
ATT=$SEALED_DIR/run/attestation.json
rm -f "$ATT"
for _ in $(seq 180); do
  if curl -fsS -m 5 -o "$ATT.part" "http://$SEALED_GUEST_IP:18090/room/attestation" 2>/dev/null; then mv "$ATT.part" "$ATT"; break; fi
  systemctl is-active -q "$UNIT" || { echo "guest stopped; see journalctl -u $UNIT and the serial log" >&2; exit 1; }
  sleep 5
done
[ -f "$ATT" ] || { echo "no attestation after 15 min; see the serial log" >&2; exit 1; }
GOT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binding"]["measurement"])' "$ATT")
cp "$ATT" "$IMG/attestation-$(date -u +%Y%m%dT%H%M%SZ).json"
if [ "$GOT" = "$EXPECTED" ]; then log "measurement matches the build: $GOT"; else log "MEASUREMENT DIFFERS: report $GOT, build $EXPECTED"; fi
log "done. hotel API (receipts front) http://$SEALED_GUEST_IP:18090, attestation $ATT"
