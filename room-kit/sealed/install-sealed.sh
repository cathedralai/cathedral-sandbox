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
if [ "${SEALED_MINER:-0}" = 1 ]; then
  # Miner hotel: the host holds no hotel key; the control plane installs one in the guest.
  [ -n "${SEALED_HOTEL_KEY_INSTALL_SIGNERS:-}" ] || { echo "SEALED_MINER=1 needs SEALED_HOTEL_KEY_INSTALL_SIGNERS (the control plane install keys)" >&2; exit 1; }
else
  [ -r "$SEALED_API_KEY_FILE" ] || { echo "hotel key file $SEALED_API_KEY_FILE missing (the kit does not make keys)" >&2; exit 1; }
fi
# Dedicated machine: the owner's raw 32-byte Ed25519 public key (launch-guest.sh).
if [ -n "${SEALED_OWNER_PUBKEY_FILE:-}" ]; then
  [ "$(stat -c %s "$SEALED_OWNER_PUBKEY_FILE" 2>/dev/null)" = 32 ] || { echo "SEALED_OWNER_PUBKEY_FILE $SEALED_OWNER_PUBKEY_FILE must hold the 32 raw bytes of an Ed25519 public key" >&2; exit 1; }
fi
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
# Not every release ships the AmdSev build in the ovmf package. Check before
# the 10 to 20 minute guest build, not after it.
[ -f "$SEALED_OVMF" ] || { echo "no AmdSev firmware at $SEALED_OVMF after apt; install ovmf-amdsev or set SEALED_OVMF" >&2; exit 1; }

# ---------------------------------------------------------------- 3. build + expected measurement
PREV_IMG=$(readlink -f "$SEALED_DIR/images/current" 2>/dev/null || true)
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
# The host link rules are set by ExecStartPre only; a host firewall reload
# (ufw) removes them and every room loses the internet while health stays
# green. A timer checks them each minute and puts them back.
cat > /etc/systemd/system/${UNIT%.service}-net.service <<EOF
[Unit]
Description=Sealed hotel $SEALED_NAME host link check
ConditionPathExists=$SEALED_DIR/sealed.env
[Service]
Type=oneshot
ExecStart=$SEALED_DIR/host-net.sh check $SEALED_DIR/sealed.env
EOF
cat > /etc/systemd/system/${UNIT%.service}-net.timer <<EOF
[Unit]
Description=Sealed hotel $SEALED_NAME host link check (every minute)
[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF
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
systemctl enable -q --now "${UNIT%.service}-net.timer"

# ---------------------------------------------------------------- 5. start and check
# A restart ends every room in the guest (a new guest, a new measurement
# unless the build was skipped). Refuse while rooms are live.
refuse_sealed_restart_with_rooms() {
  systemctl is-active -q "$UNIT" || return 0
  [ "${SEALED_RESTART_WITH_ROOMS:-0}" = 1 ] && return 0
  if [ "${SEALED_MINER:-0}" = 1 ]; then
    # The host holds no hotel key, and the guest's plain HTTP port answers
    # nothing but the attestation, so the host cannot count rooms.
    echo "sealed: miner hotel: the host holds no hotel key, so live rooms cannot be counted; drain the hotel through the control plane, then set SEALED_RESTART_WITH_ROOMS=1" >&2
    exit 1
  fi
  local live
  live=$(curl -fsS -m 10 -H "Authorization: Bearer $(tr -d ' \r\n' < "$SEALED_API_KEY_FILE")" \
    "http://$SEALED_GUEST_IP:18090/v1/sandboxes" 2>/dev/null | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("sandboxes",[])))' 2>/dev/null || echo "?")
  if [ "$live" = "?" ]; then
    echo "sealed: the hotel API on $SEALED_GUEST_IP did not answer, so live rooms cannot be counted; set SEALED_RESTART_WITH_ROOMS=1 to go on" >&2
    exit 1
  fi
  if [ "$live" -gt 0 ]; then
    echo "sealed: $live live room(s); a restart ends them with no delete receipt. Wait, or set SEALED_RESTART_WITH_ROOMS=1." >&2
    exit 1
  fi
}
refuse_sealed_restart_with_rooms
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
if [ "$GOT" = "$EXPECTED" ]; then
  log "measurement matches the build: $GOT"
  # A dedicated machine's HOST_DATA names its owner: add it to the broker's sealed_host_data.
  log "$(python3 -c 'import json,sys;b=json.load(open(sys.argv[1]))["binding"];print("tenancy", b.get("tenancy"), "host_data", b["host_data"])' "$ATT")"
  # Boot the guest again at the next host start (an unattended reboot left
  # sealed guests off until a manual start). Only a verified image is enabled.
  systemctl enable -q "$UNIT"
else
  # Do not serve a guest the operator cannot vouch for, and do not boot it
  # again at the next host start. The previous image is current again.
  log "MEASUREMENT DIFFERS: report $GOT, build $EXPECTED"
  systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
  [ -n "$PREV_IMG" ] && [ "$PREV_IMG" != "$IMG" ] && ln -sfn "$PREV_IMG" "$SEALED_DIR/images/current"
  exit 1
fi
if [ "${SEALED_MINER:-0}" = 1 ]; then
  log "done. miner hotel: HTTPS https://$SEALED_GUEST_IP:${SEALED_MINER_TLS_PORT:-18443} (public port ${SEALED_MINER_PUBLIC_PORT:-9443}), tls_spki_sha256 $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binding"].get("tls_spki_sha256"))' "$ATT"), attestation $ATT"
else
  log "done. hotel API (receipts front) http://$SEALED_GUEST_IP:18090, attestation $ATT"
fi
