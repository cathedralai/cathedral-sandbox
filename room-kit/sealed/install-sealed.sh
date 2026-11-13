#!/bin/bash
# Room kit, sealed mode: make this host run ONE sealed hotel (an AMD SEV-SNP
# guest with the room kit inside). Called as: install.sh --sealed sealed.env
#   1. assess: SEV-SNP on, free SNP ASIDs, free disk after the scratch and data disks
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
# shellcheck disable=SC1091
source "$KIT/sealed/guest-constants.sh"
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
DATA_GIB=${SEALED_DATA_GIB:-0}
HAVE_DATA_GIB=0; [ -f "$SEALED_DIR/data.raw" ] && HAVE_DATA_GIB=$(( $(du -B1 "$SEALED_DIR/data.raw" | cut -f1) / 1073741824 ))
LEFT=$(( FREE_GIB - (SEALED_SCRATCH_GIB - HAVE_GIB) - (DATA_GIB - HAVE_DATA_GIB) ))
log "free ${FREE_GIB} GiB; after a full ${SEALED_SCRATCH_GIB} GiB scratch and ${DATA_GIB} GiB data disk: ${LEFT} GiB (minimum ${SEALED_MIN_HOST_FREE_GIB})"
[ "$LEFT" -ge "$SEALED_MIN_HOST_FREE_GIB" ] || { echo "not enough disk: lower SEALED_SCRATCH_GIB or SEALED_DATA_GIB" >&2; exit 1; }
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
# The roll guard reads the data volume's owner token on the host (data_volume_owner_id).
{ [ "${SEALED_DATA_GIB:-0}" = 0 ] || command -v cryptsetup >/dev/null; } || need+=(cryptsetup-bin)
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
install -m 0644 "$KIT/sealed/guest-constants.sh" -t "$SEALED_DIR/"
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
# The data volume's key is bound to the build's launch identity (measurement,
# policy and HOST_DATA), so a new build cannot open the volume an older build
# made. Decide ownership from the launch identity recorded in the volume's own
# LUKS token, not a side file, and never drop or strand workspaces without the
# operator saying which (docs/SEALED_DATA_VOLUME.md).
SEALED_DATA_POLICY=0x30000   # must match the policy in launch-guest.sh
DATA_RESET=0
DATA_ROLL_OK=0
data_volume_restore_on_exit() {
  # A reset roll is reversible until the new build's measurement checks: stop the
  # guest, discard the fresh empty volume, and put the owner's volume back.
  if [ "$DATA_RESET" = 1 ] && [ "$DATA_ROLL_OK" = 0 ] && [ -f "$SEALED_DIR/data.raw.prev" ]; then
    systemctl stop "$UNIT" 2>/dev/null || true
    rm -f "$SEALED_DIR/data.raw"
    mv -f "$SEALED_DIR/data.raw.prev" "$SEALED_DIR/data.raw"
    log "data volume: roll not confirmed; restored the owner's volume from data.raw.prev"
  fi
}
trap data_volume_restore_on_exit EXIT
data_volume_launch_id() { # launch id of the build we are about to start: <host_data hex>
  python3 -c 'import hashlib,sys; print(hashlib.sha256((":".join(sys.argv[1:4])).encode()).hexdigest())' \
    "$EXPECTED" "$SEALED_DATA_POLICY" "$1"
}
data_volume_owner_id() { # the launch id in data.raw's token, or empty
  cryptsetup token export --token-id 0 "$SEALED_DIR/data.raw" 2>/dev/null | python3 -c 'import json,sys
try:
    t=json.load(sys.stdin)
    print(t.get("slots",{}).get("0",{}).get("launch_id","") if t.get("type")=="cathedral-sealed-data" else "")
except Exception:
    print("")' 2>/dev/null || true
}
data_volume_new_build() {
  { [ "${SEALED_DATA_GIB:-0}" != 0 ] && [ -f "$SEALED_DIR/data.raw" ]; } || return 0
  local new_hd_b64 new_hd_hex new_id owner_id choice
  # Without the binary the owner id would read as empty, which looks like another build's volume and
  # offers a reset that sets a readable customer volume aside. Stop before any choice instead.
  command -v cryptsetup >/dev/null || {
    echo "sealed: cryptsetup is not installed on this host, so the owner token of $SEALED_DIR/data.raw cannot be read. Nothing was changed and no reset or keep choice is asked. Install it (apt-get install cryptsetup-bin) and re-run." >&2
    exit 1
  }
  new_hd_b64=$(LAUNCH_PRINT_HOST_DATA=1 "$SEALED_DIR/launch-guest.sh" "$SEALED_DIR/sealed.env") \
    || { echo "sealed: could not compute the new build's HOST_DATA (launch-guest.sh)" >&2; exit 1; }
  new_hd_hex=$(python3 -c 'import base64,sys;print(base64.b64decode(sys.argv[1]).hex())' "$new_hd_b64")
  new_id=$(data_volume_launch_id "$new_hd_hex")
  owner_id=$(data_volume_owner_id)
  [ -n "$owner_id" ] && [ "$owner_id" = "$new_id" ] && return 0   # same launch identity: the new build opens it
  choice=""
  [ -f "$SEALED_DIR/data-on-new-build" ] && choice=$(tr -d ' \r\n' < "$SEALED_DIR/data-on-new-build")
  case "$choice" in
    reset)
      if [ -f "$SEALED_DIR/data.raw.prev" ] && [ "${SEALED_DATA_OVERWRITE_PREV:-0}" != 1 ]; then
        echo "sealed: data.raw.prev already exists from an earlier reset roll. Save or remove it, or set SEALED_DATA_OVERWRITE_PREV=1 to overwrite it." >&2
        exit 1
      fi
      rm -f "$SEALED_DIR/data-on-new-build"
      mv -f "$SEALED_DIR/data.raw" "$SEALED_DIR/data.raw.prev"
      DATA_RESET=1
      log "data volume: new launch identity; the owner's volume is now data.raw.prev (only that build opens it); the new build starts empty. data.raw.prev is restored if this roll is not confirmed."
      ;;
    keep)
      rm -f "$SEALED_DIR/data-on-new-build"
      log "data volume: new launch identity; data.raw kept, the new build cannot open it, so workspaces stay on the scratch disk (state locked in health) until a reset or a rekey"
      ;;
    *)
      echo "sealed: the new build cannot open the data volume its current owner made (launch identity ${owner_id:-unknown} vs $new_id): its workspaces would not come back." >&2
      echo "sealed: write the choice to $SEALED_DIR/data-on-new-build (one line), then re-run: reset (set the owner's volume aside as data.raw.prev and start empty) or keep (leave it; workspaces on the scratch disk until a reset or a rekey). The file is consumed by the run that uses it." >&2
      exit 1
      ;;
  esac
}
refuse_sealed_restart_with_rooms
data_volume_new_build
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
  # The roll is confirmed: keep the new (empty) data volume and leave the owner's
  # volume as data.raw.prev for the operator to remove once the new build is good.
  DATA_ROLL_OK=1
  [ "$DATA_RESET" = 1 ] && log "data volume: reset confirmed; the previous owner's volume is kept at $SEALED_DIR/data.raw.prev (remove it when the new build is vouched for)"
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
  # The EXIT trap restores the owner's data volume from data.raw.prev (it also
  # covers the early exits above, which the old manual restore here did not).
  exit 1
fi
if [ "${SEALED_MINER:-0}" = 1 ]; then
  log "done. miner hotel: HTTPS https://$SEALED_GUEST_IP:${SEALED_MINER_TLS_PORT:-18443} (public port ${SEALED_MINER_PUBLIC_PORT:-9443}), tls_spki_sha256 $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["binding"].get("tls_spki_sha256"))' "$ATT"), attestation $ATT"
else
  log "done. hotel API (receipts front) http://$SEALED_GUEST_IP:18090, attestation $ATT"
fi
