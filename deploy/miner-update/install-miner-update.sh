#!/usr/bin/env bash
# One-time bootstrap that enrols an already-installed SN39 SNP miner into
# signed automatic updates.
#
# This exists because the installed miner has no updater. Its version is a
# literal string in /etc/cathedral/sn39-snp-miner.env and nothing on the host
# ever changes it. So the first upgrade cannot be delivered remotely: an
# operator runs this once, and every later release arrives unattended.
#
# What it does NOT do, by design:
#   - it does not change the miner hotkey, endpoint, fleet file or any
#     validator-access material
#   - it does not change which image is pinned right now
#   - it does not grant Cathedral shell access to this host
#   - it does not enable the timer until you have seen one successful check
#
# Usage, as root inside the guest:
#   ./install-miner-update.sh --revision <40-char commit> --keys <keys.json>
set -euo pipefail

REVISION=""
KEYS_FILE=""
CHANNEL="stable"
CHANNEL_URL=""
PREFIX=/opt/cathedral-sn39-miner-update
REPOSITORY="https://github.com/cathedralai/cathedral-sandbox.git"

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --revision) REVISION="${2:-}"; shift 2 ;;
    --keys) KEYS_FILE="${2:-}"; shift 2 ;;
    --channel) CHANNEL="${2:-}"; shift 2 ;;
    --channel-url) CHANNEL_URL="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ "${REVISION}" =~ ^[0-9a-f]{40}$ ]] || die "--revision must be one 40-character commit"
[[ -f "${KEYS_FILE}" ]] || die "--keys must name the miner release public key file"
[[ "${CHANNEL}" == "stable" || "${CHANNEL}" == "canary" ]] || die "--channel must be stable or canary"
[[ -n "${CHANNEL_URL}" ]] || die "--channel-url is required"
[[ "${CHANNEL_URL}" == https://* ]] || die "--channel-url must be https"

# --- report what is installed now, before changing anything ----------------
echo "== current state =="
if [[ -f /etc/cathedral/sn39-snp-miner.env ]]; then
  # Print only the image pin. The same file holds the hotkey and the
  # validator-access digest, which are not ours to echo.
  grep -E '^SN39_SNP_MINER_IMAGE=' /etc/cathedral/sn39-snp-miner.env \
    || echo "SN39_SNP_MINER_IMAGE is not set"
else
  die "/etc/cathedral/sn39-snp-miner.env is missing; this host has no installed miner"
fi
systemctl is-active cathedral-sn39-snp-miner.service || true
systemctl is-enabled cathedral-sn39-snp-miner.service || true
if systemctl list-unit-files 'cathedral-sn39-miner-update*' --no-legend | grep -q .; then
  echo "note: an updater is already installed; this run will replace it in place"
fi

command -v git >/dev/null || die "git is required"
command -v docker >/dev/null || die "docker is required"
PYTHON="$(command -v python3.12 || command -v python3)" || die "python3 is required"

# --- install the updater at a pinned revision ------------------------------
echo "== installing updater at ${REVISION} =="
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
git clone --quiet --filter=blob:none "${REPOSITORY}" "${WORK}/src"
git -C "${WORK}/src" checkout --quiet "${REVISION}"
# Confirm we got the revision we asked for rather than whatever the remote
# resolved, so a compromised or lagging mirror cannot substitute code.
actual="$(git -C "${WORK}/src" rev-parse HEAD)"
[[ "${actual}" == "${REVISION}" ]] || die "checkout resolved to ${actual}, not ${REVISION}"

install -d -o root -g root -m 0755 "${PREFIX}"
rm -rf "${PREFIX}/src" "${PREFIX}/venv"
cp -a "${WORK}/src" "${PREFIX}/src"
"${PYTHON}" -m venv "${PREFIX}/venv"
"${PREFIX}/venv/bin/pip" install --quiet --disable-pip-version-check "cryptography>=42.0"

cat >/usr/local/sbin/cathedral-sn39-miner-update <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec env PYTHONPATH=${PREFIX}/src ${PREFIX}/venv/bin/python \\
  -m cathedral.miner_update_cli "\$@"
EOF
chmod 0755 /usr/local/sbin/cathedral-sn39-miner-update

# --- trust and configuration ----------------------------------------------
install -d -o root -g root -m 0755 /etc/cathedral
install -o root -g root -m 0644 "${KEYS_FILE}" /etc/cathedral/sn39-miner-update-keys.json
install -d -o root -g root -m 0700 /var/lib/cathedral-sn39-miner-update

cat >/etc/cathedral/sn39-miner-update.env <<EOF
CATHEDRAL_MINER_UPDATE_CHANNEL=${CHANNEL}
CATHEDRAL_MINER_UPDATE_URL=${CHANNEL_URL}
EOF
chmod 0644 /etc/cathedral/sn39-miner-update.env

install -o root -g root -m 0644 \
  "${PREFIX}/src/deploy/miner-update/cathedral-sn39-miner-update.service" \
  /etc/systemd/system/cathedral-sn39-miner-update.service
install -o root -g root -m 0644 \
  "${PREFIX}/src/deploy/miner-update/cathedral-sn39-miner-update.timer" \
  /etc/systemd/system/cathedral-sn39-miner-update.timer
systemctl daemon-reload

# --- verify without changing the miner -------------------------------------
echo "== installed. reporting status =="
/usr/local/sbin/cathedral-sn39-miner-update status

cat <<'NEXT'

The timer is deliberately NOT enabled yet.

Run one check by hand first and read what it says:

  cathedral-sn39-miner-update check \
    --channel "$(. /etc/cathedral/sn39-miner-update.env; echo "$CATHEDRAL_MINER_UPDATE_CHANNEL")" \
    --channel-url "$(. /etc/cathedral/sn39-miner-update.env; echo "$CATHEDRAL_MINER_UPDATE_URL")"

"current" means the pinned image already matches the release and nothing
happened. "activated" means it upgraded and the miner came back healthy.

Once you are happy, turn on unattended updates:

  systemctl enable --now cathedral-sn39-miner-update.timer

To pause updates at any time, without uninstalling anything:

  touch /etc/cathedral/sn39-snp-miner-update.paused

To resume:

  rm /etc/cathedral/sn39-snp-miner-update.paused
NEXT
