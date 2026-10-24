#!/usr/bin/env bash
# #1469 step 9 stub: run the customer guest beside the SN94 SNP miner.
#
# Shape mirrors scripts/run_sn94_snp_miner.sh (no free args; env pins; refuse inventing).
# This script NEVER builds QEMU argv or image digests. It only re-invokes an
# owner-reviewed Contabo/INBOX (or later published) start script whose path+sha256
# are pinned in the environment.
#
# Dry-run by default. Live execute requires CATHEDRAL_SEEDBOX_LIVE_OK=yes AND
# CATHEDRAL_CUSTOMER_GUEST_EXECUTE=yes (Fred Contabo greenlight).

set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'

readonly STARTUP_LOCK='/run/cathedral-snp-customer-guest-startup.lock'

die() {
  printf 'refusing customer-guest beside miner: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die 'this fixed startup accepts no command arguments'
[[ ${EUID} -eq 0 ]] || die 'run as root so ownership checks are authoritative'

for command in flock sha256sum stat; do
  command -v "${command}" >/dev/null 2>&1 || die "required command is missing: ${command}"
done

exec 9>"${STARTUP_LOCK}"
flock --nonblock 9 || die 'another customer-guest startup owns the host contract'

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  flock --unlock 9 >/dev/null 2>&1 || true
  exec 9>&-
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

: "${CATHEDRAL_MINER_HOTKEY:?CATHEDRAL_MINER_HOTKEY is required}"
: "${CATHEDRAL_CUSTOMER_HTTPS_ENDPOINT:?CATHEDRAL_CUSTOMER_HTTPS_ENDPOINT is required (IP:8444)}"
: "${CATHEDRAL_CUSTOMER_START_SCRIPT:?CATHEDRAL_CUSTOMER_START_SCRIPT is required (absolute path)}"
: "${CATHEDRAL_CUSTOMER_START_SCRIPT_SHA256:?CATHEDRAL_CUSTOMER_START_SCRIPT_SHA256 is required (64 hex)}"
: "${CATHEDRAL_CUSTOMER_RUN_DIR:?CATHEDRAL_CUSTOMER_RUN_DIR is required (owner-only empty or current run)}"

# Optional until Fred publishes — required only when set.
if [[ -n "${CATHEDRAL_CUSTOMER_IMAGE:-}" ]]; then
  [[ "${CATHEDRAL_CUSTOMER_IMAGE}" == *'@sha256:'* ]] \
    || die 'CATHEDRAL_CUSTOMER_IMAGE must be repo@sha256:<64-hex> when set'
  image_digest="${CATHEDRAL_CUSTOMER_IMAGE##*@sha256:}"
  [[ "${image_digest}" =~ ^[0-9a-f]{64}$ ]] \
    || die 'CATHEDRAL_CUSTOMER_IMAGE digest must be 64 lowercase hex'
fi

[[ "${CATHEDRAL_CUSTOMER_START_SCRIPT_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
  || die 'CATHEDRAL_CUSTOMER_START_SCRIPT_SHA256 must be 64 lowercase hex'

[[ "${CATHEDRAL_CUSTOMER_START_SCRIPT}" == /* ]] \
  || die 'CATHEDRAL_CUSTOMER_START_SCRIPT must be absolute'
[[ -f "${CATHEDRAL_CUSTOMER_START_SCRIPT}" && ! -L "${CATHEDRAL_CUSTOMER_START_SCRIPT}" ]] \
  || die 'start script must be a regular non-symlink file'
got_sha="$(sha256sum -- "${CATHEDRAL_CUSTOMER_START_SCRIPT}" | awk '{print $1}')"
[[ "${got_sha}" == "${CATHEDRAL_CUSTOMER_START_SCRIPT_SHA256}" ]] \
  || die "start script sha256 mismatch got=${got_sha} want=${CATHEDRAL_CUSTOMER_START_SCRIPT_SHA256}"

[[ "${CATHEDRAL_CUSTOMER_RUN_DIR}" == /* ]] \
  || die 'CATHEDRAL_CUSTOMER_RUN_DIR must be absolute'
[[ -d "${CATHEDRAL_CUSTOMER_RUN_DIR}" && ! -L "${CATHEDRAL_CUSTOMER_RUN_DIR}" ]] \
  || die 'CATHEDRAL_CUSTOMER_RUN_DIR must be a non-symlink directory'
[[ "$(stat -c '%u:%a' -- "${CATHEDRAL_CUSTOMER_RUN_DIR}")" == "$(id -u):700" ]] \
  || die 'CATHEDRAL_CUSTOMER_RUN_DIR must be mode 0700 owned by current uid'

# Endpoint shape: IPv4:8444 (customer admission / identity).
[[ "${CATHEDRAL_CUSTOMER_HTTPS_ENDPOINT}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:8444$ ]] \
  || die 'CATHEDRAL_CUSTOMER_HTTPS_ENDPOINT must be IPv4:8444'

printf 'customer-guest beside miner — preflight OK\n'
printf '  miner_hotkey=%s\n' "${CATHEDRAL_MINER_HOTKEY}"
printf '  customer_endpoint=%s\n' "${CATHEDRAL_CUSTOMER_HTTPS_ENDPOINT}"
printf '  start_script=%s\n' "${CATHEDRAL_CUSTOMER_START_SCRIPT}"
printf '  start_script_sha256=%s\n' "${got_sha}"
printf '  run_dir=%s\n' "${CATHEDRAL_CUSTOMER_RUN_DIR}"
if [[ -n "${CATHEDRAL_CUSTOMER_IMAGE:-}" ]]; then
  printf '  customer_image=%s\n' "${CATHEDRAL_CUSTOMER_IMAGE}"
else
  printf '  customer_image=(unset — fill when Fred publishes digest)\n'
fi

if [[ "${CATHEDRAL_SEEDBOX_LIVE_OK:-}" != "yes" || "${CATHEDRAL_CUSTOMER_GUEST_EXECUTE:-}" != "yes" ]]; then
  printf 'dry-run only. Set CATHEDRAL_SEEDBOX_LIVE_OK=yes and CATHEDRAL_CUSTOMER_GUEST_EXECUTE=yes after Fred Contabo go.\n'
  printf 'This stub will not invent QEMU; it will exec the pinned start script only when both gates are set.\n'
  exit 0
fi

export CATHEDRAL_CUSTOMER_RUN_DIR
export CATHEDRAL_MINER_HOTKEY
export CATHEDRAL_CUSTOMER_HTTPS_ENDPOINT
if [[ -n "${CATHEDRAL_CUSTOMER_IMAGE:-}" ]]; then
  export CATHEDRAL_CUSTOMER_IMAGE
fi

# Identity hotkey for the customer guest must equal the miner hotkey (join key).
export CATHEDRAL_CUSTOMER_IDENTITY_HOTKEY="${CATHEDRAL_MINER_HOTKEY}"

exec "${CATHEDRAL_CUSTOMER_START_SCRIPT}"
