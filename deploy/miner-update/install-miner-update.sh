#!/usr/bin/env bash
# One-time bootstrap that enrols an installed miner into signed automatic
# updates. Every later change, including to the updater itself, arrives as a
# signed release. See docs/MINER_AUTO_UPDATE.md.
#
# It does not change the running miner, its env file, its hotkey or any
# validator-access material, and it does not enable the timer.
#
# Usage, as root on the miner host:
#   ./install-miner-update.sh \
#     --revision <40-hex commit> --keys-sha256 <64-hex> \
#     --product snp-miner|audit-miner --network <network> --netuid <netuid> \
#     --channel stable|canary --channel-url https://.../<product>/<channel>.json \
#     --miner-unit <the miner's systemd unit> [--minimum-sequence <n>]
#
# --network, --netuid and --miner-unit have no defaults. The keys digest comes
# from the release announcement, not from this repository.
set -euo pipefail

REPOSITORY="https://github.com/cathedralai/cathedral-sandbox.git"
PYTHON=/usr/bin/python3
REVISION=""
KEYS_SHA256=""
PASSTHROUGH=()

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --revision) REVISION="${2:-}"; shift 2 ;;
    --keys-sha256) KEYS_SHA256="${2:-}"; shift 2 ;;
    --product|--network|--netuid|--channel|--channel-url|--miner-unit|--minimum-sequence)
      [[ $# -ge 2 ]] || die "$1 needs a value"
      PASSTHROUGH+=("$1" "$2"); shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ ${EUID} -eq 0 ]] || die "run as root"
[[ "${REVISION}" =~ ^[0-9a-f]{40}$ ]] || die "--revision must be one 40-character commit"
[[ "${KEYS_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "--keys-sha256 must be the 64-hex digest of the trust root"
command -v git >/dev/null || die "git is required"
command -v docker >/dev/null || die "docker is required"
command -v systemctl >/dev/null || die "systemd is required"

# The updater runs on the distribution's Python and cryptography package, so
# nothing is fetched from a package index as root (review finding F17).
[[ -x "${PYTHON}" ]] || die "${PYTHON} is required"
"${PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || die "${PYTHON} must be Python 3.10 or newer"
"${PYTHON}" -c 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey' \
  || die "install the distribution's python3-cryptography package first"

WORK="$(mktemp -d)"
trap 'cd /; rm -rf "${WORK}"' EXIT
git clone --quiet --filter=blob:none "${REPOSITORY}" "${WORK}/src"
git -C "${WORK}/src" checkout --quiet "${REVISION}"
# Confirm the checkout is the commit that was asked for, so a compromised or
# lagging mirror cannot substitute code or keys.
actual="$(git -C "${WORK}/src" rev-parse HEAD)"
[[ "${actual}" == "${REVISION}" ]] || die "checkout resolved to ${actual}, not ${REVISION}"

# Run from the checkout: `python -m` puts the working directory first on sys.path.
cd "${WORK}/src"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 PYTHONSAFEPATH=1 PYTHONPATH="${WORK}/src" \
  "${PYTHON}" -s -B -m cathedral.miner_bootstrap install \
  --source "${WORK}/src" --keys-sha256 "${KEYS_SHA256}" "${PASSTHROUGH[@]}"

cat <<'NEXT'

Installed. The timer is NOT enabled yet, and the miner has not changed.

1. Read the trust-root fingerprints above against the release announcement.
2. Run one check by hand and read what it says:

     cathedral-miner-update check
     cathedral-miner-update status

   "current" or "activated" is success. "deferred" means the validator-access
   snapshot has too little validity left for a safe restart.
3. Turn on unattended updates:

     systemctl enable --now cathedral-miner-update.timer

Pause at any time with `cathedral-miner-update pause`, and hold one version
with `cathedral-miner-update pin --current`.
NEXT
