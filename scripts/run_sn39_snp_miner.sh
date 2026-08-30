#!/usr/bin/env bash
# Start the fixed SN39 AMD SEV-SNP signed-fleet worker under its reviewed host boundary.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG

readonly IMAGE_PATH='ghcr.io/cathedralai/cathedral-sn39-snp-miner'
readonly RUNTIME_CONTRACT='snp-signed-validator-fleet-v1'
readonly CONTAINER_NAME='cathedral-sn39-snp-miner'
readonly CONFIG_DIRECTORY='/etc/cathedral/validator-access'
readonly STATE_DIRECTORY='/var/lib/cathedral/validator-access'
readonly SEV_GUEST_DEVICE='/dev/sev-guest'
readonly NFT_FAMILY='inet'
readonly NFT_TABLE='cathedral_sn39_snp'
readonly STARTUP_LOCK='/run/cathedral-sn39-snp-startup.lock'

die() {
  printf 'refusing SN39 SNP startup: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die 'this fixed startup accepts no command arguments'
[[ ${EUID} -eq 0 ]] || die 'run as root so owner checks and nftables are authoritative'

for command in docker flock nft mktemp stat grep; do
  command -v "${command}" >/dev/null 2>&1 || die "required command is missing: ${command}"
done

exec 9>"${STARTUP_LOCK}"
flock --nonblock 9 || die 'another SN39 SNP startup owns the host contract'

nft_rules=''
edge_installed=0
container_started=0
docker_client_pid=''

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ ${container_started} -eq 1 ]]; then
    docker rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    if [[ -n "${docker_client_pid}" ]]; then
      kill "${docker_client_pid}" >/dev/null 2>&1 || true
      wait "${docker_client_pid}" >/dev/null 2>&1 || true
    else
      kill %% >/dev/null 2>&1 || true
      wait >/dev/null 2>&1 || true
    fi
    docker rm --force "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
  if [[ ${edge_installed} -eq 1 ]]; then
    nft delete table "${NFT_FAMILY}" "${NFT_TABLE}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${nft_rules}" ]]; then
    rm -f -- "${nft_rules}"
  fi
  flock --unlock 9 >/dev/null 2>&1 || true
  exec 9>&-
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

: "${SN39_SNP_MINER_IMAGE:?SN39_SNP_MINER_IMAGE is required}"
: "${CATHEDRAL_MINER_HOTKEY:?CATHEDRAL_MINER_HOTKEY is required}"
: "${CATHEDRAL_PUBLIC_ENDPOINT:?CATHEDRAL_PUBLIC_ENDPOINT is required}"
: "${CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST:?CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST is required}"

readonly IMAGE_PREFIX="${IMAGE_PATH}@sha256:"
[[ "${SN39_SNP_MINER_IMAGE}" == "${IMAGE_PREFIX}"* ]] \
  || die 'the image must use the canonical SNP repository'
image_digest="${SN39_SNP_MINER_IMAGE#"${IMAGE_PREFIX}"}"
[[ "${image_digest}" =~ ^[0-9a-f]{64}$ ]] \
  || die 'the image must use one immutable lowercase sha256 digest'
[[ "${CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die 'the validator-access public-key file needs an exact lowercase sha256 pin'

require_root_directory() {
  local path=$1
  [[ -d "${path}" && ! -L "${path}" ]] || die "required directory is missing or linked: ${path}"
  [[ "$(stat -c '%u:%g:%a:%F' -- "${path}")" == '0:0:700:directory' ]] \
    || die "directory must be a root-owned mode-0700 directory: ${path}"
}

require_root_file() {
  local path=$1
  local mode=$2
  [[ -f "${path}" && ! -L "${path}" ]] || die "required file is missing or linked: ${path}"
  [[ "$(stat -c '%u:%g:%a:%F' -- "${path}")" == "0:0:${mode}:regular file" ]] \
    || die "file must be a root-owned mode-${mode} regular file: ${path}"
}

require_root_directory "${CONFIG_DIRECTORY}"
require_root_file "${CONFIG_DIRECTORY}/validator-access.json" 644
require_root_file "${CONFIG_DIRECTORY}/snapshot-keys.json" 644
require_root_file "${CONFIG_DIRECTORY}/fleet.json" 644
require_root_directory "${STATE_DIRECTORY}"
if [[ -e "${STATE_DIRECTORY}/validator-access.sqlite" ]]; then
  require_root_file "${STATE_DIRECTORY}/validator-access.sqlite" 600
fi

[[ -c "${SEV_GUEST_DEVICE}" && ! -L "${SEV_GUEST_DEVICE}" ]] \
  || die 'the native /dev/sev-guest character device is unavailable'
[[ -r "${SEV_GUEST_DEVICE}" && -w "${SEV_GUEST_DEVICE}" ]] \
  || die 'the native /dev/sev-guest device is not readable and writable'

docker container inspect "${CONTAINER_NAME}" >/dev/null 2>&1 \
  && die "container name is already active: ${CONTAINER_NAME}"

docker pull --platform linux/amd64 "${SN39_SNP_MINER_IMAGE}"
repo_digests="$(
  docker image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    "${SN39_SNP_MINER_IMAGE}"
)"
grep -Fx -- "${SN39_SNP_MINER_IMAGE}" <<<"${repo_digests}" >/dev/null \
  || die 'the pulled image does not report the exact requested RepoDigest'
[[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${SN39_SNP_MINER_IMAGE}")" == 'linux/amd64' ]] \
  || die 'the pulled image is not linux/amd64'
[[ "$(docker image inspect --format '{{index .Config.Labels "org.cathedral.sn39.runtime-contract"}}' "${SN39_SNP_MINER_IMAGE}")" == "${RUNTIME_CONTRACT}" ]] \
  || die 'the pulled image does not declare the reviewed SNP runtime contract'

nft_rules="$(mktemp /run/cathedral-sn39-snp-nft.XXXXXX)"
if nft list table "${NFT_FAMILY}" "${NFT_TABLE}" >/dev/null 2>&1; then
  printf 'delete table %s %s\n' "${NFT_FAMILY}" "${NFT_TABLE}" >"${nft_rules}"
else
  : >"${nft_rules}"
fi

printf '%s\n' \
  'table inet cathedral_sn39_snp {' \
  '  counter tcp_8081_accept { }' \
  '  counter tcp_8081_drop { }' \
  '  chain input {' \
  '    type filter hook input priority -5; policy accept;' \
  '    meta nfproto ipv6 tcp dport 8081 counter name tcp_8081_drop drop' \
  '    meta nfproto ipv4 tcp dport 8081 ct state invalid counter name tcp_8081_drop drop' \
  '    meta nfproto ipv4 tcp dport 8081 ct state new tcp flags & (fin|syn|rst|ack) != syn counter name tcp_8081_drop drop' \
  '    meta nfproto ipv4 tcp dport 8081 ct state new tcp flags & (fin|syn|rst|ack) == syn meter new_syn_rate { ip saddr timeout 1m limit rate over 4/second burst 8 packets } counter name tcp_8081_drop drop' \
  '    meta nfproto ipv4 tcp dport 8081 ct state new meter concurrent_connections { ip saddr ct count over 2 } counter name tcp_8081_drop drop' \
  '    meta nfproto ipv4 tcp dport 8081 ct state new tcp flags & (fin|syn|rst|ack) == syn counter name tcp_8081_accept accept' \
  '    meta nfproto ipv4 tcp dport 8081 ct state established,related counter name tcp_8081_accept accept' \
  '    meta nfproto ipv4 tcp dport 8081 counter name tcp_8081_drop drop' \
  '  }' \
  '}' >>"${nft_rules}"

nft --check --file "${nft_rules}" \
  || die 'the exact Cathedral SNP nftables transaction did not pass syntax and state checks'
edge_installed=1
nft --file "${nft_rules}" \
  || die 'the exact Cathedral SNP nftables transaction did not load atomically'
nft list table "${NFT_FAMILY}" "${NFT_TABLE}" >/dev/null 2>&1 \
  || die 'the dedicated Cathedral SNP nftables table is not readable after installation'

container_started=1
docker run --rm \
  --name "${CONTAINER_NAME}" \
  --init \
  --pull never \
  --network host \
  --read-only \
  --tmpfs /run/cathedral-snp-miner:rw,noexec,nosuid,nodev,mode=0700,size=16m \
  --mount "type=bind,src=${CONFIG_DIRECTORY},dst=/etc/cathedral/validator-access,readonly" \
  --mount "type=bind,src=${STATE_DIRECTORY},dst=/var/lib/cathedral/validator-access" \
  --device "${SEV_GUEST_DEVICE}:${SEV_GUEST_DEVICE}:rwm" \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 128 \
  --memory 1g \
  --memory-swap 1g \
  --ulimit nofile=1024:1024 \
  --stop-timeout 15 \
  --env "CATHEDRAL_MINER_HOTKEY=${CATHEDRAL_MINER_HOTKEY}" \
  --env "CATHEDRAL_PUBLIC_ENDPOINT=${CATHEDRAL_PUBLIC_ENDPOINT}" \
  --env "CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST=${CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST}" \
  "${SN39_SNP_MINER_IMAGE}" &
docker_client_pid=$!

wait "${docker_client_pid}"
