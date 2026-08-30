#!/usr/bin/env bash
# Retired GCP-specific UID124 bootstrap. Not a current mining instruction.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG HTTP_PROXY HTTPS_PROXY ALL_PROXY
unset http_proxy https_proxy all_proxy

readonly METADATA_BASE='http://metadata.google.internal/computeMetadata/v1/instance/attributes'
readonly POLLER_ATTRIBUTE='cathedral-sn39-poller'
readonly POLLER_DIGEST_ATTRIBUTE='cathedral-sn39-poller-digest'
readonly POLLER_PATH='/usr/local/libexec/cathedral-sn39-gcp-poller'
readonly SERVICE_PATH='/etc/systemd/system/cathedral-sn39-signed-fleet.service'

die() {
  printf 'refusing SN39 GCP guest bootstrap: %s\n' "$*" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || die 'bootstrap must run as root'
for command in curl docker flock install nft python3 sha256sum stat systemctl; do
  command -v "${command}" >/dev/null 2>&1 || die "required base-image command is missing: ${command}"
done

fetch_metadata() {
  local attribute=$1
  local output=$2
  curl \
    --fail \
    --silent \
    --show-error \
    --connect-timeout 2 \
    --max-time 8 \
    --noproxy '*' \
    --header 'Metadata-Flavor: Google' \
    --output "${output}" \
    "${METADATA_BASE}/${attribute}"
}

install -d -o root -g root -m 0700 /usr/local/libexec
install -d -o root -g root -m 0700 /etc/cathedral/validator-access
install -d -o root -g root -m 0700 /var/lib/cathedral/validator-access
install -d -o root -g root -m 0700 /run/cathedral-sn39

poller_candidate=$(mktemp /run/cathedral-sn39/poller.XXXXXX)
digest_candidate=$(mktemp /run/cathedral-sn39/poller-digest.XXXXXX)
service_candidate=$(mktemp /run/cathedral-sn39/service.XXXXXX)

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  for target in "${poller_candidate}" "${digest_candidate}" "${service_candidate}"; do
    if [[ -f "${target}" ]]; then unlink "${target}"; fi
  done
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

fetch_metadata "${POLLER_ATTRIBUTE}" "${poller_candidate}"
fetch_metadata "${POLLER_DIGEST_ATTRIBUTE}" "${digest_candidate}"

poller_digest=$(<"${digest_candidate}")
[[ "${poller_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || die 'poller metadata digest is not canonical'
actual_digest_line=$(sha256sum "${poller_candidate}")
actual_digest="sha256:${actual_digest_line%% *}"
[[ "${actual_digest}" == "${poller_digest}" ]] \
  || die 'poller bytes do not match their pinned digest'
IFS= read -r first_line <"${poller_candidate}"
[[ "${first_line}" == '#!/usr/bin/env python3' ]] \
  || die 'poller metadata is not the reviewed Python program'
python3 "${poller_candidate}" --print-policy >/dev/null \
  || die 'poller metadata does not pass its fixed policy self-check'
install -o root -g root -m 0700 "${poller_candidate}" "${POLLER_PATH}"

printf '%s\n' \
  '[Unit]' \
  'Description=Cathedral SN39 bounded signed-fleet metadata poller' \
  'After=docker.service network-online.target' \
  'Wants=docker.service network-online.target' \
  '' \
  '[Service]' \
  'Type=simple' \
  'User=root' \
  'Group=root' \
  'UMask=0077' \
  'ExecStart=/usr/local/libexec/cathedral-sn39-gcp-poller' \
  'Restart=on-failure' \
  'RestartSec=10s' \
  'TimeoutStartSec=8min' \
  'TimeoutStopSec=60s' \
  'KillMode=control-group' \
  'NoNewPrivileges=true' \
  'ProtectHome=true' \
  'PrivateTmp=true' \
  '' \
  '[Install]' \
  'WantedBy=multi-user.target' >"${service_candidate}"

install -o root -g root -m 0644 "${service_candidate}" "${SERVICE_PATH}"
systemctl daemon-reload
systemctl enable --now cathedral-sn39-signed-fleet.service
systemctl is-active --quiet cathedral-sn39-signed-fleet.service \
  || die 'signed-fleet poller service did not stay active'
