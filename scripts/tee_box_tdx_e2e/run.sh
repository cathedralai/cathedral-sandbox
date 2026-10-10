#!/usr/bin/env bash
# Single entry point for the TEE box end-to-end run on a TDX guest.
# See README.md in this directory. Run it against a FRESH TD: a second run in
# the same boot skips the "RTMR3 reads zero" checks.
#
#   SSH_KEY=~/.ssh/key HOST=user@203.0.113.7 ./run.sh        # everything
#   SSH_KEY=... HOST=... ./run.sh preflight|ship|setup|harness|tests|collect|summary
#
# Steps of "all": ship the code (sandbox + validator trees, the harness, the
# pinned TDX verifier), setup.sh prepare, start the test venvs in the
# background, harness pre-luks (storage refusal on plain ext4), setup.sh luks,
# harness main (checks a-g), run_tests.sh run, collect everything into
# $E2E_OUT/results/<host>-<time>/ and write RESULTS.txt there.
#
# Optional environment:
#   SSH_PORT (22), SSH_USER (when HOST has no user@)
#   E2E_OUT         local output directory (default: out/ next to this script)
#   SANDBOX_REPO    cathedral-sandbox checkout (default: the one holding this script)
#   VALIDATOR_REPO  cathedral-validator checkout (default: ../cathedral-validator
#                   next to SANDBOX_REPO)
#   SANDBOX_REF, VALIDATOR_REF   what to ship (default: origin/main of each)
#   NO_FETCH=1      do not "git fetch" before archiving the refs
#   TDX_VERIFIER    a local copy of the pinned verifier (still sha256-checked);
#                   otherwise it is downloaded once from its GitHub release
#   BASELINE_DIR    *.fails from a local run_tests.sh of the same commits
#                   (default: $E2E_OUT/baseline, used when it exists)
#   IMAGE_REF, IMAGE_DIGEST      the test image (pulled by digest)
#   SKIP_TESTS=1    skip the two test suites
# Every remote step runs detached (nohup) and is polled, so a dropped SSH
# connection does not kill it; rerun the same step to resume polling.
set -euo pipefail
umask 022
T=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${SSH_KEY:?set SSH_KEY to the private key for the box}"
: "${HOST:?set HOST to user@address of the box}"
SSH_PORT=${SSH_PORT:-22}
if [[ "$HOST" != *@* && -n "${SSH_USER:-}" ]]; then HOST="$SSH_USER@$HOST"; fi
IMAGE_REF=${IMAGE_REF:-docker.io/library/alpine}
IMAGE_DIGEST=${IMAGE_DIGEST:-sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc}
OUT=${E2E_OUT:-$T/out}
SANDBOX_REPO=${SANDBOX_REPO:-$(git -C "$T" rev-parse --show-toplevel)}
VALIDATOR_REPO=${VALIDATOR_REPO:-$SANDBOX_REPO/../cathedral-validator}
SANDBOX_REF=${SANDBOX_REF:-origin/main}
VALIDATOR_REF=${VALIDATOR_REF:-origin/main}
BASELINE_DIR=${BASELINE_DIR:-$OUT/baseline}
# The pinned strict verifier (docs/TDX_VERIFIER_RELEASE.md). Never committed:
# fetched from its release and checked against this sha256.
VERIFIER_TAG=cathedral-tdx-verifier-v1.0.0
VERIFIER_ASSET=cathedral-tdx-verifier-linux-amd64
VERIFIER_SHA256=4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148
VERIFIER_URL="https://github.com/cathedralai/cathedral-sandbox/releases/download/$VERIFIER_TAG/$VERIFIER_ASSET"
RD=tdx_e2e                       # remote directory, relative to the remote home
HVENV=/opt/cathedral-e2e/venv     # the harness venv setup.sh creates
mkdir -p "$OUT"
SSH_OPTS=(-i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=20
          -o ServerAliveInterval=20 -o ServerAliveCountMax=6
          -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$OUT/known_hosts")
SCP_OPTS=(-i "$SSH_KEY" -P "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=20
          -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$OUT/known_hosts")
STAMP_FILE="$OUT/last_run"

log() { printf '[run %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
# The remote commands are built locally on purpose.
# shellcheck disable=SC2029
rsh() { ssh "${SSH_OPTS[@]}" "$HOST" "$@"; }

# remote_step NAME 'command' [timeout_s]: run detached on the box, stream its
# log, return its exit status. Re-running the same NAME while it is still
# running only resumes polling.
remote_step() {
  local name=$1 cmd=$2 limit=${3:-3600}
  local started shown=0 rc=
  started=$(date +%s)
  rsh "cd ~/$RD && mkdir -p results && if [ -f results/$name.pid ] && kill -0 \$(cat results/$name.pid) 2>/dev/null; then echo resume; else rm -f results/$name.rc; nohup bash -c '( $cmd ); echo \$? > results/$name.rc' > results/$name.log 2>&1 < /dev/null & echo \$! > results/$name.pid; fi" >/dev/null
  log "step $name started on the box"
  while :; do
    local out
    if out=$(rsh "cd ~/$RD && tail -n +$((shown + 1)) results/$name.log; echo; echo \"@@RC \$(cat results/$name.rc 2>/dev/null)\"" 2>/dev/null); then
      local body
      body=$(printf '%s' "${out%@@RC*}")
      rc=${out##*@@RC }; rc=${rc//[[:space:]]/}
      if [ -n "$body" ]; then
        printf '%s\n' "$body" | sed "s/^/  [$name] /"
        shown=$((shown + $(printf '%s\n' "$body" | wc -l)))
      fi
      [ -n "$rc" ] && break
    else
      log "ssh poll failed; retrying"
    fi
    if [ $(( $(date +%s) - started )) -gt "$limit" ]; then log "step $name timed out locally"; return 124; fi
    sleep 5
  done
  log "step $name finished: exit $rc ($(( $(date +%s) - started )) s)"
  return "$rc"
}

# The pinned verifier at $OUT/cache/, downloaded once, sha256-checked every time.
fetch_verifier() {
  local dest="$OUT/cache/cathedral-tdx-verifier"
  mkdir -p "$OUT/cache"
  if [ -n "${TDX_VERIFIER:-}" ]; then
    cp "$TDX_VERIFIER" "$dest.tmp" && mv "$dest.tmp" "$dest"
  elif ! echo "$VERIFIER_SHA256  $dest" | sha256sum --check --status - 2>/dev/null; then
    log "downloading $VERIFIER_ASSET from release $VERIFIER_TAG"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --retry 3 --output "$dest.tmp" "$VERIFIER_URL"
    mv "$dest.tmp" "$dest"
  fi
  echo "$VERIFIER_SHA256  $dest" | sha256sum --check --status - \
    || { log "the TDX verifier at $dest does not match the pinned sha256 $VERIFIER_SHA256"; exit 1; }
  VERIFIER_PATH=$dest
}

bundle() {
  local stage="$OUT/stage"
  rm -rf "$stage"; mkdir -p "$stage/src/sandbox" "$stage/src/validator" "$stage/bin"
  if [ -z "${NO_FETCH:-}" ]; then
    git -C "$SANDBOX_REPO" fetch -q origin
    git -C "$VALIDATOR_REPO" fetch -q origin
  fi
  git -C "$SANDBOX_REPO" archive "$SANDBOX_REF" | tar -x -C "$stage/src/sandbox"
  git -C "$VALIDATOR_REPO" archive "$VALIDATOR_REF" | tar -x -C "$stage/src/validator"
  git -C "$SANDBOX_REPO" rev-parse "$SANDBOX_REF^{commit}" > "$stage/src/sandbox/.e2e-commit"
  git -C "$VALIDATOR_REPO" rev-parse "$VALIDATOR_REF^{commit}" > "$stage/src/validator/.e2e-commit"
  cp "$T"/setup.sh "$T"/harness.py "$T"/serve_worker.py "$T"/run_tests.sh "$stage/"
  fetch_verifier
  cp "$VERIFIER_PATH" "$stage/bin/cathedral-tdx-verifier"
  chmod 0755 "$stage"/*.sh "$stage"/*.py "$stage/bin/cathedral-tdx-verifier"
  tar -C "$stage" -czf "$OUT/bundle.tgz" .
  log "bundle: sandbox $(cut -c1-12 "$stage/src/sandbox/.e2e-commit"), validator $(cut -c1-12 "$stage/src/validator/.e2e-commit"), $(du -h "$OUT/bundle.tgz" | cut -f1)"
}

step_preflight() {
  log "preflight: $HOST"
  # Expanded on the box, not here.
  # shellcheck disable=SC2016
  rsh 'set -e; echo "user $(id -un) on $(hostname), kernel $(uname -r), $(nproc) vCPU, $(free -g | awk "/Mem/{print \$2}") GiB"
       sudo -n true && echo "sudo: ok"
       test -e /dev/tdx_guest && echo "tdx_guest: present"
       test -e /sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384 && echo "rtmr3 sysfs: present"
       docker --version; echo "docker root: $(sudo -n docker info --format "{{.DockerRootDir}}")"'
}

step_ship() {
  bundle
  rsh "mkdir -p ~/$RD && rm -rf ~/$RD/src ~/$RD/bin"
  scp "${SCP_OPTS[@]}" -q "$OUT/bundle.tgz" "$HOST:$RD/bundle.tgz"
  rsh "cd ~/$RD && umask 022 && tar -xzf bundle.tgz && rm bundle.tgz && mkdir -p results && ls"
  log "shipped to ~/$RD"
}

harness_cmd() {
  local phase=$1
  echo "sudo -n $HVENV/bin/python ~/$RD/harness.py --phase $phase --image-ref $IMAGE_REF --image-digest $IMAGE_DIGEST --results ~/$RD/results/harness-$phase.json"
}

step_setup_prepare() { remote_step setup-prepare "sudo -n env IMAGE_REF=$IMAGE_REF IMAGE_DIGEST=$IMAGE_DIGEST ./setup.sh prepare" 1200; }
step_setup_luks() { remote_step setup-luks "sudo -n env IMAGE_REF=$IMAGE_REF IMAGE_DIGEST=$IMAGE_DIGEST ./setup.sh luks" 1800; }
step_tests_prepare_bg() {
  rsh "cd ~/$RD && mkdir -p results && rm -f results/tests-prepare.rc && (nohup bash -c './run_tests.sh prepare; echo \$? > results/tests-prepare.rc' > results/tests-prepare.log 2>&1 < /dev/null &)"
  log "test venvs are being prepared in the background"
}
step_tests_run() {
  local waited=0
  until rsh "test -f ~/$RD/results/tests-prepare.rc"; do
    [ $waited -gt 1800 ] && { log "test venv preparation did not finish"; return 1; }
    [ $((waited % 60)) = 0 ] && log "waiting for the test venvs ($waited s)"
    sleep 10; waited=$((waited + 10))
  done
  rsh "cd ~/$RD && echo 'tests-prepare exit' \$(cat results/tests-prepare.rc); tail -n 4 results/tests-prepare.log"
  remote_step tests "./run_tests.sh run" 5400
}

step_collect() {
  local dest f
  dest="$OUT/results/$(echo "${HOST#*@}" | tr -c 'A-Za-z0-9.\n' '_')-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$dest"
  rsh "cd ~/$RD && sudo -n tar -C /var/lib/cathedral-e2e -czf results/work-logs.tgz logs results quotes 2>/dev/null; sudo -n ./setup.sh status > results/setup-status.txt 2>&1; sudo -n chown -R \$(id -u):\$(id -g) results; true"
  scp "${SCP_OPTS[@]}" -q -r "$HOST:$RD/results/." "$dest/"
  for f in "$BASELINE_DIR"/*.fails*; do [ -f "$f" ] && cp "$f" "$dest/baseline-$(basename "$f")"; done
  echo "$dest" > "$STAMP_FILE"
  log "collected into $dest"
}

step_summary() {
  local dest=${1:-$(cat "$STAMP_FILE")}
  # macOS bash with `set -u` rejects "${arr[@]}" when arr is empty.
  if [ -d "$BASELINE_DIR" ]; then
    python3 "$T/summarize.py" "$dest" "$BASELINE_DIR" | tee "$dest/RESULTS.txt"
  else
    python3 "$T/summarize.py" "$dest" | tee "$dest/RESULTS.txt"
  fi
}

main() {
  local what=${1:-all} rc=0 t0
  case "$what" in
    preflight) step_preflight ;;
    ship) step_ship ;;
    setup) step_setup_prepare && step_setup_luks ;;
    harness) remote_step harness-main "$(harness_cmd main)" 1800 ;;
    tests) step_tests_prepare_bg; step_tests_run ;;
    collect) step_collect ;;
    summary) step_summary "${2:-}" ;;
    all)
      t0=$(date +%s)
      step_preflight
      step_ship
      step_setup_prepare || { log "setup prepare failed"; step_collect; step_summary; exit 1; }
      [ -n "${SKIP_TESTS:-}" ] || step_tests_prepare_bg
      remote_step harness-pre-luks "$(harness_cmd pre-luks)" 900 || rc=1
      step_setup_luks || { log "setup luks failed"; step_collect; step_summary; exit 1; }
      remote_step harness-main "$(harness_cmd main)" 1800 || rc=1
      if [ -z "${SKIP_TESTS:-}" ]; then step_tests_run || rc=1; fi
      step_collect
      step_summary
      log "total $(( $(date +%s) - t0 )) s, exit $rc"
      return $rc ;;
    *) echo "usage: run.sh [all|preflight|ship|setup|harness|tests|collect|summary]" >&2; return 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
