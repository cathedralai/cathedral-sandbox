#!/usr/bin/env bash
# PYTHONPATH is set inside the per-suite subshells on purpose.
# shellcheck disable=SC2030,SC2031
# Run the cathedral-sandbox full test suite, and the cathedral-validator suites
# (tests/thin + scaffold/publisher/tests) against sandbox main, on this host.
# Run as the ordinary SSH user, not root (the suites assume a non-root user).
#
#   run_tests.sh prepare   create the two venvs and install what they need
#   run_tests.sh run       run both suites (in parallel unless PARALLEL=0),
#                          then re-run each suite's failures once, sequentially,
#                          to separate flakes from real failures
#   run_tests.sh all       prepare, then run
#
# Environment: R (shipped tree, default this script's dir), SB and VA (the
# sandbox and validator trees, default R/src/sandbox and R/src/validator),
# VENVS, OUT, TEST_TMPDIR (CATHEDRAL_TEST_TMPDIR, an owner-only directory),
# PYTHON, PARALLEL. See README.md for a local baseline run.
set -uo pipefail
umask 022  # as CI; the suites refuse group-writable trusted files
R=${R:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
SB=${SB:-$R/src/sandbox}
VA=${VA:-$R/src/validator}
VENVS=${VENVS:-$R/venvs}
OUT=${OUT:-$R/results}
TEST_TMPDIR=${TEST_TMPDIR:-/var/lib/cathedral-test-tmp}
PYTHON=${PYTHON:-python3}
PARALLEL=${PARALLEL:-1}
SUITE_TIMEOUT=${SUITE_TIMEOUT:-3600}
mkdir -p "$OUT" "$VENVS"
# Absolute paths: the suites run after a cd into each tree.
OUT=$(cd "$OUT" && pwd); VENVS=$(cd "$VENVS" && pwd)
if [ -d "$SB" ]; then SB=$(cd "$SB" && pwd); fi
if [ -d "$VA" ]; then VA=$(cd "$VA" && pwd); fi

log() { printf '[tests %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

make_venv() {
  local name=$1; shift
  local venv="$VENVS/$name" logf="$OUT/prepare-$name.log"
  if [ -f "$venv/.e2e-ready" ]; then log "venv $name ready"; return 0; fi
  log "creating venv $name ($*)"
  {
    rm -rf "$venv" &&
    "$PYTHON" -m venv "$venv" &&
    "$venv/bin/pip" install -q --upgrade pip &&
    "$venv/bin/pip" install -q "$@"
  } >"$logf" 2>&1 || { log "venv $name FAILED (see $logf)"; tail -5 "$logf"; return 1; }
  touch "$venv/.e2e-ready"
  log "venv $name done"
}

prepare() {
  if [ ! -d "$TEST_TMPDIR" ]; then
    if mkdir -m 0700 "$TEST_TMPDIR" 2>/dev/null; then :; else
      sudo -n install -d -o "$(id -u)" -g "$(id -g)" -m 0700 -- "$TEST_TMPDIR"
    fi
  fi
  local rc=0
  make_venv sandbox -e "${SB}[dev]" & local p1=$!
  make_venv validator -e "${VA}[test,publisher,integration]" & local p2=$!
  wait $p1 || rc=1
  wait $p2 || rc=1
  return $rc
}

# run_suite NAME DIR PYTHONPATH TARGETS...
run_suite() {
  local name=$1 dir=$2 pythonpath=$3; shift 3
  local py="$VENVS/$name/bin/python" logf="$OUT/$name-tests.log"
  local started
  started=$(date +%s)
  log "suite $name: pytest $* (log $logf)"
  (
    cd "$dir" &&
    { [ -z "$pythonpath" ] || export PYTHONPATH="$pythonpath"; } &&
    echo "HEAD $(cat "$dir/.e2e-commit" 2>/dev/null || echo unknown) python $("$py" -V 2>&1) host $(hostname)" &&
    "$py" -c 'import cathedral, sys; print("cathedral from", cathedral.__file__)' &&
    CATHEDRAL_TEST_TMPDIR="$TEST_TMPDIR" timeout "$SUITE_TIMEOUT" "$py" -m pytest -q -p no:cacheprovider -rfEs "$@"
  ) >"$logf" 2>&1
  local rc=$?
  echo "EXIT $rc ELAPSED $(( $(date +%s) - started ))s" >>"$logf"
  grep -E '^(FAILED|ERROR) ' "$logf" | sed -e 's/ - .*//' -e 's/^\(FAILED\|ERROR\) //' | sort -u >"$OUT/$name.fails"
  log "suite $name: exit $rc, $(grep -E '^[0-9]+ (passed|failed)|(passed|failed).* in [0-9.]+s' "$logf" | tail -1), $(wc -l <"$OUT/$name.fails") failing ids"
  return $rc
}

# Re-run a suite's failures once, sequentially, to tell flakes from failures.
rerun_failures() {
  local name=$1 dir=$2 pythonpath=$3
  local fails="$OUT/$name.fails" logf="$OUT/$name-rerun.log"
  : >"$OUT/$name.fails.rerun"
  [ -s "$fails" ] || return 0
  if [ "$(wc -l <"$fails")" -gt 80 ]; then
    log "suite $name: $(wc -l <"$fails") failures, too many to re-run"
    cp "$fails" "$OUT/$name.fails.rerun"
    return 0
  fi
  log "suite $name: re-running $(wc -l <"$fails") failing ids sequentially"
  (
    cd "$dir" &&
    { [ -z "$pythonpath" ] || export PYTHONPATH="$pythonpath"; } &&
    mapfile -t ids <"$fails" &&
    CATHEDRAL_TEST_TMPDIR="$TEST_TMPDIR" timeout 1800 "$VENVS/$name/bin/python" -m pytest -q -p no:cacheprovider -rfE "${ids[@]}"
  ) >"$logf" 2>&1
  grep -E '^(FAILED|ERROR) ' "$logf" | sed -e 's/ - .*//' -e 's/^\(FAILED\|ERROR\) //' | sort -u >"$OUT/$name.fails.rerun"
  log "suite $name: $(wc -l <"$OUT/$name.fails.rerun") still failing after the re-run"
}

run() {
  local rc=0
  if [ "$PARALLEL" = 1 ]; then
    run_suite sandbox "$SB" "" tests & local p1=$!
    run_suite validator "$VA" "$SB" tests/thin scaffold/publisher/tests & local p2=$!
    wait $p1 || rc=1
    wait $p2 || rc=1
  else
    run_suite sandbox "$SB" "" tests || rc=1
    run_suite validator "$VA" "$SB" tests/thin scaffold/publisher/tests || rc=1
  fi
  rerun_failures sandbox "$SB" ""
  rerun_failures validator "$VA" "$SB"
  return $rc
}

case "${1:-all}" in
  prepare) prepare ;;
  run) run ;;
  all) prepare && run ;;
  *) echo "usage: run_tests.sh prepare|run|all" >&2; exit 2 ;;
esac
