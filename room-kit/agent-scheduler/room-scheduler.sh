#!/bin/sh
# Interval job scheduler for a sealed room. POSIX sh, no systemd, no cron.
#
#   room-scheduler.sh start        launch the supervisor in tmux session "sched" (idempotent)
#   room-scheduler.sh supervise    keep "run" alive, restart it when it dies
#   room-scheduler.sh run          scheduler loop (foreground)
#
# Jobs file, one per line: <name> <interval_seconds> <command...>   (# comments ok)
# Env: SCHED_DIR (default /workspace/sched), JOBS_FILE (default $SCHED_DIR/jobs), SCHED_TICK (default 1)
SCHED_DIR=${SCHED_DIR:-/workspace/sched}
JOBS_FILE=${JOBS_FILE:-$SCHED_DIR/jobs}
TICK=${SCHED_TICK:-1}
LOG=$SCHED_DIR/log
STATE=$SCHED_DIR/state
SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
mkdir -p "$STATE"

now() { date +%s; }
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; }

# mkdir is atomic everywhere; the pid file lets us steal a lock whose owner died.
take_lock() {
  if mkdir "$1" 2>/dev/null; then echo "$2" > "$1/pid"; return 0; fi
  holder=$(cat "$1/pid" 2>/dev/null)
  if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then return 1; fi
  rm -rf "$1"
  mkdir "$1" 2>/dev/null && echo "$2" > "$1/pid"
}

# Runs in a background subshell so a slow job never delays the others.
run_job() {
  name=$1; cmd=$2; lock=$STATE/$name.lock
  if ! take_lock "$lock" "$$"; then log "job=$name event=skip reason=locked holder=$(cat "$lock/pid" 2>/dev/null)"; return; fi
  trap 'rm -rf "$lock"' EXIT
  t0=$(now); log "job=$name event=start pid=$$"
  if command -v flock >/dev/null 2>&1; then
    # Second guard when flock exists: the kernel drops it even if the pid file is wrong.
    flock -n "$STATE/$name.flock" sh -c "$cmd" >> "$SCHED_DIR/$name.out" 2>&1
  else
    sh -c "$cmd" >> "$SCHED_DIR/$name.out" 2>&1
  fi
  rc=$?
  log "job=$name event=end rc=$rc dur=$(( $(now) - t0 ))s"
}

run() {
  take_lock "$STATE/scheduler.lock" "$$" || { echo "scheduler already running" >&2; exit 0; }
  trap 'rm -rf "$STATE/scheduler.lock"' EXIT
  trap 'exit 143' TERM INT
  log "scheduler event=up pid=$$"
  while :; do
    while read -r name interval cmd; do
      case $name in ''|'#'*) continue ;; esac
      t=$(now); next=$(cat "$STATE/$name.next" 2>/dev/null || echo 0)
      [ "$t" -ge "$next" ] || continue
      # Keep the cadence fixed (no drift); if we fell far behind, do not replay missed runs.
      next=$((next + interval)); [ "$next" -gt "$t" ] || next=$((t + interval))
      echo "$next" > "$STATE/$name.next"
      ( run_job "$name" "$cmd" ) &
    done < "$JOBS_FILE"
    sleep "$TICK"
  done
}

supervise() {
  take_lock "$STATE/supervisor.lock" "$$" || { echo "supervisor already running" >&2; exit 0; }
  trap 'rm -rf "$STATE/supervisor.lock"' EXIT
  trap 'exit 143' TERM INT
  while :; do
    sh "$SELF" run; rc=$?
    log "supervisor event=scheduler_exit rc=$rc action=restart"
    sleep 2
  done
}

start() {
  if command -v tmux >/dev/null 2>&1; then
    tmux has-session -t sched 2>/dev/null && { echo "tmux session sched exists"; return 0; }
    tmux new-session -d -s sched "sh '$SELF' supervise" && echo "started in tmux session sched"
  else
    # No tmux in the image: setsid + nohup gives the same detach.
    setsid nohup sh "$SELF" supervise >> "$SCHED_DIR/supervisor.out" 2>&1 < /dev/null &
    echo "started with setsid nohup (no tmux)"
  fi
}

case ${1:-} in
  start) start ;; supervise) supervise ;; run) run ;;
  *) echo "usage: $0 start|supervise|run" >&2; exit 2 ;;
esac
