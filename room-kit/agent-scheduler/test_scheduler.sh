#!/bin/sh
# Local test: 2 s interval, checks the per-job lock, job-kill recovery and scheduler restart.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
export SCHED_DIR=$(mktemp -d) SCHED_TICK=0.2
printf 'slow 2 sleep 5\nfast 2 echo hi\n' > "$SCHED_DIR/jobs"
fail=0; ok() { echo "PASS $1"; }; bad() { echo "FAIL $1"; fail=1; }
cnt() { grep -c "$1" "$SCHED_DIR/log" 2>/dev/null; true; }
cleanup() { pkill -f "$SCHED_DIR" 2>/dev/null; sh -c "kill \$(cat $SCHED_DIR/state/*.pid 2>/dev/null)" 2>/dev/null; rm -rf "$SCHED_DIR"; }
trap cleanup EXIT

sh "$HERE/room-scheduler.sh" supervise >/dev/null 2>&1 &
SUP=$!
sleep 9
# 1. lock: slow job (5 s) is due every 2 s, so it must be skipped while running, never overlap
[ "$(cnt 'job=slow event=skip reason=locked')" -ge 1 ] && ok "lock skips overlapping slow run" || bad "no lock skip"
s=$(cnt 'job=slow event=start'); e=$(cnt 'job=slow event=end')
[ $((s - e)) -le 1 ] && ok "at most one slow run in flight" || bad "overlap: $s starts, $e ends"
[ "$(cnt 'job=fast event=end rc=0')" -ge 3 ] && ok "fast job ran on its 2 s interval" || bad "fast job did not repeat"

# 2. kill a job mid-run: end line shows non-zero rc and the next run still happens
before=$(cnt 'job=fast event=start')
pkill -f 'sleep 5' ; sleep 4
[ "$(cnt 'job=slow event=end rc=[1-9]')" -ge 1 ] && ok "killed job logged non-zero end" || bad "killed job not logged"
[ "$(cnt 'job=slow event=start')" -gt "$s" ] && ok "next slow run happened after kill" || bad "no run after job kill"

# 3. kill the scheduler: the supervisor must restart it
SCHED=$(cat "$SCHED_DIR/state/scheduler.lock/pid")
kill -9 "$SCHED"; sleep 6
[ "$(cnt 'supervisor event=scheduler_exit')" -ge 1 ] && ok "supervisor saw scheduler die" || bad "supervisor did not notice"
[ "$(cnt 'scheduler event=up')" -ge 2 ] && ok "scheduler restarted" || bad "scheduler not restarted"
after=$(cnt 'job=fast event=start'); [ "$after" -gt "$before" ] && ok "jobs keep running after restart" || bad "jobs stalled"
kill "$SUP" 2>/dev/null
exit $fail
