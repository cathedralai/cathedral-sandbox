# agent-scheduler

Interval scheduler for a sealed room. Replaces launchd and the Monitor, CronCreate and ScheduleWakeup loops (AB#203). POSIX sh only. No systemd, no cron daemon.

## Use
- Jobs file (`$SCHED_DIR/jobs`, default `/workspace/sched/jobs`): `<name> <interval_seconds> <command...>`. `#` starts a comment.
- `room-scheduler.sh start` launches a supervisor in a detached tmux session `sched`. Without tmux it falls back to `setsid nohup`. It is idempotent, so the room entrypoint can call it on every boot.
- `room-scheduler.sh run` runs the scheduler in the foreground. `supervise` restarts `run` whenever it exits.
- Env: `SCHED_DIR`, `JOBS_FILE`, `SCHED_TICK` (seconds, default 1).

## Behavior
- Lock per job: a `mkdir` lock with a pid file. A lock whose pid is dead is stolen, so a crash never wedges a job. If `flock` exists it also wraps the command. A due job whose lock is held is skipped and logged.
- Cadence is fixed: next run = previous due time + interval. After a long stall the missed runs are dropped, not replayed.
- Next-due times live in `$SCHED_DIR/state/<job>.next`, so a scheduler restart does not reset or double a run.
- Jobs run in background subshells. A slow job never delays another job.
- Log `$SCHED_DIR/log`, one line per event, UTC:
  `2026-10-30T01:00:00Z job=hourly-turn event=start pid=412`
  `2026-10-30T01:00:01Z job=hourly-turn event=end rc=0 dur=1s`
  Also `event=skip reason=locked`, `scheduler event=up`, `supervisor event=scheduler_exit`.
- Job output goes to `$SCHED_DIR/<job>.out`.

## Persistence
`/workspace` survives only when the room was created with a workspace. Otherwise state and log are lost with the room.

## Test
`./test_scheduler.sh` runs 2 s jobs and checks: the lock skips an overlapping run, a killed job is logged with a non-zero rc and runs again, and a killed scheduler is restarted by the supervisor.
