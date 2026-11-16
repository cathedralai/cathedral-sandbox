"""Cancel a background exec inside its room (AB#406).

The start wrapper writes the pid of the process that becomes the command. Under
runsc `docker exec` makes that process a group leader, so one group signal reaches
the command and its children on GNU and BusyBox rooms alike. The cancel route runs
KILL_SCRIPT in the room, which refuses a pid file the customer forged. `stopped` is
claimed only when the exec call itself returned and the process group is empty: a signal
that was sent proves nothing, and a leader that exits on TERM can leave a child behind.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from cathedral.sandbox_provider import SandboxOpError

# After the first signal the hotel waits this long for the exec call to return,
# then sends KILL itself (BusyBox timeout never escalates), all inside the window.
TERM_WAIT_SECONDS = 5.0
CANCEL_WINDOW_SECONDS = 10.0
RESULT_TTL_SECONDS = 24 * 3600
MAX_RESULTS = 4096
MAX_TOMBSTONES = 4096
# The API sends launch_by = claim + 60 s on every exec and this hotel adds the clock allowance, so the
# latest start it admits is claim + 90 s (AB#731). A cancel arrives after the claim, so its tombstone
# lives to at least claim + 300 s: far past the latest admissible start, and past the API's lost bound
# (timeout + 180 s, never under 181 s). No exec with the token can start once its cancel came first.
TOMBSTONE_SECONDS = 300
LAUNCH_CLOCK_ALLOWANCE_SECONDS = 30
# A natural finish waits at most this long for a cancel signal that is still being sent (the guard
# script's own limit is 20 s), so the stored result says whether a signal really went out.
SIGNAL_SETTLE_SECONDS = 25.0
# How often the hotel looks at the exec call and the process group while a cancel is in progress.
POLL_SECONDS = 0.1
# A cancel that arrives before the start wrapper wrote its pid file retries for this long.
PID_FILE_WAIT_SECONDS = 1.0

# Exit codes of KILL_SCRIPT. 0 means the signal went out.
REFUSED = 3
NO_PID_FILE = 4
SIGNAL_FAILED = 5


def parse_pgid(out: str) -> str | None:
    """The group id KILL_SCRIPT printed after its guard passed, or None."""
    for line in out.splitlines():
        if line.startswith("pgid=") and line[5:].isdigit() and 1 < int(line[5:]) < 10**9:
            return line[5:]
    return None


def pid_file(token: str) -> str:
    return f"/tmp/.cathedral-exec-{token}.pid"


# $1 is the pid file. `shift` drops it, so "$@" is exactly the command to run. A pid file that
# cannot be written must not stop the command: cancel then answers `unsupported` for this exec.
WRAP_SCRIPT = '{ echo $$ > "$1"; } 2>/dev/null; shift; exec "$@"'

# Runs in the room as the exec's own user. $1 pid file, $2 timeout form (gnu or busybox), $3 signal,
# $4 (optional) the process group id an earlier call validated.
# Without $4 the customer can write the pid file, so every check runs before any signal: digits only,
# pid above 1 (never `kill -TERM -1`), the process exists and leads its own group. GNU rooms also need
# the leader to be `timeout`; on BusyBox the pid is the command itself. The validated group id is
# printed (`pgid=N`) before the signal, so the hotel can keep it: once the leader is gone the guard
# above can no longer pass, but the group's children may still run.
# With $4 the hotel names the group and the pid file is not read. A group that has no live member
# answers `empty` and nothing is signalled (a group id cannot be reused while a member lives, and
# an empty group is not signalled, so a recycled pid is never hit). Signal PROBE only looks.
# `kill -SIG -PID`, never `kill -SIG -- -PID`: dash and BusyBox reject the second form.
KILL_SCRIPT = r'''f=$1; form=$2; sig=$3; g=$4
if [ -n "$g" ]; then
  case "$g" in *[!0-9]*) exit 3;; esac
  [ "${#g}" -le 9 ] || exit 3
  [ "$g" -gt 1 ] || exit 3
  live=0
  for d in /proc/[0-9]*; do
    s=$(cat "$d/stat" 2>/dev/null) || continue
    set -- ${s##*) }
    if [ "$1" != Z ] && [ "$3" = "$g" ]; then live=1; break; fi
  done
  if [ "$live" = 0 ]; then echo empty; exit 0; fi
  if [ "$sig" = PROBE ]; then echo alive; exit 0; fi
  kill -"$sig" -"$g" 2>/dev/null || exit 5
  echo sent
  exit 0
fi
[ -f "$f" ] || exit 4
p=$(head -c 32 "$f" 2>/dev/null)
case "$p" in ''|*[!0-9]*) exit 3;; esac
[ "${#p}" -le 9 ] || exit 3
[ "$p" -gt 1 ] || exit 3
s=$(cat "/proc/$p/stat" 2>/dev/null) || exit 3
set -- ${s##*) }
[ "$3" = "$p" ] || exit 3
if [ "$form" = gnu ]; then
  c=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
  case "$c" in "timeout "*) ;; *) exit 3;; esac
fi
echo "pgid=$p"
kill -"$sig" -"$p" 2>/dev/null || exit 5
exit 0'''


@dataclass
class _Running:
    user: str | None
    form: str | None
    done: threading.Event = field(default_factory=threading.Event)
    # True once a cancel signal passed the guard and went out. Never cleared: a later refused
    # signal does not undo an earlier one that landed.
    signalled: bool = False
    # Cancel signals being sent right now. finish() waits for them, so a natural end that races
    # a refused signal is stored as finished and one that races a delivered signal as cancelled.
    inflight: int = 0


class ExecRegistry:
    """Execs that are running, what happened to the ones that ended, and cancels that came first."""

    def __init__(self, max_results: int = MAX_RESULTS) -> None:
        self._lock = threading.Lock()
        self._settled = threading.Condition(self._lock)
        self._max_results = max_results
        self._running: dict[tuple[str, str], _Running] = {}
        self._results: OrderedDict[tuple[str, str], tuple[str, float]] = OrderedDict()
        self._tombstones: dict[tuple[str, str], float] = {}

    def clear(self) -> None:
        with self._lock:
            self._running.clear()
            self._results.clear()
            self._tombstones.clear()

    def begin(self, sandbox_id: str, token: str, launch_by: int | None, user: str | None, form: str | None = None) -> bool:
        """Register a start. False: a cancel came first, run nothing. Raises when the launch deadline passed."""
        key = (sandbox_id, token)
        now = time.time()
        with self._lock:
            if self._tombstones.get(key, 0) > now:
                return False
            if launch_by is not None and now > launch_by + LAUNCH_CLOCK_ALLOWANCE_SECONDS:
                raise SandboxOpError("exec_launch_expired", 409, "the exec was sent too late to start; nothing ran")
            self._running[key] = _Running(user=user, form=form)
            return True

    def entry(self, sandbox_id: str, token: str) -> _Running | None:
        with self._lock:
            return self._running.get((sandbox_id, token))

    def is_running(self, sandbox_id: str, token: str) -> bool:
        return self.entry(sandbox_id, token) is not None

    def signal_begin(self, entry: _Running) -> None:
        with self._lock:
            entry.inflight += 1

    def signal_end(self, entry: _Running, sent: bool) -> None:
        """A signal attempt is over. ``sent``: it passed the guard and went out."""
        with self._settled:
            entry.inflight -= 1
            entry.signalled = entry.signalled or sent
            self._settled.notify_all()

    def finish(self, sandbox_id: str, token: str, *, cancelled: bool | None = None) -> bool:
        """Record the end. Returns True when a cancel signal passed the guard for this exec."""
        key = (sandbox_id, token)
        with self._settled:
            entry = self._running.get(key)
            if entry is not None and cancelled is None:
                # The exec call can return while a signal is still on its way. Decide only once the
                # guard has answered; the entry stays registered meanwhile, so a cancel still finds it.
                self._settled.wait_for(lambda: entry.inflight <= 0, timeout=SIGNAL_SETTLE_SECONDS)
            self._running.pop(key, None)
            was_cancelled = bool(entry and entry.signalled) if cancelled is None else cancelled
            self._results[key] = ("cancelled" if was_cancelled else "finished", time.time())
            while len(self._results) > self._max_results:
                self._results.popitem(last=False)
        if entry is not None:
            entry.done.set()
        return was_cancelled

    def result(self, sandbox_id: str, token: str) -> str | None:
        with self._lock:
            held = self._results.get((sandbox_id, token))
            if held is None:
                return None
            if time.time() - held[1] > RESULT_TTL_SECONDS:
                del self._results[(sandbox_id, token)]
                return None
            return held[0]

    def cancel_lookup(self, sandbox_id: str, token: str) -> tuple[str, _Running | str | None]:
        """Where a cancel stands, decided under one lock hold so a start cannot slip in between.

        ("running", entry), ("result", "cancelled" | "finished"), or ("tombstoned", None) after
        remembering the cancel for an exec this hotel has not seen. begin() takes the same lock,
        so a start either registered first (the cancel sees it) or finds the tombstone.
        """
        key = (sandbox_id, token)
        with self._lock:
            entry = self._running.get(key)
            if entry is not None:
                return "running", entry
            held = self._results.get(key)
            if held is not None:
                if time.time() - held[1] <= RESULT_TTL_SECONDS:
                    return "result", held[0]
                del self._results[key]
            self._tombstone_locked(key)
            return "tombstoned", None

    def tombstone(self, sandbox_id: str, token: str) -> None:
        """Remember a cancel for an exec this hotel has not seen. A full table refuses, never forgets."""
        with self._lock:
            self._tombstone_locked((sandbox_id, token))

    def _tombstone_locked(self, key: tuple[str, str]) -> None:
        now = time.time()
        for stale in [k for k, until in self._tombstones.items() if until <= now]:
            del self._tombstones[stale]
        if key not in self._tombstones and len(self._tombstones) >= MAX_TOMBSTONES:
            raise SandboxOpError("cancel_table_full", 503, "too many pending cancels; retry shortly", retry_after=30)
        self._tombstones[key] = now + TOMBSTONE_SECONDS


registry = ExecRegistry()
