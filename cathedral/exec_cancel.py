"""Cancel a background exec inside its room (AB#406).

The start wrapper writes the pid of the process that becomes the command. Under
runsc `docker exec` makes that process a group leader, so one group signal reaches
the command and its children on GNU and BusyBox rooms alike. The cancel route runs
KILL_SCRIPT in the room, which refuses a pid file the customer forged. `stopped` is
claimed only when the exec call itself returns: a signal that was sent proves nothing.
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
# A cancel that arrives before its exec is remembered for the API's launch grace (60 s),
# the hotel's clock allowance (30 s) and a margin (60 s). After that no exec with the token can start.
TOMBSTONE_SECONDS = 150
LAUNCH_CLOCK_ALLOWANCE_SECONDS = 30

# Exit codes of KILL_SCRIPT. 0 means the signal went out.
REFUSED = 3
NO_PID_FILE = 4
SIGNAL_FAILED = 5


def pid_file(token: str) -> str:
    return f"/tmp/.cathedral-exec-{token}.pid"


# $1 is the pid file. `shift` drops it, so "$@" is exactly the command to run. A pid file that
# cannot be written must not stop the command: cancel then answers `unsupported` for this exec.
WRAP_SCRIPT = '{ echo $$ > "$1"; } 2>/dev/null; shift; exec "$@"'

# Runs in the room as the exec's own user. $1 pid file, $2 timeout form (gnu or busybox), $3 signal.
# The customer can write the pid file, so every check runs before any signal: digits only, pid
# above 1 (never `kill -TERM -1`), the process exists and leads its own group. GNU rooms also
# need the leader to be `timeout`; on BusyBox the pid is the command itself.
# `kill -SIG -PID`, never `kill -SIG -- -PID`: dash and BusyBox reject the second form.
KILL_SCRIPT = r'''f=$1; form=$2; sig=$3
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
kill -"$sig" -"$p" 2>/dev/null || exit 5
exit 0'''


@dataclass
class _Running:
    user: str | None
    form: str | None
    done: threading.Event = field(default_factory=threading.Event)
    signalled: bool = False


class ExecRegistry:
    """Execs that are running, what happened to the ones that ended, and cancels that came first."""

    def __init__(self, max_results: int = MAX_RESULTS) -> None:
        self._lock = threading.Lock()
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

    def finish(self, sandbox_id: str, token: str, *, cancelled: bool | None = None) -> bool:
        """Record the end. Returns True when a cancel signal passed the guard for this exec."""
        key = (sandbox_id, token)
        with self._lock:
            entry = self._running.pop(key, None)
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

    def tombstone(self, sandbox_id: str, token: str) -> None:
        """Remember a cancel for an exec this hotel has not seen. A full table refuses, never forgets."""
        now = time.time()
        with self._lock:
            for key in [k for k, until in self._tombstones.items() if until <= now]:
                del self._tombstones[key]
            if (sandbox_id, token) not in self._tombstones and len(self._tombstones) >= MAX_TOMBSTONES:
                raise SandboxOpError("cancel_table_full", 503, "too many pending cancels; retry shortly", retry_after=30)
            self._tombstones[(sandbox_id, token)] = now + TOMBSTONE_SECONDS


registry = ExecRegistry()
