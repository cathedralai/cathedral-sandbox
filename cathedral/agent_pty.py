"""A process on a pseudo terminal, for real interactive room terminals (AB#405).

The hotel runs ``docker exec -it <room> bash -l`` on the slave side of a PTY
it owns. ``docker exec -t`` needs its stdin to be a tty; it then allocates a
second tty inside the room, so full-screen programs (vim, top) and raw keys
work in the room while the hotel only pumps bytes.

The child does not get the PTY as its controlling terminal (that would need a
preexec hook, unsafe in a threaded server). A resize therefore sets the size
on the PTY and sends SIGWINCH to the child itself; the docker client then
reads its stdin size and resizes the tty in the room.
"""

from __future__ import annotations

import errno
import fcntl
import os
import pty
import signal
import struct
import subprocess
import termios
import threading
from typing import Callable, Sequence

READ_CHUNK = 4096
CLOSE_GRACE_SECONDS = 2.0


def _set_size(fd: int, cols: int, rows: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


class PtyProcess:
    """One child process on a PTY, with a reader thread that hands out its output.

    ``on_output(bytes)`` runs on the reader thread for every chunk;
    ``on_exit(code)`` runs once after the child is gone. Neither runs with any
    lock of this object held, so they may take the caller's own lock.
    """

    def __init__(
        self,
        argv: Sequence[str],
        *,
        cols: int,
        rows: int,
        on_output: Callable[[bytes], None],
        on_exit: Callable[[int], None],
        env: dict[str, str] | None = None,
    ) -> None:
        master, slave = pty.openpty()
        try:
            _set_size(slave, cols, rows)
            self._proc = subprocess.Popen(
                list(argv),
                stdin=slave,
                stdout=slave,
                stderr=slave,
                start_new_session=True,
                close_fds=True,
                env=env,
            )
        except BaseException:
            os.close(master)
            os.close(slave)
            raise
        os.close(slave)
        self._master = master
        # Guards the master fd: the reader closes it at EOF while write or
        # resize may run on another thread, and a closed fd number can be
        # reused by anything else in the process.
        self._fd_lock = threading.Lock()
        self._closed = False
        self._on_output = on_output
        self._on_exit = on_exit
        self.exit_code: int | None = None
        self._reader = threading.Thread(target=self._read_loop, name="cathedral-pty-reader", daemon=True)
        self._reader.start()

    @property
    def pid(self) -> int:
        return self._proc.pid

    def _read_loop(self) -> None:
        try:
            while True:
                try:
                    chunk = os.read(self._master, READ_CHUNK)
                except OSError as exc:
                    # Linux answers EIO on the master once every slave fd is closed.
                    if exc.errno in (errno.EIO, errno.EBADF):
                        break
                    raise
                if not chunk:
                    break
                self._on_output(chunk)
        finally:
            with self._fd_lock:
                if not self._closed:
                    self._closed = True
                    os.close(self._master)
            try:
                code = self._proc.wait(timeout=CLOSE_GRACE_SECONDS * 2)
            except subprocess.TimeoutExpired:
                self._signal_group(signal.SIGKILL)
                code = self._proc.wait()
            self.exit_code = code
            self._on_exit(code)

    def write(self, data: bytes) -> int:
        """Write all of *data* to the PTY. Raises BrokenPipeError once closed."""
        view = memoryview(data)
        written = 0
        while written < len(view):
            with self._fd_lock:
                if self._closed:
                    raise BrokenPipeError("terminal closed")
                try:
                    n = os.write(self._master, view[written:])
                except OSError as exc:
                    if exc.errno in (errno.EIO, errno.EBADF):
                        raise BrokenPipeError("terminal closed") from exc
                    raise
            written += n
        return written

    def resize(self, cols: int, rows: int) -> None:
        with self._fd_lock:
            if self._closed:
                return
            _set_size(self._master, cols, rows)
        if self._proc.poll() is None:
            try:
                self._proc.send_signal(signal.SIGWINCH)
            except ProcessLookupError:
                pass

    def _signal_group(self, sig: int) -> None:
        try:
            os.killpg(self._proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def close(self) -> None:
        """Hang up the child without blocking the caller; the reader reaps it."""
        if self._proc.poll() is not None:
            return
        self._signal_group(signal.SIGHUP)

        def _kill_late() -> None:
            try:
                self._proc.wait(timeout=CLOSE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                self._signal_group(signal.SIGKILL)

        threading.Thread(target=_kill_late, name="cathedral-pty-close", daemon=True).start()

    def wait(self, timeout: float | None = None) -> int | None:
        """Wait for the reader to finish (child gone, on_exit called)."""
        self._reader.join(timeout)
        return self.exit_code


__all__ = ["PtyProcess"]
