"""Reload the Docker daemon's runsc entry when the runsc tunables change.

The runsc flags (``--directfs``, ``--overlay2``, ``--num-network-channels``) are
``runtimeArgs`` of the daemon's runsc runtime in ``daemon.json``, not ``docker run``
flags, so no per-container setting can carry them. Changing them means rewriting that
one entry and reloading the daemon (``systemctl reload docker``: SIGHUP, which re-reads
``runtimes`` without restarting dockerd or any container).

This is off unless the worker is started with ``--tee-box-daemon-json PATH``. The
service calls it only while the box holds no sandbox, no warm container and no
in-flight create, so a reload can never touch a live room. Only the configured
runtime's entry is written; every other daemon key is kept as it was. After a reload
the executor's ``runtime_check`` must see exactly the new flags, or the old file is
put back and the daemon reloaded again.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence

DEFAULT_RELOAD_ARGV = ("systemctl", "reload", "docker")
MAX_DAEMON_JSON_BYTES = 256 * 1024


class DaemonReloadError(RuntimeError):
    """The daemon entry could not be written, reloaded or confirmed.

    ``restored`` is false when putting the previous file back also failed: the daemon's
    runsc flags are then unknown until the next confirmed sync or worker start.
    """

    def __init__(self, message: str, *, restored: bool = True) -> None:
        super().__init__(message)
        self.restored = restored


class DaemonReloader:
    def __init__(
        self,
        daemon_json: str,
        *,
        reload_argv: Sequence[str] = DEFAULT_RELOAD_ARGV,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        timeout: float = 60.0,
        confirm_attempts: int = 20,
        confirm_interval: float = 0.25,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not os.path.isabs(daemon_json):
            raise ValueError("the daemon.json path must be absolute")
        self.daemon_json = daemon_json
        self.reload_argv = tuple(reload_argv)
        self._runner = runner
        self._timeout = timeout
        self._attempts = max(1, confirm_attempts)
        self._interval = confirm_interval
        self._sleep = sleep

    def _read(self) -> bytes:
        try:
            with open(self.daemon_json, "rb") as handle:
                raw = handle.read(MAX_DAEMON_JSON_BYTES + 1)
        except FileNotFoundError:
            return b""
        except OSError as exc:
            raise DaemonReloadError(f"cannot read daemon.json: {type(exc).__name__}") from exc
        if len(raw) > MAX_DAEMON_JSON_BYTES:
            raise DaemonReloadError("daemon.json is too large")
        return raw

    def _write(self, raw: bytes) -> None:
        directory = os.path.dirname(self.daemon_json)
        try:
            fd, temp = tempfile.mkstemp(prefix=".daemon.json.", dir=directory)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temp, 0o644)
                os.replace(temp, self.daemon_json)
            except BaseException:
                if os.path.exists(temp):
                    os.unlink(temp)
                raise
        except OSError as exc:
            raise DaemonReloadError(f"cannot write daemon.json: {type(exc).__name__}") from exc

    def _reload(self) -> None:
        try:
            result = self._runner(
                list(self.reload_argv),
                capture_output=True,
                timeout=self._timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DaemonReloadError("daemon reload failed to run") from exc
        if result.returncode != 0:
            raise DaemonReloadError("daemon reload failed")

    def _confirm(self, check: Callable[[], tuple[bool, str]]) -> tuple[bool, str]:
        detail = ""
        for attempt in range(self._attempts):
            ok, detail = check()
            if ok:
                return True, detail
            if attempt + 1 < self._attempts:
                self._sleep(self._interval)
        return False, detail

    def sync(self, runtime_config: dict, check: Callable[[], tuple[bool, str]]) -> None:
        """Write ``runtime_config`` (``daemon_runtime_config()``), reload, then confirm.

        ``check`` is the executor's ``runtime_check`` already holding the new tunables.
        On any failure the previous file is restored and reloaded, and this raises.
        """

        previous = self._read()
        try:
            document = json.loads(previous) if previous.strip() else {}
        except (UnicodeDecodeError, ValueError) as exc:
            raise DaemonReloadError("daemon.json is not valid JSON") from exc
        if not isinstance(document, dict):
            raise DaemonReloadError("daemon.json is not a JSON object")
        runtimes = document.get("runtimes") or {}
        if not isinstance(runtimes, dict):
            raise DaemonReloadError("daemon.json runtimes is not an object")
        document["runtimes"] = {**runtimes, **runtime_config["runtimes"]}
        self._write((json.dumps(document, indent=2, sort_keys=True) + "\n").encode())
        try:
            self._reload()
            ok, detail = self._confirm(check)
            if not ok:
                raise DaemonReloadError(f"daemon did not take the new runsc flags: {detail}")
        except DaemonReloadError as exc:
            raise DaemonReloadError(str(exc), restored=self._restore(previous)) from exc

    def _restore(self, previous: bytes) -> bool:
        try:
            if previous:
                self._write(previous)
            elif os.path.exists(self.daemon_json):
                os.unlink(self.daemon_json)
            self._reload()
        except (DaemonReloadError, OSError):
            return False
        return True
