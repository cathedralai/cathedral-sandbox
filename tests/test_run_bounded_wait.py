"""_run_bounded reports a command when it ends, not at the next poll point."""

from __future__ import annotations

import os
import statistics
import subprocess
import threading
import time

import pytest

from cathedral.sandbox_guest import _run_bounded


def _run(argv, timeout=30.0):
    return _run_bounded(argv, timeout=timeout, input_bytes=None, env=None, cap=1024)


def _median_ms(seconds: float, runs: int = 5) -> float:
    out = []
    for _ in range(runs):
        start = time.perf_counter()
        result = _run(["/bin/sleep", f"{seconds:.3f}"])
        out.append((time.perf_counter() - start) * 1000)
        assert result.returncode == 0
    return statistics.median(out)


def test_reported_time_follows_the_command() -> None:
    # The poll wakes at about 63 and 113 ms, so 70 and 100 ms commands read the same.
    short = _median_ms(0.07)
    long = _median_ms(0.10)
    assert long - short > 15


def test_timeout_kills_the_child_and_raises(tmp_path) -> None:
    pidfile = tmp_path / "pid"
    start = time.perf_counter()
    with pytest.raises(subprocess.TimeoutExpired):
        _run(["sh", "-c", f"echo $$ > {pidfile}; exec sleep 5"], timeout=0.2)
    assert time.perf_counter() - start < 1.0
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    pytest.fail("child still alive after timeout")


def test_no_timeout_waits_for_the_child() -> None:
    result = _run(["/bin/sleep", "0.05"], timeout=None)
    assert result.returncode == 0


def test_no_thread_is_left_behind() -> None:
    start = threading.active_count()
    for _ in range(30):
        _run(["sh", "-c", "exit 0"])
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and threading.active_count() > start:
        time.sleep(0.01)
    assert threading.active_count() == start
