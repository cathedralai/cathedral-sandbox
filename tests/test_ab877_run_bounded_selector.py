"""AB#877: _run_bounded runs on the calling thread only and always ends."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

import pytest

from cathedral import sandbox_guest
from cathedral.sandbox_guest import _run_bounded


def _run(argv, *, timeout=10.0, input_bytes=None, cap=1 << 20, **kw):
    return _run_bounded(argv, timeout=timeout, input_bytes=input_bytes, env=None, cap=cap, **kw)


def test_a_process_left_holding_the_pipe_does_not_hold_the_call() -> None:
    # The old reader threads were joined with no limit: a background child that kept
    # stdout open held the exec (and its HTTP request) until that child ended.
    start = time.monotonic()
    result = _run(["sh", "-c", "sleep 30 & echo hi"], timeout=None)
    took = time.monotonic() - start
    assert result.returncode == 0
    assert result.stdout == b"hi\n"
    assert took < sandbox_guest.RUN_BOUNDED_EXIT_DRAIN_SECONDS + 1.5


def test_stdin_larger_than_a_pipe_buffer_is_fed_whole() -> None:
    data = os.urandom(1 << 20)
    result = _run(["cat"], input_bytes=data)
    assert result.returncode == 0
    assert result.stdout == data


def test_a_command_that_never_reads_stdin_still_ends() -> None:
    result = _run(["sh", "-c", "exit 3"], input_bytes=b"x" * (1 << 20))
    assert result.returncode == 3


def test_both_streams_are_kept_and_capped() -> None:
    script = "import sys; sys.stdout.write('o'*10); sys.stderr.write('e'*10)"
    result = _run([sys.executable, "-c", script], cap=4)
    assert result.stdout == b"ooooo" and result.stderr == b"eeeee"


def test_no_helper_thread_is_started() -> None:
    started: list[threading.Thread] = []
    orig = threading.Thread.start

    def spy(self):
        started.append(self)
        return orig(self)

    threading.Thread.start = spy
    try:
        _run(["sh", "-c", "echo a; echo b >&2"], input_bytes=b"in")
    finally:
        threading.Thread.start = orig
    assert started == []


def test_without_pidfd_the_exit_is_still_seen_and_the_limit_kept(monkeypatch) -> None:
    def no_pidfd(pid):
        raise OSError(38, "pidfd_open not here")

    monkeypatch.setattr(os, "pidfd_open", no_pidfd)
    assert _run(["sh", "-c", "echo ok"]).stdout == b"ok\n"
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _run(["sleep", "5"], timeout=0.2)
    assert time.monotonic() - start < 1.0
