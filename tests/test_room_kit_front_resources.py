"""The front test harness gives back what it takes (AB#535).

All the room-kit tests run in one process. A descriptor or thread left behind by each front adds up, and the terminal
WebSocket tests of the machine API use select(), which refuses a descriptor number of 1024 or more. A harness that leaks
one descriptor per front therefore broke those tests once enough fronts had run before them.
"""
from __future__ import annotations

import gc
import os
import socket
import threading
import time

from room_front_support import Front


def open_fds() -> int:
    """The lowest of several samples: threads that other tests left running open sockets for a moment each second."""
    gc.collect()
    lowest = None
    for _ in range(25):
        n = len(os.listdir("/dev/fd"))
        lowest = n if lowest is None else min(lowest, n)
        time.sleep(0.01)
    return lowest


def front_threads() -> int:
    return sum(1 for t in threading.enumerate() if t.name.startswith("room-front-") or getattr(t._target, "__name__", "") == "health_loop")


def one_front(tmp_path, monkeypatch, n: int) -> None:
    f = Front(tmp_path / f"f{n}", monkeypatch)
    try:
        assert f.create()[0] == 200
        assert f.exec("sbx_1")[0] == 200
    finally:
        f.close()


def test_a_front_that_is_closed_leaves_no_descriptor_behind(tmp_path, monkeypatch) -> None:
    one_front(tmp_path, monkeypatch, 0)  # warm up what is opened once per process
    before = open_fds()
    for n in range(1, 9):
        one_front(tmp_path, monkeypatch, n)
    after = open_fds()
    assert after <= before + 1, f"{after - before} descriptors left by 8 fronts"


def test_a_front_that_is_closed_leaves_no_thread_behind(tmp_path, monkeypatch) -> None:
    one_front(tmp_path, monkeypatch, 0)
    before = front_threads()
    for n in range(1, 6):
        one_front(tmp_path, monkeypatch, n)
    deadline = time.time() + 5
    while front_threads() > before and time.time() < deadline:
        time.sleep(0.05)
    assert front_threads() <= before, f"{front_threads() - before} front threads left by 5 fronts"


def test_no_test_leaves_a_default_socket_timeout_behind() -> None:
    assert socket.getdefaulttimeout() is None
