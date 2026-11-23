"""AB#877: the hotel API serves connections on kept worker threads."""

from __future__ import annotations

import http.client
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler

from cathedral import sandbox_server


class _Slow(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hold = 0.0

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        time.sleep(self.hold)
        body = threading.current_thread().name.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def _serve(hold: float, idle: float = 300.0):
    handler = type("H", (_Slow,), {"hold": hold})
    server = sandbox_server._Server(("127.0.0.1", 0), handler)
    server.worker_idle_seconds = idle
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _get(port: int) -> tuple[int, str]:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        c.request("GET", "/")
        r = c.getresponse()
        return r.status, r.read().decode()
    finally:
        c.close()


def _workers() -> int:
    return sum(1 for t in threading.enumerate() if t.name == "cathedral-sandbox-conn")


def test_a_burst_runs_at_once_and_the_next_burst_reuses_the_workers() -> None:
    base = _workers()
    server = _serve(hold=0.5)
    try:
        port = server.server_address[1]
        start = time.monotonic()
        with ThreadPoolExecutor(40) as pool:
            first = list(pool.map(lambda _: _get(port), range(40)))
        assert time.monotonic() - start < 2.0, "connections waited for a worker"
        assert all(status == 200 for status, _ in first)
        grown = _workers() - base
        assert 1 <= grown <= 40
        with ThreadPoolExecutor(40) as pool:
            second = list(pool.map(lambda _: _get(port), range(40)))
        assert all(status == 200 for status, _ in second)
        assert _workers() - base == grown, "a second burst of the same size started new threads"
    finally:
        server.shutdown()
        server.server_close()


def test_sequential_connections_share_one_worker() -> None:
    server = _serve(hold=0.0)
    try:
        port = server.server_address[1]
        names = set()
        for _ in range(20):
            status, name = _get(port)
            assert status == 200
            names.add(name)
            time.sleep(0.01)  # let the worker go back to idle
        assert len(names) <= 2
    finally:
        server.shutdown()
        server.server_close()


def test_idle_workers_end_after_the_idle_time() -> None:
    base = _workers()
    server = _serve(hold=0.2, idle=0.3)
    try:
        port = server.server_address[1]
        with ThreadPoolExecutor(10) as pool:
            assert all(s == 200 for s, _ in pool.map(lambda _: _get(port), range(10)))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _workers() > base:
            time.sleep(0.05)
        # Idle workers leave; a new connection starts one again.
        assert _workers() - base <= 1
        assert _get(port)[0] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_server_close_ends_the_workers() -> None:
    base = _workers()
    server = _serve(hold=0.1)
    port = server.server_address[1]
    with ThreadPoolExecutor(8) as pool:
        assert all(s == 200 for s, _ in pool.map(lambda _: _get(port), range(8)))
    assert _workers() > base
    server.shutdown()
    server.server_close()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _workers() > base:
        time.sleep(0.05)
    assert _workers() == base


def test_a_failed_thread_start_leaves_nothing_queued(monkeypatch) -> None:
    server = _serve(hold=0.0)
    try:
        def no_thread(self):
            raise RuntimeError("can't start new thread")

        monkeypatch.setattr(threading.Thread, "start", no_thread)
        try:
            server.process_request(None, ("127.0.0.1", 1))
        except RuntimeError:
            pass
        monkeypatch.undo()
        assert server._workers == 0
        assert server._pool_queue.empty()
    finally:
        server.shutdown()
        server.server_close()
