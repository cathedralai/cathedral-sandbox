"""The API listener must hold a burst of new connections.

Every call to the API is a new TCP connection (HTTP/1.0). With the stdlib
listen backlog of 5, a burst overflowed the queue: Linux dropped the extra
connection attempts and each caller retried 1 s later (measured on the sealed
pool, 11 Nov 2026: 100 commands at once, 15 to 24 of them held for 1 s or more).
"""

from __future__ import annotations

import http.client
import threading
import time

from cathedral.sandbox_server import Response, serve

BURST = 64


class _StubApp:
    def dispatch(self, method, path, headers, body):  # noqa: ANN001, ARG002
        return Response.json(200, {})


def test_listener_asks_for_a_backlog_of_1024() -> None:
    httpd = serve(_StubApp())
    try:
        assert httpd.request_queue_size == 1024
    finally:
        httpd.server_close()


def test_a_burst_of_new_connections_is_answered_without_a_connect_retry() -> None:
    # The listener is bound and listening but nothing accepts yet, so every
    # connection of the burst has to fit in the listen queue. With a backlog of
    # 5 the kernel drops or resets the rest: on Linux they come back 1 s later.
    httpd = serve(_StubApp())
    host, port = httpd.server_address
    results: list[tuple[int | None, float]] = [(None, 0.0)] * BURST

    def one(i: int) -> None:
        start = time.monotonic()
        status = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/v1/status")
            status = conn.getresponse().status
            conn.close()
        except OSError:
            pass
        results[i] = (status, time.monotonic() - start)

    callers = [threading.Thread(target=one, args=(i,)) for i in range(BURST)]
    server = threading.Thread(target=httpd.serve_forever, daemon=True)
    try:
        for t in callers:
            t.start()
        time.sleep(0.1)
        server.start()
        for t in callers:
            t.join(timeout=10)
    finally:
        httpd.shutdown()
        httpd.server_close()

    answered = [seconds for status, seconds in results if status == 200]
    assert len(answered) == BURST, f"{BURST - len(answered)} of {BURST} connections got no answer"
    assert max(answered) < 0.7, f"slowest answer took {max(answered):.2f} s: a connect retry"
