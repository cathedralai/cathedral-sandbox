"""The API listener must hold a burst of new connections.

Every call to the API is a new TCP connection (HTTP/1.0). With the stdlib
listen backlog of 5, a burst overflowed the queue: Linux dropped the extra
connection attempts and each caller retried 1 s later (measured on the sealed
pool, 11 Nov 2026: 100 commands at once, 15 to 24 of them held for 1 s or more).
"""

from __future__ import annotations

import socket
import threading

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


def test_the_listen_queue_holds_a_burst_while_nothing_accepts() -> None:
    # The listener is bound and listening but nothing accepts yet, so every
    # connection has to fit in the listen queue. They are opened one at a time,
    # so the kernel's count of queued connections is exact for each attempt.
    # With a backlog of 5 the queue is full after a handful and the next
    # connect gets no answer. No timing bound: only whether each one connects.
    httpd = serve(_StubApp())
    host, port = httpd.server_address
    conns: list[socket.socket] = []
    server = threading.Thread(target=httpd.serve_forever, daemon=True)
    started = False
    try:
        for _ in range(BURST):
            try:
                conns.append(socket.create_connection((host, port), timeout=2))
            except OSError:
                break
        assert len(conns) == BURST, f"the listen queue held only {len(conns)} of {BURST} connections"

        for conn in conns:
            conn.sendall(b"GET /v1/status HTTP/1.0\r\n\r\n")
        server.start()
        started = True
        for conn in conns:
            conn.settimeout(30)
            assert conn.recv(64).startswith(b"HTTP/1.0 200"), "a queued connection was not answered"
    finally:
        for conn in conns:
            conn.close()
        if started:
            httpd.shutdown()
        httpd.server_close()
