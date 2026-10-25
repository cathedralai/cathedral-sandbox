"""Client for the hotel egress daemon (room kit ``room_egress.py``).

The egress daemon runs as root on the hotel, outside every guest. It owns the
per-room nftables rules, the hotel DNS resolver and the SNI/HTTP egress proxy.
The sandbox API runs as an unprivileged user. It tells the daemon the policy of
each guest over a Unix socket:

    PUT    /rooms/<container_id>   {"sandbox_id": ..., "policy": {"mode", "allow"}}
    DELETE /rooms/<container_id>

The daemon finds the guest address itself (Engine API of the room daemon),
applies the policy in one nftables transaction and answers with the applied
canonical policy and its sha256. A guest with no applied policy has no egress:
the daemon denies by default.

Settings:
  CATHEDRAL_ROOM_EGRESS_SOCKET   path of the Unix socket. Unset: no egress
                                 daemon; allowlist and deny_all fail closed to
                                 network "none".
  CATHEDRAL_ROOM_EGRESS_TIMEOUT  seconds to wait for one answer (default 120,
                                 5 to 600). The daemon asks the room docker
                                 daemon for the guest address. In a create
                                 storm that answer can take many seconds
                                 (#298).
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import time
from typing import Any, Mapping

from cathedral.sandbox_provider import SandboxOpError


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


DEFAULT_TIMEOUT = 120.0
# The daemon restarts in about 1 s (Restart=always, RestartSec=1). A call that
# finds no listener tries again for about this long. A call that timed out is
# not sent again: the daemon may still be working on it.
CONNECT_RETRY_SECONDS = 5.0
FORGET_TIMEOUT = 30.0


def _env_timeout() -> float:
    raw = os.environ.get("CATHEDRAL_ROOM_EGRESS_TIMEOUT", "").strip()
    try:
        value = float(raw) if raw else DEFAULT_TIMEOUT
    except ValueError:
        value = DEFAULT_TIMEOUT
    return min(max(value, 5.0), 600.0)


class _NotConnected(Exception):
    def __init__(self, exc: OSError) -> None:
        super().__init__(str(exc))
        self.exc = exc


class EgressClient:
    def __init__(
        self, socket_path: str, *, timeout: float = DEFAULT_TIMEOUT, connect_retry: float = CONNECT_RETRY_SECONDS
    ) -> None:
        self.socket_path = socket_path
        self.timeout = timeout
        self.connect_retry = connect_retry

    @classmethod
    def from_env(cls) -> "EgressClient | None":
        path = os.environ.get("CATHEDRAL_ROOM_EGRESS_SOCKET", "").strip()
        return cls(path, timeout=_env_timeout()) if path else None

    def _call(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,
        connect_retry: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        deadline = time.monotonic() + (self.connect_retry if connect_retry is None else connect_retry)
        delay = 0.2
        while True:
            try:
                return self._call_once(method, path, body, timeout or self.timeout)
            except _NotConnected as nc:
                if time.monotonic() + delay > deadline:
                    raise SandboxOpError(
                        "egress_unavailable", 503, f"hotel egress daemon did not answer: {nc.exc}", retry_after=10
                    ) from None
                time.sleep(delay)
                delay = min(delay * 2, 1.0)

    def _call_once(
        self, method: str, path: str, body: Mapping[str, Any] | None, timeout: float
    ) -> tuple[int, dict[str, Any]]:
        conn = _UnixHTTPConnection(self.socket_path, timeout)
        try:
            try:
                conn.connect()
            except (FileNotFoundError, ConnectionRefusedError, BlockingIOError) as exc:
                # No listener (a restart) or a full backlog: nothing was sent.
                raise _NotConnected(exc) from None
            raw = json.dumps(body).encode() if body is not None else None
            headers = {"Content-Type": "application/json"} if raw is not None else {}
            conn.request(method, path, body=raw, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            raise SandboxOpError(
                "egress_unavailable", 503, f"hotel egress daemon did not answer: {exc}", retry_after=10
            ) from None
        finally:
            conn.close()
        try:
            doc = json.loads(data) if data else {}
        except ValueError:
            doc = {}
        return resp.status, doc

    def apply(self, container_id: str, sandbox_id: str, policy: Mapping[str, Any]) -> dict[str, Any]:
        """Apply *policy* to the guest. Return the daemon's answer (ip, policy, policy_sha256)."""
        status, doc = self._call("PUT", f"/rooms/{container_id}", {"sandbox_id": sandbox_id, "policy": dict(policy)})
        if status != 200:
            err = doc.get("error") if isinstance(doc.get("error"), dict) else {}
            raise SandboxOpError(
                "egress_unavailable",
                503,
                f"hotel egress daemon refused the policy ({status}): {err.get('message') or doc}"[:400],
                retry_after=10,
            )
        if doc.get("policy") != dict(policy):
            raise SandboxOpError("egress_unavailable", 503, "hotel egress daemon applied a different policy")
        return doc

    def forget(self, container_id: str) -> None:
        """Drop the guest's policy (deny by default). Best effort: the daemon
        also drops policies of containers that are gone."""
        try:
            # Short, and no wait for a restart: a delete must not wait on a
            # busy daemon. The daemon's reconcile pass drops the policy of a
            # gone container anyway.
            self._call("DELETE", f"/rooms/{container_id}", timeout=min(self.timeout, FORGET_TIMEOUT), connect_retry=0)
        except SandboxOpError:
            pass
