"""Client for the hotel egress daemon (room kit ``room_egress.py``).

The egress daemon runs as root on the hotel, outside every guest. It owns the
per-room nftables rules, the hotel DNS resolver and the SNI/HTTP egress proxy.
The sandbox API runs as an unprivileged user. It tells the daemon the policy of
each guest over a Unix socket:

    PUT    /rooms/<container_id>   {"sandbox_id": ..., "policy": {"mode", "allow"}}
    DELETE /rooms/<container_id>

The daemon finds the guest address itself (docker inspect on the room daemon),
applies the policy in one nftables transaction and answers with the applied
canonical policy and its sha256. A guest with no applied policy has no egress:
the daemon denies by default.

Setting: CATHEDRAL_ROOM_EGRESS_SOCKET (path of the Unix socket). Unset: no
egress daemon; allowlist and deny_all fail closed to network "none".
"""

from __future__ import annotations

import http.client
import json
import os
import socket
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


class EgressClient:
    def __init__(self, socket_path: str, *, timeout: float = 30.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "EgressClient | None":
        path = os.environ.get("CATHEDRAL_ROOM_EGRESS_SOCKET", "").strip()
        return cls(path) if path else None

    def _call(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        conn = _UnixHTTPConnection(self.socket_path, self.timeout)
        try:
            raw = json.dumps(body).encode() if body is not None else None
            headers = {"Content-Type": "application/json"} if raw is not None else {}
            conn.request(method, path, body=raw, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except OSError as exc:
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
            self._call("DELETE", f"/rooms/{container_id}")
        except SandboxOpError:
            pass
