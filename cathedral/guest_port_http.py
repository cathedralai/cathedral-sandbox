"""Hotel-mediated HTTP dial to 127.0.0.1:<port> inside a room (AB#605).

The sealed port URL proxy asks the hotel to reach a guest localhost port.
This module runs that hop: one HTTP request/response through the room's
network namespace (or the process host for the in-memory provider).

Raw TCP streaming and broker byte-streaming remain build-card work; this
path is enough for the spike's staging curl→200 proof once hotels ship it.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import quote, urlencode

from cathedral.sandbox_provider import SandboxOpError

# Headers the hotel never forwards into the guest (Cathedral / hop metadata).
_DROP_REQUEST = frozenset({
    "authorization", "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
    "host", "content-length", "x-guest-method", "x-guest-target",
    "x-access-token", "x-api-key", "cookie",
})
_DROP_RESPONSE = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
})


@dataclass(frozen=True)
class GuestHttpResult:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


def _target(path: str, query: str) -> str:
    target = path if path.startswith("/") else f"/{path}"
    if query:
        return f"{target}?{query}"
    return target


def _request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in _DROP_REQUEST
    }


def dial_loopback(
    port: int,
    *,
    method: str,
    path: str,
    query: str = "",
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    timeout_seconds: float = 30.0,
) -> GuestHttpResult:
    """HTTP round-trip to 127.0.0.1:<port> in the current network namespace."""
    if port < 1 or port > 65535:
        raise SandboxOpError("invalid_port", 400, f"port must be 1..65535, got {port}")
    method = method.upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise SandboxOpError("invalid_method", 400, f"unsupported method {method}")
    target = _target(path or "/", query or "")
    forwarded = _request_headers(headers or {})
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_seconds)
        try:
            conn.request(method, target, body=body or None, headers=forwarded)
            response = conn.getresponse()
            raw_headers = tuple(
                (name, value)
                for name, value in response.getheaders()
                if name.lower() not in _DROP_RESPONSE
            )
            payload = response.read() if method != "HEAD" else b""
            return GuestHttpResult(status=int(response.status), headers=raw_headers, body=payload)
        finally:
            conn.close()
    except (OSError, http.client.HTTPException) as exc:
        raise SandboxOpError(
            "port_unreachable",
            502,
            f"nothing answered on 127.0.0.1:{port}: {type(exc).__name__}",
        ) from exc


_NSENTER_SCRIPT = r"""
import http.client, json, sys
port = int(sys.argv[1])
method = sys.argv[2]
target = sys.argv[3]
timeout = float(sys.argv[4])
header_count = int(sys.argv[5])
headers = {}
args = sys.argv[6:]
for i in range(header_count):
    name = args[i * 2]
    value = args[i * 2 + 1]
    headers[name] = value
body = sys.stdin.buffer.read()
try:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, target, body=body or None, headers=headers)
        response = conn.getresponse()
        payload = response.read() if method != "HEAD" else b""
        meta = {
            "status": int(response.status),
            "headers": [[n, v] for n, v in response.getheaders()],
            "body_len": len(payload),
        }
        sys.stdout.buffer.write(json.dumps(meta).encode() + b"\n")
        sys.stdout.buffer.write(payload)
    finally:
        conn.close()
except Exception as exc:  # noqa: BLE001 — hotel maps this to port_unreachable
    sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
    sys.exit(2)
"""


def dial_container_loopback(
    container_id: str,
    port: int,
    *,
    method: str,
    path: str,
    query: str = "",
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    timeout_seconds: float = 30.0,
    nsenter: str = "/usr/bin/nsenter",
    docker: str = "docker",
) -> GuestHttpResult:
    """Dial 127.0.0.1:<port> inside a Docker room via its network namespace."""
    if port < 1 or port > 65535:
        raise SandboxOpError("invalid_port", 400, f"port must be 1..65535, got {port}")
    method = method.upper()
    inspect = subprocess.run(
        [docker, "inspect", "--format",
         "{{.NetworkSettings.SandboxKey}} {{.State.Running}} {{.HostConfig.Runtime}}", container_id],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if inspect.returncode != 0:
        raise SandboxOpError("sandbox_not_found", 404, f"container {container_id} is gone")
    parts = inspect.stdout.strip().split()
    if len(parts) < 2 or parts[1].lower() != "true":
        raise SandboxOpError("sandbox_not_running", 409, "the room is not running")
    netns = parts[0]
    runtime = parts[2] if len(parts) > 2 else ""
    if _runtime_has_own_kernel(runtime):
        # AB#772: gVisor (and Kata) keep the guest's network stack inside
        # the sandbox. The Docker netns loopback is not the guest's, so a
        # dial there is always refused. Dial from inside the room instead.
        return _dial_in_room(
            container_id, port, method=method, path=path, query=query,
            headers=headers, body=body, timeout_seconds=timeout_seconds, docker=docker,
        )
    if not netns or netns == "<no":
        raise SandboxOpError("port_unreachable", 502, "the room has no network namespace to dial")
    if not os.path.exists(netns):
        raise SandboxOpError("port_unreachable", 502, f"room netns missing: {netns}")
    argv = [nsenter, f"--net={netns}", sys.executable, "-c", _NSENTER_SCRIPT,
            *_script_args(port, method, path, query, headers, timeout_seconds)]
    return _run_dial(argv, port, body=body, timeout_seconds=timeout_seconds)


def _runtime_has_own_kernel(runtime: str) -> bool:
    # Same rule as sandbox_guest.runtime_has_kernel_isolation, kept local so
    # this module does not import the Docker provider.
    name = (runtime or "").strip().lower()
    return name.startswith("runsc") or "kata" in name


def _script_args(port, method, path, query, headers, timeout_seconds) -> list[str]:
    target = _target(path or "/", query or "")
    forwarded = _request_headers(headers or {})
    flat: list[str] = []
    for name, value in forwarded.items():
        flat.extend([name, value])
    return [str(port), method, target, str(timeout_seconds), str(len(forwarded)), *flat]


def _dial_in_room(
    container_id: str,
    port: int,
    *,
    method: str,
    path: str,
    query: str,
    headers: Mapping[str, str] | None,
    body: bytes,
    timeout_seconds: float,
    docker: str,
) -> GuestHttpResult:
    """Run the dial script inside the room with the room's own python3."""
    argv = [docker, "exec", "-i", container_id, "python3", "-c", _NSENTER_SCRIPT,
            *_script_args(port, method, path, query, headers, timeout_seconds)]
    return _run_dial(argv, port, body=body, timeout_seconds=timeout_seconds, in_room=True)


_BAD_HEADER = re.compile(r"[\r\n\x00]")


def _run_dial(argv: list[str], port: int, *, body: bytes, timeout_seconds: float,
              in_room: bool = False) -> GuestHttpResult:
    try:
        completed = subprocess.run(
            argv,
            input=body or b"",
            capture_output=True,
            timeout=max(timeout_seconds + 5.0, 10.0),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxOpError("port_unreachable", 502, f"dial timed out on 127.0.0.1:{port}") from exc
    except FileNotFoundError as exc:
        tool = "docker" if in_room else "nsenter"
        raise SandboxOpError("port_unreachable", 502, f"{tool} is not installed on this hotel") from exc
    if in_room and completed.returncode in (126, 127):
        # docker exec: the command could not run (no python3 in the image).
        raise SandboxOpError(
            "port_unreachable", 502,
            "this room's image has no python3, which a port dial into a gVisor room needs",
        )
    if completed.returncode != 0:
        detail = (completed.stderr or b"").decode("utf-8", "replace").strip()[:200]
        raise SandboxOpError(
            "port_unreachable",
            502,
            detail or f"nothing answered on 127.0.0.1:{port}",
        )
    raw = completed.stdout
    try:
        head, _, rest = raw.partition(b"\n")
        meta = json.loads(head.decode("utf-8"))
        body_len = int(meta["body_len"])
        payload = rest[:body_len]
        status = int(meta["status"])
        if not 100 <= status <= 599:
            raise ValueError("status out of range")
        headers_out = tuple(
            (str(name), str(value))
            for name, value in meta.get("headers") or []
            if str(name).lower() not in _DROP_RESPONSE
        )
        # In a gVisor room the guest writes this JSON line itself: never let a CR, LF
        # or NUL reach send_header, where it would split the hotel's own response.
        if any(_BAD_HEADER.search(n) or _BAD_HEADER.search(v) for n, v in headers_out):
            raise ValueError("control character in a guest header")
        return GuestHttpResult(status=status, headers=headers_out, body=payload)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SandboxOpError("port_unreachable", 502, "hotel dial returned a broken answer") from exc


def encode_query(query: Mapping[str, list[str]] | None) -> str:
    if not query:
        return ""
    pairs: list[tuple[str, str]] = []
    for key, values in query.items():
        for value in values:
            pairs.append((key, value))
    return urlencode(pairs, quote_via=quote)
