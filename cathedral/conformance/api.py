"""A small standard-library client for the sandbox API.

Checks look at status codes themselves (a 429 or a 204 is often the thing
under test), so calls return a ``Response`` and never raise on HTTP errors.
The transport is injectable so the checks can run against a fake in tests.
"""

from __future__ import annotations

import json as jsonlib
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

# The public edge refuses generic HTTP library user agents.
USER_AGENT = "cathedral-conformance/0.1"

TERMINAL_STATES = {"failed", "deleted", "deleting"}


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    data: bytes = b""
    elapsed_s: float = 0.0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        try:
            return jsonlib.loads(self.data or b"null")
        except ValueError:
            return None

    def summary(self) -> str:
        body = self.json()
        if isinstance(body, dict):
            detail = body.get("detail")
            nested = detail if isinstance(detail, dict) else {}
            code = (body.get("error_code") or body.get("code") or body.get("error")
                    or nested.get("error_code") or nested.get("code") or nested.get("error"))
            message = body.get("message") or body.get("detail")
            return f"HTTP {self.status} {code or ''} {message or ''}".strip()
        return f"HTTP {self.status}"


# (method, url, headers, body, timeout) -> Response
Transport = Callable[[str, str, dict[str, str], bytes | None, float], Response]


def urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes | None,
                     timeout: float) -> Response:
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            data = reply.read()
            return Response(reply.status, dict(reply.headers), data, time.monotonic() - started)
    except urllib.error.HTTPError as exc:
        return Response(exc.code, dict(exc.headers or {}), exc.read(), time.monotonic() - started)
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        # No answer: status 0, so a check reports it instead of crashing the run.
        return Response(0, {}, str(exc).encode(), time.monotonic() - started)


class Api:
    def __init__(self, base_url: str, api_key: str, *, team: str | None = None,
                 transport: Transport = urllib_transport,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_key}", "User-Agent": USER_AGENT}
        if team:
            self.headers["X-Cathedral-Team"] = team
        self.transport = transport
        self.clock = clock
        self.sleep = sleep

    def call(self, method: str, path: str, *, json: Any = None, params: Any = None,
             body: bytes | None = None, content_type: str | None = None,
             key: str | None = None, timeout: float = 60.0) -> Response:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        headers = dict(self.headers)
        if json is not None:
            body = jsonlib.dumps(json).encode()
            content_type = "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        if key:
            headers["Idempotency-Key"] = key
        return self.transport(method, url, headers, body, timeout)

    # -- sandbox helpers ---------------------------------------------------

    def get_sandbox(self, sandbox_id: str) -> Response:
        return self.call("GET", f"/v1/sandboxes/{sandbox_id}")

    def wait_running(self, sandbox_id: str, timeout_s: float, poll_s: float = 1.0) -> tuple[dict, float]:
        """Poll until the sandbox runs or ends. Returns (last view, seconds waited)."""
        started = self.clock()
        view: dict = {}
        while True:
            reply = self.get_sandbox(sandbox_id)
            if reply.ok:
                view = reply.json() or {}
                if view.get("state") == "running" or view.get("state") in TERMINAL_STATES:
                    return view, self.clock() - started
            if self.clock() - started >= timeout_s:
                return view, self.clock() - started
            self.sleep(poll_s)

    def exec(self, sandbox_id: str, command: str | list[str], *, timeout_seconds: int = 30,
             user: str | None = None) -> Response:
        body: dict[str, Any] = {"command": command, "timeout_seconds": timeout_seconds}
        if user:
            body["user"] = user
        return self.call("POST", f"/v1/sandboxes/{sandbox_id}/exec", json=body,
                         timeout=timeout_seconds + 15)

    def delete(self, sandbox_id: str, *, key: str | None = None) -> Response:
        return self.call("DELETE", f"/v1/sandboxes/{sandbox_id}",
                         key=key or f"conf-delete-{uuid.uuid4().hex}")
