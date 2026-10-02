"""A thin Python SDK for the Cathedral sandbox API (§3 style note).

The requirements say *"A thin Python SDK (async) on top is welcome but not required;
we can write it."*  This is that thin surface: it speaks the documented REST contract
and nothing more, so Harbor/verifiers-style callers get typed-ish helpers over the same
routes the customer's vendor would expose.

It is deliberately transport-agnostic.  A :class:`Transport` turns
``(method, path, headers, body)`` into ``(status, headers, body)``; two are provided:

* :class:`DispatchTransport` calls an in-process :class:`~cathedral.sandbox_server.SandboxApplication`
  directly — no socket — which is how the SDK is unit-tested here.
* :class:`HttpTransport` talks to a real listener (``serve(...)`` or the hosted
  ``cathedral.computer`` API) over ``urllib``.

Errors are surfaced as :class:`SandboxAPIError` carrying the stable ``code`` from the
spec's JSON error body, so callers can branch on ``quota_exhausted`` / ``key_revoked`` /
``range_not_satisfiable`` and so on rather than parsing prose.

Async is intentionally left as an exercise (the spec says "we can write it"); keeping the
transport synchronous keeps this module dependency-free and trivially testable.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


class Transport(Protocol):
    """The one operation the SDK needs: perform an HTTP request, return the response."""

    def request(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, Mapping[str, str], bytes]: ...


class SandboxAPIError(RuntimeError):
    """A non-2xx response, carrying the spec's stable error ``code``."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


@dataclass
class DispatchTransport:
    """Drive a :class:`SandboxApplication` in-process (used by the tests)."""

    app: Any
    api_key: str = "k1"

    def request(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, Mapping[str, str], bytes]:
        resp = self.app.dispatch(method, path, dict(headers), body)
        return resp.status, resp.headers, resp.body


@dataclass
class HttpTransport:
    """Talk to a real HTTP listener (``serve(...)`` or the hosted runtime)."""

    base_url: str
    api_key: str

    def request(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> tuple[int, Mapping[str, str], bytes]:
        url = self.base_url.rstrip("/") + path
        req = urllib.request.Request(url, data=body or None, method=method)
        for key, value in headers.items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req) as response:  # noqa: S310 - fixed local/hosted base URL
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:  # 4xx/5xx still carry a JSON error body
            return exc.code, dict(exc.headers or {}), exc.read()


class SandboxClient:
    """Thin wrapper over the §3 REST surface.

    ``base_url``/``api_key`` build an :class:`HttpTransport`; pass an explicit
    ``transport`` (e.g. a :class:`DispatchTransport`) to drive the API in-process.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        transport: Transport | None = None,
    ) -> None:
        if transport is None:
            if not base_url or not api_key:
                raise ValueError("SandboxClient needs base_url+api_key or an explicit transport")
            transport = HttpTransport(base_url, api_key)
            self._api_key = api_key
        else:
            self._api_key = getattr(transport, "api_key", api_key) or ""
        self._transport = transport

    # ------------------------------------------------------------------ plumbing
    def _headers(self, *, idempotency: str | None = None, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self._api_key}"}
        if idempotency is not None:
            headers["Idempotency-Key"] = idempotency
        if extra:
            headers.update(extra)
        return headers

    def _call(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        expect_json: bool = True,
    ) -> Any:
        status, resp_headers, raw = self._transport.request(method, path, dict(headers or {}), body or b"")
        payload: Any
        if expect_json and raw:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = raw
        else:
            payload = raw
        if 200 <= status < 300:
            return payload, resp_headers
        code = "error"
        message = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        if isinstance(payload, dict) and "error" in payload:
            code = payload["error"].get("code", code)
            message = payload["error"].get("message", message)
        raise SandboxAPIError(status, code, message)

    def _json(self, method: str, path: str, payload: Any = None, **kw: Any) -> Any:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        result, _ = self._call(method, path, body=body, **kw)
        return result

    # ------------------------------------------------------------------ §3.1 create / read / list
    def create(
        self,
        *,
        image: str | None = None,
        snapshot_id: str | None = None,
        build: Mapping[str, Any] | None = None,
        resources: Mapping[str, Any] | None = None,
        env: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
        ttl_seconds: int | None = None,
        count: int = 1,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if image is not None:
            body["image"] = image
        if snapshot_id is not None:
            body["snapshot_id"] = snapshot_id
        if build is not None:
            body["build"] = dict(build)
        if resources is not None:
            body["resources"] = dict(resources)
        if env:
            body["env"] = dict(env)
        if labels:
            body["labels"] = dict(labels)
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if count != 1:
            body["count"] = count
        return self._json(
            "POST", "/v1/sandboxes", body,
            headers=self._headers(idempotency=idempotency_key),
        )

    def get(self, sandbox_id: str) -> dict[str, Any]:
        return self._json("GET", f"/v1/sandboxes/{sandbox_id}", None, headers=self._headers())

    def wait(self, sandbox_id: str, timeout_seconds: int = 120) -> dict[str, Any]:
        return self._json(
            "POST", f"/v1/sandboxes/{sandbox_id}/wait", {"timeout_seconds": timeout_seconds},
            headers=self._headers(),
        )

    def list(self, *, labels: Sequence[str] = (), state: str | None = None) -> list[dict[str, Any]]:
        query = _query(label=list(labels), state=state)
        doc = self._json("GET", f"/v1/sandboxes{query}", None, headers=self._headers())
        return doc["sandboxes"]

    def delete(self, sandbox_id: str) -> None:
        self._call("DELETE", f"/v1/sandboxes/{sandbox_id}", headers=self._headers(), expect_json=False)

    def bulk_delete(self, *, labels: Sequence[str]) -> None:
        query = _query(label=list(labels))
        self._call("DELETE", f"/v1/sandboxes{query}", headers=self._headers(), expect_json=False)

    # ------------------------------------------------------------------ §3.2 exec / processes
    def exec(
        self,
        sandbox_id: str,
        cmd: str | Sequence[str],
        *,
        timeout_seconds: int | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        stdin: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"cmd": cmd if isinstance(cmd, str) else list(cmd)}
        if timeout_seconds is not None:
            body["timeout_seconds"] = timeout_seconds
        if env:
            body["env"] = dict(env)
        if cwd is not None:
            body["cwd"] = cwd
        if stdin is not None:
            body["stdin"] = stdin
        return self._json("POST", f"/v1/sandboxes/{sandbox_id}/exec", body, headers=self._headers())

    def start_process(self, sandbox_id: str, cmd: str | Sequence[str]) -> dict[str, Any]:
        body = {"cmd": cmd if isinstance(cmd, str) else list(cmd)}
        return self._json("POST", f"/v1/sandboxes/{sandbox_id}/processes", body, headers=self._headers())

    def process_logs(self, sandbox_id: str, process_id: str) -> str:
        doc = self._json("GET", f"/v1/sandboxes/{sandbox_id}/processes/{process_id}/logs", None, headers=self._headers())
        return doc["logs"]

    def stop_process(self, sandbox_id: str, process_id: str) -> None:
        self._call("DELETE", f"/v1/sandboxes/{sandbox_id}/processes/{process_id}", headers=self._headers(), expect_json=False)

    # ------------------------------------------------------------------ §3.3 files / tar / stat
    def write_file(self, sandbox_id: str, path: str, data: bytes, *, mode: int | None = None) -> dict[str, Any]:
        query = _query(path=path, mode=oct(mode)[-4:] if mode is not None else None)
        return self._call(
            "PUT", f"/v1/sandboxes/{sandbox_id}/files{query}", body=data, headers=self._headers(),
        )[0]

    def read_file(self, sandbox_id: str, path: str, *, max_bytes: int | None = None, range_header: str | None = None) -> bytes:
        query = _query(path=path, max_bytes=max_bytes)
        headers = self._headers(extra={"Range": range_header} if range_header else None)
        return self._call("GET", f"/v1/sandboxes/{sandbox_id}/files{query}", headers=headers, expect_json=False)[0]

    def write_tar(self, sandbox_id: str, path: str, tarball: bytes) -> dict[str, Any]:
        query = _query(path=path)
        return self._call("PUT", f"/v1/sandboxes/{sandbox_id}/tar{query}", body=tarball, headers=self._headers())[0]

    def read_tar(self, sandbox_id: str, path: str) -> bytes:
        query = _query(path=path)
        return self._call("GET", f"/v1/sandboxes/{sandbox_id}/tar{query}", headers=self._headers(), expect_json=False)[0]

    def stat(self, sandbox_id: str, path: str) -> dict[str, Any]:
        query = _query(path=path)
        return self._json("GET", f"/v1/sandboxes/{sandbox_id}/stat{query}", None, headers=self._headers())

    # ------------------------------------------------------------------ §3.4 lifecycle
    def heartbeat(self, sandbox_id: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        return self._json(
            "POST", f"/v1/sandboxes/{sandbox_id}/heartbeat",
            {"ttl_seconds": ttl_seconds} if ttl_seconds is not None else {},
            headers=self._headers(),
        )

    # ------------------------------------------------------------------ §3.5 snapshot / fork
    def snapshot(self, sandbox_id: str) -> dict[str, Any]:
        return self._json("POST", f"/v1/sandboxes/{sandbox_id}/snapshot", {}, headers=self._headers())

    def fork(self, snapshot_id: str, count: int = 1, **kw: Any) -> dict[str, Any]:
        return self.create(snapshot_id=snapshot_id, count=count, **kw)

    def list_snapshots(self) -> list[dict[str, Any]]:
        return self._json("GET", "/v1/snapshots", None, headers=self._headers())["snapshots"]

    def delete_snapshot(self, snapshot_id: str) -> bool:
        return self._json("DELETE", f"/v1/snapshots/{snapshot_id}", None, headers=self._headers())["deleted"]

    # ------------------------------------------------------------------ §3.7 network / expose
    def set_network(self, sandbox_id: str, mode: str, allow: Sequence[str] = ()) -> dict[str, Any]:
        return self._json(
            "POST", f"/v1/sandboxes/{sandbox_id}/network",
            {"mode": mode, "allow": list(allow)},
            headers=self._headers(),
        )

    def expose(self, sandbox_id: str, port: int) -> dict[str, Any]:
        return self._json("POST", f"/v1/sandboxes/{sandbox_id}/expose", {"port": port}, headers=self._headers())

    # ------------------------------------------------------------------ §3.9 images
    def prefetch(self, images: Sequence[str]) -> str:
        return self._json("POST", "/v1/images/prefetch", {"images": list(images)}, headers=self._headers())["operation_id"]

    def image_status(self, ref: str) -> dict[str, Any]:
        return self._json("GET", f"/v1/images/{ref}", None, headers=self._headers())

    # ------------------------------------------------------------------ §3.13 logs / usage / status
    def logs(self, sandbox_id: str) -> dict[str, Any]:
        return self._json("GET", f"/v1/sandboxes/{sandbox_id}/logs", None, headers=self._headers())

    def quota(self) -> dict[str, Any]:
        return self._json("GET", "/v1/quota", None, headers=self._headers())

    def usage(self, *, group_by: str = "label.job", labels: Sequence[str] = ()) -> dict[str, Any]:
        query = _query(group_by=group_by, label=list(labels))
        return self._json("GET", f"/v1/usage{query}", None, headers=self._headers())

    def status(self) -> dict[str, Any]:
        return self._json("GET", "/v1/status", None, headers=self._headers())

    def get_operation(self, operation_id: str) -> dict[str, Any]:
        return self._json("GET", f"/v1/operations/{operation_id}", None, headers=self._headers())


def _query(**params: Any) -> str:
    from urllib.parse import urlencode

    pairs: list[tuple[str, Any]] = []
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            for item in value:
                pairs.append((key, item))
        else:
            pairs.append((key, value))
    return "?" + urlencode(pairs) if pairs else ""


__all__ = [
    "DispatchTransport",
    "HttpTransport",
    "SandboxAPIError",
    "SandboxClient",
    "Transport",
]
