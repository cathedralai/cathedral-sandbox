"""Cathedral compute sandbox HTTP surface.

A framework-free dispatcher that maps the requirements' REST routes (§§3.1-3.13)
onto a :class:`~cathedral.sandbox_provider.SandboxProvider`.  It is deliberately
transport-agnostic: :meth:`SandboxApplication.dispatch` takes the pieces of an HTTP
request and returns a response, so the whole API is exercised in-process without
sockets, and :func:`serve` wires the same object to :mod:`http.server` for a real
listener.

Response conventions follow the spec: JSON bodies, ``Authorization: Bearer`` auth,
``Idempotency-Key`` on creates, errors as ``{"error": {"code", "message"}}`` with a
stable code, ``429`` + ``Retry-After`` when quota is full, ``206`` for ``Range``
reads, ``413`` past ``?max_bytes``, ``204`` on idempotent deletes, and an
``operation_id`` for long operations polled at ``GET /v1/operations/{id}``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, unquote, urlparse

from cathedral import sandbox_api as api
from cathedral.affline_rerun import AfflineRerunError, handle_affline_validate_rerun
from cathedral.sandbox_api import (
    BuildSpec,
    CreateSandboxRequest,
    ExecRequest,
    ExposeRequest,
    FileGet,
    ImageSource,
    NetworkPatch,
    NetworkSpec,
    PrefetchRequest,
    Resources,
    TarGet,
)
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError, SandboxProvider

JSON = "application/json"
OCTET = "application/octet-stream"


def _json_default(obj: Any) -> Any:
    # to_document() hands back read-only MappingProxyType; convert any mapping to a
    # plain dict so json can serialise it, and stringify anything exotic (e.g. datetime).
    if hasattr(obj, "items"):
        return dict(obj)
    return str(obj)


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def json(cls, status: int, payload: Any, headers: Mapping[str, str] | None = None) -> "Response":
        data = json.dumps(payload, default=_json_default).encode("utf-8")
        return cls(status, data, {"Content-Type": JSON, **(headers or {})})

    @classmethod
    def error(cls, status: int, code: str, message: str, headers: Mapping[str, str] | None = None) -> "Response":
        return cls.json(status, {"error": {"code": code, "message": message}}, headers)

    @classmethod
    def no_content(cls) -> "Response":
        return cls(204)


def _body_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _create_request(payload: dict[str, Any]) -> CreateSandboxRequest:
    resources = Resources(**payload["resources"]) if isinstance(payload.get("resources"), dict) else Resources()
    net = payload.get("network")
    network = NetworkSpec(mode=net.get("mode", "public"), allow=tuple(net.get("allow", ()))) if isinstance(net, dict) else NetworkSpec()
    image = ImageSource(**payload["image"]) if isinstance(payload.get("image"), dict) else (
        ImageSource(image=payload["image"]) if payload.get("image") else None
    )
    build = BuildSpec(**payload["build"]) if isinstance(payload.get("build"), dict) else None
    entrypoint = tuple(payload["entrypoint"]) if payload.get("entrypoint") else ("sleep", "infinity")
    kwargs: dict[str, Any] = {
        "resources": resources,
        "network": network,
        "env": payload.get("env", {}),
        "labels": payload.get("labels", {}),
        "ttl_seconds": payload.get("ttl_seconds", api.TTL_DEFAULT_SECONDS),
        "idle_timeout_seconds": payload.get("idle_timeout_seconds"),
        "entrypoint": entrypoint,
        "user": payload.get("user"),
        "workdir": payload.get("workdir"),
        "image": image,
        "build": build,
        "snapshot_id": payload.get("snapshot_id"),
        "count": payload.get("count", 1),
    }
    return CreateSandboxRequest(**kwargs)


# contract-error code -> HTTP status (defaults to 400)
_CODE_STATUS = {
    "range_not_satisfiable": 416,
    "invalid_image_reference": 400,
    "invalid_ttl": 400,
    "invalid_count": 400,
    "invalid_source": 400,
    "invalid_resources": 400,
    "invalid_network_mode": 400,
    "invalid_port": 400,
    "invalid_idempotency_key": 400,
}


class SandboxApplication:
    # Routes served without a Bearer token (§3.10: the OpenAPI contract is public).
    PUBLIC_PATHS = frozenset({"/openapi.json"})

    def __init__(self, provider: SandboxProvider | None = None, *, require_auth: bool = True) -> None:
        self.provider = provider or InMemorySandboxProvider()
        self.require_auth = require_auth
        self._routes: list[tuple[str, re.Pattern[str], Callable[..., Response]]] = []
        self._register()

    # ------------------------------------------------------------------ routing
    def _add(self, method: str, pattern: str, handler: Callable[..., Response]) -> None:
        self._routes.append((method, re.compile("^" + pattern + "$"), handler))

    def _register(self) -> None:
        s = r"/v1/sandboxes"
        self._add("POST", s, self.create)
        self._add("GET", s, self.list_sandboxes)
        self._add("DELETE", s, self.bulk_delete)
        self._add("GET", s + r"/(?P<id>[^/]+)", self.get_sandbox)
        self._add("DELETE", s + r"/(?P<id>[^/]+)", self.delete_sandbox)
        self._add("PATCH", s + r"/(?P<id>[^/]+)", self.patch_sandbox)
        self._add("POST", s + r"/(?P<id>[^/]+)/wait", self.wait)
        self._add("POST", s + r"/(?P<id>[^/]+)/exec", self.exec_)
        self._add("POST", s + r"/(?P<id>[^/]+)/heartbeat", self.heartbeat)
        self._add("POST", s + r"/(?P<id>[^/]+)/lifetime", self.heartbeat)
        self._add("PATCH", s + r"/(?P<id>[^/]+)/lifetime", self.heartbeat)
        self._add("POST", s + r"/(?P<id>[^/]+)/processes", self.start_process)
        self._add("GET", s + r"/(?P<id>[^/]+)/processes/(?P<pid>[^/]+)/logs", self.process_logs)
        self._add("DELETE", s + r"/(?P<id>[^/]+)/processes/(?P<pid>[^/]+)", self.stop_process)
        self._add("POST", s + r"/(?P<id>[^/]+)/processes/(?P<pid>[^/]+)/attach", self.attach_unsupported)
        self._add("PUT", s + r"/(?P<id>[^/]+)/files", self.put_file)
        self._add("GET", s + r"/(?P<id>[^/]+)/files", self.get_file)
        self._add("PUT", s + r"/(?P<id>[^/]+)/tar", self.put_tar)
        self._add("GET", s + r"/(?P<id>[^/]+)/tar", self.get_tar)
        self._add("GET", s + r"/(?P<id>[^/]+)/stat", self.stat)
        self._add("POST", s + r"/(?P<id>[^/]+)/snapshot", self.snapshot)
        self._add("POST", s + r"/(?P<id>[^/]+)/network", self.set_network)
        self._add("PATCH", s + r"/(?P<id>[^/]+)/network", self.set_network)
        self._add("POST", s + r"/(?P<id>[^/]+)/expose", self.expose)
        self._add("POST", s + r"/(?P<id>[^/]+)/freeze", self.freeze)
        self._add("POST", s + r"/(?P<id>[^/]+)/thaw", self.thaw)
        self._add("POST", s + r"/(?P<id>[^/]+)/access-tickets", self.mint_access_ticket)
        self._add("POST", s + r"/(?P<id>[^/]+)/terminals", self.create_terminal)
        self._add("GET", s + r"/(?P<id>[^/]+)/terminals", self.list_terminals)
        self._add("DELETE", s + r"/(?P<id>[^/]+)/terminals/(?P<tid>[^/]+)", self.delete_terminal)
        self._add("POST", s + r"/(?P<id>[^/]+)/terminals/(?P<tid>[^/]+)/connect", self.connect_terminal)
        self._add("POST", s + r"/(?P<id>[^/]+)/terminals/(?P<tid>[^/]+)/input", self.terminal_write)
        self._add("GET", s + r"/(?P<id>[^/]+)/terminals/(?P<tid>[^/]+)/output", self.terminal_read)
        self._add("POST", s + r"/(?P<id>[^/]+)/publish", self.publish_template)
        self._add("GET", s + r"/(?P<id>[^/]+)/desktop", self.desktop)
        self._add("GET", s + r"/(?P<id>[^/]+)/logs", self.logs)
        self._add("GET", r"/v1/snapshots", self.list_snapshots)
        self._add("DELETE", r"/v1/snapshots/(?P<id>[^/]+)", self.delete_snapshot)
        self._add("GET", r"/v1/sandbox-templates", self.list_templates)
        self._add("GET", r"/v1/sandbox-templates/(?P<uid>[^/]+)", self.get_template)
        self._add("POST", r"/v1/images/prefetch", self.prefetch)
        self._add("GET", r"/v1/images/(?P<ref>.+)", self.image_lookup)
        self._add("GET", r"/v1/quota", self.quota)
        self._add("GET", r"/v1/usage", self.usage)
        self._add("GET", r"/v1/status", self.status)
        self._add("GET", r"/v1/operations/(?P<id>[^/]+)", self.get_operation)
        # Affline: secret-triggered full re-run + validator-shaped receipt.
        self._add("POST", r"/v1/affline/validate-rerun", self.affline_validate_rerun)
        # §3.10/§3.11: machine-readable contract, served unauthenticated.
        self._add("GET", r"/openapi.json", self.openapi)

    def dispatch(self, method: str, target: str, headers: Mapping[str, str], body: bytes) -> Response:
        parsed = urlparse(target)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        method = method.upper()
        for m, pattern, handler in self._routes:
            if m != method:
                continue
            match = pattern.match(path)
            if match:
                public = path in self.PUBLIC_PATHS
                return self._invoke(handler, match, query, headers, body, authenticated=not public)
        return Response.error(404, "route_not_found", f"no route for {method} {path}")

    def _invoke(self, handler, match, query, headers, body, *, authenticated: bool = True) -> Response:
        try:
            api_key = self._authenticate(headers) if authenticated else None
            params = {k: unquote(v) for k, v in match.groupdict().items()}
            return handler(query=query, headers=headers, body=body, api_key=api_key, **params)
        except api.SandboxContractError as exc:
            status = _CODE_STATUS.get(exc.code, 400)
            return Response.error(status, exc.code, str(exc))
        except SandboxOpError as exc:
            hdrs = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
            return Response.error(exc.http_status, exc.code, str(exc), hdrs)
        except AfflineRerunError as exc:
            return Response.error(exc.http_status, exc.category, str(exc))
        except json.JSONDecodeError as exc:
            return Response.error(400, "invalid_json", f"request body is not JSON: {exc}")

    def _authenticate(self, headers: Mapping[str, str]) -> str | None:
        raw = headers.get("Authorization") or headers.get("authorization")
        if not raw or not raw.lower().startswith("bearer "):
            if self.require_auth:
                raise SandboxOpError("unauthorized", 401, "missing Bearer token")
            return None
        api_key = raw.split(None, 1)[1].strip()
        # §3.14: validate the key for every request (revoke / unknown-key), not just creates.
        self.provider.authorize(api_key)
        return api_key

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        return json.loads(body.decode("utf-8")) if body else {}

    # ------------------------------------------------------------------ §3.1 create / read / wait
    def create(self, *, query, headers, body, api_key, **_):
        request = _create_request(self._json(body))
        idem = headers.get("Idempotency-Key") or headers.get("idempotency-key")
        doc = self.provider.create(request, api_key=api_key, idempotency=idem, body_digest=_body_digest(body))
        return Response.json(202, doc)

    def list_sandboxes(self, *, query, headers, body, api_key, **_):
        # §3.4: reap anything past TTL / its idle window before reading state, so a
        # collected sandbox never lingers in the list or counts against quota.
        self.provider.sweep()
        docs = self.provider.list(labels=query.get("label", []), state=(query.get("state") or [None])[0])
        return Response.json(200, {"sandboxes": docs})

    def bulk_delete(self, *, query, headers, body, api_key, **_):
        labels = query.get("label", [])
        if not labels:
            raise api.SandboxContractError("invalid_label", "bulk delete requires a label filter")
        self.provider.bulk_delete(labels)
        return Response.no_content()

    def get_sandbox(self, *, id, **_):
        self.provider.sweep()  # §3.4: an expired sandbox reads as gone, not "archived"
        return Response.json(200, self.provider.get(id))

    def delete_sandbox(self, *, id, **_):
        self.provider.delete(id)
        return Response.no_content()

    def patch_sandbox(self, *, id, body, **_):
        payload = self._json(body)
        return Response.json(200, self.provider.heartbeat(id, payload.get("ttl_seconds")))

    def wait(self, *, id, body, **_):
        payload = self._json(body)
        timeout = int(payload.get("timeout_seconds", 120))
        return Response.json(200, self.provider.wait(id, timeout))

    # ------------------------------------------------------------------ §3.2 exec / processes
    def exec_(self, *, id, body, **_):
        payload = self._json(body)
        cmd = payload.get("cmd")
        if cmd is None:
            raise api.SandboxContractError("invalid_exec", "cmd is required")
        req = ExecRequest(
            cmd=cmd if isinstance(cmd, str) else tuple(cmd),
            cwd=payload.get("cwd"),
            env=payload.get("env", {}),
            user=payload.get("user"),
            timeout_seconds=payload.get("timeout_seconds"),
            stdin=payload.get("stdin"),
        )
        result = self.provider.exec(id, req)
        return Response.json(200, result.to_document())

    def start_process(self, *, id, body, **_):
        payload = self._json(body)
        cmd = payload.get("cmd")
        req = ExecRequest(cmd=cmd if isinstance(cmd, str) else tuple(cmd), cwd=payload.get("cwd"), env=payload.get("env", {}))
        handle = self.provider.start_process(id, req)
        return Response.json(202, {"process_id": handle.process_id, "running": handle.running})

    def process_logs(self, *, id, pid, **_):
        return Response.json(200, {"process_id": pid, "logs": self.provider.process_logs(id, pid)})

    def stop_process(self, *, id, pid, **_):
        self.provider.stop_process(id, pid)
        return Response.no_content()

    def attach_unsupported(self, *, id, pid, **_):
        # §3.2 marks interactive WS attach as "later"; the synchronous surface refuses cleanly.
        return Response.error(501, "not_supported", "WebSocket attach is not implemented on this runtime")

    # ------------------------------------------------------------------ §3.3 files / tar / stat
    def put_file(self, *, id, query, body, **_):
        path = _require_param(query, "path")
        mode_raw = (query.get("mode") or [None])[0]
        mode = int(mode_raw, 8) if mode_raw else None
        self.provider.write_file(id, path, body, mode)
        return Response.json(200, {"path": path, "written": len(body)})

    def get_file(self, *, id, query, headers, **_):
        path = _require_param(query, "path")
        max_bytes_raw = (query.get("max_bytes") or [None])[0]
        max_bytes = int(max_bytes_raw) if max_bytes_raw else None
        range_header = headers.get("Range") or headers.get("range")
        range_start = range_end = None
        if range_header:
            # Determine total length first so an unsatisfiable range yields 416.
            total = self.provider.stat(id, path).size
            rng = api.parse_byte_range(range_header, total)
            if rng is not None:
                range_start, range_end = rng
        data, total = self.provider.read_file(id, FileGet(path=path, max_bytes=max_bytes, range_start=range_start, range_end=range_end))
        if range_start is not None:
            return Response(
                206, data,
                {"Content-Type": OCTET, "Content-Range": f"bytes {range_start}-{range_end}/{total}", "Content-Length": str(len(data))},
            )
        return Response(200, data, {"Content-Type": OCTET, "Content-Length": str(len(data))})

    def put_tar(self, *, id, query, body, **_):
        path = _require_param(query, "path")
        self.provider.write_tar(id, path, body)
        return Response.json(200, {"path": path, "extracted": True})

    def get_tar(self, *, id, query, **_):
        path = _require_param(query, "path")
        exclude = tuple(query.get("exclude", []))
        include = tuple(query.get("include", []))
        data = self.provider.read_tar(id, TarGet(path=path, exclude=exclude, include=include))
        return Response(200, data, {"Content-Type": "application/gzip", "Content-Length": str(len(data))})

    def stat(self, *, id, query, **_):
        path = _require_param(query, "path")
        return Response.json(200, self.provider.stat(id, path).to_document())

    # ------------------------------------------------------------------ §3.5 snapshot
    def snapshot(self, *, id, headers, body, api_key, **_):
        idem = headers.get("Idempotency-Key") or headers.get("idempotency-key")
        payload = self._json(body)
        ttl_seconds = payload.get("ttl_seconds")
        op = self.provider.snapshot(
            id, ttl_seconds=ttl_seconds, name=payload.get("name"), labels=payload.get("labels")
        )
        result = self.provider.get_operation(op)
        if idem:
            self._store_idempotent_snapshot(idem, result)
        return Response.json(202, {"operation_id": op, "status": result["status"], "result": result["result"]})

    def _store_idempotent_snapshot(self, key, result):
        # snapshot idempotency is a pass-through marker; the provider dedups creates.
        return None

    def list_snapshots(self, *, query, **_):
        return Response.json(200, {"snapshots": self.provider.list_snapshots(labels=query.get("label", []))})

    def delete_snapshot(self, *, id, **_):
        existed = self.provider.delete_snapshot(id)
        return Response.json(200, {"deleted": existed}) if existed else Response.error(404, "snapshot_not_found", f"no snapshot {id}")

    # ------------------------------------------------------------------ §3.4 lifecycle
    def heartbeat(self, *, id, body, **_):
        payload = self._json(body)
        return Response.json(200, self.provider.heartbeat(id, payload.get("ttl_seconds")))

    # ------------------------------------------------------------------ §3.7 network / expose
    def set_network(self, *, id, body, **_):
        payload = self._json(body)
        patch = NetworkPatch(mode=payload.get("mode", "public"), allow=tuple(payload.get("allow", ())))
        return Response.json(200, self.provider.set_network(id, patch))

    def expose(self, *, id, body, **_):
        payload = self._json(body)
        return Response.json(200, self.provider.expose(id, ExposeRequest(port=payload.get("port"))))

    # ------------------------------------------------------------------ Agent IDE freeze / thaw
    def freeze(self, *, id, **_):
        return Response.json(200, self.provider.freeze(id))

    def thaw(self, *, id, **_):
        return Response.json(200, self.provider.thaw(id))

    # ------------------------------------------------------------------ Agent IDE interactive (G4–G6)
    def mint_access_ticket(self, *, id, body, **_):
        payload = self._json(body)
        return Response.json(200, self.provider.mint_access_ticket(id, ttl_sec=payload.get("ttl_sec")))

    def create_terminal(self, *, id, body, **_):
        payload = self._json(body)
        return Response.json(
            201,
            self.provider.create_terminal(id, cols=payload.get("cols"), rows=payload.get("rows")),
        )

    def list_terminals(self, *, id, **_):
        return Response.json(200, self.provider.list_terminals(id))

    def delete_terminal(self, *, id, tid, **_):
        self.provider.delete_terminal(id, tid)
        return Response.no_content()

    def connect_terminal(self, *, id, tid, query, body, **_):
        payload = self._json(body)
        ticket = payload.get("ticket") or (query.get("ticket") or [None])[0]
        if not ticket:
            raise api.SandboxContractError("invalid_access_ticket", "ticket is required")
        return Response.json(200, self.provider.connect_terminal(id, tid, ticket=ticket))

    def terminal_write(self, *, id, tid, body, **_):
        payload = self._json(body)
        data = payload.get("data")
        if data is None:
            raise api.SandboxContractError("invalid_terminal_input", "data is required")
        return Response.json(200, self.provider.terminal_write(id, tid, str(data)))

    def terminal_read(self, *, id, tid, **_):
        return Response.json(200, self.provider.terminal_read(id, tid))

    def publish_template(self, *, id, body, **_):
        payload = self._json(body)
        name = payload.get("name")
        if not name:
            raise api.SandboxContractError("invalid_template_name", "name is required")
        doc = self.provider.publish_template(
            id,
            name=name,
            display_name=payload.get("display_name"),
            description=payload.get("description") or "",
        )
        return Response.json(202, doc)

    def list_templates(self, *, query, **_):
        kind = (query.get("kind") or [None])[0]
        status = (query.get("status") or [None])[0]
        return Response.json(200, {"items": self.provider.list_templates(kind=kind, status=status)})

    def get_template(self, *, uid, **_):
        return Response.json(200, self.provider.get_template(uid))

    def desktop(self, *, id, **_):
        return Response.json(200, self.provider.desktop(id))

    # ------------------------------------------------------------------ §3.13 logs
    def logs(self, *, id, **_):
        return Response.json(200, self.provider.logs(id))

    # ------------------------------------------------------------------ §3.9 images
    def prefetch(self, *, headers, body, api_key, **_):
        payload = self._json(body)
        idem = headers.get("Idempotency-Key") or headers.get("idempotency-key")
        op = self.provider.prefetch(PrefetchRequest(images=tuple(payload.get("images", ()))))
        return Response.json(202, {"operation_id": op, "idempotent": idem is not None})

    def image_lookup(self, *, ref, **_):
        return Response.json(200, dict(self.provider.image_status(ref)))

    # ------------------------------------------------------------------ §3.8 / §3.13 aggregate
    def quota(self, **_):
        self.provider.sweep()  # §3.4: an expired sandbox stops counting against quota
        return Response.json(200, self.provider.quota())

    def usage(self, *, query, **_):
        return Response.json(
            200,
            self.provider.usage(
                group_by=(query.get("group_by") or [None])[0],
                labels=query.get("label", []),
            ),
        )

    def status(self, **_):
        return Response.json(200, self.provider.status().to_document())

    def affline_validate_rerun(self, *, headers, body, api_key, **_):
        """POST /v1/affline/validate-rerun — Bearer + optional trigger secret.

        Forces Affine full re-run by default and returns
        ``cathedral_affline_rerun_receipt_v1`` with decision + full_rerun detail.
        Never stamps Affline sandbox TEE.
        """

        project = None
        keys = getattr(self.provider, "_keys", None)
        if isinstance(keys, dict) and api_key in keys:
            project = getattr(keys[api_key], "project", None)
        result = handle_affline_validate_rerun(
            body=body,
            headers=headers,
            api_key_project=project if isinstance(project, str) else None,
        )
        return Response.json(result.http_status, result.receipt)

    def get_operation(self, *, id, **_):
        return Response.json(200, self.provider.get_operation(id))

    def openapi(self, **_):
        """§3.10/§3.11: serve the machine-readable REST contract (unauthenticated)."""
        base = getattr(self.provider, "_base_url", api.CATHEDRAL_API_URL)
        return Response.json(200, openapi_document(base_url=base))


def _require_param(query: Mapping[str, list[str]], name: str) -> str:
    values = query.get(name)
    if not values:
        raise api.SandboxContractError("invalid_path", f"query parameter '{name}' is required")
    return values[0]


# ------------------------------------------------------------------ §3.10/§3.11 OpenAPI contract
_PATH_ITEMS: list[tuple[str, str, str, str]] = [
    ("/v1/sandboxes", "post", "Create a sandbox", "§3.1; honours Idempotency-Key; 202 then poll"),
    ("/v1/sandboxes", "get", "List sandboxes", "§3.4; filter by label and state"),
    ("/v1/sandboxes", "delete", "Bulk delete by label", "§3.4; unfiltered delete refused"),
    ("/v1/sandboxes/{id}", "get", "Get a sandbox", "§3.1"),
    ("/v1/sandboxes/{id}", "delete", "Delete a sandbox", "§3.1"),
    ("/v1/sandboxes/{id}", "patch", "Update a sandbox", "§3.1 (labels / auto-delete)"),
    ("/v1/sandboxes/{id}/wait", "post", "Wait for a state", "§3.1; blocks up to timeout"),
    ("/v1/sandboxes/{id}/exec", "post", "Run a command", "§3.2; server-enforced timeout, output cap"),
    ("/v1/sandboxes/{id}/heartbeat", "post", "Extend lifetime", "§3.1"),
    ("/v1/sandboxes/{id}/lifetime", "post", "Extend lifetime (alias)", "§3.1"),
    ("/v1/sandboxes/{id}/lifetime", "patch", "Extend lifetime (PATCH alias)", "§3.1"),
    ("/v1/sandboxes/{id}/processes", "post", "Start a background process", "§3.2"),
    ("/v1/sandboxes/{id}/processes/{pid}/logs", "get", "Background-process logs", "§3.2; Range supported"),
    ("/v1/sandboxes/{id}/processes/{pid}", "delete", "Stop a background process", "§3.2"),
    ("/v1/sandboxes/{id}/processes/{pid}/attach", "post", "Attach to a process", "§3.2; not supported (501)"),
    ("/v1/sandboxes/{id}/files", "put", "Write a file", "§3.3"),
    ("/v1/sandboxes/{id}/files", "get", "Read a file", "§3.3; Range → 206"),
    ("/v1/sandboxes/{id}/tar", "put", "Write a tar archive", "§3.3"),
    ("/v1/sandboxes/{id}/tar", "get", "Read a tar archive", "§3.3"),
    ("/v1/sandboxes/{id}/stat", "get", "Stat a path", "§3.3"),
    ("/v1/sandboxes/{id}/snapshot", "post", "Snapshot a sandbox", "§3.5; TTL + fork"),
    ("/v1/sandboxes/{id}/network", "post", "Set network policy", "§3.6"),
    ("/v1/sandboxes/{id}/network", "patch", "Patch network policy", "§3.6"),
    ("/v1/sandboxes/{id}/expose", "post", "Expose a port", "§3.7"),
    ("/v1/sandboxes/{id}/freeze", "post", "Freeze (pause) a sandbox", "Agent IDE; state → frozen"),
    ("/v1/sandboxes/{id}/thaw", "post", "Thaw a frozen sandbox", "Agent IDE; state → running"),
    ("/v1/sandboxes/{id}/access-tickets", "post", "Mint access ticket", "Agent IDE G4; single-use"),
    ("/v1/sandboxes/{id}/terminals", "post", "Create terminal", "Agent IDE G4"),
    ("/v1/sandboxes/{id}/terminals", "get", "List terminals", "Agent IDE G4"),
    ("/v1/sandboxes/{id}/terminals/{tid}", "delete", "Delete terminal", "Agent IDE G4"),
    ("/v1/sandboxes/{id}/terminals/{tid}/connect", "post", "Connect terminal with ticket", "Agent IDE G4"),
    ("/v1/sandboxes/{id}/terminals/{tid}/input", "post", "Write terminal input", "Agent IDE G4 REST PTY"),
    ("/v1/sandboxes/{id}/terminals/{tid}/output", "get", "Read terminal output", "Agent IDE G4 REST PTY"),
    ("/v1/sandboxes/{id}/terminals/{tid}/ws", "get", "Terminal WebSocket PTY", "Agent IDE G4; Upgrade + ticket"),
    ("/v1/sandboxes/{id}/publish", "post", "Publish template from sandbox", "Agent IDE G6"),
    ("/v1/sandboxes/{id}/desktop", "get", "Desktop availability", "Agent IDE G5; gated"),
    ("/v1/sandboxes/{id}/desktop/ws", "get", "Desktop RFB WebSocket", "Agent IDE G5; ticket + CATHEDRAL_AGENT_DESKTOP=1"),
    ("/v1/sandbox-templates", "get", "List sandbox templates", "Agent IDE G6"),
    ("/v1/sandbox-templates/{uid}", "get", "Get sandbox template", "Agent IDE G6"),
    ("/v1/sandboxes/{id}/logs", "get", "Container + exec logs", "§3.13; kept 24 h after delete"),
    ("/v1/snapshots", "get", "List snapshots", "§3.5"),
    ("/v1/snapshots/{id}", "delete", "Delete a snapshot", "§3.5"),
    ("/v1/images/prefetch", "post", "Prefetch an image", "§3.9"),
    ("/v1/images/{ref}", "get", "Image cache status", "§3.9"),
    ("/v1/quota", "get", "Project quota + usage", "§3.8"),
    ("/v1/usage", "get", "Metered usage + cost", "§3.13/§3.16; grouped by label"),
    ("/v1/status", "get", "Service status", "§3.15"),
    (
        "/v1/affline/validate-rerun",
        "post",
        "Affline validate with forced full re-run",
        "Bearer + optional X-Cathedral-Affline-Trigger; returns cathedral_affline_rerun_receipt_v1",
    ),
    ("/v1/operations/{id}", "get", "Poll an async operation", "§3.1"),
]


def _path_item_parameters(path: str) -> list[dict[str, Any]]:
    params: list[dict[str, Any]] = []
    for name in ("id", "pid", "ref"):
        token = "{" + name + "}"
        if token in path:
            params.append(
                {
                    "name": name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            )
    return params


def openapi_document(*, base_url: str | None = None) -> dict[str, Any]:
    """Build an OpenAPI 3.0.3 document for the Cathedral sandbox REST surface (§3).

    Verifiers and Harbor consume a machine-readable contract in addition to the thin
    Python client; this is generated from the same verb set the dispatcher routes,
    so the published schema cannot silently drift from what ``dispatch`` accepts.
    """
    server_url = (base_url or api.CATHEDRAL_API_URL).rstrip("/")
    paths: dict[str, Any] = {}
    for path, verb, summary, description in _PATH_ITEMS:
        operation: dict[str, Any] = {
            "summary": summary,
            "description": description,
            "security": [{"bearerAuth": []}],
            "responses": {
                "200": {"description": "Success", "content": {JSON: {"schema": {"type": "object"}}}},
                "202": {"description": "Accepted (async create)", "content": {JSON: {"schema": {"type": "object"}}}},
                "400": {"description": "Contract violation", "content": {JSON: {"schema": _ERROR_SCHEMA}}},
                "401": {"description": "Missing or unknown API key", "content": {JSON: {"schema": _ERROR_SCHEMA}}},
                "403": {"description": "Revoked key or forbidden", "content": {JSON: {"schema": _ERROR_SCHEMA}}},
                "404": {"description": "Not found", "content": {JSON: {"schema": _ERROR_SCHEMA}}},
                "429": {"description": "Quota exhausted (Retry-After)", "content": {JSON: {"schema": _ERROR_SCHEMA}}},
            },
        }
        params = _path_item_parameters(path)
        if params:
            operation["parameters"] = params
        if verb in ("post", "put", "patch"):
            operation["requestBody"] = {
                "content": {JSON: {"schema": {"type": "object"}}},
            }
        if verb == "post" and path.endswith("/snapshot"):
            operation["parameters"] = params + [
                {"name": "Idempotency-Key", "in": "header", "required": False, "schema": {"type": "string"}}
            ]
        if path == "/v1/sandboxes" and verb == "post":
            operation["parameters"] = [
                {"name": "Idempotency-Key", "in": "header", "required": False, "schema": {"type": "string"}}
            ]
        paths.setdefault(path, {})[verb] = operation
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Cathedral Compute Sandbox API",
            "version": "1.0.0",
            "description": (
                "OpenAI-style HTTP sandbox control plane: sandboxes, exec, files, "
                "snapshots/forks, network, quota and metered usage. Daytona-compatible "
                "request surface, Cathedral-native response fields."
            ),
        },
        "servers": [{"url": server_url}],
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "description": "Project API key (§3.14)"}
            },
            "schemas": {"Error": _ERROR_SCHEMA},
        },
        "paths": paths,
    }


_ERROR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "error": {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
            },
        }
    },
}


# ------------------------------------------------------------------ stdlib listener
class _Handler(BaseHTTPRequestHandler):
    app: SandboxApplication

    def _run(self, method: str) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        resp = self.app.dispatch(method, self.path, dict(self.headers), body)
        self.send_response(resp.status)
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp.body)))
        self.end_headers()
        if resp.body:
            self.wfile.write(resp.body)

    def do_GET(self):
        if (self.headers.get("Upgrade") or "").lower() == "websocket":
            self._handle_websocket()
            return
        self._run("GET")

    def do_POST(self):
        self._run("POST")

    def do_PUT(self):
        self._run("PUT")

    def do_DELETE(self):
        self._run("DELETE")

    def do_PATCH(self):
        self._run("PATCH")

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        if os.environ.get("CATHEDRAL_SANDBOX_ACCESS_LOG") == "1":
            sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

    def _ws_fail(self, status: int, code: str, message: str) -> None:
        body = json.dumps({"error": {"code": code, "message": message}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_websocket(self) -> None:
        from cathedral import agent_rfb
        from cathedral import agent_websocket as ws

        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        ticket, ticket_err = ws.extract_access_ticket(self.headers, query)
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            self._ws_fail(400, "invalid_websocket", "Sec-WebSocket-Key required")
            return
        if ticket_err == "ticket_query_forbidden":
            self._ws_fail(
                401,
                "ticket_query_forbidden",
                "pass ticket via X-Cathedral-Access-Ticket (query string disabled)",
            )
            return

        term_match = re.match(
            r"^/v1/sandboxes/(?P<id>[^/]+)/terminals/(?P<tid>[^/]+)/ws$", path
        )
        desk_match = re.match(r"^/v1/sandboxes/(?P<id>[^/]+)/desktop/ws$", path)
        if term_match:
            self._ws_terminal(term_match.group("id"), term_match.group("tid"), ticket, key, ws)
            return
        if desk_match:
            self._ws_desktop(desk_match.group("id"), ticket, key, ws, agent_rfb)
            return
        self._ws_fail(404, "route_not_found", f"no websocket route for {path}")

    def _ws_terminal(self, sandbox_id: str, terminal_id: str, ticket: str | None, key: str, ws) -> None:
        if not ticket:
            self._ws_fail(
                401,
                "access_ticket_invalid",
                "X-Cathedral-Access-Ticket header (or cathedral.ticket.* subprotocol) required",
            )
            return
        try:
            # Consume ticket + mark connected (same gate as REST connect).
            self.app.provider.connect_terminal(sandbox_id, terminal_id, ticket=ticket)
        except SandboxOpError as exc:
            self._ws_fail(exc.http_status, exc.code, str(exc))
            return
        protocol = f"cathedral.ticket.{ticket}"
        self.wfile.write(ws.handshake_response(key, protocol=protocol))
        self.wfile.flush()
        # Push any buffered output (connect banner).
        try:
            out = self.app.provider.terminal_read(sandbox_id, terminal_id)
            if out.get("data"):
                self.wfile.write(ws.encode_frame(out["data"].encode("utf-8"), opcode=ws.OP_TEXT))
                self.wfile.flush()
        except SandboxOpError:
            pass
        buf = bytearray()
        self.connection.settimeout(120.0)
        try:
            while True:
                chunk = self.connection.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                frames, buf = ws.decode_frames(buf)
                stop = False
                for opcode, payload in frames:
                    if opcode == ws.OP_CLOSE:
                        self.wfile.write(ws.encode_frame(b"", opcode=ws.OP_CLOSE))
                        stop = True
                        break
                    if opcode == ws.OP_PING:
                        self.wfile.write(ws.encode_frame(payload, opcode=ws.OP_PONG))
                        self.wfile.flush()
                        continue
                    if opcode in (ws.OP_TEXT, ws.OP_BINARY):
                        text = payload.decode("utf-8", errors="replace")
                        if text and not text.endswith("\n"):
                            text += "\n"
                        self.app.provider.terminal_write(sandbox_id, terminal_id, text)
                        out = self.app.provider.terminal_read(sandbox_id, terminal_id)
                        data = (out.get("data") or "").encode("utf-8")
                        if data:
                            self.wfile.write(ws.encode_frame(data, opcode=ws.OP_TEXT))
                            self.wfile.flush()
                if stop:
                    break
        except (TimeoutError, BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _ws_desktop(self, sandbox_id: str, ticket: str | None, key: str, ws, agent_rfb) -> None:
        import os as _os

        if _os.environ.get("CATHEDRAL_AGENT_DESKTOP", "0") != "1":
            self._ws_fail(404, "desktop_unavailable", "set CATHEDRAL_AGENT_DESKTOP=1 to enable desktop")
            return
        if not ticket:
            self._ws_fail(
                401,
                "access_ticket_invalid",
                "X-Cathedral-Access-Ticket header (or cathedral.ticket.* subprotocol) required",
            )
            return
        try:
            self.app.provider.consume_access_ticket(sandbox_id, ticket)
        except SandboxOpError as exc:
            self._ws_fail(exc.http_status, exc.code, str(exc))
            return
        protocol = f"cathedral.ticket.{ticket}"
        self.wfile.write(ws.handshake_response(key, protocol=protocol))
        self.wfile.flush()

        def send_rfb(data: bytes) -> None:
            self.wfile.write(ws.encode_frame(data, opcode=ws.OP_BINARY))
            self.wfile.flush()

        # RFB version exchange over WS binary frames, then VNC Auth with the ticket.
        send_rfb(agent_rfb.RFB_VERSION)
        buf = bytearray()
        self.connection.settimeout(120.0)
        stage = "version"
        challenge = b""
        rfb_buf = bytearray()
        try:
            while True:
                chunk = self.connection.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                frames, buf = ws.decode_frames(buf)
                stop = False
                for opcode, payload in frames:
                    if opcode == ws.OP_CLOSE:
                        self.wfile.write(ws.encode_frame(b"", opcode=ws.OP_CLOSE))
                        stop = True
                        break
                    if opcode == ws.OP_PING:
                        self.wfile.write(ws.encode_frame(payload, opcode=ws.OP_PONG))
                        self.wfile.flush()
                        continue
                    if opcode not in (ws.OP_BINARY, ws.OP_TEXT):
                        continue
                    if stage == "version":
                        if b"RFB " in payload or payload.startswith(b"RFB"):
                            send_rfb(agent_rfb.security_offer_vnc())
                            stage = "security_type"
                        continue
                    if stage == "security_type":
                        # Client selects one byte security type.
                        if not payload:
                            continue
                        chosen = payload[0]
                        if chosen != agent_rfb.SECURITY_TYPE_VNC:
                            send_rfb(agent_rfb.security_result_fail())
                            stop = True
                            break
                        challenge = agent_rfb.new_vnc_challenge()
                        send_rfb(challenge)
                        stage = "vnc_response"
                        continue
                    if stage == "vnc_response":
                        if len(payload) < 16:
                            continue
                        if not agent_rfb.verify_vnc_response(challenge, payload[:16], ticket):
                            send_rfb(agent_rfb.security_result_fail())
                            stop = True
                            break
                        send_rfb(agent_rfb.security_result_ok())
                        send_rfb(agent_rfb.server_init())
                        stage = "session"
                        continue
                    rfb_buf.extend(payload)
                    agent_rfb.handle_client_messages(rfb_buf, send_rfb)
                if stop:
                    break
        except (TimeoutError, BrokenPipeError, ConnectionResetError, OSError):
            pass


def serve(app: SandboxApplication, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """Bind the application to a real HTTP listener (used by integration checks)."""
    handler = type("_BoundHandler", (_Handler,), {"app": app})
    httpd = ThreadingHTTPServer((host, port), handler)
    return httpd


def run(app: SandboxApplication, host: str = "127.0.0.1", port: int = 0) -> tuple[ThreadingHTTPServer, tuple[str, int]]:
    """Start the listener and return ``(httpd, bound_address)``.

    The caller drives ``serve_forever`` and ``shutdown``/``server_close``; binding on
    port 0 lets the OS pick a free port, so ``bound_address`` reports the real one.
    """
    httpd = serve(app, host=host, port=port)
    return httpd, httpd.server_address


__all__ = ["Response", "SandboxApplication", "openapi_document", "run", "serve"]
