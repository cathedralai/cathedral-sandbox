"""AB#385 slice 3: every mutating route of the room API is signed at the receipts front.

The guard test walks the room API's own route table. A route that is neither a row of SIGNED nor on
UNSIGNED below (with the reason it stays unsigned) fails it, so a route added later cannot reach a
sealed hotel without a receipt by accident.
"""
from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from cathedral.sandbox_server import SandboxApplication

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_routes_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32
AUTH = {"Authorization": "Bearer " + KEY.decode()}

S = r"/v1/sandboxes/(?P<id>[^/]+)"
# Room API routes that stay unsigned, each with its reason. Keyed by (method, the API's own pattern).
UNSIGNED = {
    ("GET", r"/v1/sandboxes"): "read: lists rooms",
    ("GET", S): "read: one room",
    ("POST", S + r"/wait"): "read: long poll for a room's state",
    ("PATCH", S): "keepalive: the broker's heartbeat; a receipt per keepalive would stay on the chain",
    ("POST", S + r"/heartbeat"): "keepalive: as PATCH /v1/sandboxes/{id}",
    ("POST", S + r"/lifetime"): "keepalive: as PATCH /v1/sandboxes/{id}",
    ("PATCH", S + r"/lifetime"): "keepalive: as PATCH /v1/sandboxes/{id}",
    ("POST", S + r"/exec-sealed"): "internal: the front's own route for a sealed exec; refused 404 to callers",
    ("PUT", S + r"/env-sealed"): "internal: the front's own route for a sealed env overlay; refused 404 to callers",
    ("POST", S + r"/sealed-mark"): "internal: the front's own call before a room's first secret lands; refused 404 to callers",
    ("GET", S + r"/processes/(?P<pid>[^/]+)/logs"): "read: a process's output",
    ("POST", S + r"/processes/(?P<pid>[^/]+)/attach"): "unsupported: the API always answers 501",
    ("GET", S + r"/entries"): "read: a directory listing",
    ("GET", S + r"/stat"): "read: file metadata",
    ("GET", S + r"/terminals"): "read: lists terminals",
    ("GET", S + r"/terminals/(?P<tid>[^/]+)/output"): (
        "read toward the room: it drains only the reader's buffer; polled, so a receipt per poll would "
        "fill the chain. What goes into a terminal (create, connect, input, resize, delete) is signed"),
    ("GET", S + r"/desktop"): "read: desktop status",
    ("GET", S + r"/logs"): "read: a room's logs",
    ("GET", r"/v1/snapshots"): "read: lists snapshots",
    ("POST", r"/v1/snapshots/(?P<id>[^/]+)/push"): (
        "refused: the front answers 403 snapshot_push_refused, unsent; a sealed machine does not push a "
        "snapshot to a registry (AB#604)"),
    ("GET", r"/v1/workspaces"): "read: lists workspaces",
    ("GET", r"/v1/workspaces/(?P<name>[^/]+)"): "read: one workspace",
    ("GET", r"/v1/workspaces/(?P<name>[^/]+)/versions"): "read: a workspace's versions",
    ("GET", r"/v1/secrets"): "read: secret names, never values",
    ("GET", r"/v1/sandbox-templates"): "read: lists templates",
    ("GET", r"/v1/sandbox-templates/(?P<uid>[^/]+)"): "read: one template",
    ("GET", r"/v1/images"): "read: the caller's cached images and pins",
    ("GET", r"/v1/images/(?P<ref>.+)"): "read: an image's state",
    ("GET", r"/v1/quota"): "read",
    ("GET", r"/v1/usage"): "read",
    ("GET", r"/v1/status"): "read",
    ("GET", r"/v1/operations/(?P<id>[^/]+)"): "read: an operation's state",
    ("GET", r"/openapi.json"): "read: the API contract",
}
SAMPLE = {"id": "sbx_9", "pid": "p_7", "tid": "t_1", "port": "8080", "name": "ws1", "uid": "tpl1",
          "ref": "alpine:3.20"}


def _api_routes() -> list[tuple[str, str, str]]:
    """(method, pattern, a sample path) for every route of the room API."""
    out = []
    for method, compiled, _handler in SandboxApplication(require_auth=False)._routes:
        pattern = compiled.pattern[1:-1]  # _add wraps each pattern in ^...$
        sample = re.sub(r"\(\?P<(\w+)>[^)]*\)", lambda m: SAMPLE[m[1]], pattern)
        assert compiled.match(sample), (method, pattern, sample)
        out.append((method, pattern, sample))
    return out


def _signed(method: str, path: str) -> str | None:
    return next((a for m, p, a in rr.SIGNED if m == method and p.match(path)), None)


def test_every_api_route_is_signed_or_unsigned_with_a_reason() -> None:
    routes = _api_routes()
    missing = [(m, p) for m, p, sample in routes if _signed(m, sample) is None and (m, p) not in UNSIGNED]
    assert not missing, f"room API routes neither signed nor on UNSIGNED with a reason: {missing}"
    both = [(m, p) for m, p, sample in routes if _signed(m, sample) is not None and (m, p) in UNSIGNED]
    assert not both, f"signed routes still on UNSIGNED: {both}"
    stale = set(UNSIGNED) - {(m, p) for m, p, _s in routes}
    assert not stale, f"UNSIGNED names routes the API no longer has: {stale}"
    assert all(reason.strip() for reason in UNSIGNED.values())


def test_every_signed_row_names_a_route_the_api_has() -> None:
    routes = _api_routes()
    for method, pattern, action in rr.SIGNED:
        assert any(m == method and pattern.match(sample) for m, _p, sample in routes), (method, action)


def test_every_unsigned_route_other_than_a_get_has_a_reason_that_is_not_read() -> None:
    # A method other than GET is a read only when it says so: POST .../wait.
    for (method, pattern), reason in UNSIGNED.items():
        if method != "GET" and reason.startswith("read"):
            assert pattern.endswith("/wait"), (method, pattern)


SLICE3 = [(m, p, a) for m, p, a in rr.SIGNED_SLICE3]


def _sample_for(method: str, action: str) -> str:
    for m, _p, sample in _api_routes():
        if m == method and _signed(m, sample) == action:
            return sample
    raise AssertionError(action)


@pytest.fixture
def front(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    seen: list[tuple[str, str, bytes, dict]] = []
    answers: dict[str, tuple[int, bytes]] = {}  # path -> (status, body) to answer instead

    class Api(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def handle_any(self):
            n = int(self.headers.get("Content-Length") or 0)
            seen.append((self.command, self.path, self.rfile.read(n) if n else b"", dict(self.headers)))
            status = 201 if self.command == "POST" and self.path.endswith("/terminals") else 200
            body = json.dumps({"ok": True, "path": self.path}).encode()
            status, body = answers.get(self.path, (status, body))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_any

    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    ledger = rr.Ledger("room-a", str(tmp_path))
    server = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, KEY, "/nonexistent.sock", pool_scan=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    front_answers[id(ledger)] = answers
    yield server.server_address[1], seen, ledger
    server.shutdown()
    api.shutdown()


front_answers: dict[int, dict] = {}


def _call(port: int, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers={**AUTH, **(headers or {})})
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _statement(headers: dict) -> dict:
    raw = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))["statement"]


@pytest.mark.parametrize(("method", "action"), [(m, a) for m, _p, a in SLICE3])
def test_each_slice3_route_returns_a_receipt(front, method, action) -> None:
    port, seen, ledger = front
    path = _sample_for(method, action)
    body = b'{"x":1}' if method in ("POST", "PUT") else None
    status, headers, out = _call(port, method, path, body)
    assert status in (200, 201) and "X-Room-Receipt" in headers, (action, status, headers)
    st = _statement(headers)
    assert st["action"] == action and st["status"] == status
    assert st["target"] == f"{method} {path}"
    assert st["sandbox_id"] == ("sbx_9" if path.startswith("/v1/sandboxes/") else None)
    assert st["result_sha256"] == rr.sha(out)
    assert st["command_sha256"] is None
    if action == "snapshot_delete":
        assert st["snapshot_id"] == "sbx_9"
    if action == "secret_put":
        assert st["customer_request_sha256"] is None and st["customer_request_withheld"] == "secret_value"
    else:
        assert st["customer_request_sha256"] == rr.sha(body or b"")
        assert "customer_request_withheld" not in st
    assert len(seen) == 1 and seen[0][:3] == (method, path, body or b"")
    assert len(ledger.chain) == 1


def test_a_chain_of_every_slice3_action_verifies_offline(front, tmp_path) -> None:
    port, _seen, ledger = front
    headers_seen = []
    for method, _p, action in SLICE3:
        _status, headers, _out = _call(port, method, _sample_for(method, action),
                                       b"{}" if method in ("POST", "PUT") else None)
        headers_seen.append(headers["X-Room-Receipt"])
    assert [r["statement"]["action"] for r in ledger.chain] == [a for _m, _p, a in SLICE3]
    att, chain = tmp_path / "att.json", tmp_path / "chain.json"
    att.write_text(json.dumps(ledger.attestation()))
    chain.write_text(json.dumps({"binding_sha256": ledger.binding_sha256, "head": ledger.head,
                                 "receipts": ledger.chain}))
    proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att),
                           "--receipts", str(chain)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["verdict"] == "PASS"
    # Each header on its own verifies against the same attestation.
    cmd = [sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att)]
    for h in headers_seen:
        cmd += ["--receipt-header", h]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_tampered_slice3_receipt_fails(front, tmp_path) -> None:
    port, _seen, ledger = front
    _call(port, "POST", "/v1/sandboxes/sbx_9/terminals/t_1/input", b'{"data":"ls\\n"}')
    bad = json.loads(json.dumps(ledger.chain))
    bad[0]["statement"]["action"] = "terminal_resize"
    att, chain = tmp_path / "att.json", tmp_path / "chain.json"
    att.write_text(json.dumps(ledger.attestation()))
    chain.write_text(json.dumps({"binding_sha256": ledger.binding_sha256, "head": ledger.head, "receipts": bad}))
    proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att),
                           "--receipts", str(chain)], capture_output=True, text=True, check=False)
    assert proc.returncode != 0


def test_without_the_key_nothing_is_signed(front) -> None:
    port, _seen, ledger = front
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("PUT", "/v1/sandboxes/sbx_9/directories?path=/work/d", body=b"")
    r = c.getresponse()
    r.read()
    assert "X-Room-Receipt" not in dict(r.getheaders())
    assert ledger.chain == []


def test_terminal_output_stays_unsigned(front) -> None:
    port, _seen, ledger = front
    status, headers, _out = _call(port, "GET", "/v1/sandboxes/sbx_9/terminals/t_1/output")
    assert status == 200 and "X-Room-Receipt" not in headers and ledger.chain == []


def test_port_http_passes_the_guest_target_headers(front) -> None:
    port, seen, _ledger = front
    status, headers, _out = _call(port, "POST", "/v1/sandboxes/sbx_9/ports/8080/http", b"hi",
                                  {"X-Guest-Method": "PUT", "X-Guest-Target": "/a?b=1"})
    assert status == 200 and _statement(headers)["action"] == "port_http"
    assert seen[0][3]["X-Guest-Method"] == "PUT" and seen[0][3]["X-Guest-Target"] == "/a?b=1"


@pytest.mark.parametrize("body", [
    b'{"note":"\\ud800"}',  # a lone surrogate escape: parses, cannot be encoded
    b'{"cmd":["rm","-rf","/"]}',  # a JSON file that looks like an exec
    b'not json \xff\xfe',
])
def test_a_file_body_is_signed_as_bytes(front, body) -> None:
    port, seen, _ledger = front
    status, headers, _out = _call(port, "PUT", "/v1/sandboxes/sbx_9/files?path=/work/a.json", body)
    assert status == 200
    st = _statement(headers)
    assert st["action"] == "file_put" and st["customer_request_sha256"] == rr.sha(body)
    assert st["command_sha256"] is None
    assert seen[0][2] == body


def test_a_slice3_body_with_a_lone_surrogate_is_signed_not_refused(front) -> None:
    port, _seen, _ledger = front
    body = b'{"data":"\\udc00"}'
    status, headers, _out = _call(port, "POST", "/v1/sandboxes/sbx_9/terminals/t_1/input", body)
    assert status == 200 and _statement(headers)["customer_request_sha256"] == rr.sha(body)


@pytest.mark.parametrize(("method", "tail", "kind"), [
    ("PUT", "/directories", "signed"),
    ("DELETE", "/entries", "signed"),
    ("POST", "/ports/80/http", "signed"),
    ("POST", "/publish", "signed"),
    ("POST", "/terminals", "other"),
    ("POST", "/terminals/t1/input", "other"),
    ("POST", "/access-tickets", "other"),
    ("GET", "/terminals/t1/output", "other"),
])
def test_route_kind_keeps_terminals_closed_on_serial_rooms(method, tail, kind) -> None:
    assert rr.route_kind(method, "/v1/sandboxes/sbx_9" + tail) == kind


@pytest.mark.parametrize("status", [200, 500])
def test_a_guest_port_answer_is_never_parsed(front, status) -> None:
    # The room's own server chose these bytes: JSON nested past the parser's limit must not cost the receipt.
    port, _seen, ledger = front
    deep = b"[" * 100_000 + b"]" * 100_000
    front_answers[id(ledger)]["/v1/sandboxes/sbx_9/ports/8080/http"] = (status, deep)
    got, headers, out = _call(port, "POST", "/v1/sandboxes/sbx_9/ports/8080/http", b"")
    assert got == status and out == deep and "X-Room-Receipt-Error" not in headers
    st = _statement(headers)
    assert st["action"] == "port_http" and st["result_sha256"] == rr.sha(deep) and st["sandbox_id"] == "sbx_9"


def test_a_deeply_nested_api_answer_does_not_cost_the_receipt(front) -> None:
    port, _seen, ledger = front
    deep = b"[" * 100_000 + b"]" * 100_000
    front_answers[id(ledger)]["/v1/workspaces"] = (400, deep)
    got, headers, _out = _call(port, "POST", "/v1/workspaces", b"[" * 100_000 + b"]" * 100_000)
    assert got == 400 and _statement(headers)["action"] == "workspace_create"


def test_a_snapshot_delete_names_the_snapshot_the_api_deletes(front) -> None:
    port, seen, _ledger = front
    _got, headers, _out = _call(port, "DELETE", "/v1/snapshots/%73nap_1")
    st = _statement(headers)
    assert st["snapshot_id"] == "snap_1" and st["target"] == "DELETE /v1/snapshots/%73nap_1"
    assert seen[0][1] == "/v1/snapshots/%73nap_1"
