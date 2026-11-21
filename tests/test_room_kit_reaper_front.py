"""AB#385: the TTL reaper deletes through the receipts front, so each TTL delete has a signed receipt.

The room API removes a room past its limit by itself only after expires_at plus its grace (300 s); the
front deletes it first, REAP_AFTER_SECONDS after expires_at, with a delete receipt that says reason ttl.
"""
from __future__ import annotations

import datetime
import http.client
import importlib.util
import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_reaper_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32
AUTH = {"Authorization": "Bearer " + KEY.decode()}
NOW = 1_800_000_000.0


def _iso(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()


class FakeApi:
    """A room API that lists rooms with their expires_at and records what the front sent."""

    def __init__(self) -> None:
        self.rooms: dict[str, str] = {}
        self.on_get: dict[str, str] = {}  # room -> expires_at its GET answers (a heartbeat since the list)
        self.drop_delete = False
        self.seen: list[tuple[str, str, str]] = []
        api = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def send(self, status: int, doc) -> None:
                body = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                api.seen.append(("GET", self.path, self.headers.get("Authorization", "")))
                if self.path == "/v1/sandboxes":
                    return self.send(200, {"sandboxes": [{"id": r, "expires_at": e} for r, e in api.rooms.items()]})
                room = self.path.rsplit("/", 1)[-1]
                if room not in api.rooms:
                    return self.send(404, {"error": {"code": "sandbox_not_found"}})
                self.send(200, {"id": room, "expires_at": api.on_get.get(room, api.rooms[room])})

            def do_DELETE(self):  # noqa: N802
                api.seen.append(("DELETE", self.path, self.headers.get("Authorization", "")))
                if api.drop_delete:
                    self.close_connection = True
                    self.connection.shutdown(2)
                    return
                api.rooms.pop(self.path.rsplit("/", 1)[-1], None)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def deletes(self) -> list[str]:
        return [path for method, path, _auth in self.seen if method == "DELETE"]


@pytest.fixture
def front(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    api = FakeApi()
    ledger = rr.Ledger("room-a", str(tmp_path))
    server = rr.Server(("127.0.0.1", 0), ledger, api.httpd.server_address[1], 1, KEY, "/nonexistent.sock",
                       pool_scan=False)
    yield server, api, ledger
    server.server_close()
    api.httpd.shutdown()


def test_a_room_past_its_limit_is_deleted_with_a_signed_ttl_receipt(front) -> None:
    server, api, ledger = front
    api.rooms = {"sbx_old": _iso(NOW - rr.REAP_AFTER_SECONDS - 1), "sbx_new": _iso(NOW + 60),
                 "sbx_edge": _iso(NOW - rr.REAP_AFTER_SECONDS + 1)}
    signed = server.reap_due(NOW)
    assert api.deletes() == ["/v1/sandboxes/sbx_old"]
    assert [m for m, _p, auth in api.seen] and all(auth == "Bearer " + KEY.decode() for _m, _p, auth in api.seen)
    assert len(signed) == 1 and ledger.chain == signed
    st = signed[0]["statement"]
    assert st["action"] == "delete" and st["reason"] == "ttl" and st["sandbox_id"] == "sbx_old"
    assert st["target"] == "DELETE /v1/sandboxes/sbx_old" and st["status"] == 204
    assert st["ttl_expires_at"] == _iso(NOW - rr.REAP_AFTER_SECONDS - 1)
    assert st["result_sha256"] == rr.sha(b"") and st["customer_request_sha256"] == rr.sha(b"")
    # A second pass finds nothing more to do.
    assert server.reap_due(NOW) == [] and len(api.deletes()) == 1


def test_a_heartbeat_since_the_list_saves_the_room(front) -> None:
    server, api, ledger = front
    api.rooms = {"sbx_1": _iso(NOW - 100)}
    api.on_get = {"sbx_1": _iso(NOW + 600)}
    assert server.reap_due(NOW) == []
    assert api.deletes() == [] and ledger.chain == []


def test_a_room_with_a_request_in_flight_is_left_for_the_next_pass(front) -> None:
    server, api, ledger = front
    api.rooms = {"sbx_1": _iso(NOW - 100)}
    with ledger.lock:
        ledger.in_flight["sbx_1"] = 1
    assert server.reap_due(NOW) == [] and api.deletes() == []
    with ledger.lock:
        ledger.in_flight.pop("sbx_1")
    assert len(server.reap_due(NOW)) == 1 and api.deletes() == ["/v1/sandboxes/sbx_1"]
    with ledger.lock:
        assert ledger.in_flight == {} and ledger.busy == set()


def test_a_lost_delete_answer_is_signed_as_502(front) -> None:
    server, api, ledger = front
    api.rooms = {"sbx_1": _iso(NOW - 100)}
    api.drop_delete = True
    signed = server.reap_due(NOW)
    assert len(signed) == 1
    st = signed[0]["statement"]
    assert st["status"] == 502 and st["reason"] == "ttl" and st["result_sha256"] == rr.sha(rr.REAP_NO_ANSWER)
    assert len(api.deletes()) == 1  # sent once, never again in the same pass


@pytest.mark.parametrize("doc", [
    {"id": "sbx_1", "expires_at": "not a time"},
    {"id": "sbx_1", "expires_at": "2026-01-01T00:00:00"},  # no offset
    {"id": "sbx_1"},
    {"id": "a/b", "expires_at": "2020-01-01T00:00:00+00:00"},
    {"id": "sbx%31", "expires_at": "2020-01-01T00:00:00+00:00"},
    {"id": 7, "expires_at": "2020-01-01T00:00:00+00:00"},
])
def test_an_unreadable_room_document_is_never_due(front, doc) -> None:
    server, _api, _ledger = front
    assert server.reap_is_due(doc, NOW) is False


def test_no_pass_before_the_startup_scan(front) -> None:
    server, api, _ledger = front
    api.rooms = {"sbx_1": _iso(NOW - 100)}
    server.pool_scan_ready = False
    assert server.reap_due(NOW) == [] and api.seen == []


def test_a_failed_list_deletes_nothing(front) -> None:
    server, api, _ledger = front
    api.httpd.shutdown()
    api.httpd.server_close()
    assert server.reap_due(NOW) == []


def test_the_reap_thread_runs_only_when_asked(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    api = FakeApi()
    api.rooms = {"sbx_1": _iso(time.time() - 100)}
    ledger = rr.Ledger("room-a", str(tmp_path))
    off = rr.Server(("127.0.0.1", 0), ledger, api.httpd.server_address[1], 1, KEY, "/x.sock", pool_scan=False)
    assert off.reap_thread is None
    off.server_close()
    on = rr.Server(("127.0.0.1", 0), ledger, api.httpd.server_address[1], 1, KEY, "/x.sock", pool_scan=False,
                   reap_seconds=0.05)
    try:
        deadline = time.monotonic() + 5
        while not api.deletes() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert api.deletes() == ["/v1/sandboxes/sbx_1"]
        assert ledger.chain[-1]["statement"]["reason"] == "ttl"
    finally:
        on.server_close()
        api.httpd.shutdown()


# ---------------------------------------------------------------- the real room API behind the real front

def test_the_real_api_room_is_reaped_signed_and_the_chain_verifies(tmp_path, monkeypatch) -> None:
    from cathedral.sandbox_provider import InMemorySandboxProvider
    from cathedral.sandbox_server import SandboxApplication, run

    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    provider = InMemorySandboxProvider()
    # No API reaper thread: the API's own collection waits for its grace, which this test never reaches.
    httpd, (_, api_port) = run(SandboxApplication(provider, require_auth=False))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    ledger = rr.Ledger("room-a", str(tmp_path))
    server = rr.Server(("127.0.0.1", 0), ledger, api_port, 1, KEY, "/x.sock", pool_scan=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
        c.request("POST", "/v1/sandboxes", body=json.dumps({"image": "alpine:3.20", "ttl_seconds": 1}), headers=AUTH)
        r = c.getresponse()
        room = json.loads(r.read())["id"]
        assert r.status in (200, 201, 202)
        # The front's clock runs past expires_at + REAP_AFTER_SECONDS; the API's own deadline (+300 s) is not reached.
        signed = server.reap_due(time.time() + 1 + rr.REAP_AFTER_SECONDS + 1)
        assert [s["statement"]["sandbox_id"] for s in signed] == [room]
        st = signed[0]["statement"]
        assert st["action"] == "delete" and st["reason"] == "ttl" and 200 <= st["status"] < 300
        assert room not in ledger.incarnations
        c.request("GET", f"/v1/sandboxes/{room}", headers=AUTH)
        r = c.getresponse()
        r.read()
        assert r.status == 404
        server.look_one(room)  # the look signs no second end for a room the reaper already deleted
        assert [s["statement"]["action"] for s in ledger.chain] == ["create", "delete"]
        att, chain = tmp_path / "att.json", tmp_path / "chain.json"
        att.write_text(json.dumps(ledger.attestation()))
        chain.write_text(json.dumps({"binding_sha256": ledger.binding_sha256, "head": ledger.head,
                                     "receipts": ledger.chain}))
        proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att),
                               "--receipts", str(chain)], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out = json.loads(proc.stdout)
        assert out["verdict"] == "PASS"
    finally:
        server.shutdown()
        httpd.shutdown()
        provider.close()


def test_a_heartbeat_during_the_reap_is_refused_so_the_limit_read_is_the_one_deleted_on(tmp_path, monkeypatch) -> None:
    # Review of #645: on an ordinary room a delete holds no token, so a heartbeat could land between the
    # reaper's last look at expires_at and its DELETE. The reaping mark closes that window.
    from cathedral.sandbox_provider import InMemorySandboxProvider
    from cathedral.sandbox_server import SandboxApplication, run

    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    provider = InMemorySandboxProvider()
    httpd, (_, api_port) = run(SandboxApplication(provider, require_auth=False))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    ledger = rr.Ledger("room-a", str(tmp_path))
    server = rr.Server(("127.0.0.1", 0), ledger, api_port, 1, KEY, "/x.sock", pool_scan=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    def call(method: str, path: str, doc=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request(method, path, body=json.dumps(doc) if doc is not None else None, headers=AUTH)
        r = c.getresponse()
        return r.status, r.read()

    try:
        status, out = call("POST", "/v1/sandboxes", {"image": "alpine:3.20", "ttl_seconds": 1})
        room = json.loads(out)["id"]
        seen: list[tuple[int, bytes]] = []
        real_get = server.api_get

        def racing_get(path: str, timeout: float, total: float | None = None):
            if path == f"/v1/sandboxes/{room}":
                seen.append(call("PATCH", f"/v1/sandboxes/{room}", {"ttl_seconds": 600}))  # a heartbeat
                seen.append(call("GET", f"/v1/sandboxes/{room}"))  # a read still passes
            return real_get(path, timeout, total)

        monkeypatch.setattr(server, "api_get", racing_get)
        signed = server.reap_due(time.time() + 1 + rr.REAP_AFTER_SECONDS + 1)
        assert seen[0][0] == 409 and json.loads(seen[0][1])["error"]["code"] == "room_reaping"
        assert seen[1][0] == 200
        assert [s["statement"]["reason"] for s in signed] == ["ttl"]
        assert ledger.reaping == set()
        assert call("GET", f"/v1/sandboxes/{room}")[0] == 404
    finally:
        server.shutdown()
        httpd.shutdown()
        provider.close()


def test_the_reaping_mark_refuses_writes_but_not_reads_or_a_delete(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    ledger = rr.Ledger("room-a", str(tmp_path))
    ledger.reaping.add("sbx_1")
    for kind in ("other", "signed", "claim"):
        turn, refusal = ledger.enter("sbx_1", kind)
        assert turn is None and refusal[1] == "room_reaping"
    for kind in ("read", "record_read", "delete"):
        turn, refusal = ledger.enter("sbx_1", kind)
        assert refusal is None
        ledger.leave(turn)
    turn, refusal = ledger.enter("sbx_2", "other")
    assert refusal is None
    ledger.leave(turn)
