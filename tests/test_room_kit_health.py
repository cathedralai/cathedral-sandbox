"""Room kit health under load and receipt chain paging (sealed hotel, run 5)."""

from __future__ import annotations

import http.client
import importlib.util
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

KIT = Path(__file__).resolve().parents[1] / "room-kit"


def _load(name: str, monkeypatch=None):
    spec = importlib.util.spec_from_file_location(f"kit_{name}", KIT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _serve(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server.server_address[1]


def _get(port: int, path: str, key: str = "k" * 32) -> tuple[int, dict, float]:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    t0 = time.monotonic()
    c.request("GET", path, headers={"Authorization": "Bearer " + key})
    r = c.getresponse()
    body = r.read()
    took = time.monotonic() - t0
    hdrs = dict(r.getheaders())
    c.close()
    return r.status, {"body": json.loads(body), "headers": hdrs}, took


def test_health_answers_from_cache_when_building_the_document_is_slow(monkeypatch) -> None:
    monkeypatch.setenv("ROOM_DOCKER_SOCK", "/nonexistent.sock")
    health = _load("room_health")
    calls = {"n": 0}

    def slow_document():
        calls["n"] += 1
        time.sleep(0.5)  # a host at full CPU
        return {"room_id": "r", "n": calls["n"]}

    monkeypatch.setattr(health, "document", slow_document)
    health.Handler.key = "k" * 32
    threading.Thread(target=health.doc_loop, daemon=True).start()
    time.sleep(0.8)  # the first document is built
    port = _serve(ThreadingHTTPServer(("127.0.0.1", 0), health.Handler))
    status, doc, took = _get(port, "/room/health")
    assert status == 200 and doc["body"]["room_id"] == "r"
    assert took < 0.2, took
    assert "X-Health-Age-Ms" in doc["headers"]
    status, _, _ = _get(port, "/room/health", key="x" * 32)
    assert status == 401


class _Upstream(BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).hits += 1
        body = json.dumps({"room_id": "sealed", "slots": 10}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Ledger:
    sealed = True
    binding_sha256 = "ab" * 32
    chain: list = []
    lock = threading.Lock()


def test_receipts_front_serves_health_from_its_cache(monkeypatch) -> None:
    receipts = _load("room_receipts")
    monkeypatch.setattr(receipts.Server, "sev_log", lambda self: ["SEV-SNP"])
    up_port = _serve(ThreadingHTTPServer(("127.0.0.1", 0), _Upstream))
    srv = receipts.Server(("127.0.0.1", 0), _Ledger(), 1, up_port, b"k" * 32, "/nonexistent.sock")
    port = _serve(srv)
    deadline = time.time() + 5
    while srv.health[1] is None and time.time() < deadline:
        time.sleep(0.05)
    hits = _Upstream.hits
    for _ in range(20):
        status, doc, took = _get(port, "/room/health")
        assert status == 200 and doc["body"]["sealed"] is True and doc["body"]["room_id"] == "sealed"
        assert took < 0.2, took
    # 20 health calls cost at most one or two upstream calls (the 1 s refresh), not 20.
    assert _Upstream.hits - hits <= 3
    status, _, _ = _get(port, "/room/health", key="x" * 32)
    assert status == 401


class _Broker(BaseHTTPRequestHandler):
    total = 25_000
    seen: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = parse_qs(urlsplit(self.path).query)
        after, limit = int(q["after"][0]), min(int(q["limit"][0]), 10_000)
        type(self).seen.append((after, limit))
        page = [{"statement": {"sequence": i + 1}} for i in range(after, min(after + limit, self.total))]
        body = json.dumps({"binding_sha256": "b", "head": f"h{self.total}", "count": len(page), "receipts": page}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.parametrize("total", [25_000, 20_000, 0])
def test_verifier_reads_the_whole_chain_page_by_page(tmp_path, total) -> None:
    pytest.importorskip("cryptography")
    verify = _load("verify_receipts")
    _Broker.total, _Broker.seen = total, []
    port = _serve(ThreadingHTTPServer(("127.0.0.1", 0), _Broker))
    doc = verify.fetch_chain(f"http://127.0.0.1:{port}", "sealed-1", "key")
    assert doc["count"] == total and len(doc["receipts"]) == total
    assert [r["statement"]["sequence"] for r in doc["receipts"]] == list(range(1, total + 1))
    assert doc["head"] == f"h{total}"
    assert [a for a, _ in _Broker.seen] == list(range(0, total + 1, 10_000))
