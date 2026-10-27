"""Escape Room nonce plant on the receipts front (room_receipts.py)."""
from __future__ import annotations

import base64
import http.client
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_escape_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32
NONCE = "control-plane-nonce-1"


def _fake_report() -> bytes:
    report = bytearray(0x4A0)
    report[0:4] = (3).to_bytes(4, "little")
    report[0x08:0x10] = (0x30000).to_bytes(8, "little")
    report[0x90:0xC0] = bytes.fromhex("ab" * 48)
    report[0xC0:0xE0] = bytes.fromhex("cd" * 32)
    report[0x180:0x188] = bytes.fromhex("01" * 8)
    report[0x1A0:0x1E0] = bytes.fromhex("ef" * 64)
    return bytes(report)


def _sealed_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
    monkeypatch.setattr(rr, "snp_report", lambda _data: _fake_report())
    return rr.Ledger("room-a", str(tmp_path))


def _front(tmp_path, monkeypatch, *, escape: str | None, sealed: bool, plaintext: str | None = None):
    if escape is None:
        monkeypatch.delenv("ROOM_ESCAPE", raising=False)
    else:
        monkeypatch.setenv("ROOM_ESCAPE", escape)
    if plaintext is None:
        monkeypatch.delenv("ROOM_ESCAPE_ALLOW_PLAINTEXT", raising=False)
    else:
        monkeypatch.setenv("ROOM_ESCAPE_ALLOW_PLAINTEXT", plaintext)
    plant_dir = tmp_path / "escape-room"
    monkeypatch.setenv("ROOM_ESCAPE_NONCE_PATH", str(plant_dir / "nonce"))
    if sealed:
        ledger = _sealed_ledger(tmp_path / "store", monkeypatch)
    else:
        monkeypatch.setattr(rr, "tsm_provider", lambda: None)
        ledger = rr.Ledger("room-a", str(tmp_path / "store"))

    class Api(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    Thread(target=api.serve_forever, daemon=True).start()
    server = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, KEY, "/nonexistent.sock")
    Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1], ledger, plant_dir


def _request(port: int, method: str, path: str, body: bytes | None = None, key: bytes | None = KEY):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {}
    if key is not None:
        headers["Authorization"] = "Bearer " + key.decode()
    if body is not None:
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _receipt(headers: dict) -> dict:
    raw = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def test_signed_routes_do_not_proxy_the_plant() -> None:
    def action(method, path):
        return next((a for m, p, a in rr.SIGNED if m == method and p.match(path)), None)

    assert action("POST", "/room/escape-nonce") is None
    assert action("GET", "/room/escape-plant-key") is None


def test_plant_is_refused_when_escape_is_off(tmp_path, monkeypatch) -> None:
    port, ledger, plant_dir = _front(tmp_path, monkeypatch, escape=None, sealed=True)
    status, _headers, out = _request(port, "POST", "/room/escape-nonce",
                                     json.dumps({"window_id": "win-1", "nonce": NONCE}).encode())
    assert status == 403 and b"escape_disabled" in out
    assert ledger.chain == []
    assert not (plant_dir / "nonce").exists()


def test_plant_is_refused_on_a_level1_hotel(tmp_path, monkeypatch) -> None:
    port, ledger, plant_dir = _front(tmp_path, monkeypatch, escape="1", sealed=False)
    status, _headers, out = _request(port, "POST", "/room/escape-nonce",
                                     json.dumps({"window_id": "win-1", "nonce": NONCE}).encode())
    assert status == 403 and b"escape_disabled" in out
    assert ledger.sealed is False
    assert ledger.chain == []
    assert not (plant_dir / "nonce").exists()


def test_plant_requires_the_hotel_key(tmp_path, monkeypatch) -> None:
    port, ledger, _plant_dir = _front(tmp_path, monkeypatch, escape="1", sealed=True)
    status, _headers, _out = _request(port, "POST", "/room/escape-nonce",
                                      json.dumps({"window_id": "win-1", "nonce": NONCE}).encode(),
                                      key=None)
    assert status == 401
    status, _headers, _out = _request(port, "POST", "/room/escape-nonce",
                                      json.dumps({"window_id": "win-1", "nonce": NONCE}).encode(),
                                      key=b"wrong-key-wrong-key-wrong-key-xx")
    assert status == 401
    assert ledger.chain == []


def test_plaintext_is_refused_unless_flagged(tmp_path, monkeypatch) -> None:
    port, ledger, plant_dir = _front(tmp_path, monkeypatch, escape="1", sealed=True)
    status, _headers, out = _request(port, "POST", "/room/escape-nonce",
                                     json.dumps({"window_id": "win-1", "nonce": NONCE}).encode())
    assert status == 409 and b"plaintext_forbidden" in out
    assert ledger.chain == []
    assert not (plant_dir / "nonce").exists()


def test_encrypted_plant_writes_root_only_and_never_echoes(tmp_path, monkeypatch) -> None:
    port, ledger, plant_dir = _front(tmp_path, monkeypatch, escape="1", sealed=True)
    status, headers, key_body = _request(port, "GET", "/room/escape-plant-key")
    assert status == 200
    key_doc = json.loads(key_body)
    assert key_doc["algorithm"] == rr.PLANT_ALGORITHM
    pub = X25519PublicKey.from_public_bytes(base64.b64decode(key_doc["x25519_public_b64"]))
    env = rr.seal_plant_nonce(NONCE.encode(), pub, "room-a", "win-1")
    env["window_id"] = "win-1"
    status, headers, out = _request(port, "POST", "/room/escape-nonce", json.dumps(env).encode())
    assert status == 200
    body = json.loads(out)
    assert body == {"encrypted": True, "ok": True, "path": str(plant_dir / "nonce"), "window_id": "win-1"}
    dumped = json.dumps({"body": body, "headers": headers, "chain": ledger.chain})
    assert NONCE not in dumped
    assert NONCE not in out.decode()
    assert NONCE.encode() not in out
    st = _receipt(headers)["statement"]
    assert st["action"] == rr.PLANT_ACTION
    assert st["window_id"] == "win-1"
    assert st["sandbox_id"] is None
    assert st["encrypted"] is True
    assert st["nonce_sha256"] == rr.sha(NONCE.encode())
    assert st["path"] == str(plant_dir / "nonce")
    assert "nonce" not in st
    assert NONCE not in json.dumps(st)
    nonce_path = plant_dir / "nonce"
    assert nonce_path.read_bytes() == (NONCE + "\n").encode()
    assert nonce_path.stat().st_mode & 0o777 == 0o400
    assert plant_dir.stat().st_mode & 0o777 == 0o700
    assert (plant_dir / "window").read_text() == "win-1\n"
    assert (plant_dir / "window").stat().st_mode & 0o777 == 0o444


def test_plaintext_plant_when_flagged_still_omits_nonce_from_receipt(tmp_path, monkeypatch) -> None:
    port, ledger, plant_dir = _front(tmp_path, monkeypatch, escape="1", sealed=True, plaintext="1")
    status, headers, out = _request(port, "POST", "/room/escape-nonce",
                                    json.dumps({"window_id": "win-2", "nonce": NONCE}).encode())
    assert status == 200
    body = json.loads(out)
    assert body["encrypted"] is False and body["window_id"] == "win-2"
    assert NONCE not in json.dumps(body)
    st = _receipt(headers)["statement"]
    assert st["action"] == rr.PLANT_ACTION and st["encrypted"] is False
    assert "nonce" not in st and NONCE not in json.dumps(st)
    assert (plant_dir / "nonce").read_text() == NONCE + "\n"
    assert (plant_dir / "nonce").stat().st_mode & 0o777 == 0o400


def test_wrong_ciphertext_does_not_write(tmp_path, monkeypatch) -> None:
    port, ledger, plant_dir = _front(tmp_path, monkeypatch, escape="1", sealed=True)
    other = X25519PrivateKey.generate().public_key()
    env = rr.seal_plant_nonce(NONCE.encode(), other, "room-a", "win-1")
    env["window_id"] = "win-1"
    status, _headers, out = _request(port, "POST", "/room/escape-nonce", json.dumps(env).encode())
    assert status == 400 and b"ciphertext does not open" in out
    assert NONCE not in out.decode()
    assert ledger.chain == []
    assert not (plant_dir / "nonce").exists()


def test_plant_key_is_hidden_when_escape_is_off(tmp_path, monkeypatch) -> None:
    port, _ledger, _plant_dir = _front(tmp_path, monkeypatch, escape="0", sealed=True)
    status, _headers, out = _request(port, "GET", "/room/escape-plant-key")
    assert status == 403 and b"escape_disabled" in out


def test_seal_open_round_trip() -> None:
    priv = X25519PrivateKey.generate()
    env = rr.seal_plant_nonce(NONCE.encode(), priv.public_key(), "hotel", "win-9")
    assert rr.open_plant_nonce(env, priv, "hotel", "win-9") == NONCE
    with pytest.raises(rr.PlantError):
        rr.open_plant_nonce(env, priv, "hotel", "win-other")
