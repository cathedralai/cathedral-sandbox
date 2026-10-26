"""Level 1 hotel receipts: an Ed25519 chain with no SNP hardware (#288)."""

from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, KIT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rr = _load("room_receipts")
vr = _load("verify_receipts")


def _fake_report() -> bytes:
    report = bytearray(0x4A0)
    report[0:4] = (3).to_bytes(4, "little")
    report[0x08:0x10] = (0x30000).to_bytes(8, "little")
    report[0x90:0xC0] = bytes.fromhex("ab" * 48)
    report[0xC0:0xE0] = bytes.fromhex("cd" * 32)
    report[0x180:0x188] = bytes.fromhex("01" * 8)
    report[0x1A0:0x1E0] = bytes.fromhex("ef" * 64)
    return bytes(report)


def _serve(handler) -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = json.dumps({"room_id": "room-a", "slots": 2}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _get(port: int) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/room/health", headers={"Authorization": "Bearer " + ("k" * 32)})
    response = conn.getresponse()
    body = json.loads(response.read())
    conn.close()
    assert response.status == 200
    return body


def _chain(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)

    def no_snp(_data: bytes) -> bytes:
        raise AssertionError("level 1 must not ask for an SNP report")

    monkeypatch.setattr(rr, "snp_report", no_snp)
    ledger = rr.Ledger("room-a", str(tmp_path))
    ledger.sign({
        "action": "create", "target": "POST /v1/sandboxes", "sandbox_id": "sbx_1", "status": 201,
        "customer_request_sha256": "aa" * 32, "command_sha256": None, "image": "alpine:3.20",
        "image_digest": None, "result_sha256": "bb" * 32,
    })
    ledger.sign({
        "action": "exec", "target": "POST /v1/sandboxes/sbx_1/exec", "sandbox_id": "sbx_1", "status": 200,
        "customer_request_sha256": "cc" * 32, "command_sha256": "dd" * 32, "image": None,
        "image_digest": None, "result_sha256": "ee" * 32,
    })
    return ledger


def _verify_cli(tmp_path: Path, attestation: dict, receipts: dict) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    att = tmp_path / "attestation.json"
    chain = tmp_path / "receipts.json"
    att.write_text(json.dumps(attestation))
    chain.write_text(json.dumps(receipts))
    return subprocess.run(
        [sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att), "--receipts", str(chain)],
        capture_output=True, text=True, check=False,
    )


def test_level1_chain_verifies_offline_without_snp(tmp_path, monkeypatch) -> None:
    ledger = _chain(tmp_path, monkeypatch)
    assert ledger.sealed is False
    assert ledger.binding["schema"] == rr.HOTEL_BINDING_SCHEMA == vr.HOTEL_BINDING_SCHEMA
    assert ledger.binding["level"] == "hotel"
    assert ledger.binding["schema"] != rr.BINDING_SCHEMA
    for snp_field in ("measurement", "chip_id", "reported_tcb", "policy", "host_data"):
        assert snp_field not in ledger.binding
    assert "report_b64" not in ledger.attestation()
    assert [r["statement"]["schema"] for r in ledger.chain] == [rr.HOTEL_RECEIPT_SCHEMA, rr.HOTEL_RECEIPT_SCHEMA]
    assert ledger.chain[0]["statement"]["previous_receipt_sha256"] == ledger.binding_sha256
    assert ledger.chain[1]["statement"]["previous_receipt_sha256"] == ledger.chain[0]["receipt_sha256"]

    proc = _verify_cli(tmp_path, ledger.attestation(), {
        "binding_sha256": ledger.binding_sha256, "head": ledger.head, "receipts": ledger.chain,
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["verdict"] == "PASS"
    assert out["attestation"]["level"] == "hotel"
    assert "amd" not in out["attestation"]
    assert out["chain"]["receipts"] == 2
    assert out["chain"]["links_checked"] == 2
    assert out["chain"]["contiguous"] is True
    assert out["chain"]["first"] == 1 and out["chain"]["last"] == 2
    assert out["checked"] == "whole chain to the head the server named"


def test_tampered_level1_receipt_fails(tmp_path, monkeypatch) -> None:
    ledger = _chain(tmp_path / "good", monkeypatch)
    receipts = {
        "binding_sha256": ledger.binding_sha256, "head": ledger.head,
        "receipts": json.loads(json.dumps(ledger.chain)),
    }
    raw = bytearray(base64.b64decode(receipts["receipts"][1]["signature_b64"]))
    raw[0] ^= 0x01
    receipts["receipts"][1]["signature_b64"] = base64.b64encode(bytes(raw)).decode()
    proc = _verify_cli(tmp_path / "bad", ledger.attestation(), receipts)
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["verdict"] == "FAIL"
    assert "signature" in out["reason"]


def test_other_tsm_provider_is_level1(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: "tdx_guest")
    def no_snp(_data: bytes) -> bytes:
        raise AssertionError("level 1 must not ask for an SNP report")

    monkeypatch.setattr(rr, "snp_report", no_snp)
    ledger = rr.Ledger("room-a", str(tmp_path))
    assert ledger.sealed is False
    assert ledger.binding["level"] == "hotel"
    assert "measurement" not in ledger.binding


def test_sev_guest_reuses_the_zero_report(tmp_path, monkeypatch) -> None:
    """A sealed start still asks for two reports: facts, then the binding."""
    report = _fake_report()
    calls: list[bytes] = []

    def fake_read(data: bytes) -> tuple[str, bytes]:
        calls.append(data)
        return "sev_guest", report

    monkeypatch.setattr(rr, "_ZERO_REPORT", None)
    monkeypatch.setattr(rr, "_read_tsm", fake_read)
    real_isdir = os.path.isdir

    def isdir(path: str) -> bool:
        if path == rr.TSM:
            return True
        return real_isdir(path)

    monkeypatch.setattr(rr.os.path, "isdir", isdir)
    ledger = rr.Ledger("room-a", str(tmp_path))
    assert ledger.sealed is True
    assert ledger.binding["schema"] == rr.BINDING_SCHEMA
    assert calls[0] == bytes(64)
    assert calls[1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)
    assert len(calls) == 2


def test_sev_guest_keeps_the_sealed_binding(tmp_path, monkeypatch) -> None:
    report = _fake_report()
    calls: list[bytes] = []

    def fake_snp(data: bytes) -> bytes:
        calls.append(data)
        return report

    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
    monkeypatch.setattr(rr, "snp_report", fake_snp)
    ledger = rr.Ledger("room-a", str(tmp_path))
    assert ledger.sealed is True
    assert ledger.binding["schema"] == "cathedral_sealed_hotel_binding_v1"
    assert ledger.receipt_schema == "cathedral_sealed_hotel_receipt_v1"
    assert "level" not in ledger.binding
    assert ledger.binding["measurement"] == "ab" * 48
    assert ledger.binding["policy"] == "0x30000"
    attestation = ledger.attestation()
    assert attestation["report_b64"]
    assert len(calls) == 2
    assert calls[0] == bytes(64)
    assert calls[1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)
    signed = ledger.sign({"action": "create", "status": 201})
    assert signed["statement"]["schema"] == "cathedral_sealed_hotel_receipt_v1"


def test_sealed_verification_still_requires_the_snp_report(tmp_path) -> None:
    binding = {"schema": rr.BINDING_SCHEMA, "hotel": "room-a", "receipt_key_ed25519_b64": "AA=="}
    att = {"binding": binding, "binding_sha256": rr.sha(rr.canonical(binding))}
    with pytest.raises((KeyError, vr.Fail)):
        vr.verify_attestation(att, None, None, str(tmp_path), None, True)


def test_level1_health_does_not_say_sealed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    monkeypatch.setattr(rr.Server, "sev_log", lambda self: [])
    ledger = rr.Ledger("room-a", str(tmp_path))
    upstream = _serve(_Upstream)
    server = rr.Server(("127.0.0.1", 0), ledger, 1, upstream, b"k" * 32, "/nonexistent.sock")
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    deadline = time.time() + 5
    while server.health[1] is None and time.time() < deadline:
        time.sleep(0.05)
    body = _get(port)
    assert body.get("sealed") is not True
    assert "sealed" not in body
    assert body["room_id"] == "room-a"
    assert body["receipts"]["binding_sha256"] == ledger.binding_sha256


def test_install_defaults_and_caddy_front() -> None:
    script = r"""
set -euo pipefail
source "$RECEIPTS"
unset ROOM_RECEIPTS ROOM_RECEIPTS_LISTEN ROOM_HOTEL_NAME
ROOM_API_PORT=18090
ROOM_HEALTH_PORT=18091
ROOM_ID=room-a
receipts_apply_defaults
printf '%s %s %s %s\n' "$ROOM_RECEIPTS" "$ROOM_RECEIPTS_LISTEN" "$ROOM_HOTEL_NAME" "$(receipts_api_upstream)"
ROOM_RECEIPTS=0
printf 'off %s\n' "$(receipts_api_upstream)"
ROOM_RECEIPTS=1
ROOM_RECEIPTS_LISTEN=127.0.0.1:18090
if receipts_apply_defaults; then echo collision-allowed; exit 1; fi
ROOM_RECEIPTS_LISTEN=guest:18090
ROOM_HOTEL_NAME=room-a
receipts_apply_defaults
printf 'guest %s\n' "$(receipts_api_upstream)"
ROOM_RECEIPTS_LISTEN=0.0.0.0:18092
printf 'wild %s\n' "$(receipts_api_upstream)"
"""
    proc = subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, check=False,
        env={"RECEIPTS": str(KIT / "lib" / "receipts_mode.sh"), "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0] == "1 127.0.0.1:18092 room-a 127.0.0.1:18092"
    assert lines[1] == "off 127.0.0.1:18090"
    assert lines[2] == "guest guest:18090"
    assert lines[3] == "wild 127.0.0.1:18092"
    install = (KIT / "install.sh").read_text()
    assert 'reverse_proxy $ROOM_API_UPSTREAM' in install
    assert "reverse_proxy 127.0.0.1:$ROOM_HEALTH_PORT" in install
    assert "receipts_apply_defaults" in install


def test_guest_filtered_chain_verifies(tmp_path, monkeypatch) -> None:
    # The broker gives a guest only its own receipts, with the hotel's head.
    # A filtered chain is a subset: each receipt is checked, not the whole chain.
    ledger = _chain(tmp_path, monkeypatch)
    proc = _verify_cli(tmp_path, ledger.attestation(), {
        "binding_sha256": ledger.binding_sha256, "head": ledger.head, "filtered": True,
        "receipts": ledger.chain[1:],
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["verdict"] == "PASS"
    # The doc says it is filtered, so only each receipt was checked: say so.
    assert out["checked"] == "each receipt; not that none are missing"


def test_fetch_chain_pages_a_filtered_chain_by_raw_offset(monkeypatch) -> None:
    # The broker filters each hotel page, so a guest page is short while the
    # hotel has more. Paging must follow the hotel's offset ("scanned"), not
    # the number of receipts the guest got back.
    monkeypatch.setattr(vr, "PAGE", 3)
    raw = [{"seq": i, "mine": i in (2, 5, 7)} for i in range(1, 9)]
    asked = []

    def fake_get(url, _key):
        after = int(url.split("after=")[1].split("&")[0])
        asked.append(after)
        page = raw[after:after + 3]
        return {"head": "h", "filtered": True, "scanned": len(page),
                "receipts": [r for r in page if r["mine"]]}

    monkeypatch.setattr(vr, "get", fake_get)
    doc = vr.fetch_chain("https://b", "h1", "k")
    assert [r["seq"] for r in doc["receipts"]] == [2, 5, 7]
    assert asked == [0, 3, 6]
    assert doc["filtered"] is True


def _sealed_att(cmdline: str) -> dict:
    binding = {"schema": rr.BINDING_SCHEMA, "hotel": "room-a", "receipt_key_ed25519_b64": "AA==",
               "measurement": "ab" * 48, "chip_id": "ef" * 64, "reported_tcb": "01" * 8,
               "host_data": "cd" * 32, "policy": "0x30000", "kernel_cmdline": cmdline}
    bsha = rr.sha(rr.canonical(binding))
    report = bytearray(_fake_report())
    report[0x50:0x90] = bytes.fromhex(bsha) + bytes(32)
    return {"binding": binding, "binding_sha256": bsha, "report_b64": base64.b64encode(bytes(report)).decode()}


def test_verifier_refuses_a_debug_sealed_build(tmp_path) -> None:
    # A debug build gives the host root SSH into the guest. The SNP policy is
    # the same, so the measured cmdline flag is what tells them apart.
    ok = vr.verify_attestation(_sealed_att("rdinit=/init cathedral.debug=0"), None, None, str(tmp_path), None, True)
    assert "cathedral.debug=0" in ok["kernel_cmdline"]
    with pytest.raises(vr.Fail):
        vr.verify_attestation(_sealed_att("rdinit=/init cathedral.debug=1"), None, None, str(tmp_path), None, True)


def test_a_fresh_hotel_with_no_receipts_verifies(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    fresh = rr.Ledger("room-b", str(tmp_path / "b"))
    proc = _verify_cli(tmp_path, fresh.attestation(), {"binding_sha256": fresh.binding_sha256, "head": fresh.head, "receipts": []})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["chain"]["receipts"] == 0


def test_sealed_flags_refuse_a_level1_answer(tmp_path, monkeypatch) -> None:
    # A sealed guest whose TSM is missing silently runs level 1. The customer
    # who asked for a measurement must not get PASS from a level-1 binding.
    ledger = _chain(tmp_path, monkeypatch)
    att = tmp_path / "attestation.json"
    chain = tmp_path / "receipts.json"
    att.write_text(json.dumps(ledger.attestation()))
    chain.write_text(json.dumps({"binding_sha256": ledger.binding_sha256, "head": ledger.head, "receipts": ledger.chain}))
    for flags in (["--expected-measurement", "ab" * 48], ["--ark-sha256", "cd" * 32], ["--require-sealed"]):
        proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att), "--receipts", str(chain), *flags],
                              capture_output=True, text=True, check=False)
        assert proc.returncode == 1, flags
        assert "level 1" in json.loads(proc.stdout)["reason"], proc.stdout
