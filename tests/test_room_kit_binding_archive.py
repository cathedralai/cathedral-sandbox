"""Broker archived bindings verify receipts from earlier boots (AB#381)."""

from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


vr = _load("verify_receipts_archive_t", KIT / "verify_receipts.py")
rr = _load("room_receipts_archive_t", KIT / "room_receipts.py")


def _raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()


def _receipt(key: Ed25519PrivateKey, statement: dict) -> dict:
    return {
        "statement": statement,
        "signature_b64": base64.b64encode(key.sign(vr.canonical(statement))).decode(),
        "receipt_sha256": vr.sha(vr.canonical(statement)),
    }


def _binding(hotel: str, key: Ed25519PrivateKey, *, tag: str) -> tuple[dict, str]:
    binding = {
        "schema": "cathedral_sealed_hotel_binding_v1",
        "hotel": hotel,
        "boot_id": tag,
        "measurement": "ab" * 48,
        "chip_id": "cd" * 64,
        "reported_tcb": "01" * 8,
        "policy": "0x30000",
        "host_data": "ef" * 32,
        "receipt_key_ed25519_b64": base64.b64encode(_raw_pub(key)).decode(),
    }
    bsha = vr.sha(vr.canonical(binding))
    return binding, bsha


def _att(binding: dict, bsha: str) -> dict:
    report = bytearray(0x4A0)
    report[0:4] = (3).to_bytes(4, "little")
    report[0x50:0x90] = bytes.fromhex(bsha) + bytes(32)
    report[0x90:0xC0] = bytes.fromhex(binding["measurement"])
    report[0xC0:0xE0] = bytes.fromhex(binding["host_data"])
    report[0x180:0x188] = bytes.fromhex(binding["reported_tcb"])
    report[0x1A0:0x1E0] = bytes.fromhex(binding["chip_id"])
    report[0x08:0x10] = int(binding["policy"], 16).to_bytes(8, "little")
    return {"binding": binding, "binding_sha256": bsha, "report_b64": base64.b64encode(bytes(report)).decode()}


class Broker(BaseHTTPRequestHandler):
    live_att: dict
    archives: dict[str, dict]

    def log_message(self, *_args) -> None:
        return

    def _auth(self) -> str | None:
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def do_GET(self) -> None:
        if self.path.startswith("/v1/broker/bindings/"):
            if self._auth() != "operator":
                self.send_response(401)
                self.end_headers()
                return
            sha = self.path.rsplit("/", 1)[-1].lower()
            raw = self.archives.get(sha)
            if raw is None:
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/v1/hotels/h1/attestation" and self._auth() == "guest":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(Broker.live_att).encode())
            return
        if self.path.startswith("/v1/hotels/h1/receipts") and self._auth() == "guest":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(Broker.chain_page).encode())
            return
        self.send_response(404)
        self.end_headers()


def _serve(handler) -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


def _cli(tmp_path: Path, *argv: str) -> dict:
    proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), *argv],
                          capture_output=True, text=True)
    assert proc.stdout.strip(), proc.stderr
    return json.loads(proc.stdout)


@pytest.fixture()
def fixtures(tmp_path: Path):
    old_key, new_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    old_binding, old_bsha = _binding("h1", old_key, tag="boot-old")
    new_binding, new_bsha = _binding("h1", new_key, tag="boot-new")
    Broker.archives = {old_bsha: old_binding}
    Broker.live_att = _att(new_binding, new_bsha)
    st = {
        "schema": "cathedral_sealed_hotel_receipt_v1",
        "binding_sha256": old_bsha,
        "hotel": "h1",
        "sequence": 1,
        "previous_receipt_sha256": old_bsha,
        "action": "create",
        "status": 202,
        "sandbox_id": "room-a",
    }
    old_rc = _receipt(old_key, st)
    st_live = {**st, "binding_sha256": new_bsha, "sequence": 1, "previous_receipt_sha256": new_bsha}
    live_rc = _receipt(new_key, st_live)
    Broker.chain_page = {"binding_sha256": new_bsha, "head": live_rc["receipt_sha256"],
                         "receipts": [old_rc, live_rc], "scanned": 2}
    guest = tmp_path / "guest.key"
    op = tmp_path / "operator.key"
    guest.write_text("guest\n")
    op.write_text("operator\n")
    att = tmp_path / "att.json"
    chain = tmp_path / "chain.json"
    att.write_text(json.dumps(Broker.live_att))
    chain.write_text(json.dumps({"receipts": [old_rc, live_rc]}))
    return {"base": _serve(Broker), "guest": guest, "operator": op, "att": att, "chain": chain,
            "old_bsha": old_bsha, "new_bsha": new_bsha}


def test_fetch_archived_binding_unit(fixtures) -> None:
    doc = vr.fetch_archived_binding(fixtures["base"], "operator", fixtures["old_bsha"])
    assert doc["binding_sha256"] == fixtures["old_bsha"]
    assert doc["binding"]["boot_id"] == "boot-old"


def test_stale_receipts_fail_without_operator_key(fixtures) -> None:
    out = _cli(fixtures["att"].parent, "--attestation", str(fixtures["att"]), "--receipts", str(fixtures["chain"]),
               "--skip-amd")
    assert out["verdict"] == "FAIL"
    assert "operator-key-file" in out["reason"] or "earlier binding" in out["reason"]


def test_broker_path_checks_archived_receipts(fixtures) -> None:
    out = _cli(
        fixtures["att"].parent,
        "--broker",
        fixtures["base"],
        "--key-file",
        str(fixtures["guest"]),
        "--operator-key-file",
        str(fixtures["operator"]),
        "--hotel",
        "h1",
        "--skip-amd",
    )
    # Archived sealed bindings have no SNP report: signatures check, attestation
    # is NOT PROVEN (AB#381 HOLD). Do not fold them into an attested PASS.
    assert out["verdict"] == "NOT PROVEN", out
    assert out["chain"]["receipts"] == 2
    assert fixtures["old_bsha"] in out["chain"]["bindings"]
    assert out["attestation"]["archived_chains"][0]["signatures_ok"] == 1
    assert "no SNP report" in out["not_proven"][0]


def test_mismatched_archive_refused(fixtures) -> None:
    key = fixtures["old_bsha"]
    saved = Broker.archives[key]
    Broker.archives[key] = {**saved, "boot_id": "forged"}
    out = _cli(
        fixtures["att"].parent,
        "--broker",
        fixtures["base"],
        "--key-file",
        str(fixtures["guest"]),
        "--operator-key-file",
        str(fixtures["operator"]),
        "--hotel",
        "h1",
        "--skip-amd",
    )
    assert out["verdict"] == "FAIL"
    assert "does not hash" in out["reason"]
    Broker.archives[key] = saved
