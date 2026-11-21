"""Guest ingress served from the sealed guest and the signed expose (AB#422).

The front (room_receipts.py) with ROOM_GUEST_INGRESS=1 and a zone: room_ingress
serves HTTPS with the key the binding names, gets its certificate over DNS-01
through the broker (here a stub CA and a stub broker that applies the Go rules),
and answers POST /v1/sandboxes/<id>/expose itself with a signed receipt that
verify_receipts checks against the binding. Flag off: expose goes to the API.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
sys.path.insert(0, str(KIT))
sys.path.insert(0, str(ROOT / "tests"))
import room_acme  # noqa: E402
import room_ingress  # noqa: E402
import room_receipts as rr  # noqa: E402
import verify_receipts as vr  # noqa: E402
from acme_stub import StubBroker, StubCA  # noqa: E402

KEY = b"k" * 32
AUTH = {"Authorization": "Bearer " + KEY.decode()}
HOTEL = "room-a"
ZONE = "hotels.example.com"
ROOM = "sbx_0123456789ab"
HOST = f"sbx-0123456789ab-8080.{HOTEL}.{ZONE}"


def _fake_report(report_data: bytes) -> bytes:
    report = bytearray(0x4A0)
    report[0:4] = (3).to_bytes(4, "little")
    report[0x08:0x10] = (0x30000).to_bytes(8, "little")
    report[0x50:0x90] = report_data
    report[0x90:0xC0] = bytes.fromhex("ab" * 48)
    report[0xC0:0xE0] = bytes.fromhex("cd" * 32)
    report[0x180:0x188] = bytes.fromhex("01" * 8)
    report[0x1A0:0x1E0] = bytes.fromhex("ef" * 64)
    return bytes(report)


class Api(BaseHTTPRequestHandler):
    """The room API behind the front: one running room, one stopped, the AB#605 dial and the 501 expose."""

    protocol_version = "HTTP/1.1"
    seen: list = []

    def log_message(self, *args):
        pass

    def _reply(self, status: int, body: bytes, headers=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in headers or []:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self.seen.append(("GET", self.path, dict(self.headers), b""))
        if self.path == f"/v1/sandboxes/{ROOM}":
            return self._reply(200, json.dumps({"id": ROOM, "state": "running"}).encode())
        if self.path == "/v1/sandboxes/sbx_stopped":
            return self._reply(200, json.dumps({"id": "sbx_stopped", "state": "stopped"}).encode())
        return self._reply(404, b'{"error":{"code":"sandbox_not_found","message":"no such room"}}')

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        self.seen.append(("POST", self.path, dict(self.headers), body))
        if self.path.endswith("/expose"):
            return self._reply(501, b'{"error":{"code":"expose_not_supported"}}')
        if self.path.startswith(f"/v1/sandboxes/{ROOM}/ports/"):
            return self._reply(200, b"hello from the room port", [("X-App", "yes")])
        return self._reply(404, b"{}")

    def do_DELETE(self):  # noqa: N802
        self.seen.append(("DELETE", self.path, dict(self.headers), b""))
        return self._reply(200, b'{"ok":true}')


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
    monkeypatch.setattr(rr, "snp_report", _fake_report)
    Api.seen = []
    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    ledger = rr.Ledger(HOTEL, str(tmp_path / "store"), ingress=rr.GuestIngress(HOTEL, zone=ZONE))
    config = room_ingress.IngressConfig(zone=ZONE, broker_url="http://127.0.0.1:1", listen=("127.0.0.1", 0))
    state = room_ingress.IngressState(ledger.ingress, HOTEL, config, str(tmp_path))
    ledger.ingress.serving = state
    front = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, KEY, "/nonexistent.sock", pool_scan=False)
    threading.Thread(target=front.serve_forever, daemon=True).start()
    ingress = room_ingress.IngressServer(("127.0.0.1", 0), state, api.server_address[1], KEY)
    threading.Thread(target=ingress.serve_forever, daemon=True).start()
    dns: dict = {}
    ca = StubCA(dns)
    broker = StubBroker(dns, ZONE, HOTEL, ledger.key.public_key(), ledger.binding_sha256)
    keeper = room_ingress.CertKeeper(
        state, ledger.key, ledger.binding_sha256,
        client=room_acme.AcmeClient(ca.directory, sleep=lambda s: None),
        dns=room_acme.BrokerDNS01(broker.base, ZONE, HOTEL, ledger.key, ledger.binding_sha256),
        log=lambda *a, **k: None)
    yield {"front": front.server_address[1], "ingress": ingress.server_address[1], "ledger": ledger,
           "state": state, "keeper": keeper, "ca": ca, "broker": broker}
    for s in (front, ingress, api):
        s.shutdown()
    ca.close()
    broker.close()


def _call(port: int, method: str, path: str, body: bytes | None = None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers={**AUTH, **(headers or {})})
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _expose(w, room=ROOM, port=8080):
    return _call(w["front"], "POST", f"/v1/sandboxes/{room}/expose", json.dumps({"port": port}).encode())


def _receipt(headers: dict) -> dict:
    raw = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def _https(port: int, host: str, method="GET", path="/hello?x=1", headers=None, body=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    tls = ctx.wrap_socket(raw, server_hostname=host)
    der = tls.getpeercert(binary_form=True)
    c = http.client.HTTPConnection(host)
    c.sock = tls
    c.request(method, path, body=body, headers={"Host": host, **(headers or {})})
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    tls.close()
    cert = x509.load_der_x509_certificate(der)
    spki = hashlib.sha256(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    return out, spki, cert


def _attestation(ledger) -> dict:
    return json.loads(rr.canonical(ledger.attestation()))


# ---------------------------------------------------------------- binding and certificate

def test_binding_names_the_zone_with_the_key(world) -> None:
    gi = world["ledger"].binding["guest_ingress"]
    assert gi == {"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": world["ledger"].ingress.tls_spki_sha256,
                  "zone": ZONE}


def test_before_the_certificate_the_same_key_serves_self_issued_and_expose_waits(world) -> None:
    (status, _h, _b), spki, cert = _https(world["ingress"], HOST)
    assert spki == world["ledger"].binding["guest_ingress"]["tls_spki_sha256"]
    assert status == 404  # nothing exposed yet
    assert cert.issuer == cert.subject  # self-issued
    status, headers, body = _expose(world)
    assert status == 503 and json.loads(body)["error"]["code"] == "ingress_not_ready"
    st = _receipt(headers)["statement"]
    assert st["action"] == "expose" and st["status"] == 503 and "expose_url" not in st


def test_certificate_comes_over_dns01_through_the_broker_for_the_guest_key(world) -> None:
    world["keeper"].once()
    assert world["state"].ready
    (_s, _h, _b), spki, cert = _https(world["ingress"], HOST)
    assert spki == world["ledger"].binding["guest_ingress"]["tls_spki_sha256"]
    assert cert.issuer != cert.subject
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert sorted(sans) == sorted([f"{HOTEL}.{ZONE}", f"*.{HOTEL}.{ZONE}"])
    calls = world["broker"].calls
    assert [c[0] for c in calls] == [200, 200] and len(calls[0][1]) == 2 and calls[1][1] == []


def test_keeper_keeps_serving_and_backs_off_when_the_broker_refuses(world) -> None:
    world["broker"].refuse = True
    waits = []
    keeper = world["keeper"]
    keeper._sleep = lambda s: (waits.append(s), len(waits) >= 3)[1]
    keeper.run()
    assert waits == [30, 60, 120]
    assert not world["state"].ready


# ---------------------------------------------------------------- the signed expose

def test_expose_answers_the_url_and_signs_port_host_and_key(world) -> None:
    world["keeper"].once()
    status, headers, body = _expose(world)
    assert status == 200, body
    doc = json.loads(body)
    url = f"https://{HOST}/"
    assert doc == {"port": 8080, "url": url, "host": HOST, "status": "exposed",
                   "tls_spki_sha256": world["ledger"].ingress.tls_spki_sha256}
    rc = _receipt(headers)
    st = rc["statement"]
    assert st["action"] == "expose" and st["sandbox_id"] == ROOM and st["status"] == 200
    assert (st["expose_port"], st["expose_url"], st["expose_host"]) == (8080, url, HOST)
    assert st["ingress_tls_spki_sha256"] == world["ledger"].binding["guest_ingress"]["tls_spki_sha256"]
    # The API's own expose (501) is never called.
    assert not [s for s in Api.seen if s[1].endswith("/expose")]
    att = _attestation(world["ledger"])
    out = vr.verify_receipts(att, [rc])
    assert out["signatures_ok"] == 1
    assert vr.check_exposes(att, [rc]) == [{"sequence": st["sequence"], "sandbox_id": ROOM, "port": 8080, "url": url,
                                            "tls_spki_sha256": st["ingress_tls_spki_sha256"]}]


def test_verify_cli_checks_the_expose_header_and_the_peer_key(world, tmp_path) -> None:
    world["keeper"].once()
    _s, headers, _b = _expose(world)
    (_st, _h, _b2), spki, _c = _https(world["ingress"], HOST)
    att = tmp_path / "att.json"
    att.write_text(json.dumps(_attestation(world["ledger"])))
    base = [sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att), "--skip-amd",
            "--receipt-header", headers["X-Room-Receipt"]]
    run = subprocess.run(base + ["--ingress-spki-sha256", spki], capture_output=True, text=True, timeout=60)
    out = json.loads(run.stdout)
    assert out["chain"]["exposes"][0]["url"] == f"https://{HOST}/", run.stdout
    assert out["attestation"]["guest_ingress"]["peer_checked"] is True
    assert out["attestation"]["guest_ingress"]["zone"] == ZONE
    bad = subprocess.run(base + ["--ingress-spki-sha256", "0" * 64], capture_output=True, text=True, timeout=60)
    assert bad.returncode == 1 and "not the key the binding names" in bad.stdout


@pytest.mark.parametrize("field, value, reason", [
    ("ingress_tls_spki_sha256", "0" * 64, "another ingress key"),
    ("expose_host", f"other-8080.{HOTEL}.{ZONE}", "host is not"),
    ("expose_url", "https://evil.example/", "URL is not"),
    ("expose_port", 0, "not a TCP port"),
])
def test_check_exposes_refuses_a_receipt_that_does_not_match_the_binding(world, field, value, reason) -> None:
    world["keeper"].once()
    _s, headers, _b = _expose(world)
    rc = _receipt(headers)
    rc["statement"][field] = value
    with pytest.raises(vr.Fail, match=reason):
        vr.check_exposes(_attestation(world["ledger"]), [rc])


@pytest.mark.parametrize("room, port, status, code", [
    (ROOM, 0, 400, "invalid_port"),
    (ROOM, True, 400, "invalid_port"),
    ("sbx_missing", 8080, 404, "sandbox_not_found"),
    ("sbx_stopped", 8080, 409, "sandbox_not_running"),
])
def test_expose_refusals_are_signed_and_name_no_url(world, room, port, status, code) -> None:
    world["keeper"].once()
    got, headers, body = _expose(world, room, port)
    assert got == status and json.loads(body)["error"]["code"] == code
    st = _receipt(headers)["statement"]
    assert st["status"] == status and "expose_url" not in st


def test_expose_needs_the_key(world) -> None:
    world["keeper"].once()
    c = http.client.HTTPConnection("127.0.0.1", world["front"], timeout=10)
    c.request("POST", f"/v1/sandboxes/{ROOM}/expose", body=b'{"port":8080}')
    assert c.getresponse().status == 401


# ---------------------------------------------------------------- the HTTPS path to the room port

def test_https_to_the_exposed_host_reaches_the_room_port_with_the_front_key_only(world) -> None:
    world["keeper"].once()
    _expose(world)
    (status, headers, body), _spki, _c = _https(world["ingress"], HOST, method="POST", path="/hello?x=1",
                                                headers={"Authorization": "Bearer customer", "X-Guest-Target": "/evil",
                                                         "X-Mine": "1"}, body=b"ping")
    assert status == 200 and body == b"hello from the room port" and headers.get("X-App") == "yes"
    method, path, sent, sent_body = [s for s in Api.seen if "/ports/" in s[1]][-1]
    assert (method, path, sent_body) == ("POST", f"/v1/sandboxes/{ROOM}/ports/8080/http", b"ping")
    assert sent["Authorization"] == "Bearer " + KEY.decode()
    assert sent["X-Guest-Method"] == "POST" and sent["X-Guest-Target"] == "/hello?x=1"
    assert sent["X-Mine"] == "1"


def test_unexposed_port_and_foreign_hosts_answer_404(world) -> None:
    world["keeper"].once()
    _expose(world)
    for host in (f"sbx-0123456789ab-9090.{HOTEL}.{ZONE}", f"{HOTEL}.{ZONE}", f"x.{HOST}", "evil.example",
                 f"sbx-0123456789ab-8080.other.{ZONE}"):
        (status, _h, _b), _spki, _c = _https(world["ingress"], host)
        assert status == 404, host


def test_deleting_the_room_ends_its_urls(world) -> None:
    world["keeper"].once()
    _expose(world)
    assert _https(world["ingress"], HOST)[0][0] == 200
    status, _h, _b = _call(world["front"], "DELETE", f"/v1/sandboxes/{ROOM}")
    assert status == 200
    assert _https(world["ingress"], HOST)[0][0] == 404


def test_flag_off_sends_expose_to_the_api_as_before(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
    monkeypatch.setattr(rr, "snp_report", _fake_report)
    Api.seen = []
    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    # The key without a zone (#494 as merged): nothing serves, expose is the API's.
    ledger = rr.Ledger(HOTEL, str(tmp_path / "store"), ingress=rr.GuestIngress(HOTEL))
    assert "zone" not in ledger.binding["guest_ingress"]
    front = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, KEY, "/nonexistent.sock", pool_scan=False)
    threading.Thread(target=front.serve_forever, daemon=True).start()
    try:
        status, headers, _b = _call(front.server_address[1], "POST", f"/v1/sandboxes/{ROOM}/expose", b'{"port":8080}')
        assert status == 501
        assert "expose_url" not in _receipt(headers)["statement"]
        assert [s[1] for s in Api.seen] == [f"/v1/sandboxes/{ROOM}/expose"]
    finally:
        front.shutdown()
        api.shutdown()


def test_room_label_shape() -> None:
    assert room_ingress.room_label("sbx_0123456789ab", 8080) == "sbx-0123456789ab-8080"
    assert room_ingress.room_label("SBX_1", 80) is None
    assert room_ingress.room_label("a/b", 80) is None
    assert room_ingress.room_label("x" * 60, 8080) is None


def test_config_from_env() -> None:
    assert room_ingress.IngressConfig.from_env({}) is None
    cfg = room_ingress.IngressConfig.from_env({"ROOM_INGRESS_ZONE": ZONE, "ROOM_INGRESS_BROKER_URL": "https://b.example",
                                               "ROOM_INGRESS_TLS_LISTEN": "10.215.0.2:8443"})
    assert cfg.listen == ("10.215.0.2", 8443) and cfg.public_port == 443
    assert cfg.directory_url == room_acme.LETS_ENCRYPT_DIRECTORY
    for bad in ({"ROOM_INGRESS_BROKER_URL": "http://b.example"}, {"ROOM_INGRESS_ZONE": "Bad_Zone"},
                {"ROOM_INGRESS_TLS_LISTEN": "8443"}, {"ROOM_ACME_DIRECTORY": "http://acme.example/dir"}):
        env = {"ROOM_INGRESS_ZONE": ZONE, "ROOM_INGRESS_BROKER_URL": "https://b.example",
               "ROOM_INGRESS_TLS_LISTEN": "10.215.0.2:8443", **bad}
        with pytest.raises(ValueError):
            room_ingress.IngressConfig.from_env(env)


def test_public_port_other_than_443_is_in_the_url(world) -> None:
    state = world["state"]
    state.config = room_ingress.IngressConfig(zone=ZONE, broker_url="https://b.example", listen=("127.0.0.1", 1),
                                              public_port=8443)
    assert state.url_for("sbx-1-80") == (f"sbx-1-80.{HOTEL}.{ZONE}", f"https://sbx-1-80.{HOTEL}.{ZONE}:8443/")


# ---------------------------------------------------------------- build-guest.sh: measured room.env and firewall

BASH = shutil.which("bash")
BUILD = (KIT / "sealed" / "build-guest.sh").read_text()
BLOCK = BUILD[BUILD.index("# >>> guest ingress"):BUILD.index("# <<< guest ingress")]


def _resolve(**env) -> subprocess.CompletedProcess[str]:
    lines = "".join(f"{k}={shlex.quote(v)}\n" for k, v in env.items())
    script = (f"set -euo pipefail\nMINER=${{MINER:-0}}\n{lines}{BLOCK}\n"
              'printf "%s|%s|%s|%s" "$INGRESS_ZONE" "${INGRESS_TLS_PORT:-}" "${INGRESS_BROKER_URL:-}" "${ACME_DIRECTORY:-}"')
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin"})


@pytest.mark.skipif(BASH is None, reason="needs bash")
def test_build_without_a_zone_changes_nothing() -> None:
    assert _resolve().stdout == "|||"
    assert _resolve(SEALED_ROOM_GUEST_INGRESS="1").stdout == "|||"
    assert _resolve(SEALED_INGRESS_ZONE=ZONE).stdout == "|||"  # the key flag is off


@pytest.mark.skipif(BASH is None, reason="needs bash")
def test_build_with_a_zone_resolves_and_checks() -> None:
    ok = _resolve(SEALED_ROOM_GUEST_INGRESS="1", SEALED_INGRESS_ZONE=ZONE, SEALED_INGRESS_BROKER_URL="https://live.example")
    assert ok.returncode == 0, ok.stderr
    assert ok.stdout == f"{ZONE}|8443|https://live.example|{room_acme.LETS_ENCRYPT_DIRECTORY}"
    for bad in ({"SEALED_INGRESS_BROKER_URL": ""}, {"SEALED_INGRESS_BROKER_URL": "http://live.example"},
                {"SEALED_INGRESS_ZONE": "Hotels.Example.com"}, {"SEALED_INGRESS_TLS_PORT": "18090"},
                {"SEALED_INGRESS_TLS_PORT": "70000"}, {"SEALED_ACME_DIRECTORY": "http://x/dir"},
                {"SEALED_ROOM_GUEST_INGRESS": "yes"}):
        env = {"SEALED_ROOM_GUEST_INGRESS": "1", "SEALED_INGRESS_ZONE": ZONE,
               "SEALED_INGRESS_BROKER_URL": "https://live.example", **bad}
        assert _resolve(**env).returncode != 0, bad


def test_build_opens_the_ingress_port_and_writes_the_measured_settings_only_with_a_zone() -> None:
    assert 'iifname \\"uplink\\" tcp dport $INGRESS_TLS_PORT accept' in BUILD
    rule = BUILD.index('tcp dport $INGRESS_TLS_PORT accept')
    assert BUILD.rindex('if [ -n "$INGRESS_ZONE" ]; then', 0, rule) > BUILD.index("# >>> guest ingress")
    env = BUILD.split('if [ -n "$INGRESS_ZONE" ]; then\n  cat >> "$R/opt/room-kit/room.env"')[1].split("\nfi\n")[0]
    for key in ("ROOM_INGRESS_ZONE=", "ROOM_INGRESS_BROKER_URL=", "ROOM_INGRESS_TLS_LISTEN=$SEALED_GUEST_IP:",
                "ROOM_ACME_DIRECTORY="):
        assert key in env
    assert BUILD.index("# >>> guest ingress") < BUILD.index("PKGS=")


def test_installer_ships_both_modules_and_passes_the_settings() -> None:
    install = (KIT / "install.sh").read_text()
    assert 'install -m 0644 "$KIT/room_ingress.py" "$ROOM_OPT/bin/room_ingress.py"' in install
    assert 'install -m 0644 "$KIT/room_acme.py" "$ROOM_OPT/bin/room_acme.py"' in install
    assert "Environment=ROOM_INGRESS_ZONE=$ROOM_INGRESS_ZONE" in install


def test_two_content_lengths_or_chunked_are_refused(world) -> None:
    world["keeper"].once()
    _expose(world)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for extra, want in ((b"Content-Length: 1\r\nContent-Length: 2\r\n", b" 413 "),
                        (b"Transfer-Encoding: chunked\r\n", b" 411 ")):
        tls = ctx.wrap_socket(socket.create_connection(("127.0.0.1", world["ingress"]), timeout=10),
                              server_hostname=HOST)
        tls.sendall(b"POST / HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\n" + extra + b"\r\nab")
        assert want in tls.recv(200).split(b"\r\n")[0] + b" "
        tls.close()


def test_a_serial_room_is_never_exposed(world) -> None:
    world["keeper"].once()
    with world["ledger"].lock:
        world["ledger"].serial.add(ROOM)
    status, headers, body = _expose(world)
    assert status == 409 and json.loads(body)["error"]["code"] == "room_serial_unsigned"
    assert "expose_url" not in _receipt(headers)["statement"]
    assert _https(world["ingress"], HOST)[0][0] == 404


def test_start_turns_serving_on_only_when_configured_and_bound(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
    monkeypatch.setattr(rr, "snp_report", _fake_report)
    monkeypatch.setattr(room_ingress.CertKeeper, "start", lambda self: None)
    ledger = rr.Ledger(HOTEL, str(tmp_path / "store"), ingress=rr.GuestIngress(HOTEL, zone=ZONE))
    assert room_ingress.start(ledger, {}, 1, KEY, str(tmp_path)) is None and ledger.ingress.serving is None
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen()
    env = {"ROOM_INGRESS_ZONE": ZONE, "ROOM_INGRESS_BROKER_URL": "https://b.example",
           "ROOM_INGRESS_TLS_LISTEN": f"127.0.0.1:{busy.getsockname()[1]}"}
    with pytest.raises(OSError):
        room_ingress.start(ledger, env, 1, KEY, str(tmp_path))
    assert ledger.ingress.serving is None  # expose stays the API's
    busy.close()  # the same port, now free
    state = room_ingress.start(ledger, env, 1, KEY, str(tmp_path), log=lambda *a, **k: None)
    assert ledger.ingress.serving is state and not state.ready
