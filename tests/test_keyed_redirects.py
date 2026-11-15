"""Keyed Python clients must stop at the first redirect response (AB#749)."""

from __future__ import annotations

import importlib.util
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cathedral.claims_room import HttpBrokerTransport
from cathedral.conformance.api import Api, urllib_transport
from cathedral.no_redirect import NoRedirect, RedirectRefused
from cathedral.sandbox_client import HttpTransport

ROOT = Path(__file__).resolve().parents[1]


def standalone(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


archive = standalone("binding_archive_redirect", "room-kit/binding_archive.py")
verifier = standalone("verify_receipts_redirect", "room-kit/verify_receipts.py")
bench = standalone("sealed_bench_redirect", "scripts/sealed_bench.py")


class Recorder(BaseHTTPRequestHandler):
    def do_GET(self):
        self._answer()

    def do_POST(self):
        self._answer()

    def _answer(self):
        self.server.seen.append((self.command, self.path, self.headers.get("Authorization")))
        if self.server.redirect is not None:
            self.send_response(self.server.code)
            self.send_header("Location", self.server.redirect)
            self.end_headers()
        else:
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *_args):
        pass


def server(*, tls=False, tmp_path=None):
    web = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    web.seen = []
    web.redirect = None
    web.code = 302
    if tls:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
                .not_valid_after(datetime.now(UTC) + timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
                )
                .sign(key, hashes.SHA256()))
        cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.TraditionalOpenSSL,
                                               serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))
        web.socket = context.wrap_socket(web.socket, server_side=True)
        web.cert_file = cert_file
    thread = threading.Thread(target=web.serve_forever, daemon=True)
    thread.start()
    return web, thread


@pytest.fixture
def origins(tmp_path, monkeypatch):
    first, first_thread = server(tls=True, tmp_path=tmp_path)
    second, second_thread = server()
    monkeypatch.setenv("SSL_CERT_FILE", str(first.cert_file))
    try:
        yield (f"https://localhost:{first.server_port}", first,
               f"http://127.0.0.1:{second.server_port}", second)
    finally:
        first.shutdown()
        second.shutdown()
        first.server_close()
        second.server_close()
        first_thread.join()
        second_thread.join()


def call_client(name, base):
    if name == "archive":
        return archive.fetch_archived_binding(base, "a" * 64, "secret-key")
    if name == "verifier":
        return verifier.get(base + "/input", "secret-key")
    if name == "bench":
        return bench.Api(base, "secret-key").call("POST", "/input", {})
    if name == "sdk":
        return HttpTransport(base, "secret-key").request(
            "GET", "/input", {"Authorization": "Bearer secret-key"}, b""
        )
    if name == "claims":
        return HttpBrokerTransport(base).request("POST", "/input",
                                                 {"Authorization": "Bearer secret-key"}, b"{}", 5)
    if name == "conformance":
        return urllib_transport(
            "GET", base + "/input", {"Authorization": "Bearer secret-key"}, None, 5
        )
    raise AssertionError(name)


@pytest.mark.parametrize("name", ["archive", "verifier", "bench", "sdk", "claims", "conformance"])
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_cross_origin_redirect_never_forwards_key(origins, name, code):
    base, first, destination, second = origins
    first.code = code
    first.redirect = destination + "/secret-path?token=hidden"
    try:
        result = call_client(name, base)
    except (ValueError, OSError, verifier.Fail, bench.BenchError) as exc:
        message = str(exc)
    else:
        assert name == "conformance"
        assert result.status == 0
        message = result.data.decode()
    assert "redirect refused" in message
    assert "secret-path" not in message and "hidden" not in message
    assert len(first.seen) == 1
    assert first.seen[0][2] == "Bearer secret-key"
    assert second.seen == []


@pytest.mark.parametrize("location", ["/relative?token=hidden", "https://localhost:65534/same?token=hidden",
                                      "http://127.0.0.1:65534/downgrade?token=hidden",
                                      "javascript:alert(hidden)", "http://example.com:bad/path?token=hidden"])
def test_other_redirect_targets_are_refused(origins, location):
    base, first, _, _ = origins
    first.redirect = location
    with pytest.raises(bench.BenchError, match="redirect refused") as exc:
        bench.Api(base, "secret-key").call("GET", "/input")
    assert "hidden" not in str(exc.value)
    assert len(first.seen) == 1


def test_conformance_poll_stops_on_redirect(origins):
    base, first, _, _ = origins
    first.redirect = "/second"
    api = Api(base, "secret-key", sleep=lambda _seconds: pytest.fail("redirect retried"))
    view, _ = api.wait_running("sbx_one", 30)
    assert view["state"] == "failed"
    assert "redirect refused" in view["error"]
    assert len(first.seen) == 1


def test_redirect_handler_closes_response_without_reading_body():
    class Response:
        closed = False

        def close(self):
            self.closed = True

        def read(self):
            pytest.fail("redirect body was read")

    class Request:
        full_url = "https://example.com/start"

    response = Response()
    with pytest.raises(RedirectRefused, match="redirect refused to example.org") as exc:
        NoRedirect().http_error_302(Request(), response, 302, "Found",
                                    {"Location": "https://user:password@example.org/private?token=hidden"})
    assert response.closed
    assert "private" not in str(exc.value)
    assert "password" not in str(exc.value)
    assert "hidden" not in str(exc.value)
