"""In-guest ACME DNS-01 client for Preview URL certificates (room-kit/room_acme.py, AB#422).

Against a stub RFC 8555 CA (tests/acme_stub.py) and a stub of the broker's
challenge route, and cross-checked with the Go handler itself
(broker/acme_dns_pyclient_test.go) through a static and a fresh vector.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
VECTOR = ROOT / "tests" / "vectors" / "acme_dns01_v1.json"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from acme_stub import StubBroker, StubCA  # noqa: E402


sys.path.insert(0, str(KIT))
import room_acme as acme  # noqa: E402  (room_ingress imports it by this name too)

ZONE = "hotels.example.com"  # broker/acme_dns_test.go acmeTestZone
HOTEL = "a"
BINDING = "1" * 64  # acmeTestBind
NAMES = [f"{HOTEL}.{ZONE}", f"*.{HOTEL}.{ZONE}"]
SEED = bytes(range(1, 33))
STATIC_TS = 1700000000
STATIC_VALUES = [acme.dns01_txt_value("token-1.thumb"), acme.dns01_txt_value("token-2.thumb")]


def _pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


class Captured:
    """An opener that records the request and answers 200."""

    def __init__(self):
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)

        class R:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return b"{}"
        return R()


def _vector(key: Ed25519PrivateKey, values: list[str], clock) -> dict:
    cap = Captured()
    dns = acme.BrokerDNS01("https://broker.example", ZONE, HOTEL, key, BINDING, opener=cap, clock=clock)
    dns.set_values(values)
    req = cap.requests[0]
    assert req.get_method() == "PUT"
    assert req.full_url == "https://broker.example/v1/broker/acme-challenge"
    return {"public_key_b64": _pub_b64(key), "body_b64": base64.b64encode(req.data).decode(),
            "signature_b64": req.get_header("X-cathedral-hotel-signature"), "values": values}


# ---------------------------------------------------------------- the broker request format

def test_the_client_makes_exactly_the_static_vector_the_go_test_checks() -> None:
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    assert _vector(key, STATIC_VALUES, lambda: STATIC_TS) == json.loads(VECTOR.read_text())


def test_signature_is_over_the_purpose_line_and_the_raw_body() -> None:
    key = Ed25519PrivateKey.generate()
    vec = _vector(key, STATIC_VALUES[:1], lambda: STATIC_TS)
    body = base64.b64decode(vec["body_b64"])
    key.public_key().verify(base64.b64decode(vec["signature_b64"]), b"cathedral-acme-dns01-v1\n" + body)
    assert set(json.loads(body)) == {"purpose", "zone", "hotel", "binding_sha256", "values", "ts"}


def test_ts_always_moves_forward_within_one_second() -> None:
    cap = Captured()
    dns = acme.BrokerDNS01("https://broker.example", ZONE, HOTEL, Ed25519PrivateKey.generate(), BINDING,
                           opener=cap, clock=lambda: 1000.4)
    dns.set_values(STATIC_VALUES)
    dns.set_values([])
    ts = [json.loads(r.data)["ts"] for r in cap.requests]
    assert ts == [1000, 1001]


def test_plain_http_only_to_loopback() -> None:
    with pytest.raises(ValueError):
        acme.BrokerDNS01("http://broker.example", ZONE, HOTEL, Ed25519PrivateKey.generate(), BINDING)
    with pytest.raises(ValueError):
        acme.AcmeClient("http://acme.example/dir")
    acme.AcmeClient("http://127.0.0.1:1/dir")


@pytest.mark.skipif(shutil.which("go") is None, reason="go not installed")
def test_go_handler_accepts_a_fresh_request_from_this_client(tmp_path) -> None:
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "vector.json"
    path.write_text(json.dumps(_vector(key, STATIC_VALUES, __import__("time").time)))
    env = {**os.environ, "ACME_PY_VECTOR": str(path), "GOFLAGS": "-count=1"}
    run = subprocess.run(["go", "test", "-run", "TestACMEDNSPythonClient", "-v", "."], cwd=ROOT / "broker",
                         env=env, capture_output=True, text=True, timeout=600)
    assert run.returncode == 0, run.stdout[-3000:] + run.stderr[-3000:]
    assert "--- PASS: TestACMEDNSPythonClientFreshVector" in run.stdout
    assert "--- PASS: TestACMEDNSPythonClientStaticVector" in run.stdout


# ---------------------------------------------------------------- the ACME order

@pytest.fixture
def world():
    dns: dict = {}
    receipt_key = Ed25519PrivateKey.generate()
    broker = StubBroker(dns, ZONE, HOTEL, receipt_key.public_key(), BINDING)
    cas = []

    def ca(**kw):
        c = StubCA(dns, **kw)
        cas.append(c)
        return c
    yield dns, receipt_key, broker, ca
    broker.close()
    for c in cas:
        c.close()


def _client(ca, receipt_key, broker):
    client = acme.AcmeClient(ca.directory, sleep=lambda s: None)
    dns = acme.BrokerDNS01(broker.base, ZONE, HOTEL, receipt_key, BINDING)
    return client, dns


def test_obtains_a_certificate_for_the_guest_key_and_both_names(world) -> None:
    dns, receipt_key, broker, make_ca = world
    ca = make_ca()
    client, broker_dns = _client(ca, receipt_key, broker)
    key = ec.generate_private_key(ec.SECP256R1())
    chain = client.obtain(NAMES, key, broker_dns, dns_wait=0)
    leaf = acme.check_chain(chain, NAMES, key)
    assert leaf.public_key().public_numbers() == key.public_key().public_numbers()
    # Both names proved on the one record the broker lets this hotel set, then removed.
    assert [values for status, values in broker.calls] == [broker.calls[0][1], []]
    assert len(broker.calls[0][1]) == 2
    assert dns[f"_acme-challenge.{HOTEL}.{ZONE}"] == []
    assert ca.log[0] == "/acct" and "/order" in ca.log


def test_a_second_order_reuses_the_account(world) -> None:
    _dns, receipt_key, broker, make_ca = world
    ca = make_ca()
    client, broker_dns = _client(ca, receipt_key, broker)
    key = ec.generate_private_key(ec.SECP256R1())
    client.obtain(NAMES, key, broker_dns, dns_wait=0)
    client.obtain(NAMES, key, broker_dns, dns_wait=0)
    assert ca.log.count("/acct") == 1 and ca.log.count("/order") == 2


def test_bad_nonce_is_retried_once(world) -> None:
    _dns, receipt_key, broker, make_ca = world
    ca = make_ca(bad_nonce_once=True)
    client, broker_dns = _client(ca, receipt_key, broker)
    key = ec.generate_private_key(ec.SECP256R1())
    acme.check_chain(client.obtain(NAMES, key, broker_dns, dns_wait=0), NAMES, key)


def test_broker_refusal_fails_the_order_and_names_only_the_status(world) -> None:
    _dns, receipt_key, broker, make_ca = world
    broker.refuse = True  # e.g. the hotel is not admitted yet
    ca = make_ca()
    client, broker_dns = _client(ca, receipt_key, broker)
    with pytest.raises(acme.AcmeError, match="broker acme-challenge answered 403 forbidden"):
        client.obtain(NAMES, ec.generate_private_key(ec.SECP256R1()), broker_dns, dns_wait=0)


def test_wrong_record_makes_the_authorization_invalid_and_the_record_is_still_removed(world) -> None:
    dns, receipt_key, broker, make_ca = world
    ca = make_ca()
    client, broker_dns = _client(ca, receipt_key, broker)
    real = broker_dns.set_values

    def wrong(values):
        real([acme.dns01_txt_value("not-the-key-authorization")] if values else [])
    broker_dns.set_values = wrong
    with pytest.raises(acme.AcmeError, match="authorization is invalid"):
        client.obtain(NAMES, ec.generate_private_key(ec.SECP256R1()), broker_dns, dns_wait=0)
    assert dns[f"_acme-challenge.{HOTEL}.{ZONE}"] == []


def test_a_certificate_for_another_key_is_never_returned(world) -> None:
    _dns, receipt_key, broker, make_ca = world
    ca = make_ca(issue_other_key=True)
    client, broker_dns = _client(ca, receipt_key, broker)
    with pytest.raises(acme.AcmeError, match="another key"):
        client.obtain(NAMES, ec.generate_private_key(ec.SECP256R1()), broker_dns, dns_wait=0)


def test_renewal_is_two_thirds_into_the_life(world) -> None:
    _dns, receipt_key, broker, make_ca = world
    ca = make_ca(lifetime_days=90)
    client, broker_dns = _client(ca, receipt_key, broker)
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = acme.check_chain(client.obtain(NAMES, key, broker_dns, dns_wait=0), NAMES, key)
    start, end = leaf.not_valid_before_utc.timestamp(), leaf.not_valid_after_utc.timestamp()
    assert end - start == pytest.approx(90 * 86400, abs=120)
    assert acme.renew_at(leaf) == pytest.approx(start + (end - start) * 2 / 3, abs=1)


def test_account_key_is_never_in_its_repr() -> None:
    k = acme.AccountKey()
    assert "PRIVATE" not in repr(k).upper() and k.jwk["kty"] == "EC" and len(k.thumbprint()) == 43


def test_a_long_hotel_name_leaves_the_common_name_out(world) -> None:
    from cryptography import x509
    long_names = [f"{'h' * 45}.hotels.cathedral.computer", f"*.{'h' * 45}.hotels.cathedral.computer"]
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.load_der_x509_csr(acme.make_csr(long_names, key))
    assert len(long_names[0]) > 64 and list(csr.subject) == []
    sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert sans == long_names
    short = x509.load_der_x509_csr(acme.make_csr(NAMES, key))
    assert short.subject.rfc4514_string() == f"CN={NAMES[0]}"


def test_poll_stops_at_a_terminal_authorization_state() -> None:
    client = acme.AcmeClient("http://127.0.0.1:1/dir", sleep=lambda s: None)
    client.post = lambda url, payload, **k: acme.Answer(200, {}, b'{"status":"deactivated"}')
    with pytest.raises(acme.AcmeError, match="authorization is deactivated"):
        client._poll("http://127.0.0.1:1/authz/1", {"valid"}, "authorization")
