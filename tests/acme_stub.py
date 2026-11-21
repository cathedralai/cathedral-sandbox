"""A small RFC 8555 CA and a broker DNS-01 stub for the AB#422 tests.

StubCA checks what a real CA checks for this client: every POST is a JWS
(ES256) with a fresh nonce, the request URL, and a jwk (newAccount) or a
known kid; a dns-01 challenge is valid only when the stub DNS holds
base64url(sha256(token "." thumbprint)) at _acme-challenge.<name>; the CSR
names exactly the order's identifiers. StubBroker applies the rules of
broker/acme_dns.go handleACMEChallenge.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict) -> str:
    doc = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(doc.encode()).digest())


def jwk_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


class _Server(ThreadingHTTPServer):
    daemon_threads = True


def _serve(handler_cls, owner):
    srv = _Server(("127.0.0.1", 0), handler_cls)
    srv.owner = owner
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class StubCA:
    def __init__(self, dns: dict, *, bad_nonce_once: bool = False, issue_other_key: bool = False,
                 lifetime_days: int = 90):
        self.dns = dns
        self.lock = threading.Lock()
        self.nonces: set[str] = set()
        self.n = 0
        self.accounts: dict[str, dict] = {}
        self.orders: dict[str, dict] = {}
        self.authzs: dict[str, dict] = {}
        self.challs: dict[str, str] = {}  # chall id -> authz id
        self.bad_nonce_once = bad_nonce_once
        self.issue_other_key = issue_other_key
        self.lifetime_days = lifetime_days
        self.log: list[str] = []
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stub CA")])
        now = datetime.datetime.now(datetime.UTC)
        self.ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                        .public_key(self.ca_key.public_key()).serial_number(1)
                        .not_valid_before(now - datetime.timedelta(days=1))
                        .not_valid_after(now + datetime.timedelta(days=3650))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                        .sign(self.ca_key, hashes.SHA256()))
        self.srv = _serve(_CAHandler, self)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    @property
    def directory(self) -> str:
        return self.base + "/dir"

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()

    def nonce(self) -> str:
        with self.lock:
            self.n += 1
            v = f"nonce-{self.n}-{b64url(hashlib.sha256(str(self.n).encode()).digest()[:8])}"
            self.nonces.add(v)
            return v

    def next_id(self) -> str:
        with self.lock:
            self.n += 1
            return str(self.n)


class _CAHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    @property
    def ca(self) -> StubCA:
        return self.server.owner

    def send(self, status: int, doc=None, headers=None, raw: bytes | None = None, ctype="application/json"):
        body = raw if raw is not None else (json.dumps(doc).encode() if doc is not None else b"")
        self.send_response(status)
        self.send_header("Replay-Nonce", self.ca.nonce())
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def problem(self, status: int, kind: str, detail: str):
        return self.send(status, {"type": f"urn:ietf:params:acme:error:{kind}", "detail": detail},
                         ctype="application/problem+json")

    def do_GET(self):
        if self.path == "/dir":
            b = self.ca.base
            return self.send(200, {"newNonce": b + "/nonce", "newAccount": b + "/acct", "newOrder": b + "/order"})
        if self.path == "/nonce":
            return self.send(204)
        return self.send(404, {})

    do_HEAD = do_GET

    def do_POST(self):
        ca = self.ca
        if self.headers.get("Content-Type") != "application/jose+json":
            return self.problem(415, "malformed", "content type")
        jws = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        prot = json.loads(b64url_decode(jws["protected"]))
        url = ca.base + self.path
        if prot.get("alg") != "ES256" or prot.get("url") != url:
            return self.problem(400, "malformed", "alg or url")
        if ca.bad_nonce_once:
            ca.bad_nonce_once = False
            with ca.lock:
                ca.nonces.discard(prot.get("nonce"))
            return self.problem(400, "badNonce", "try again")
        with ca.lock:
            if prot.get("nonce") not in ca.nonces:
                return self.problem(400, "badNonce", "unknown nonce")
            ca.nonces.discard(prot["nonce"])
        if self.path == "/acct":
            if "jwk" not in prot or "kid" in prot:
                return self.problem(400, "malformed", "newAccount needs jwk")
            jwk = prot["jwk"]
        else:
            if "jwk" in prot or prot.get("kid") not in ca.accounts:
                return self.problem(400, "accountDoesNotExist", "kid")
            jwk = ca.accounts[prot["kid"]]
        sig = b64url_decode(jws["signature"])
        try:
            jwk_key(jwk).verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                                f"{jws['protected']}.{jws['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return self.problem(400, "malformed", "signature")
        payload = json.loads(b64url_decode(jws["payload"])) if jws["payload"] else None
        ca.log.append(self.path)
        thumb = jwk_thumbprint(jwk)
        if self.path == "/acct":
            assert payload.get("termsOfServiceAgreed") is True
            kid = ca.base + "/acct/" + ca.next_id()
            ca.accounts[kid] = jwk
            return self.send(201, {"status": "valid"}, {"Location": kid})
        if self.path == "/order":
            oid = ca.next_id()
            idents = payload["identifiers"]
            authz_urls = []
            for ident in idents:
                aid = ca.next_id()
                cid = ca.next_id()
                ca.authzs[aid] = {"status": "pending", "identifier": ident, "token": b64url(hashlib.sha256(aid.encode()).digest()),
                                  "chall": cid, "thumb": thumb}
                ca.challs[cid] = aid
                authz_urls.append(f"{ca.base}/authz/{aid}")
            ca.orders[oid] = {"status": "pending", "identifiers": idents, "authorizations": authz_urls,
                              "finalize": f"{ca.base}/finalize/{oid}", "cert": None}
            return self.send(201, self.order_doc(oid), {"Location": f"{ca.base}/orders/{oid}"})
        m = re.fullmatch(r"/authz/(\d+)", self.path)
        if m:
            a = ca.authzs[m[1]]
            return self.send(200, {"status": a["status"], "identifier": a["identifier"], "challenges": [
                {"type": "http-01", "url": f"{ca.base}/chall-http/{a['chall']}", "token": "x"},
                {"type": "dns-01", "url": f"{ca.base}/chall/{a['chall']}", "token": a["token"],
                 "status": a["status"]}]})
        m = re.fullmatch(r"/chall/(\d+)", self.path)
        if m:
            assert payload == {}
            a = ca.authzs[ca.challs[m[1]]]
            name = "_acme-challenge." + a["identifier"]["value"].removeprefix("*.")
            want = b64url(hashlib.sha256(f"{a['token']}.{a['thumb']}".encode()).digest())
            a["status"] = "valid" if want in ca.dns.get(name, []) else "invalid"
            return self.send(200, {"type": "dns-01", "status": "processing", "token": a["token"]})
        m = re.fullmatch(r"/orders/(\d+)", self.path)
        if m:
            return self.send(200, self.order_doc(m[1]))
        m = re.fullmatch(r"/finalize/(\d+)", self.path)
        if m:
            order = ca.orders[m[1]]
            if self.order_doc(m[1])["status"] != "ready":
                return self.problem(403, "orderNotReady", "not ready")
            csr = x509.load_der_x509_csr(b64url_decode(payload["csr"]))
            assert csr.is_signature_valid
            sans = sorted(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                          .get_values_for_type(x509.DNSName))
            if sans != sorted(i["value"] for i in order["identifiers"]):
                return self.problem(400, "badCSR", "names")
            pub = ec.generate_private_key(ec.SECP256R1()).public_key() if ca.issue_other_key else csr.public_key()
            now = datetime.datetime.now(datetime.UTC)
            leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca.ca_cert.subject)
                    .public_key(pub).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(minutes=1))
                    .not_valid_after(now + datetime.timedelta(days=ca.lifetime_days))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False)
                    .sign(ca.ca_key, hashes.SHA256()))
            order["cert"] = leaf.public_bytes(Encoding.PEM) + ca.ca_cert.public_bytes(Encoding.PEM)
            return self.send(200, self.order_doc(m[1]))
        m = re.fullmatch(r"/cert/(\d+)", self.path)
        if m:
            return self.send(200, raw=ca.orders[m[1]]["cert"], ctype="application/pem-certificate-chain")
        return self.send(404, {})

    def order_doc(self, oid: str) -> dict:
        ca = self.ca
        o = ca.orders[oid]
        states = [ca.authzs[u.rsplit("/", 1)[1]]["status"] for u in o["authorizations"]]
        if o["cert"] is not None:
            status = "valid"
        elif "invalid" in states:
            status = "invalid"
        elif all(s == "valid" for s in states):
            status = "ready"
        else:
            status = "pending"
        doc = {"status": status, "identifiers": o["identifiers"], "authorizations": o["authorizations"],
               "finalize": o["finalize"]}
        if status == "valid":
            doc["certificate"] = f"{ca.base}/cert/{oid}"
        if status == "invalid":
            doc["error"] = {"type": "urn:ietf:params:acme:error:unauthorized"}
        return doc


TXT_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
BROKER_KEYS = {"purpose", "zone", "hotel", "binding_sha256", "values", "ts"}


class StubBroker:
    """broker/acme_dns.go handleACMEChallenge, for one admitted hotel whose binding names *public*."""

    def __init__(self, dns: dict, zone: str, hotel: str, public: Ed25519PublicKey, binding_sha256: str):
        self.dns, self.zone, self.hotel, self.public, self.binding = dns, zone, hotel, public, binding_sha256
        self.last_ts = 0
        self.calls: list[tuple[int, list]] = []
        self.refuse = False
        self.srv = _serve(_BrokerHandler, self)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


class _BrokerHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status: int, code: str):
        body = json.dumps({"error": {"code": code}} if status != 200 else {"ok": True}).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        b: StubBroker = self.server.owner
        if self.path != "/v1/broker/acme-challenge":
            return self.reply(404, "not_found")
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            req = json.loads(raw)
        except ValueError:
            return self.reply(400, "invalid_json")
        if not isinstance(req, dict) or set(req) - BROKER_KEYS:
            return self.reply(400, "invalid_json")  # DisallowUnknownFields
        try:
            sig = base64.b64decode(self.headers.get("X-Cathedral-Hotel-Signature", ""), validate=True)
        except ValueError:
            sig = b""
        ok = len(sig) == 64 and req.get("purpose") == "cathedral-acme-dns01-v1" and req.get("zone") == b.zone \
            and req.get("hotel") == b.hotel and str(req.get("binding_sha256", "")).lower() == b.binding and not b.refuse
        if ok:
            try:
                b.public.verify(sig, b"cathedral-acme-dns01-v1\n" + raw)
            except InvalidSignature:
                ok = False
        if not ok:
            b.calls.append((403, []))
            return self.reply(403, "forbidden")
        values = req.get("values") or []
        if len(values) > 2 or not all(isinstance(v, str) and TXT_RE.fullmatch(v) for v in values):
            return self.reply(400, "invalid_request")
        if not isinstance(req.get("ts"), int) or req["ts"] <= b.last_ts:
            return self.reply(409, "replayed_request")
        b.last_ts = req["ts"]
        b.dns[f"_acme-challenge.{b.hotel}.{b.zone}"] = list(values)
        b.calls.append((200, list(values)))
        return self.reply(200, "")
