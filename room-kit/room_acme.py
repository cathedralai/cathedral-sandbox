#!/usr/bin/env python3
"""Room kit: in-guest ACME client for Preview URL certificates (AB#422).

The sealed guest proves <hotel id>.<zone> and *.<hotel id>.<zone> to an ACME
CA (Let's Encrypt by default) over DNS-01, for the TLS key the receipts front
made in the guest (room_receipts.GuestIngress). Nothing here leaves the
guest's memory: the ACME account key is made per process and never written,
and the certificate key is the ingress key the binding names.

DNS-01 runs through the broker's challenge service (broker/acme_dns.go,
broker README "Preview URL certificates"): PUT /v1/broker/acme-challenge with
a body the hotel signs with its receipt key, the Ed25519 key its attested
binding names. The broker lets each hotel set only
_acme-challenge.<hotel id>.<zone>.

Only the standard library and the pinned cryptography package. RFC 8555
(ACME), RFC 7515/7518 (JWS, ES256), RFC 7638 (JWK thumbprint).
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

LETS_ENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
# broker/acme_dns.go: acmeDNSPurpose, acmeDNSSigHdr. The signed message is the
# purpose, a newline, then the raw body bytes, exactly as sent.
DNS01_PURPOSE = "cathedral-acme-dns01-v1"
DNS01_SIGNATURE_HEADER = "X-Cathedral-Hotel-Signature"
DNS01_ROUTE = "/v1/broker/acme-challenge"
HTTP_TIMEOUT = 30
MAX_ANSWER_BYTES = 1 << 20
POLL_LIMIT_SECONDS = 300


class AcmeError(Exception):
    """An ACME or broker step failed. The message names the step and status, never a key."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _json_bytes(doc) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode()


def loopback_http_ok(url: str) -> bool:
    """Plain http only to a loopback host (tests and a local stub CA). Everything else must be https."""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return True
    return parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")


# ---------------------------------------------------------------- the broker DNS-01 call

def dns01_txt_value(key_authorization: str) -> str:
    """RFC 8555 8.4: base64url(sha256(key authorization)), 43 characters."""
    return b64url(hashlib.sha256(key_authorization.encode()).digest())


def dns01_body(zone: str, hotel: str, binding_sha256: str, values: list[str], ts: int) -> bytes:
    """The body broker/acme_dns.go decodes (acmeChallengeRequest, unknown fields refused)."""
    return _json_bytes({"purpose": DNS01_PURPOSE, "zone": zone, "hotel": hotel,
                        "binding_sha256": binding_sha256, "values": list(values), "ts": int(ts)})


def dns01_signed_message(body: bytes) -> bytes:
    """broker/acme_dns.go acmeDNSSignedMessage."""
    return DNS01_PURPOSE.encode() + b"\n" + body


def dns01_signature(receipt_key: Ed25519PrivateKey, body: bytes) -> str:
    """Standard base64 (with padding) of the Ed25519 signature, as the broker decodes it."""
    return base64.b64encode(receipt_key.sign(dns01_signed_message(body))).decode()


class BrokerDNS01:
    """Sets the hotel's one challenge record through the broker, signed with the receipt key."""

    def __init__(self, broker_url: str, zone: str, hotel: str, receipt_key: Ed25519PrivateKey,
                 binding_sha256: str, opener: Callable | None = None, clock: Callable[[], float] = time.time):
        if not loopback_http_ok(broker_url):
            raise ValueError("the broker URL must be https")
        self.url = broker_url.rstrip("/") + DNS01_ROUTE
        self.zone, self.hotel, self.binding_sha256 = zone, hotel, binding_sha256
        self._key = receipt_key
        self._open = opener or urllib.request.urlopen
        self._clock = clock
        self._last_ts = 0

    def __repr__(self) -> str:
        return f"BrokerDNS01(url={self.url!r}, hotel={self.hotel!r})"

    def next_ts(self) -> int:
        # The broker takes a ts only if it is later than the last one it accepted from this hotel.
        ts = max(int(self._clock()), self._last_ts + 1)
        self._last_ts = ts
        return ts

    def set_values(self, values: list[str]) -> None:
        """Make the TXT record exactly *values* (an empty list removes it)."""
        body = dns01_body(self.zone, self.hotel, self.binding_sha256, values, self.next_ts())
        req = urllib.request.Request(self.url, data=body, method="PUT", headers={
            "Content-Type": "application/json", DNS01_SIGNATURE_HEADER: dns01_signature(self._key, body)})
        try:
            with self._open(req, timeout=HTTP_TIMEOUT) as res:
                res.read(MAX_ANSWER_BYTES)
        except urllib.error.HTTPError as exc:
            code = ""
            try:
                code = json.loads(exc.read(4096)).get("error", {}).get("code", "")
            except (ValueError, AttributeError):
                pass
            raise AcmeError(f"broker acme-challenge answered {exc.code} {code}".strip()) from None
        except OSError as exc:
            raise AcmeError(f"broker acme-challenge did not answer ({type(exc).__name__})") from None


# ---------------------------------------------------------------- JWS (ES256)

class AccountKey:
    """The ACME account key: P-256, made here, never written anywhere."""

    def __init__(self, key: ec.EllipticCurvePrivateKey | None = None):
        self._key = key or ec.generate_private_key(ec.SECP256R1())
        nums = self._key.public_key().public_numbers()
        self.jwk = {"crv": "P-256", "kty": "EC",
                    "x": b64url(nums.x.to_bytes(32, "big")), "y": b64url(nums.y.to_bytes(32, "big"))}

    def __repr__(self) -> str:
        return "AccountKey(P-256)"

    def thumbprint(self) -> str:
        """RFC 7638: sha256 over the required members in lexicographic order, no whitespace."""
        return b64url(hashlib.sha256(_json_bytes({k: self.jwk[k] for k in ("crv", "kty", "x", "y")})).digest())

    def sign(self, protected: dict, payload) -> bytes:
        prot = b64url(_json_bytes(protected))
        pay = "" if payload is None else b64url(_json_bytes(payload))
        der = self._key.sign(f"{prot}.{pay}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return _json_bytes({"protected": prot, "payload": pay,
                            "signature": b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))})


@dataclass
class Answer:
    status: int
    headers: dict
    body: bytes

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError:
            raise AcmeError(f"ACME answer {self.status} is not JSON") from None


class AcmeClient:
    """A small RFC 8555 client: one account per process, orders for DNS names, DNS-01 only."""

    def __init__(self, directory_url: str, account: AccountKey | None = None, contact_email: str = "",
                 opener: Callable | None = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        if not loopback_http_ok(directory_url):
            raise ValueError("the ACME directory URL must be https")
        self.directory_url = directory_url
        self.account = account or AccountKey()
        self.contact_email = contact_email
        self._open = opener or urllib.request.urlopen
        self._sleep, self._clock = sleep, clock
        self.directory: dict | None = None
        self.kid: str | None = None
        self._nonce: str | None = None

    # -- transport
    def _http(self, method: str, url: str, body: bytes | None = None, headers: dict | None = None) -> Answer:
        if not loopback_http_ok(url):
            raise AcmeError("the ACME server named a URL that is not https")
        req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        try:
            with self._open(req, timeout=HTTP_TIMEOUT) as res:
                ans = Answer(res.status, {k.lower(): v for k, v in res.headers.items()}, res.read(MAX_ANSWER_BYTES))
        except urllib.error.HTTPError as exc:
            ans = Answer(exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read(MAX_ANSWER_BYTES))
        except OSError as exc:
            raise AcmeError(f"ACME {method} did not answer ({type(exc).__name__})") from None
        nonce = ans.headers.get("replay-nonce")
        if nonce:
            self._nonce = nonce
        return ans

    def _dir(self) -> dict:
        if self.directory is None:
            ans = self._http("GET", self.directory_url)
            if ans.status != 200:
                raise AcmeError(f"ACME directory answered {ans.status}")
            doc = ans.json()
            for k in ("newNonce", "newAccount", "newOrder"):
                if not isinstance(doc.get(k), str):
                    raise AcmeError(f"ACME directory has no {k}")
            self.directory = doc
        return self.directory

    def _fresh_nonce(self) -> str:
        if self._nonce is None:
            self._http("HEAD", self._dir()["newNonce"])
            if self._nonce is None:
                raise AcmeError("ACME newNonce gave no Replay-Nonce")
        nonce, self._nonce = self._nonce, None
        return nonce

    def post(self, url: str, payload, *, use_jwk: bool = False, accept: str | None = None) -> Answer:
        """A signed POST (payload None: POST-as-GET). One retry on badNonce (RFC 8555 6.5)."""
        for attempt in (1, 2):
            protected = {"alg": "ES256", "nonce": self._fresh_nonce(), "url": url}
            if use_jwk:
                protected["jwk"] = self.account.jwk
            else:
                if self.kid is None:
                    raise AcmeError("no ACME account yet")
                protected["kid"] = self.kid
            headers = {"Content-Type": "application/jose+json"}
            if accept:
                headers["Accept"] = accept
            ans = self._http("POST", url, self.account.sign(protected, payload), headers)
            if ans.status == 400 and attempt == 1 and b"badNonce" in ans.body:
                continue
            return ans
        return ans

    # -- account and order
    def register(self) -> str:
        payload = {"termsOfServiceAgreed": True}
        if self.contact_email:
            payload["contact"] = [f"mailto:{self.contact_email}"]
        ans = self.post(self._dir()["newAccount"], payload, use_jwk=True)
        if ans.status not in (200, 201) or not ans.headers.get("location"):
            raise AcmeError(f"ACME newAccount answered {ans.status}{_problem(ans)}")
        self.kid = ans.headers["location"]
        return self.kid

    def _poll(self, url: str, done: set[str], what: str) -> dict:
        start = self._clock()
        while True:
            ans = self.post(url, None)
            if ans.status != 200:
                raise AcmeError(f"ACME {what} answered {ans.status}{_problem(ans)}")
            doc = ans.json()
            status = doc.get("status")
            if status in done:
                return doc
            if status == "invalid":
                raise AcmeError(f"ACME {what} is invalid{_problem_doc(doc)}")
            if self._clock() - start > POLL_LIMIT_SECONDS:
                raise AcmeError(f"ACME {what} still {status} after {POLL_LIMIT_SECONDS} s")
            self._sleep(_retry_after(ans.headers.get("retry-after")))

    def obtain(self, names: list[str], key: ec.EllipticCurvePrivateKey, dns: BrokerDNS01,
               dns_wait: float = 20.0) -> str:
        """A certificate chain (PEM) for *names* on *key*, proven over DNS-01 through *dns*.

        Every name must share one challenge record: <id>.<zone> and *.<id>.<zone>
        both prove at _acme-challenge.<id>.<zone>, which is the one name the
        broker lets this hotel set. The record is removed afterwards, whatever
        the outcome.
        """
        if self.kid is None:
            self.register()
        ans = self.post(self._dir()["newOrder"], {"identifiers": [{"type": "dns", "value": n} for n in names]})
        if ans.status != 201 or not ans.headers.get("location"):
            raise AcmeError(f"ACME newOrder answered {ans.status}{_problem(ans)}")
        order_url, order = ans.headers["location"], ans.json()
        pending: list[str] = []
        values: list[str] = []
        for authz_url in order.get("authorizations") or []:
            ans = self.post(authz_url, None)
            if ans.status != 200:
                raise AcmeError(f"ACME authorization answered {ans.status}{_problem(ans)}")
            authz = ans.json()
            if authz.get("status") == "valid":
                continue
            chall = next((c for c in authz.get("challenges") or [] if c.get("type") == "dns-01"), None)
            if chall is None or not isinstance(chall.get("token"), str) or not isinstance(chall.get("url"), str):
                raise AcmeError("ACME authorization offers no dns-01 challenge")
            value = dns01_txt_value(f"{chall['token']}.{self.account.thumbprint()}")
            if value not in values:
                values.append(value)
            pending.append(authz_url)
            pending.append(chall["url"])
        if len(values) > 2:
            raise AcmeError("more than two challenge values: the broker keeps at most two on one record")
        try:
            if values:
                dns.set_values(values)
                self._sleep(dns_wait)
                for authz_url, chall_url in zip(pending[0::2], pending[1::2]):
                    ans = self.post(chall_url, {})
                    if ans.status != 200:
                        raise AcmeError(f"ACME challenge answered {ans.status}{_problem(ans)}")
                for authz_url in pending[0::2]:
                    self._poll(authz_url, {"valid"}, "authorization")
        finally:
            if values:
                try:
                    dns.set_values([])
                except AcmeError:
                    pass  # the broker replaces the record whole at the next order
        order = self._poll(order_url, {"ready", "valid", "processing"}, "order")
        if order.get("status") == "ready":
            ans = self.post(order["finalize"], {"csr": b64url(make_csr(names, key))})
            if ans.status != 200:
                raise AcmeError(f"ACME finalize answered {ans.status}{_problem(ans)}")
        order = self._poll(order_url, {"valid"}, "order")
        cert_url = order.get("certificate")
        if not isinstance(cert_url, str):
            raise AcmeError("ACME order is valid but names no certificate")
        ans = self.post(cert_url, None, accept="application/pem-certificate-chain")
        if ans.status != 200:
            raise AcmeError(f"ACME certificate answered {ans.status}")
        chain = ans.body.decode("ascii", "replace")
        check_chain(chain, names, key)
        return chain


def make_csr(names: list[str], key: ec.EllipticCurvePrivateKey) -> bytes:
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256())).public_bytes(Encoding.DER)


def check_chain(chain_pem: str, names: list[str], key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """The leaf is for *key* and names every name: never serve a certificate for another key."""
    try:
        certs = x509.load_pem_x509_certificates(chain_pem.encode())
    except ValueError:
        raise AcmeError("the ACME certificate is not a PEM chain") from None
    leaf = certs[0]
    if leaf.public_key().public_numbers() != key.public_key().public_numbers():
        raise AcmeError("the ACME certificate is for another key")
    try:
        sans = set(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                   .get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        sans = set()
    if not set(names) <= sans:
        raise AcmeError("the ACME certificate does not name every requested name")
    return leaf


def renew_at(leaf: x509.Certificate) -> float:
    """When to renew: two thirds into the certificate's life (Let's Encrypt's advice), as a Unix time."""
    start = leaf.not_valid_before_utc.timestamp()
    end = leaf.not_valid_after_utc.timestamp()
    return start + (end - start) * 2 / 3


def _retry_after(value) -> float:
    try:
        return min(max(float(value), 1.0), 30.0)
    except (TypeError, ValueError):
        return 2.0


def _problem(ans: Answer) -> str:
    try:
        return _problem_doc(json.loads(ans.body))
    except ValueError:
        return ""


def _problem_doc(doc) -> str:
    if not isinstance(doc, dict):
        return ""
    err = doc.get("error") if isinstance(doc.get("error"), dict) else doc
    kind = err.get("type") if isinstance(err, dict) else None
    return f" ({kind})" if isinstance(kind, str) else ""
