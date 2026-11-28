#!/usr/bin/env python3
# WARNING: never a real private key here. The fixture's test keys are public by design (the RSA
# primes are in the fixture, the other keys come from the fixed seeds below) and must never be
# used as an identity: anyone can sign a re-wrap answer with them.
"""Make tests/fixtures/vm_rewrap_answer_v2.json and tests/fixtures/vm_ssh_key_shapes_v1.json
(AB#1022, spec r3 7.5 with the r4 erratum): the signed re-wrap answer and the key shape that
VM create allows, as shared vectors for the guest init, the host, the broker and verify_vm.py.

The answer v2 is the v1 envelope plus "sig", one SSHSIG blob (OpenSSH PROTOCOL.sshsig) by the
identity's ssh_public_key:

  M = b"cathedral.vm.rewrap-answer/v2\\0" || offer_sha256 (32 raw bytes) || epk (32)
      || nonce (12) || ct (48)                                   154 bytes
  D = b"SSHSIG" || string(NAMESPACE) || string("") || string("sha512") || string(SHA-512(M))

and the signature over D per key type (docs/VM_GUEST.md "Re-wrap answer v2"). Every signature
here is deterministic (Ed25519, RSA PKCS#1 v1.5, ECDSA with RFC 6979), so --check compares
bytes. The keys are test keys, public by design: the RSA primes are kept in the fixture so it
can be made again, and the others come from fixed seeds. Never use one as a VM identity.

reference_verify() is the erratum 2.4 verifier in Python. It gives each case its expected
refusal code (None for a valid answer); the Go guest must give the same. The test also runs
OpenSSH's ssh-keygen over every case whose "openssh_accepts" is set, so the cases where OpenSSH
and the guest differ (RSA SHA-256, a short RSA signature, a non-minimal mpint, a reserved field
that is not empty, and others) are shown.

  make_vm_rewrap_answer_vectors.py            write both fixtures
  make_vm_rewrap_answer_vectors.py --check    exit 1 if either file on disk differs
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[1]
ANSWER_FIXTURE = REPO / "tests" / "fixtures" / "vm_rewrap_answer_v2.json"
SHAPE_FIXTURE = REPO / "tests" / "fixtures" / "vm_ssh_key_shapes_v1.json"
ENVELOPE_FIXTURE = REPO / "tests" / "fixtures" / "vm_rewrap_envelope_v1.json"

SCHEMA = "cathedral.vm.rewrap-answer/v2"
DOMAIN = SCHEMA.encode() + b"\0"
NAMESPACE = "vm-rewrap-answer-v2@cathedral.computer"
HASH = "sha512"
ANSWER_MAX = 4096
SIG_MAX = 2400
KEY_BLOB_MAX = 1100
FIELDS = ("ct", "epk", "nonce", "offer_sha256", "schema", "sig")
LENGTHS = {"epk": 32, "nonce": 12, "ct": 48}
SK_USER_PRESENT = 0x01

CURVES = {  # SSH curve name: (cryptography curve, hash, point bytes)
    "nistp256": (ec.SECP256R1(), hashes.SHA256(), 65),
    "nistp384": (ec.SECP384R1(), hashes.SHA384(), 97),
    "nistp521": (ec.SECP521R1(), hashes.SHA512(), 133),
}
ORDERS = {
    "nistp256": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "nistp384": int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
    "nistp521": int("01FF" + "FFFFFFFF" * 7 + "FFFFFFFA"
                    "51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
}
# y^2 = x^3 - 3x + b over GF(p) (SEC 2): create checks that an ECDSA point is on its curve.
CURVE_FIELDS = {
    "nistp256": (2**256 - 2**224 + 2**192 + 2**96 - 1,
                 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B),
    "nistp384": (2**384 - 2**128 - 2**96 + 2**32 - 1,
                 int("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
                     "C656398D8A2ED19D2A85C8EDD3EC2AEF", 16)),
    "nistp521": (2**521 - 1,
                 int("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
                     "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16)),
}
# Key type: (signature type, curve or None).
KEY_TYPES = {
    "ssh-ed25519": ("ssh-ed25519", None),
    "ecdsa-sha2-nistp256": ("ecdsa-sha2-nistp256", "nistp256"),
    "ecdsa-sha2-nistp384": ("ecdsa-sha2-nistp384", "nistp384"),
    "ecdsa-sha2-nistp521": ("ecdsa-sha2-nistp521", "nistp521"),
    "ssh-rsa": ("rsa-sha2-512", None),
    "sk-ssh-ed25519@openssh.com": ("sk-ssh-ed25519@openssh.com", None),
    "sk-ecdsa-sha2-nistp256@openssh.com": ("sk-ecdsa-sha2-nistp256@openssh.com", "nistp256"),
}


class Refused(Exception):
    """A reference refusal; args[0] is the code the guest must give."""


# ---------------------------------------------------------------- SSH wire encoding

def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def string(data: bytes | str) -> bytes:
    data = data.encode() if isinstance(data, str) else data
    return u32(len(data)) + data


def mpint(n: int) -> bytes:
    if n == 0:
        return string(b"")
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return string(b"\0" + raw if raw[0] & 0x80 else raw)


class Reader:
    def __init__(self, data: bytes, code: str):
        self.data, self.pos, self.code = data, 0, code

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise Refused(self.code)
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def mpint(self, code: str) -> int:
        raw = self.string()
        # Minimal and positive: no leading zero unless the next byte's top bit is set.
        if not raw or raw[0] & 0x80 or (raw[0] == 0 and (len(raw) == 1 or not raw[1] & 0x80)):
            raise Refused(code)
        return int.from_bytes(raw, "big")

    def end(self, code: str) -> None:
        if self.pos != len(self.data):
            raise Refused(code)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def strict_b64(text: str) -> bytes:
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        raise Refused("sig_encoding") from None
    if b64(raw) != text:
        raise Refused("sig_encoding")
    return raw


def canonical(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def message(answer: dict) -> bytes:
    return (DOMAIN + bytes.fromhex(answer["offer_sha256"]) + base64.b64decode(answer["epk"])
            + base64.b64decode(answer["nonce"]) + base64.b64decode(answer["ct"]))


def signed_data(m: bytes, namespace: str = NAMESPACE, hash_name: str = HASH) -> bytes:
    digest = hashlib.new(hash_name, m).digest()
    return b"SSHSIG" + string(namespace) + string(b"") + string(hash_name) + string(digest)


def sshsig(public_blob: bytes, signature: bytes, namespace: str = NAMESPACE, hash_name: str = HASH,
           version: int = 1, reserved: bytes = b"") -> bytes:
    return (b"SSHSIG" + u32(version) + string(public_blob) + string(namespace) + string(reserved)
            + string(hash_name) + string(signature))


def on_curve(curve: str, point: bytes) -> bool:
    """POINT (0x04 || x || y) satisfies its curve's equation, with x and y below p."""
    p, b = CURVE_FIELDS[curve]
    size = (len(point) - 1) // 2
    x, y = int.from_bytes(point[1:1 + size], "big"), int.from_bytes(point[1 + size:], "big")
    return x < p and y < p and (y * y - (x * x * x - 3 * x + b)) % p == 0


# ---------------------------------------------------------------- test keys

def seed(label: str) -> bytes:
    return hashlib.sha256(b"cathedral-vm-rewrap-answer-v2-test-key/" + label.encode()).digest()


class Key:
    """A test key: its SSH public blob and how it signs SSHSIG's D."""

    def __init__(self, kind: str, private, application: bytes = b"ssh:"):
        self.kind, self.private, self.application = kind, private, application
        self.curve = KEY_TYPES[kind][1]

    @property
    def blob(self) -> bytes:
        pub = self.private.public_key()
        if self.kind in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
            raw = pub.public_bytes_raw()
            tail = string(self.application) if self.kind.startswith("sk-") else b""
            return string(self.kind) + string(raw) + tail
        if self.curve:
            point = pub.public_bytes(encoding=_X962, format=_UNCOMPRESSED)
            tail = string(self.application) if self.kind.startswith("sk-") else b""
            return string(self.kind) + string(self.curve) + string(point) + tail
        numbers = pub.public_numbers()
        return string("ssh-rsa") + mpint(numbers.e) + mpint(numbers.n)

    @property
    def line(self) -> str:
        return f"{self.kind} {b64(self.blob)}"

    def sign(self, d: bytes, sig_type: str | None = None, flags: int = SK_USER_PRESENT, counter: int = 7,
             rsa_hash=None) -> bytes:
        """The signature string over D: what OpenSSH's sshkey_sign makes for this key."""
        if self.kind == "ssh-ed25519":
            return string(sig_type or self.kind) + string(self.private.sign(d))
        if self.kind == "ssh-rsa":
            sig_type = sig_type or "rsa-sha2-512"
            algorithm = rsa_hash or {"rsa-sha2-512": hashes.SHA512(), "rsa-sha2-256": hashes.SHA256(),
                                     "ssh-rsa": hashes.SHA1()}[sig_type]
            return string(sig_type) + string(self.private.sign(d, padding.PKCS1v15(), algorithm))
        if self.kind.startswith("sk-"):
            data = (hashlib.sha256(self.application).digest() + bytes([flags]) + u32(counter)
                    + hashlib.sha256(d).digest())
            if self.curve:
                r, s = decode_dss_signature(self.private.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
                inner = mpint(r) + mpint(s)
            else:
                inner = self.private.sign(data)
            return string(sig_type or self.kind) + string(inner) + bytes([flags]) + u32(counter)
        r, s = decode_dss_signature(self.private.sign(d, ec.ECDSA(CURVES[self.curve][1], deterministic_signing=True)))
        return string(sig_type or self.kind) + string(mpint(r) + mpint(s))


_X962, _UNCOMPRESSED = Encoding.X962, PublicFormat.UncompressedPoint


def ed25519_key(label: str, kind: str = "ssh-ed25519", application: bytes = b"ssh:") -> Key:
    return Key(kind, ed25519.Ed25519PrivateKey.from_private_bytes(seed(label)), application)


def ecdsa_key(label: str, curve: str, kind: str | None = None, application: bytes = b"ssh:") -> Key:
    order = ORDERS[curve]
    scalar = int.from_bytes(hashlib.sha512(seed(label)).digest() * 2, "big") % (order - 1) + 1
    return Key(kind or f"ecdsa-sha2-{curve}", ec.derive_private_key(scalar, CURVES[curve][0]), application)


def rsa_key(primes: dict) -> Key:
    p, q, e = int(primes["p"], 16), int(primes["q"], 16), primes["e"]
    n, d = p * q, pow(e, -1, (p - 1) * (q - 1))
    numbers = rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q),
                                    rsa.RSAPublicNumbers(e, n))
    return Key("ssh-rsa", numbers.private_key())


def rsa_primes(bits: int, kept: dict | None) -> dict:
    """The fixture's primes when it has them (so --check makes the same bytes), else new ones."""
    if kept:
        return kept
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    numbers = private.private_numbers()
    return {"bits": bits, "e": 65537, "p": format(numbers.p, "x"), "q": format(numbers.q, "x")}


# ---------------------------------------------------------------- the reference verifier (erratum 2.4)

def parse_public(blob: bytes) -> tuple[str, object, bytes]:
    """(key type, cryptography public key, sk application) for an SSH public key blob."""
    r = Reader(blob, "key_format")
    kind = r.string().decode("ascii", "replace")
    if kind not in KEY_TYPES:
        raise Refused("key_format")
    curve = KEY_TYPES[kind][1]
    application = b""
    if kind in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        raw = r.string()
        if len(raw) != 32:
            raise Refused("key_format")
        public = ed25519.Ed25519PublicKey.from_public_bytes(raw)
    elif curve:
        if r.string() != curve.encode():
            raise Refused("key_format")
        try:
            public = ec.EllipticCurvePublicKey.from_encoded_point(CURVES[curve][0], r.string())
        except ValueError:
            raise Refused("key_format") from None
    else:
        e, n = r.mpint("key_format"), r.mpint("key_format")
        public = rsa.RSAPublicNumbers(e, n).public_key()
    if kind.startswith("sk-"):
        application = r.string()
    r.end("key_format")
    return kind, public, application


def reference_verify(body: bytes, identity_line: str) -> None:
    """Refuse (raise Refused(code)) an answer slot body the guest must not act on."""
    if len(body) > ANSWER_MAX:
        raise Refused("answer_too_long")
    try:
        doc = json.loads(body)
    except ValueError:
        raise Refused("answer_schema") from None
    if not isinstance(doc, dict) or sorted(doc) != list(FIELDS) or doc["schema"] != SCHEMA \
            or not all(isinstance(doc[k], str) for k in FIELDS) or canonical(doc).encode() != body:
        raise Refused("answer_schema")
    for name, size in LENGTHS.items():
        # The padded base64 of exactly size bytes, canonical, as every mailbox reader takes it.
        try:
            raw = base64.b64decode(doc[name], validate=True)
        except ValueError:
            raise Refused("answer_schema") from None
        if len(raw) != size or b64(raw) != doc[name]:
            raise Refused("answer_schema")
    if len(doc["offer_sha256"]) != 64 or doc["offer_sha256"].strip("0123456789abcdef"):
        raise Refused("answer_schema")
    blob = strict_b64(doc["sig"])
    if len(blob) > SIG_MAX:
        raise Refused("sig_too_long")

    r = Reader(blob, "sshsig_format")
    if r.take(6) != b"SSHSIG":
        raise Refused("sshsig_format")
    if r.u32() != 1:
        raise Refused("sshsig_version")
    public_blob, namespace, reserved, hash_name, signature = (r.string() for _ in range(5))
    r.end("sshsig_format")
    identity_blob = base64.b64decode(identity_line.split(" ")[1])
    if public_blob != identity_blob:
        raise Refused("publickey_mismatch")
    if namespace != NAMESPACE.encode():
        raise Refused("namespace")
    if reserved:
        raise Refused("reserved")
    if hash_name != HASH.encode():
        raise Refused("hash_algorithm")

    kind, public, application = parse_public(public_blob)
    want_type, curve = KEY_TYPES[kind]
    d = signed_data(message(doc))
    s = Reader(signature, "signature_encoding")
    if s.string() != want_type.encode():
        raise Refused("signature_type")
    try:
        if kind in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
            raw = s.string()
            if len(raw) != 64:
                raise Refused("signature_encoding")
            data = d
            if kind.startswith("sk-"):
                flags, counter = s.take(1), s.take(4)
                if not flags[0] & SK_USER_PRESENT:
                    raise Refused("sk_user_presence")
                data = hashlib.sha256(application).digest() + flags + counter + hashlib.sha256(d).digest()
            s.end("signature_encoding")
            public.verify(raw, data)
        elif curve:
            inner = Reader(s.string(), "signature_encoding")
            rr, ss = inner.mpint("signature_encoding"), inner.mpint("signature_encoding")
            inner.end("signature_encoding")
            if not (0 < rr < ORDERS[curve] and 0 < ss < ORDERS[curve]):
                raise Refused("signature_encoding")
            data, algorithm = d, CURVES[curve][1]
            if kind.startswith("sk-"):
                flags, counter = s.take(1), s.take(4)
                if not flags[0] & SK_USER_PRESENT:
                    raise Refused("sk_user_presence")
                data = hashlib.sha256(application).digest() + flags + counter + hashlib.sha256(d).digest()
                algorithm = hashes.SHA256()
            s.end("signature_encoding")
            public.verify(encode_dss_signature(rr, ss), data, ec.ECDSA(algorithm))
        else:
            raw = s.string()
            s.end("signature_encoding")
            if len(raw) != (public.key_size + 7) // 8:
                raise Refused("signature_encoding")
            public.verify(raw, d, padding.PKCS1v15(), hashes.SHA512())
    except InvalidSignature:
        raise Refused("signature_invalid") from None


def refusal(body: bytes, identity_line: str) -> str | None:
    try:
        reference_verify(body, identity_line)
    except Refused as refused:
        return refused.args[0]
    return None


# ---------------------------------------------------------------- the key shape at create (erratum 2.5)

def key_shape(line: str) -> str | None:
    """Why VM create refuses this key for re-wrap (None: allowed). The checks, in order."""
    kind, text = line.split(" ")
    blob = base64.b64decode(text, validate=True)
    if len(blob) > KEY_BLOB_MAX:
        return "key_blob_too_long"
    r = Reader(blob, "key_format")
    try:
        if r.string() != kind.encode() or kind not in KEY_TYPES:
            return "key_format"
        curve = KEY_TYPES[kind][1]
        if kind in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
            if len(r.string()) != 32:
                return "ed25519_key"
        elif curve:
            if r.string() != curve.encode():
                return "ecdsa_curve"
            point = r.string()
            if len(point) != CURVES[curve][2] or point[0] != 4 or not on_curve(curve, point):
                return "ecdsa_point"
        else:
            e = r.mpint("rsa_exponent")
            n = r.mpint("key_format")
            if e % 2 == 0 or not 3 <= e < 1 << 31:
                return "rsa_exponent"
            if not 2048 <= n.bit_length() <= 8192:
                return "rsa_modulus_bits"
        if kind.startswith("sk-"):
            r.string()
        r.end("key_trailing")
    except Refused as refused:
        return refused.args[0]
    return None


def shape_cases(keys: dict) -> list:
    def line(blob: bytes) -> str:
        return f"{blob[4:4 + struct.unpack('>I', blob[:4])[0]].decode()} {b64(blob)}"

    ed, p256 = keys["ed25519"], keys["ecdsa-nistp256"]
    raw_ed = ed.private.public_key().public_bytes_raw()
    point = p256.private.public_key().public_bytes(encoding=_X962, format=_UNCOMPRESSED)
    odd = lambda bits: (1 << (bits - 1)) | 1  # noqa: E731 - a modulus of exactly that many bits
    fill = KEY_BLOB_MAX - len(string("sk-ssh-ed25519@openssh.com") + string(raw_ed) + string(b""))
    cases = [(name, key.line) for name, key in sorted(keys.items()) if name != "other-ed25519"]
    cases += [
        ("sk-ed25519-blob-1100", line(string("sk-ssh-ed25519@openssh.com") + string(raw_ed) + string(b"s" * fill))),
        ("sk-ed25519-blob-1101", line(string("sk-ssh-ed25519@openssh.com") + string(raw_ed) + string(b"s" * (fill + 1)))),
        ("rsa-1024", line(string("ssh-rsa") + mpint(65537) + mpint(odd(1024)))),
        ("rsa-2047", line(string("ssh-rsa") + mpint(65537) + mpint(odd(2047)))),
        ("rsa-8193", line(string("ssh-rsa") + mpint(65537) + mpint(odd(8193)))),
        ("rsa-16384", line(string("ssh-rsa") + mpint(65537) + mpint(odd(16384)))),
        ("rsa-even-exponent", line(string("ssh-rsa") + mpint(65536) + mpint(odd(2048)))),
        ("rsa-exponent-1", line(string("ssh-rsa") + mpint(1) + mpint(odd(2048)))),
        ("rsa-exponent-2^31+1", line(string("ssh-rsa") + mpint((1 << 31) + 1) + mpint(odd(2048)))),
        ("ed25519-31-bytes", line(string("ssh-ed25519") + string(raw_ed[:31]))),
        ("ed25519-trailing", line(string("ssh-ed25519") + string(raw_ed) + b"\0")),
        ("ecdsa-curve-mismatch", line(string("ecdsa-sha2-nistp256") + string("nistp384") + string(point))),
        ("ecdsa-compressed-point", line(string("ecdsa-sha2-nistp256") + string("nistp256")
                                        + string(b"\x02" + point[1:33]))),
        ("ecdsa-point-off-curve", line(string("ecdsa-sha2-nistp256") + string("nistp256")
                                       + string(point[:-1] + bytes([point[-1] ^ 1])))),
    ]
    return [{"name": name, "ssh_public_key": text, "refusal": key_shape(text)} for name, text in cases]


# ---------------------------------------------------------------- the answer cases

def armor(blob: bytes) -> str:
    text = b64(blob)
    lines = [text[i:i + 70] for i in range(0, len(text), 70)]
    return "-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n"


def build(kept: dict) -> tuple[dict, dict]:
    envelope = json.loads(ENVELOPE_FIXTURE.read_text())["cases"][0]["answer"]
    base = {k: envelope[k] for k in ("ct", "epk", "nonce", "offer_sha256")}
    primes = {bits: rsa_primes(bits, kept.get(f"rsa-{bits}")) for bits in (2048, 8192)}
    keys = {
        "ed25519": ed25519_key("ed25519"),
        "ecdsa-nistp256": ecdsa_key("ecdsa-nistp256", "nistp256"),
        "ecdsa-nistp384": ecdsa_key("ecdsa-nistp384", "nistp384"),
        "ecdsa-nistp521": ecdsa_key("ecdsa-nistp521", "nistp521"),
        "rsa-2048": rsa_key(primes[2048]),
        "rsa-8192": rsa_key(primes[8192]),
        "sk-ed25519": ed25519_key("sk-ed25519", "sk-ssh-ed25519@openssh.com"),
        "sk-ecdsa-nistp256": ecdsa_key("sk-ecdsa-nistp256", "nistp256", "sk-ecdsa-sha2-nistp256@openssh.com"),
        "other-ed25519": ed25519_key("other"),
    }

    def answer_for(key: Key, fields: dict, **sig_options) -> dict:
        doc = dict(fields, schema=SCHEMA)
        m = message(doc)
        namespace = sig_options.pop("namespace", NAMESPACE)
        hash_name = sig_options.pop("hash_name", HASH)
        version = sig_options.pop("version", 1)
        signature = key.sign(signed_data(m, namespace, hash_name), **sig_options)
        doc["sig"] = b64(sshsig(key.blob, signature, namespace, hash_name, version))
        return doc

    def variant(label: str, i: int) -> dict:
        ct = hashlib.sha512(f"{label}/{i}".encode()).digest()[:48]
        return dict(base, ct=b64(ct))

    cases = []

    def add(name, identity, body, openssh, note):
        body = body if isinstance(body, str) else canonical(body)
        doc = None
        try:
            doc = json.loads(body)
        except ValueError:
            pass
        case = {"name": name, "identity_ssh_public_key": identity.line, "body": body, "body_bytes": len(body.encode()),
                "refusal": refusal(body.encode(), identity.line), "openssh_accepts": openssh, "note": note}
        if isinstance(doc, dict) and all(k in doc for k in ("offer_sha256", "epk", "nonce", "ct")):
            try:
                case["message_hex"] = message(doc).hex()
            except ValueError:
                pass
        cases.append(case)

    for name, key in keys.items():
        if name != "other-ed25519":
            add(f"valid-{name}", key, answer_for(key, base), True, f"a valid answer signed by the {key.kind} key")

    ed, rsa2048, p256 = keys["ed25519"], keys["rsa-2048"], keys["ecdsa-nistp256"]
    good = answer_for(ed, base)
    for field in ("offer_sha256", "epk", "nonce", "ct"):
        changed = dict(good)
        if field == "offer_sha256":
            changed[field] = hashlib.sha256(b"an earlier offer").hexdigest()
        else:
            raw = bytearray(base64.b64decode(changed[field]))
            raw[0] ^= 1
            changed[field] = b64(bytes(raw))
        add(f"message-{field}-changed", ed, changed, False,
            f"{field} changed after signing: a genuine signature cannot carry another {field}")
    add("other-key", ed, answer_for(keys["other-ed25519"], base), True,
        "signed by another key, which the blob names: OpenSSH accepts it without an allowed-signers file")
    add("namespace-file", ed, answer_for(ed, base, namespace="file"), False, "SSHSIG namespace file")
    add("hash-sha256", ed, answer_for(ed, base, hash_name="sha256"), True,
        "hash_algorithm sha256: OpenSSH allows it; the guest takes sha512 only")
    add("version-2", ed, answer_for(ed, base, version=2), False, "SSHSIG version 2")
    blob = base64.b64decode(good["sig"])
    add("trailing-byte", ed, dict(good, sig=b64(blob + b"\0")), False, "one byte after the SSHSIG blob")
    add("rsa-sha2-256", rsa2048, answer_for(rsa2048, base, sig_type="rsa-sha2-256"), True,
        "an RSA signature with SHA-256: OpenSSH accepts it; the guest takes rsa-sha2-512 only")
    add("rsa-ssh-rsa-sha1", rsa2048, answer_for(rsa2048, base, sig_type="ssh-rsa"), False,
        "an RSA signature with SHA-1 (type ssh-rsa)")

    # A short RSA signature that OpenSSH pads: one whose first byte is zero, with that byte dropped.
    for i in range(4096):
        fields = variant("rsa-short", i)
        doc = answer_for(rsa2048, fields)
        r = Reader(base64.b64decode(doc["sig"]), "x")
        r.take(10)
        parts = [r.string() for _ in range(5)]
        inner = Reader(parts[4], "x")
        sig_type, raw = inner.string(), inner.string()
        if raw[0] == 0:
            short = sshsig(parts[0], string(sig_type) + string(raw[1:]))
            add("rsa-short-signature", rsa2048, dict(doc, sig=b64(short)), True,
                "an RSA signature one byte shorter than the modulus: OpenSSH left-pads it; the guest refuses")
            break
    else:
        raise SystemExit("no RSA signature with a leading zero byte in 4096 tries")

    # A non-minimal mpint that OpenSSH trims: r with a leading zero it does not need.
    for i in range(256):
        fields = variant("mpint", i)
        d = signed_data(message(dict(fields, schema=SCHEMA)))
        rr, ss = decode_dss_signature(p256.private.sign(d, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        raw_r = rr.to_bytes((rr.bit_length() + 7) // 8, "big")
        if not raw_r[0] & 0x80:
            signature = string(p256.kind) + string(string(b"\0" + raw_r) + mpint(ss))
            doc = dict(fields, schema=SCHEMA, sig=b64(sshsig(p256.blob, signature)))
            add("ecdsa-mpint-not-minimal", p256, doc, True,
                "ECDSA r with an unneeded leading zero: OpenSSH trims it; the guest refuses")
            break
    else:
        raise SystemExit("no ECDSA r with a clear top bit in 256 tries")

    zero_r = string(p256.kind) + string(mpint(0) + mpint(1))
    add("ecdsa-r-zero", p256, dict(base, schema=SCHEMA, sig=b64(sshsig(p256.blob, zero_r))), False, "ECDSA r = 0")
    raw64 = ed.sign(signed_data(message(good)))[4 + 11 + 4:]
    sig63 = string("ssh-ed25519") + string(raw64[:63])
    add("ed25519-signature-63-bytes", ed, dict(good, sig=b64(sshsig(ed.blob, sig63))), False,
        "an Ed25519 signature one byte short")
    sk = keys["sk-ed25519"]
    add("sk-no-user-presence", sk, answer_for(sk, base, flags=0), True,
        "an sk-ed25519 signature with the user-present bit clear (a key made with -O no-touch-required): "
        "check-novalidate accepts it, so verify_vm.py rewrap checks the bit itself; the guest refuses")
    add("sk-plain-signature-type", sk, answer_for(sk, base, sig_type="ssh-ed25519"), False,
        "an sk-ed25519 key with a signature of type ssh-ed25519")
    # Erratum 2.6 negatives inside the blob: trailing bytes in the signature string, r or s at n,
    # a reserved field that is not empty, and a blob cut short (a reader must refuse, not panic).
    add("ed25519-trailing-in-signature", ed, dict(good, sig=b64(sshsig(ed.blob, string("ssh-ed25519")
        + string(raw64) + b"\0"))), False, "one byte after the Ed25519 signature, inside the signature string")
    d256 = signed_data(message(dict(base, schema=SCHEMA)))
    r256, s256 = decode_dss_signature(p256.private.sign(d256, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    p256_good = dict(base, schema=SCHEMA, sig=b64(sshsig(p256.blob, string(p256.kind) + string(mpint(r256) + mpint(s256)))))
    assert refusal(canonical(p256_good).encode(), p256.line) is None
    n256 = ORDERS["nistp256"]
    for name, inner, note in (
            ("ecdsa-trailing-after-s", mpint(r256) + mpint(s256) + b"\0", "one byte after s, inside the ECDSA signature"),
            ("ecdsa-r-equals-n", mpint(n256) + mpint(s256), "ECDSA r = n"),
            ("ecdsa-s-equals-n", mpint(r256) + mpint(n256), "ECDSA s = n")):
        add(name, p256, dict(p256_good, sig=b64(sshsig(p256.blob, string(p256.kind) + string(inner)))), False, note)
    add("reserved-not-empty", ed, dict(good, sig=b64(sshsig(ed.blob, ed.sign(signed_data(message(good))),
                                                            reserved=b"x"))), True,
        "SSHSIG reserved is not empty: OpenSSH ignores the field; the guest refuses")
    add("sshsig-truncated", ed, dict(good, sig=b64(blob[:-10])), False,
        "the SSHSIG cut 10 bytes short: its last string runs past the end")
    add("sshsig-truncated-in-header", ed, dict(good, sig=b64(blob[:8])), False, "the SSHSIG cut inside its version")

    # More binding and encoding cases (the #820 review, P3-b).
    sk_sig = base64.b64decode(answer_for(sk, base)["sig"])
    for name, at, note in (("sk-flags-changed", -5, "the sk flags changed after signing (user-present still set)"),
                           ("sk-counter-changed", -1, "the sk counter changed after signing")):
        changed = bytearray(sk_sig)
        changed[at] ^= 0x04 if at == -5 else 0x01
        add(name, sk, dict(base, schema=SCHEMA, sig=b64(bytes(changed))), False, note)
    for i in range(256):
        fields = variant("mpint-negative", i)
        d = signed_data(message(dict(fields, schema=SCHEMA)))
        rr, ss = decode_dss_signature(p256.private.sign(d, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        raw_r = rr.to_bytes(32, "big")
        if raw_r[0] & 0x80:
            signature = string(p256.kind) + string(string(raw_r) + mpint(ss))
            add("ecdsa-mpint-negative", p256, dict(fields, schema=SCHEMA, sig=b64(sshsig(p256.blob, signature))),
                False, "ECDSA r with its top bit set and no leading zero: a negative mpint")
            break
    else:
        raise SystemExit("no ECDSA r with its top bit set in 256 tries")
    add("body-not-canonical-space", ed, canonical(good).replace('",', '", ', 1), None, "a space in the JSON body")
    add("body-not-canonical-key-order", ed, "{" + ",".join(f'"{k}":{json.dumps(good[k])}' for k in
        ("epk", "ct", "nonce", "offer_sha256", "schema", "sig")) + "}", None, "the JSON keys out of order")
    add("offer-sha256-uppercase", ed, dict(good, offer_sha256=good["offer_sha256"].upper()), None,
        "offer_sha256 in uppercase hex")

    v1 = dict(base, schema="cathedral.vm.rewrap-answer/v1")
    add("answer-v1", ed, v1, None, "a v1 answer, with no signature")
    pad = SIG_MAX + 1 - len(blob)
    add("sig-2401-bytes", ed, dict(good, sig=b64(blob + b"\0" * pad)), None, "a sig field of 2401 bytes once decoded")
    add("answer-4097-bytes", ed, _exact_long(good, blob), None,
        "an answer of 4097 bytes: the length is refused before any parse")
    add("sig-not-canonical-base64", ed, dict(good, sig=_padding_bit(good["sig"])), None,
        "a sig whose base64 has a nonzero padding bit")
    add("epk-not-canonical-base64", ed, dict(good, epk=_padding_bit(good["epk"])), None,
        "an epk whose base64 has a nonzero padding bit: it decodes to the signed bytes, and every "
        "mailbox reader refuses it before the signature")

    valid = [c for c in cases if c["refusal"] is None]
    answers = {
        "schema": "cathedral.vm.rewrap-answer-vectors/v2",
        "spec": "VM runtime spec r3 7.5 with the r4 erratum (AB#1022); docs/VM_GUEST.md \"Re-wrap answer v2\"",
        "answer_schema": SCHEMA,
        "message": "domain || offer_sha256 (32 raw bytes) || epk (32) || nonce (12) || ct (48)",
        "message_domain_hex": DOMAIN.hex(),
        "namespace": NAMESPACE,
        "hash_algorithm": HASH,
        "answer_max_bytes": ANSWER_MAX,
        "sig_max_bytes": SIG_MAX,
        "largest_valid_body_bytes": max(c["body_bytes"] for c in valid),
        "cases": cases,
        "test_keys": {"note": "never a real private key; the fixture's test keys are public by design and must "
                              "never be used as an identity. The RSA primes are kept so --check can rebuild the "
                              "same bytes; the other keys come from fixed seeds in the generator.",
                      **{f"rsa-{bits}": primes[bits] for bits in (2048, 8192)}},
    }
    shapes = {
        "schema": "cathedral.vm.ssh-key-shapes/v1",
        "spec": "VM runtime spec r4 erratum 2.5 (AB#1022): the key shape VM create allows, so every re-wrap "
                "answer fits 4096 bytes and the guest can verify it. Checked at create only: parse_identity "
                "and the init's CheckSSHKey keep accepting every key they accept today.",
        "key_blob_max_bytes": KEY_BLOB_MAX,
        "rsa_modulus_bits": [2048, 8192],
        "cases": shape_cases({k: v for k, v in keys.items()}),
    }
    return answers, shapes


def _exact_long(good: dict, blob: bytes) -> str:
    """An answer of exactly ANSWER_MAX + 1 bytes: the longest canonical one that fits, then spaces.
    Base64 grows 4 characters at a time, so the sig alone cannot always land on 4097."""
    extra = 0
    while len(canonical(dict(good, sig=b64(blob + b"\0" * (extra + 1))))) <= ANSWER_MAX:
        extra += 1
    body = canonical(dict(good, sig=b64(blob + b"\0" * extra)))
    return body + " " * (ANSWER_MAX + 1 - len(body))


def _padding_bit(text: str) -> str:
    """TEXT with the lowest bit of its last data character set: the same length, a different
    string, and one that strict decoders refuse because the padding bits are not zero."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    data = text.rstrip("=")
    if len(data) == len(text):
        raise SystemExit("this sig has no padding to spoil")
    last = alphabet.index(data[-1])
    return data[:-1] + alphabet[last | 1] + text[len(data):]


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    kept = json.loads(ANSWER_FIXTURE.read_text())["test_keys"] if ANSWER_FIXTURE.exists() else {}
    if args.check and not kept:
        print(f"{ANSWER_FIXTURE} is missing", file=sys.stderr)
        return 1
    answers, shapes = build(kept)
    texts = {ANSWER_FIXTURE: render(answers), SHAPE_FIXTURE: render(shapes)}
    if args.check:
        stale = [path.name for path, text in texts.items() if not path.exists() or path.read_text() != text]
        if stale:
            print("differs from the generator: " + ", ".join(stale), file=sys.stderr)
        return 1 if stale else 0
    for path, text in texts.items():
        path.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
