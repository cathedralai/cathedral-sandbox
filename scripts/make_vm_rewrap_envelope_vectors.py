#!/usr/bin/env python3
"""Make tests/fixtures/vm_rewrap_envelope_v1.json (AB#999, VM runtime spec r3 7.5 and its 27 Nov
errata): the re-wrap answer envelope, from fixed keys so the bytes are reproducible.

The construction is room_receipts._seal_envelope with its own info and AAD:
  shared = X25519(customer ephemeral private, VM offer public)
  key    = HKDF-SHA256(ikm=shared, salt=AAD, info=b"cathedral.vm-rewrap.v1" || epk || vm_pub, 32)
  ct     = AES-256-GCM(key, nonce, R, AAD)             (R is 32 bytes, ct is 48 with its tag)
  AAD    = offer_sha256 as 64 lowercase hex ASCII bytes

The Go guest (room-kit/custom-guest/internal/vmmailbox) must open every vector, and verify_vm.py
rewrap (VM2) must produce them. The keys here are test keys and protect nothing.

  make_vm_rewrap_envelope_vectors.py            write the fixture
  make_vm_rewrap_envelope_vectors.py --check    exit 1 if the file on disk differs
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

INFO = b"cathedral.vm-rewrap.v1"
FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "vm_rewrap_envelope_v1.json"


def raw_public(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def seal(vm_private: bytes, customer_private: bytes, nonce: bytes, offer_body: bytes, secret: bytes) -> dict:
    vm = X25519PrivateKey.from_private_bytes(vm_private)
    customer = X25519PrivateKey.from_private_bytes(customer_private)
    vm_pub, epk = raw_public(vm), raw_public(customer)
    offer_sha256 = hashlib.sha256(offer_body).hexdigest()
    aad = offer_sha256.encode("ascii")
    shared = customer.exchange(vm.public_key())
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=aad, info=INFO + epk + vm_pub).derive(shared)
    ct = AESGCM(key).encrypt(nonce, secret, aad)
    assert len(ct) == 48
    return {
        "vm_private_hex": vm_private.hex(), "vm_public_b64": b64(vm_pub),
        "customer_private_hex": customer_private.hex(),
        "offer_body_utf8": offer_body.decode("ascii"), "offer_sha256": offer_sha256,
        "recovery_key_hex": secret.hex(), "shared_hex": shared.hex(), "wrapping_key_hex": key.hex(),
        "answer": {"schema": "cathedral.vm.rewrap-answer/v1", "offer_sha256": offer_sha256,
                   "epk": b64(epk), "nonce": b64(nonce), "ct": b64(ct)},
    }


def build() -> dict:
    def seed(label: str) -> bytes:
        return hashlib.sha256(b"cathedral-vm-rewrap-vector/" + label.encode()).digest()

    cases = []
    for name in ("one", "two"):
        # The offer body is a stand-in: the envelope only needs its sha256 as the AAD.
        offer_body = ('{"schema":"cathedral.vm.rewrap-offer/v1","vector":"' + name + '"}').encode()
        cases.append(seal(seed("vm-" + name), seed("customer-" + name), seed("nonce-" + name)[:12],
                          offer_body, seed("recovery-" + name)))
    return {
        "spec": "VM runtime spec r3 7.5 and the 27 Nov 14:44Z errata",
        "hkdf_info": INFO.decode("ascii"),
        "aad": "offer_sha256 as 64 lowercase hex ASCII bytes; also the HKDF salt",
        "key_info_order": "info || epk || vm_pub",
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if args.check:
        return 0 if FIXTURE.read_text() == text else 1
    FIXTURE.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
