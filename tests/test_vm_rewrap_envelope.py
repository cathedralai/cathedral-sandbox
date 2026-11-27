"""AB#999 VM1b: the re-wrap envelope fixture is what its generator makes, and an independent
decrypt from the fixture's own keys gives R (spec r3 7.5 and the 27 Nov errata)."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

REPO = Path(__file__).resolve().parents[1]
GEN = REPO / "scripts" / "make_vm_rewrap_envelope_vectors.py"
FIXTURE = REPO / "tests" / "fixtures" / "vm_rewrap_envelope_v1.json"


def test_fixture_is_what_the_generator_makes():
    assert subprocess.run([sys.executable, str(GEN), "--check"]).returncode == 0


def test_every_case_opens_with_the_vm_key_and_the_documented_construction():
    doc = json.loads(FIXTURE.read_text())
    assert doc["hkdf_info"] == "cathedral.vm-rewrap.v1"
    for case in doc["cases"]:
        vm = X25519PrivateKey.from_private_bytes(bytes.fromhex(case["vm_private_hex"]))
        ans = case["answer"]
        epk, nonce, ct = (base64.b64decode(ans[k], validate=True) for k in ("epk", "nonce", "ct"))
        aad = ans["offer_sha256"].encode("ascii")
        assert ans["offer_sha256"] == hashlib.sha256(case["offer_body_utf8"].encode()).hexdigest()
        vm_pub = vm.public_key().public_bytes_raw()
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=aad,
                   info=b"cathedral.vm-rewrap.v1" + epk + vm_pub).derive(vm.exchange(X25519PublicKey.from_public_bytes(epk)))
        assert AESGCM(key).decrypt(nonce, ct, aad).hex() == case["recovery_key_hex"]
        # The AAD matters: the same ciphertext under another offer name does not open.
        try:
            AESGCM(key).decrypt(nonce, ct, b"0" * 64)
        except Exception:
            continue
        raise AssertionError("another AAD opened the envelope")
