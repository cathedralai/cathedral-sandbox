"""Sealed-hotel receipts carry the room network policy; the verifier prints
the policy timeline per room and checks each policy sha256."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KIT = Path(__file__).resolve().parents[1] / "room-kit"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, KIT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rr = _load("room_receipts")
vr = _load("verify_receipts")


def test_signed_routes_include_the_network_switch() -> None:
    def action(method, path):
        return next((a for m, p, a in rr.SIGNED if m == method and p.match(path)), None)

    assert action("PUT", "/v1/sandboxes/sbx_1/network") == "network_set"
    assert action("POST", "/v1/sandboxes/sbx_1/network") == "network_set"
    assert action("POST", "/v1/sandboxes") == "create"
    assert action("GET", "/v1/sandboxes/sbx_1/network") is None


def test_policy_from_the_hotel_answer() -> None:
    pol = {"mode": "allowlist", "allow": ["pypi.org"]}
    res = {"id": "sbx_1", "network": {"mode": "allowlist", "allow": ["pypi.org"], "policy": pol, "policy_sha256": "x"}}
    assert rr.Handler.network_policy("create", 202, res) == pol
    assert rr.Handler.network_policy("network_set", 200, {"network": {"policy": pol}}) == pol
    assert rr.Handler.network_policy("network_set", 409, {"network": {"policy": pol}}) is None
    assert rr.Handler.network_policy("exec", 200, res) is None
    assert rr.Handler.network_policy("create", 202, {"network": {"mode": "public"}}) is None


class Chain:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.binding = {"schema": rr.BINDING_SCHEMA, "receipt_key_ed25519_b64": base64.b64encode(pub).decode()}
        self.bsha = rr.sha(rr.canonical(self.binding))
        self.head = self.bsha
        self.receipts = []

    def sign(self, **fields):
        st = {"schema": rr.RECEIPT_SCHEMA, "binding_sha256": self.bsha, "sequence": len(self.receipts) + 1,
              "previous_receipt_sha256": self.head, "issued_at": 1000 + len(self.receipts), **fields}
        rc = {"statement": st, "signature_b64": base64.b64encode(self.key.sign(rr.canonical(st))).decode(),
              "receipt_sha256": rr.sha(rr.canonical(st))}
        self.head = rc["receipt_sha256"]
        self.receipts.append(rc)

    def policy(self, action, room, mode, allow=(), status=200, sha=None):
        pol = {"mode": mode, "allow": list(allow)}
        self.sign(action=action, sandbox_id=room, status=status, network_policy=pol,
                  network_policy_sha256=sha or rr.sha(rr.canonical(pol)))


def test_policy_timeline_per_room() -> None:
    c = Chain()
    c.policy("create", "sbx_a", "allowlist", ["files.pythonhosted.org", "pypi.org"], status=202)
    c.sign(action="exec", sandbox_id="sbx_a", status=200)
    c.policy("network_set", "sbx_a", "deny_all")
    c.policy("network_set", "sbx_a", "internet")
    c.sign(action="create", sandbox_id="sbx_b", status=202)  # an old receipt with no policy
    c.policy("network_set", "sbx_a", "allowlist", ["files.pythonhosted.org", "pypi.org"])
    c.sign(action="delete", sandbox_id="sbx_a", status=204)
    att = {"binding": c.binding, "binding_sha256": c.bsha}
    assert vr.verify_receipts(att, c.receipts, c.head)["receipts"] == 7
    tl = vr.policy_timeline(c.receipts)
    assert list(tl) == ["sbx_a"]
    assert [(e["action"], e.get("mode")) for e in tl["sbx_a"]] == [
        ("create", "allowlist"), ("network_set", "deny_all"), ("network_set", "internet"),
        ("network_set", "allowlist"), ("delete", None)]
    assert tl["sbx_a"][0]["policy_sha256"] == rr.sha(rr.canonical({"mode": "allowlist", "allow": ["files.pythonhosted.org", "pypi.org"]}))


def test_policy_sha_mismatch_fails() -> None:
    c = Chain()
    c.policy("network_set", "sbx_a", "internet", sha="0" * 64)
    with pytest.raises(vr.Fail, match="network_policy_sha256"):
        vr.policy_timeline(c.receipts)
