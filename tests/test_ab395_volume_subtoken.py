"""AB#395: per-mount storage sub-token (prefix, IP, expiry, no delete)."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import volume_chain as vc
from cathedral import volume_subtoken as st

T0 = 1_800_000_000
PREFIX = "volumes/vol-1/"


@pytest.fixture
def world():
    key = Ed25519PrivateKey.generate()
    registry = vc.VolumeRegistry(key, now=lambda: T0, lease_seconds=600)
    registry.create("vol-1", "customer-1")
    holder = Ed25519PrivateKey.generate()
    lease = registry.grant("vol-1", {"schema": vc.SEALED_BINDING_SCHEMA, "hotel": "h", "boot_id": "b",
                                     "receipt_key_ed25519_b64": vc.public_b64(holder), "measurement": "aa" * 48})
    return key, lease


def issue(world, **kw):
    key, lease = world
    args = dict(prefix=PREFIX, source_ip="203.0.113.7", ttl_seconds=300, now=lambda: T0)
    args.update(kw)
    return st.issue(key, lease, **args)


def refused(code, fn, *a, **kw):
    with pytest.raises(vc.VolumeRefused) as exc:
        fn(*a, **kw)
    assert exc.value.code == code


def call(world, token, **kw):
    args = dict(op="put", key=PREFIX + "data/ab", source_ip="203.0.113.7", now=lambda: T0 + 10)
    args.update(kw)
    return st.authorize(token, vc.public_b64(world[0]), **args)


def test_allowed_request(world):
    token = issue(world)
    for op in ("get", "put", "list"):
        assert call(world, token, op=op)["volume_id"] == "vol-1"


def test_delete_is_never_allowed(world):
    token = issue(world)
    refused("op_not_allowed", call, world, token, op="delete")
    refused("bad_ops", issue, world, ops=("get", "delete"))


def test_prefix_and_traversal(world):
    token = issue(world)
    refused("outside_prefix", call, world, token, key="volumes/vol-2/data/ab")
    refused("outside_prefix", call, world, token, key="volumes/vol-1")
    refused("outside_prefix", call, world, token, key=PREFIX + "../vol-2/x")
    for bad in ("volumes/vol-1", "/volumes/vol-1/", "volumes/../x/", "a//b/", ""):
        refused("bad_prefix", issue, world, prefix=bad)


def test_source_ip(world):
    token = issue(world)
    refused("wrong_source_ip", call, world, token, source_ip="203.0.113.8")
    refused("bad_source_ip", call, world, token, source_ip="not-an-ip")
    refused("bad_source_ip", issue, world, source_ip="203.0.113.0/24")


def test_expiry_capped_by_lease_and_max_ttl(world):
    token = issue(world, ttl_seconds=10_000)
    assert token["statement"]["expires_at"] == T0 + 600
    refused("token_expired", call, world, token, now=lambda: T0 + 600)
    short = issue(world, ttl_seconds=30)
    refused("token_expired", call, world, short, now=lambda: T0 + 30)
    refused("bad_ttl", issue, world, ttl_seconds=0)
    refused("lease_expired", issue, world, now=lambda: T0 + 600)


def test_tampering_and_wrong_signer(world):
    token = issue(world)
    forged = {**token, "statement": {**token["statement"], "prefix": "volumes/"}}
    refused("bad_signature", call, world, forged)
    other = Ed25519PrivateKey.generate()
    _, lease = world
    foreign = st.issue(other, lease, prefix=PREFIX, source_ip="203.0.113.7", ttl_seconds=60, now=lambda: T0)
    refused("bad_signature", call, world, foreign)
    refused("malformed", call, world, {})


def test_token_is_not_a_chain_statement(world):
    key, lease = world
    token = issue(world)
    refused("wrong_schema", vc._check_signed, token, vc.LEASE_SCHEMA, None, "bad")
    refused("wrong_schema", st.authorize, lease, vc.public_b64(key), op="get", key=PREFIX + "x", source_ip="203.0.113.7")
