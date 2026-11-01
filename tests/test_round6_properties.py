"""Review round 6, property pass (hypothesis).

Two kinds of property: a parser on the customer path raises only what its
caller catches (anything else is a 500 or a crashed daemon task), and the
producer and the consumer of a network policy agree (what the hotel API
accepted is what the egress daemon enforces).

Needs hypothesis (a dev extra); the module is skipped where it is absent.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import struct
import sys
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cathedral import sandbox_api as api
from cathedral.sandbox_server import _create_request

ROOT = Path(__file__).resolve().parents[1]
# Examples per property. CI runs the default; raise it for a deeper local pass:
#   CATHEDRAL_PROPERTY_EXAMPLES=3000 python -m pytest tests/test_round6_properties.py
N = int(os.environ.get("CATHEDRAL_PROPERTY_EXAMPLES", "200"))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "room-kit" / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


egress = _load("room_egress")
try:
    receipts = _load("room_receipts")
except Exception as exc:  # noqa: BLE001 - an optional dependency on this machine
    receipts = None
    RECEIPTS_SKIP = str(exc)

# What sandbox_server._invoke turns into a 400 invalid_request.
API_400 = (api.SandboxContractError, TypeError, ValueError, KeyError, OverflowError, RecursionError)

json_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**30), max_value=10**30)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=40)
)
json_values = st.recursive(
    json_scalars,
    lambda inner: st.lists(inner, max_size=6) | st.dictionaries(st.text(max_size=12), inner, max_size=6),
    max_leaves=30,
)
FIELDS = [
    "image", "build", "snapshot_id", "count", "resources", "network", "env", "labels", "ttl_seconds",
    "entrypoint", "user", "workdir", "idle_timeout_seconds", "vcpu", "memory_gib", "disk_gib", "gpu",
    "mode", "allow", "dockerfile", "context_tar_url", "content_hash", "registry_auth", "username", "password",
    "sealed", "name", "ttl",
]
payloads = st.dictionaries(st.sampled_from(FIELDS) | st.text(max_size=12), json_values, max_size=10)


@settings(max_examples=3 * N, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(payloads)
def test_every_create_payload_ends_in_a_400_or_a_request(payload) -> None:
    # Any other exception type is a 500 to the customer and a traceback on the hotel.
    try:
        _create_request(payload)
    except API_400:
        pass


# ---------------------------------------------------------------- network: producer vs consumer

label = st.from_regex(r"[a-z0-9](?:[a-z0-9-]{0,14}[a-z0-9])?", fullmatch=True)
hostname = st.lists(label, min_size=1, max_size=5).map(".".join)
ipv4 = st.integers(min_value=0, max_value=2**32 - 1).map(lambda n: str(ipaddress.ip_address(n)))
cidr = st.tuples(ipv4, st.integers(min_value=0, max_value=32)).map(lambda t: f"{t[0]}/{t[1]}")
entry = st.one_of(
    hostname,
    hostname.map(lambda h: "*." + h),
    hostname.map(lambda h: h + ":443"),
    hostname.map(lambda h: h + ":80"),
    hostname.map(lambda h: h + ":8080"),
    hostname.map(lambda h: h.upper() + "."),
    hostname.map(lambda h: " " + h + " "),
    ipv4,
    cidr,
    ipv4.map(lambda i: i + ":443"),
    st.text(max_size=64),
)
allows = st.lists(entry, max_size=8)
modes = st.sampled_from(["public", "internet", "deny_all", "allowlist", "none", "PUBLIC", ""]) | st.text(max_size=8)


def _is_net(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


@settings(max_examples=3 * N, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(modes, allows)
def test_a_policy_the_api_accepts_is_the_policy_the_daemon_enforces(mode, allow) -> None:
    try:
        spec = api.NetworkSpec(mode=mode, allow=tuple(allow))
    except api.SandboxContractError:
        return
    policy = dict(spec.policy)
    if policy["mode"] == "none":
        return  # no interface at all: the hotel never asks the daemon (a later switch maps none to deny_all)
    # The daemon checks again at the enforcement point; it must not refuse
    # what the API already promised the customer (the room would start with
    # no policy applied and the create would fail late).
    parsed = egress.Policy.parse(policy)
    if parsed.mode != "allowlist":
        assert not policy.get("allow")
        return
    for e in policy["allow"]:
        if _is_net(e):
            net = ipaddress.ip_network(e, strict=False)
            assert any(net.subnet_of(ipaddress.ip_network(n)) for n in parsed.nets), (e, parsed.nets)
            continue
        # A named entry may carry ":80" or ":443". allows_name takes the
        # port as its own argument (the proxy splits SNI/Host from the
        # destination port), so split the entry the way the daemon does.
        kind, name, ports = egress.classify(e)
        probe = "sub." + name if kind == "wild" else name
        assert parsed.allows_name(probe), (e, parsed)
        for p in ports or (80, 443):
            assert parsed.allows_name(probe, p), (e, p, parsed)
        if kind == "wild":
            assert not parsed.allows_name(name) or name in parsed.hosts


@settings(max_examples=2 * N, deadline=None)
@given(st.dictionaries(st.text(max_size=12), json_values, max_size=6))
def test_the_daemon_policy_parser_raises_only_value_errors(doc) -> None:
    # The daemon reloads its table from disk through Policy.parse; any other
    # exception type stops the reload.
    try:
        egress.Policy.parse(doc)
    except ValueError:
        pass


@settings(max_examples=3 * N, deadline=None)
@given(st.text(max_size=300))
def test_allows_name_never_raises(name) -> None:
    p = egress.Policy.parse({"mode": "allowlist", "allow": ["example.com", "*.pypi.org", "8.8.8.0/24"]})
    p.allows_name(name)


# ---------------------------------------------------------------- DNS front

def _question(name: str, qtype: int) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".") if part)
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", qtype, 1)


@settings(max_examples=5 * N, deadline=None)
@given(st.binary(max_size=600) | st.builds(_question, hostname, st.integers(min_value=0, max_value=65535)))
def test_dns_question_raises_only_what_the_resolver_catches(msg) -> None:
    # Resolver.decide catches exactly (ValueError, IndexError, struct.error);
    # anything else kills the datagram handler for that query.
    try:
        name, qtype, end = egress.dns_question(msg)
    except (ValueError, IndexError, struct.error):
        return
    assert isinstance(name, str) and 0 <= qtype < 65536 and end >= 12
    reply = egress.dns_reply(msg, end, egress.NXDOMAIN)
    assert reply[:2] == msg[:2] and len(reply) >= 12


@settings(max_examples=2 * N, deadline=None)
@given(hostname, st.integers(min_value=0, max_value=65535))
def test_a_well_formed_question_round_trips(name, qtype) -> None:
    got_name, got_type, end = egress.dns_question(_question(name, qtype))
    assert got_name == name.lower() and got_type == qtype and end == len(_question(name, qtype))


# ---------------------------------------------------------------- receipts canonical form

@pytest.mark.skipif(receipts is None, reason="room_receipts did not import here")
@settings(max_examples=2 * N, deadline=None)
@given(json_values)
def test_canonical_form_is_a_fixed_point_and_raises_only_for_lone_surrogates(doc) -> None:
    try:
        first = receipts.canonical(doc)
    except UnicodeEncodeError:
        return  # a lone surrogate; the front answers 400 before the API runs
    assert receipts.canonical(json.loads(first.decode())) == first


# ---------------------------------------------------------------- header parsers

@settings(max_examples=2 * N, deadline=None)
@given(st.text(max_size=40), st.integers(min_value=0, max_value=10**9))
def test_parse_byte_range_raises_only_contract_errors(header, length) -> None:
    try:
        api.parse_byte_range(header, length)
    except api.SandboxContractError:
        pass


@settings(max_examples=2 * N, deadline=None)
@given(st.text(max_size=200))
def test_validate_idempotency_key_raises_only_contract_errors(key) -> None:
    try:
        api.validate_idempotency_key(key)
    except api.SandboxContractError:
        pass
