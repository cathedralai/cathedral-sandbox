"""Central access: a root-signed delegation, then per-request signatures."""

from __future__ import annotations

import base64
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral import central_access as ca
from cathedral.common import ChannelBinding, ChannelBindingType
from cathedral.policy_registry import canonical_json
from cathedral.validator_access import ValidatorAccessState

# The subnet is deploy-time config with no default; draw one per run.
NETWORK = "finney"
NETUID = random.SystemRandom().randrange(1, 65_536)
OTHER_NETUID = (NETUID % 65_535) + 1
WORKER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
OTHER_WORKER = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
ROOT_SEED = b"r" * 32
OTHER_ROOT_SEED = b"o" * 32
CENTRAL_SEED = b"c" * 32
NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC)
BINDING = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"t" * 32)
BODY = b"{}"
PATH = "/v1/capabilities"


def _public(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


ROOT_KEYS = {"cathedral-root-1": _public(ROOT_SEED)}


def _delegation(**overrides) -> dict[str, object]:
    fields = {
        "root_key_id": "cathedral-root-1",
        "root_seed": ROOT_SEED,
        "central_key": _public(CENTRAL_SEED),
        "routes": [PATH],
        "network": NETWORK,
        "netuid": NETUID,
        "sequence": 5,
        "issued_at": NOW - timedelta(hours=1),
        "expires_at": NOW + timedelta(hours=1),
    }
    fields.update(overrides)
    return ca.sign_delegation(**fields)


def _resign(document: dict[str, object], seed: bytes) -> dict[str, object]:
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(canonical_json(unsigned))
    unsigned["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return unsigned


def _header(delegation=None, *, central_seed=CENTRAL_SEED, nonce=b"n" * 32, **overrides) -> str:
    fields = {
        "delegation": delegation if delegation is not None else _delegation(),
        "central_seed": central_seed,
        "worker_hotkey": WORKER,
        "network": NETWORK,
        "netuid": NETUID,
        "method": "POST",
        "path": PATH,
        "body": BODY,
        "channel_binding": BINDING,
        "nonce": nonce,
        "issued_at": NOW - timedelta(seconds=10),
        "expires_at": NOW + timedelta(seconds=60),
    }
    fields.update(overrides)
    return ca.build_central_request_header(**fields)


def _edit_request(header: str, seed: bytes = CENTRAL_SEED, **changes) -> str:
    document = json.loads(base64.b64decode(header))
    document.update(changes)
    return base64.b64encode(canonical_json(_resign(document, seed))).decode("ascii")


@pytest.fixture
def authorizer(tmp_path: Path) -> ca.CentralAccessAuthorizer:
    state = ca.open_central_access_state(str(tmp_path / "central-access.sqlite"))
    return ca.CentralAccessAuthorizer(
        ROOT_KEYS,
        worker_hotkey=WORKER,
        network=NETWORK,
        netuid=NETUID,
        channel_binding=BINDING,
        state=state,
    )


def _accept(authorizer, header, *, body=BODY, now=NOW, path=PATH):
    request = authorizer.preauthorize(header, method="POST", path=path, now=now)
    return authorizer.finalize(request, body=body, now=now)


def test_a_delegated_signed_request_is_accepted_once(authorizer):
    header = _header()
    caller = _accept(authorizer, header)
    assert caller == "central:" + hashlib.sha256(_public(CENTRAL_SEED)).hexdigest()
    with pytest.raises(ca.CentralAccessError, match="replayed"):
        _accept(authorizer, header)
    assert _accept(authorizer, _header(nonce=b"m" * 32)) == caller


@pytest.mark.parametrize(
    ("delegation", "match"),
    [
        (lambda: _resign(_delegation(), OTHER_ROOT_SEED), "signature verification failed"),
        (
            lambda: _resign({**_delegation(), "root_key_id": "someone-else"}, ROOT_SEED),
            "untrusted root",
        ),
        (
            lambda: _delegation(
                issued_at=NOW - timedelta(hours=3), expires_at=NOW - timedelta(hours=2)
            ),
            "expired",
        ),
        (
            lambda: _delegation(
                issued_at=NOW + timedelta(minutes=5), expires_at=NOW + timedelta(hours=1)
            ),
            "future",
        ),
        (
            lambda: _resign({**_delegation(), "expires_at": "2026-09-29T12:00:01Z"}, ROOT_SEED),
            "too long",
        ),
        (lambda: _delegation(netuid=OTHER_NETUID), "subnet does not match"),
        (lambda: _delegation(network="test"), "subnet does not match"),
        (lambda: _resign({**_delegation(), "routes": ["/v1/sat-work"]}, ROOT_SEED), "routes"),
        (lambda: _resign({**_delegation(), "routes": [PATH, PATH]}, ROOT_SEED), "routes"),
        (lambda: _resign({**_delegation(), "extra": 1}, ROOT_SEED), "fields are invalid"),
        (lambda: _resign({**_delegation(), "netuid": True}, ROOT_SEED), "netuid"),
        (lambda: _resign({**_delegation(), "sequence": 0}, ROOT_SEED), "sequence"),
        (
            lambda: _resign({**_delegation(), "central_key_base64": "AA=="}, ROOT_SEED),
            "central key",
        ),
    ],
)
def test_a_bad_delegation_is_refused(authorizer, delegation, match):
    document = delegation()
    header = _edit_request(_header(), delegation=document)
    with pytest.raises(ca.CentralAccessError, match=match):
        _accept(authorizer, header)


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"worker_hotkey": OTHER_WORKER}, "worker does not match"),
        ({"netuid": OTHER_NETUID}, "subnet does not match"),
        ({"channel_binding_digest_hex": "75" * 32}, "channel key does not match"),
        ({"channel_binding_type": "application_key_sha256"}, "channel type does not match"),
        ({"path": "/v1/evidence"}, "target does not match"),
        ({"method": "GET"}, "target does not match"),
        ({"issued_at": "2026-09-28T11:58:30Z", "expires_at": "2026-09-28T11:59:59Z"}, "expired"),
        ({"issued_at": "2026-09-28T11:58:00Z", "expires_at": "2026-09-28T12:00:01Z"}, "too long"),
        ({"issued_at": "2026-09-28T12:00:20Z", "expires_at": "2026-09-28T12:01:00Z"}, "future"),
        ({"nonce_hex": "XY" * 32}, "nonce is invalid"),
        ({"body_sha256": "sha256:" + "0" * 63}, "body digest is invalid"),
        ({"issued_at": "2026-02-30T00:00:00Z"}, "canonical UTC"),
        ({"schema": "cathedral_validator_request_v1"}, "schema is unsupported"),
    ],
)
def test_a_bad_request_is_refused_before_the_body_is_read(authorizer, changes, match):
    header = _edit_request(_header(), **changes)
    with pytest.raises(ca.CentralAccessError, match=match):
        authorizer.preauthorize(header, method="POST", path=PATH, now=NOW)


def test_a_request_must_not_outlive_its_delegation(authorizer):
    delegation = _delegation(expires_at=NOW + timedelta(seconds=30))
    with pytest.raises(ca.CentralAccessError, match="outlives"):
        _accept(authorizer, _header(delegation))


def test_the_route_must_be_granted_by_the_delegation(authorizer):
    header = _header(path="/v1/sat-work")
    with pytest.raises(ca.CentralAccessError, match="does not grant this route"):
        _accept(authorizer, header, path="/v1/sat-work")


def test_only_the_delegated_key_can_sign_requests(authorizer):
    with pytest.raises(ca.CentralAccessError, match="request signature verification failed"):
        _accept(authorizer, _header(central_seed=ROOT_SEED))


def test_a_tampered_request_fails_its_signature(authorizer):
    document = json.loads(base64.b64decode(_header()))
    document["nonce_hex"] = "ab" * 32
    header = base64.b64encode(canonical_json(document)).decode("ascii")
    with pytest.raises(ca.CentralAccessError, match="request signature verification failed"):
        _accept(authorizer, header)


def test_the_body_must_match_the_signed_digest(authorizer):
    with pytest.raises(ca.CentralAccessError, match="body does not match"):
        _accept(authorizer, _header(), body=b'{"x":1}')


def test_a_non_canonical_header_is_refused(authorizer):
    document = json.loads(base64.b64decode(_header()))
    header = base64.b64encode(json.dumps(document, indent=1).encode()).decode("ascii")
    with pytest.raises(ca.CentralAccessError, match="canonical JSON"):
        _accept(authorizer, header)


@pytest.mark.parametrize("header", ["", "not base64!", None, "A" * 40000])
def test_a_malformed_header_is_refused(authorizer, header):
    with pytest.raises(ca.CentralAccessError):
        _accept(authorizer, header)


def test_a_naive_time_is_refused(authorizer):
    with pytest.raises(ca.CentralAccessError, match="UTC"):
        _accept(authorizer, _header(), now=NOW.replace(tzinfo=None))


def test_an_older_delegation_is_refused_after_a_newer_one(authorizer):
    _accept(authorizer, _header(_delegation(sequence=7)))
    with pytest.raises(ca.CentralAccessError, match="older than one already accepted"):
        _accept(authorizer, _header(_delegation(sequence=6), nonce=b"m" * 32))


def test_a_revoked_delegation_is_refused_before_and_after_the_body(authorizer):
    delegation = _delegation()
    digest = ca.verify_delegation(
        delegation, ROOT_KEYS, network=NETWORK, netuid=NETUID, now=NOW
    ).digest
    request = authorizer.preauthorize(_header(delegation), method="POST", path=PATH, now=NOW)
    authorizer.install_revocations(
        ca.sign_revocations(
            root_key_id="cathedral-root-1",
            root_seed=ROOT_SEED,
            sequence=1,
            issued_at=NOW,
            revoked=[digest],
        )
    )
    with pytest.raises(ca.CentralAccessError, match="revoked"):
        authorizer.finalize(request, body=BODY, now=NOW)
    with pytest.raises(ca.CentralAccessError, match="revoked"):
        authorizer.preauthorize(
            _header(delegation, nonce=b"m" * 32), method="POST", path=PATH, now=NOW
        )


def test_revocation_lists_only_move_forward(authorizer):
    def revocations(sequence, revoked, seed=ROOT_SEED):
        return ca.sign_revocations(
            root_key_id="cathedral-root-1",
            root_seed=seed,
            sequence=sequence,
            issued_at=NOW,
            revoked=revoked,
        )

    authorizer.install_revocations(revocations(3, []))
    with pytest.raises(ca.CentralAccessError, match="older"):
        authorizer.install_revocations(revocations(2, []))
    with pytest.raises(ca.CentralAccessError, match="without a new sequence"):
        authorizer.install_revocations(revocations(3, ["sha256:" + "a" * 64]))
    with pytest.raises(ca.CentralAccessError, match="signature verification failed"):
        authorizer.install_revocations(revocations(4, [], seed=OTHER_ROOT_SEED))
    with pytest.raises(ca.CentralAccessError, match="sorted delegation digests"):
        authorizer.install_revocations(_resign({**revocations(4, []), "revoked": ["x"]}, ROOT_SEED))


def test_root_keys_load_only_under_the_miner_pin(tmp_path):
    path = tmp_path / "central-root-keys.json"
    path.write_bytes(
        canonical_json({"cathedral-root-1": base64.b64encode(_public(ROOT_SEED)).decode("ascii")})
    )
    pin = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    assert ca.load_central_root_keys(str(path), pinned_digest=pin) == ROOT_KEYS
    with pytest.raises(ca.CentralAccessError, match="does not match"):
        ca.load_central_root_keys(str(path), pinned_digest="sha256:" + "0" * 64)
    with pytest.raises(ca.CentralAccessError, match="sha256"):
        ca.load_central_root_keys(str(path), pinned_digest="")


def test_central_replay_state_is_separate_from_validator_state(tmp_path):
    with pytest.raises(ca.CentralAccessError, match="durable replay state"):
        ca.CentralAccessAuthorizer(
            ROOT_KEYS,
            worker_hotkey=WORKER,
            network=NETWORK,
            netuid=NETUID,
            channel_binding=BINDING,
            state=object(),
        )
    with pytest.raises(ca.CentralAccessError, match="pinned root key"):
        ca.CentralAccessAuthorizer(
            {},
            worker_hotkey=WORKER,
            network=NETWORK,
            netuid=NETUID,
            channel_binding=BINDING,
            state=ValidatorAccessState(str(tmp_path / "state.sqlite")),
        )


def _revocations(sequence, revoked, seed=ROOT_SEED):
    return ca.sign_revocations(
        root_key_id="cathedral-root-1",
        root_seed=seed,
        sequence=sequence,
        issued_at=NOW,
        revoked=revoked,
    )


@pytest.mark.parametrize("routes", [[{"a": 1}], [1, "x"], [None]])
def test_non_string_delegation_routes_are_refused_not_raised(authorizer, routes):
    document = _resign({**_delegation(), "routes": routes}, ROOT_SEED)
    header = _edit_request(_header(), delegation=document)
    with pytest.raises(ca.CentralAccessError, match="routes"):
        authorizer.preauthorize(header, method="POST", path=PATH, now=NOW)


@pytest.mark.parametrize("revoked", [[{"a": 1}], [1, "x"], [None]])
def test_non_string_revocations_are_refused_not_raised(authorizer, revoked):
    document = _resign({**_revocations(1, []), "revoked": revoked}, ROOT_SEED)
    with pytest.raises(ca.CentralAccessError, match="sorted delegation digests"):
        authorizer.install_revocations(document)


def test_only_post_is_served_even_when_the_request_signs_another_method(authorizer):
    header = _header(method="GET")
    with pytest.raises(ca.CentralAccessError, match="target does not match"):
        authorizer.preauthorize(header, method="GET", path=PATH, now=NOW)


def test_a_request_expires_at_exactly_its_expiry(authorizer):
    expires_at = NOW + timedelta(seconds=60)
    with pytest.raises(ca.CentralAccessError, match="request has expired"):
        authorizer.preauthorize(_header(), method="POST", path=PATH, now=expires_at)
    assert authorizer.preauthorize(
        _header(), method="POST", path=PATH, now=expires_at - timedelta(seconds=1)
    )


def test_a_delegation_expires_at_exactly_its_expiry():
    delegation = _delegation()
    expires_at = NOW + timedelta(hours=1)
    with pytest.raises(ca.CentralAccessError, match="delegation has expired"):
        ca.verify_delegation(delegation, ROOT_KEYS, network=NETWORK, netuid=NETUID, now=expires_at)
    assert ca.verify_delegation(
        delegation,
        ROOT_KEYS,
        network=NETWORK,
        netuid=NETUID,
        now=expires_at - timedelta(seconds=1),
    )


@pytest.mark.parametrize("delay", [60, 61])
def test_finalize_refuses_a_request_that_expired_while_its_body_was_read(authorizer, delay):
    request = authorizer.preauthorize(_header(), method="POST", path=PATH, now=NOW)
    with pytest.raises(ca.CentralAccessError, match="request has expired"):
        authorizer.finalize(request, body=BODY, now=NOW + timedelta(seconds=delay))


def test_finalize_refuses_a_delegation_superseded_while_its_body_was_read(authorizer):
    stale = authorizer.preauthorize(
        _header(_delegation(sequence=5)), method="POST", path=PATH, now=NOW
    )
    _accept(authorizer, _header(_delegation(sequence=7), nonce=b"m" * 32))
    with pytest.raises(ca.CentralAccessError, match="older than one already accepted"):
        authorizer.finalize(stale, body=BODY, now=NOW)


def test_a_revocation_list_is_capped(authorizer):
    digests = sorted("sha256:" + hashlib.sha256(str(i).encode()).hexdigest() for i in range(4097))
    with pytest.raises(ca.CentralAccessError, match="sorted delegation digests"):
        authorizer.install_revocations(_revocations(1, digests))
    authorizer.install_revocations(_revocations(1, digests[: ca.MAX_REVOKED_DELEGATIONS]))


def test_root_key_ids_must_be_canonical(tmp_path):
    path = tmp_path / "central-root-keys.json"
    path.write_bytes(
        canonical_json({"Cathedral Root": base64.b64encode(_public(ROOT_SEED)).decode("ascii")})
    )
    pin = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ca.CentralAccessError, match="root key id is not canonical"):
        ca.load_central_root_keys(str(path), pinned_digest=pin)


def test_central_replay_state_has_its_own_smaller_cap(tmp_path):
    state = ca.open_central_access_state(str(tmp_path / "central.sqlite"))
    assert state.max_replay_entries == ca.MAX_CENTRAL_REPLAY_ENTRIES
    with pytest.raises(ca.CentralAccessError, match="central replay cap"):
        ca.CentralAccessAuthorizer(
            ROOT_KEYS,
            worker_hotkey=WORKER,
            network=NETWORK,
            netuid=NETUID,
            channel_binding=BINDING,
            state=ca.CentralAccessState(
                str(tmp_path / "validator-sized.sqlite"), max_replay_entries=4096
            ),
        )
    with pytest.raises(ca.CentralAccessError, match="durable replay state"):
        ca.CentralAccessAuthorizer(
            ROOT_KEYS,
            worker_hotkey=WORKER,
            network=NETWORK,
            netuid=NETUID,
            channel_binding=BINDING,
            state=ValidatorAccessState(str(tmp_path / "validator-state.sqlite")),
        )


def _authorizer_on(path: Path) -> ca.CentralAccessAuthorizer:
    return ca.CentralAccessAuthorizer(
        ROOT_KEYS,
        worker_hotkey=WORKER,
        network=NETWORK,
        netuid=NETUID,
        channel_binding=BINDING,
        state=ca.open_central_access_state(str(path)),
    )


def test_a_restarted_authorizer_still_refuses_an_older_delegation(tmp_path):
    path = tmp_path / "central-access.sqlite"
    first = _authorizer_on(path)
    _accept(first, _header(_delegation(sequence=7)))
    first.state.close()

    restarted = _authorizer_on(path)
    with pytest.raises(ca.CentralAccessError, match="older than one already accepted"):
        restarted.preauthorize(
            _header(_delegation(sequence=6), nonce=b"m" * 32), method="POST", path=PATH, now=NOW
        )
    _accept(restarted, _header(_delegation(sequence=7), nonce=b"m" * 32))
    assert restarted.state.delegation_high_water() == 7


def test_a_newer_delegation_is_refused_when_its_high_water_cannot_be_stored(authorizer):
    authorizer.state.raise_delegation_high_water = lambda _sequence: None
    with pytest.raises(ca.CentralAccessError, match="could not be recorded"):
        authorizer.preauthorize(_header(), method="POST", path=PATH, now=NOW)


def test_an_unreadable_high_water_refuses_to_start(tmp_path):
    state = ca.open_central_access_state(str(tmp_path / "central-access.sqlite"))
    state.close()
    with pytest.raises(ca.CentralAccessError, match="high-water is unreadable"):
        ca.CentralAccessAuthorizer(
            ROOT_KEYS,
            worker_hotkey=WORKER,
            network=NETWORK,
            netuid=NETUID,
            channel_binding=BINDING,
            state=state,
        )


def test_the_stored_high_water_only_rises(tmp_path):
    state = ca.open_central_access_state(str(tmp_path / "central-access.sqlite"))
    assert state.delegation_high_water() == 0
    assert state.raise_delegation_high_water(9) == 9
    assert state.raise_delegation_high_water(4) == 9
    assert state.delegation_high_water() == 9


def test_workers_sharing_one_state_file_honour_each_others_high_water(tmp_path):
    path = tmp_path / "central-access.sqlite"
    first = _authorizer_on(path)
    second = _authorizer_on(path)
    _accept(second, _header(_delegation(sequence=5)))
    _accept(first, _header(_delegation(sequence=7), nonce=b"m" * 32))
    assert second.state.delegation_high_water() == 7

    with pytest.raises(ca.CentralAccessError, match="older than one already accepted"):
        second.preauthorize(
            _header(_delegation(sequence=5), nonce=b"k" * 32), method="POST", path=PATH, now=NOW
        )
    _accept(second, _header(_delegation(sequence=7), nonce=b"q" * 32))


def test_finalize_honours_a_high_water_another_worker_raised_mid_request(tmp_path):
    path = tmp_path / "central-access.sqlite"
    first = _authorizer_on(path)
    second = _authorizer_on(path)
    pending = second.preauthorize(
        _header(_delegation(sequence=5)), method="POST", path=PATH, now=NOW
    )
    _accept(first, _header(_delegation(sequence=7), nonce=b"m" * 32))
    with pytest.raises(ca.CentralAccessError, match="older than one already accepted"):
        second.finalize(pending, body=BODY, now=NOW)


def test_finalize_refuses_when_the_high_water_cannot_be_read(authorizer):
    request = authorizer.preauthorize(_header(), method="POST", path=PATH, now=NOW)
    authorizer.state.delegation_high_water = lambda: None
    with pytest.raises(ca.CentralAccessError, match="high-water is unreadable"):
        authorizer.finalize(request, body=BODY, now=NOW)


def test_a_scoped_request_needs_its_scope_and_signs_its_method(authorizer):
    # The TEE box maps each request to a scope; the delegation must grant it.
    target = "/v1/sandboxes/sbx-" + "0" * 24 + "/files?path=/a"
    delegation = _delegation(routes=["tee-box:files"])
    header = _header(delegation, method="GET", path=target, body=b"")
    request = authorizer.preauthorize(
        header, method="GET", path=target, now=NOW, scope="tee-box:files"
    )
    assert authorizer.finalize(request, body=b"", now=NOW).startswith("central:")
    header = _header(delegation, method="GET", path=target, body=b"", nonce=b"m" * 32)
    with pytest.raises(ca.CentralAccessError, match="does not grant this route"):
        authorizer.preauthorize(header, method="GET", path=target, now=NOW, scope="tee-box:exec")
    with pytest.raises(ca.CentralAccessError, match="target does not match"):
        authorizer.preauthorize(
            header, method="DELETE", path=target, now=NOW, scope="tee-box:files"
        )
    with pytest.raises(ca.CentralAccessError, match="scope is unknown"):
        authorizer.preauthorize(header, method="GET", path=target, now=NOW, scope=PATH)
    # A scope is never a path route, and a path route is never a scope.
    with pytest.raises(ca.CentralAccessError, match="does not grant this route"):
        _accept(authorizer, _header(nonce=b"k" * 32, delegation=delegation))
    header = _header(nonce=b"j" * 32, path="tee-box:files", delegation=delegation)
    with pytest.raises(ca.CentralAccessError, match="target does not match"):
        _accept(authorizer, header, path="tee-box:files")
