from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import sqlite3
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sr25519
from bittensor_wallet import Keypair
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

import cathedral.validator_access as access_module
import cathedral.worker as worker_module
from cathedral.channel import tls_spki_binding
from cathedral.common import ChannelBinding, ChannelBindingType, Evidence, EvidenceKind
from cathedral.lanes.sat import _canonical_instance, _compute_challenge_id
from cathedral.lanes.sat_types import SatInstance, SatWorkItem
from cathedral.policy_registry import canonical_json
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.validator_access import (
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
    VALIDATOR_REQUEST_HEADER,
    WORKER_FLEET_SCHEMA,
    SignedValidatorSnapshotProvider,
    ValidatorAccessState,
    ValidatorAccessError,
    ValidatorRequestAuthorizer,
    ValidatorRequestLimiter,
    build_validator_request_header,
    fleet_response,
    load_sr25519_verifier,
    sign_validator_access_snapshot,
    singleton_fleet,
    validate_fleet_document,
    verify_validator_access_snapshot,
)
from cathedral.worker import WorkerServer


NOW = datetime(2026, 8, 29, 5, 0, 0, tzinfo=UTC)
SNAPSHOT_SEED = b"s" * 32
NETWORK = "finney"
NETUID = 94
FROZEN_WALLET_SIGNATURE = (
    "0DDT6KLO2IU3A4/D7kiWOdP16JSmXtHLkcFMSI/J1SL0qCLNS+zOo50oGylZTgQiECQ5vG4HxL8oCxyjs/4+iw=="
)


def _base58(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + (encoded or "1")


def _hotkey(public_key: bytes) -> str:
    payload = b"\x2a" + public_key
    checksum = hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()[:2]
    return _base58(payload + checksum)


VALIDATOR_PAIR = sr25519.pair_from_seed(b"v" * 32)
OTHER_VALIDATOR_PAIR = sr25519.pair_from_seed(b"o" * 32)
WORKER_PAIR = sr25519.pair_from_seed(b"w" * 32)
VALIDATOR_HOTKEY = _hotkey(VALIDATOR_PAIR[0])
OTHER_VALIDATOR_HOTKEY = _hotkey(OTHER_VALIDATOR_PAIR[0])
WORKER_HOTKEY = _hotkey(WORKER_PAIR[0])


def _snapshot_document(
    *,
    validator_hotkey: str = VALIDATOR_HOTKEY,
    uid: int = 30,
    stake_rao: int = 2_000,
    minimum_stake_rao: int = 1_000,
    block: int = 8_948_557,
    block_hash: str = "0x" + "a" * 64,
    generated_at: datetime = NOW,
    expires_at: datetime | None = None,
    netuid: int = NETUID,
) -> dict[str, object]:
    expires_at = expires_at or generated_at + timedelta(minutes=10)
    return {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": NETWORK,
        "netuid": netuid,
        "block": block,
        "block_hash": block_hash,
        "block_is_finalized": True,
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minimum_stake_rao": minimum_stake_rao,
        "validators": [
            {
                "hotkey": validator_hotkey,
                "uid": uid,
                "validator_permit": True,
                "stake_rao": stake_rao,
            }
        ],
        "signing_key_id": "cathedral-validator-access",
    }


def _signed_snapshot(**kwargs: object) -> bytes:
    return canonical_json(
        sign_validator_access_snapshot(_snapshot_document(**kwargs), SNAPSHOT_SEED)
    )


def _snapshot(**kwargs: object):
    verify_at = kwargs.pop("verify_at", NOW)
    assert isinstance(verify_at, datetime)
    expected_netuid = kwargs.pop("expected_netuid", NETUID)
    assert isinstance(expected_netuid, int)
    signing_public = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return verify_validator_access_snapshot(
        _signed_snapshot(**kwargs),
        {"cathedral-validator-access": signing_public},
        network=NETWORK,
        netuid=expected_netuid,
        required_minimum_stake_rao=1_000,
        now=verify_at,
    )


def _two_validator_snapshot(*, generated_at: datetime, expires_at: datetime):
    document = _snapshot_document(
        generated_at=generated_at,
        expires_at=expires_at,
    )
    document["validators"] = [
        {
            "hotkey": VALIDATOR_HOTKEY,
            "uid": 30,
            "validator_permit": True,
            "stake_rao": 2_000,
        },
        {
            "hotkey": OTHER_VALIDATOR_HOTKEY,
            "uid": 31,
            "validator_permit": True,
            "stake_rao": 2_000,
        },
    ]
    signing_public = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return verify_validator_access_snapshot(
        canonical_json(sign_validator_access_snapshot(document, SNAPSHOT_SEED)),
        {"cathedral-validator-access": signing_public},
        network=NETWORK,
        netuid=NETUID,
        required_minimum_stake_rao=1_000,
        now=generated_at,
    )


def _binding(byte: int = 1) -> ChannelBinding:
    return ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, bytes((byte,)) * 32)


def _header(
    *,
    body: bytes = b"{}",
    path: str = "/v1/fleet",
    binding: ChannelBinding | None = None,
    nonce: bytes = b"n" * 32,
    validator_hotkey: str = VALIDATOR_HOTKEY,
    pair=VALIDATOR_PAIR,
    netuid: int = NETUID,
) -> str:
    return build_validator_request_header(
        validator_hotkey=validator_hotkey,
        worker_hotkey=WORKER_HOTKEY,
        network=NETWORK,
        netuid=netuid,
        method="POST",
        path=path,
        body=body,
        channel_binding=binding or _binding(),
        nonce=nonce,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=60),
        signer=lambda message: sr25519.sign(pair, message),
    )


def test_snapshot_verifies_finalized_permit_and_exact_stake_gate():
    snapshot = _snapshot()

    assert snapshot.block == 8_948_557
    assert snapshot.qualifies(VALIDATOR_HOTKEY, at=NOW)
    assert snapshot.validators[VALIDATOR_HOTKEY].uid == 30


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"validator_permit": False}, "permit"),
        ({"stake_rao": 999}, "stake"),
    ],
)
def test_snapshot_rejects_unqualified_rows(change, match):
    document = _snapshot_document()
    row = document["validators"][0]
    assert isinstance(row, dict)
    row.update(change)
    encoded = canonical_json(sign_validator_access_snapshot(document, SNAPSHOT_SEED))
    key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )

    with pytest.raises(ValidatorAccessError, match=match):
        verify_validator_access_snapshot(
            encoded,
            {"cathedral-validator-access": key},
            network=NETWORK,
            netuid=NETUID,
            required_minimum_stake_rao=1_000,
            now=NOW,
        )


@pytest.mark.parametrize("boolean_netuid", [True, False])
def test_snapshot_refuses_boolean_netuid_equal_to_expected_integer(boolean_netuid: bool):
    expected_netuid = int(boolean_netuid)

    with pytest.raises(ValidatorAccessError, match="snapshot netuid must be an integer"):
        _snapshot(netuid=boolean_netuid, expected_netuid=expected_netuid)

    snapshot = _snapshot(netuid=expected_netuid, expected_netuid=expected_netuid)
    assert type(snapshot.netuid) is int
    assert snapshot.netuid == expected_netuid


def test_snapshot_stake_floor_comes_from_worker_configuration():
    key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )

    with pytest.raises(ValidatorAccessError, match="does not match worker policy"):
        verify_validator_access_snapshot(
            _signed_snapshot(minimum_stake_rao=1_000),
            {"cathedral-validator-access": key},
            network=NETWORK,
            netuid=NETUID,
            required_minimum_stake_rao=2_000,
            now=NOW,
        )

    with pytest.raises(ValidatorAccessError, match="maximum age"):
        verify_validator_access_snapshot(
            _signed_snapshot(),
            {"cathedral-validator-access": key},
            network=NETWORK,
            netuid=NETUID,
            required_minimum_stake_rao=1_000,
            max_age_seconds=3_601,
            now=NOW,
        )

    with pytest.raises(ValidatorAccessError, match="validity window is too long"):
        verify_validator_access_snapshot(
            _signed_snapshot(expires_at=NOW + timedelta(seconds=3_601)),
            {"cathedral-validator-access": key},
            network=NETWORK,
            netuid=NETUID,
            required_minimum_stake_rao=1_000,
            now=NOW,
        )


def test_snapshot_rejects_duplicate_uid_and_hotkey_rows():
    key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    for duplicate_field in ("uid", "hotkey"):
        document = _snapshot_document()
        first = document["validators"][0]
        assert isinstance(first, dict)
        second = dict(first)
        second["hotkey"] = OTHER_VALIDATOR_HOTKEY
        second["uid"] = 31
        second[duplicate_field] = first[duplicate_field]
        document["validators"] = sorted([first, second], key=lambda row: str(row["hotkey"]))
        encoded = canonical_json(sign_validator_access_snapshot(document, SNAPSHOT_SEED))

        with pytest.raises(ValidatorAccessError, match=f"duplicate validator {duplicate_field}"):
            verify_validator_access_snapshot(
                encoded,
                {"cathedral-validator-access": key},
                network=NETWORK,
                netuid=NETUID,
                required_minimum_stake_rao=1_000,
                now=NOW,
            )


def test_bittensor_wallet_signature_matches_direct_worker_verifier():
    pair = Keypair.create_from_seed("0x" + "76" * 32)
    message = canonical_json(
        {
            "schema": "cathedral_validator_request_v1",
            "validator_hotkey": pair.ss58_address,
            "fixture": "bittensor-wallet-to-direct-sr25519-v1",
        }
    )
    runtime_signature = pair.sign(message)
    frozen_signature = base64.b64decode(FROZEN_WALLET_SIGNATURE)

    assert pair.ss58_address == VALIDATOR_HOTKEY
    assert (
        pair.public_key.hex() == "7c9d4a91777f0af25a6524d91365714ad0b1352bcaa7d6829bab4ae0b0b48a5b"
    )
    assert len(runtime_signature) == 64
    assert load_sr25519_verifier()(frozen_signature, message, pair.public_key)
    assert load_sr25519_verifier()(runtime_signature, message, pair.public_key)
    assert not load_sr25519_verifier()(frozen_signature, message + b"x", pair.public_key)


def test_signed_request_binds_identity_body_target_channel_and_replay(tmp_path: Path):
    state = ValidatorAccessState(str(tmp_path / "validator-access.sqlite"))
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=_binding(),
        state=state,
        signature_verifier=load_sr25519_verifier(),
    )
    header = _header()

    preauthorized = authorizer.preauthorize(
        header,
        method="POST",
        path="/v1/fleet",
        now=NOW,
    )
    assert preauthorized is not None
    assert preauthorized.validator_hotkey == VALIDATOR_HOTKEY
    assert authorizer.finalize(preauthorized, body=b'{"changed":true}', now=NOW) is None
    assert authorizer.finalize(preauthorized, body=b"{}", now=NOW) == VALIDATOR_HOTKEY
    assert not authorizer.authorize(header, method="POST", path="/v1/fleet", body=b"{}", now=NOW)
    assert not authorizer.authorize(
        _header(nonce=b"2" * 32),
        method="POST",
        path="/v1/fleet",
        body=b'{"changed":true}',
        now=NOW,
    )
    assert not authorizer.authorize(
        _header(nonce=b"3" * 32, binding=_binding(2)),
        method="POST",
        path="/v1/fleet",
        body=b"{}",
        now=NOW,
    )
    assert not authorizer.authorize(
        _header(nonce=b"4" * 32),
        method="POST",
        path="/v1/evidence",
        body=b"{}",
        now=NOW,
    )


def test_unqualified_validator_signature_is_rejected(tmp_path: Path):
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=_binding(),
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )
    assert not authorizer.authorize(
        _header(
            validator_hotkey=OTHER_VALIDATOR_HOTKEY,
            pair=OTHER_VALIDATOR_PAIR,
        ),
        method="POST",
        path="/v1/fleet",
        body=b"{}",
        now=NOW,
    )


@pytest.mark.parametrize("boolean_netuid", [True, False])
def test_signed_request_refuses_boolean_netuid_equal_to_worker_netuid(
    tmp_path: Path, boolean_netuid: bool
):
    worker_netuid = int(boolean_netuid)
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(netuid=worker_netuid, expected_netuid=worker_netuid),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=_binding(),
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )
    assert authorizer.snapshot_provider.netuid == boolean_netuid
    boolean_header = _header(netuid=boolean_netuid)

    assert authorizer.preauthorize(boolean_header, method="POST", path="/v1/fleet", now=NOW) is None
    assert not authorizer.authorize(
        boolean_header,
        method="POST",
        path="/v1/fleet",
        body=b"{}",
        now=NOW,
    )
    # The refusal happens before replay state, so the same nonce with an
    # integer netuid is the only change needed for the request to pass.
    assert authorizer.authorize(
        _header(netuid=worker_netuid),
        method="POST",
        path="/v1/fleet",
        body=b"{}",
        now=NOW,
    )


def test_replay_rejection_survives_authorizer_restart(tmp_path: Path):
    state_path = str(tmp_path / "validator-access.sqlite")
    first = ValidatorRequestAuthorizer(
        _snapshot(),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=_binding(),
        state=ValidatorAccessState(state_path),
        signature_verifier=load_sr25519_verifier(),
    )
    header = _header()
    assert first.authorize(header, method="POST", path="/v1/fleet", body=b"{}", now=NOW)

    restarted = ValidatorRequestAuthorizer(
        _snapshot(),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=_binding(),
        state=ValidatorAccessState(state_path),
        signature_verifier=load_sr25519_verifier(),
    )
    assert not restarted.authorize(header, method="POST", path="/v1/fleet", body=b"{}", now=NOW)


def test_replay_rows_never_become_reusable_after_wall_clock_rollback(tmp_path: Path):
    state = ValidatorAccessState(str(tmp_path / "validator-access.sqlite"))
    first_expiry = NOW + timedelta(minutes=1)
    assert state.check_and_record_request(
        VALIDATOR_HOTKEY,
        "11" * 32,
        now=NOW,
        expires_at=first_expiry,
    )

    advanced = NOW + timedelta(minutes=1, seconds=1)
    assert state.check_and_record_request(
        VALIDATOR_HOTKEY,
        "22" * 32,
        now=advanced,
        expires_at=advanced + timedelta(minutes=1),
    )

    # The first row was pruned after its expiry. A backward wall-clock step
    # must still fail closed instead of admitting the captured first request.
    rolled_back = NOW + timedelta(seconds=30)
    assert not state.check_and_record_request(
        VALIDATOR_HOTKEY,
        "11" * 32,
        now=rolled_back,
        expires_at=first_expiry,
    )


def test_verified_validator_limiter_bounds_concurrency_rate_and_key_count():
    current = [10.0]
    limiter = ValidatorRequestLimiter(
        max_concurrent=1,
        requests_per_window=2,
        window_seconds=10,
        max_keys=2,
        clock=lambda: current[0],
    )

    first = limiter.acquire(VALIDATOR_HOTKEY)
    assert first is not None
    assert limiter.active_count(VALIDATOR_HOTKEY) == 1
    assert limiter.acquire(VALIDATOR_HOTKEY) is None
    other = limiter.acquire(OTHER_VALIDATOR_HOTKEY)
    assert other is not None
    other.release()
    first.release()
    assert limiter.active_count(VALIDATOR_HOTKEY) == 0

    second = limiter.acquire(VALIDATOR_HOTKEY)
    assert second is not None
    second.release()
    assert limiter.acquire(VALIDATOR_HOTKEY) is None

    current[0] = 20.0
    after_window = limiter.acquire(VALIDATOR_HOTKEY)
    assert after_window is not None
    after_window.release()


def test_snapshot_provider_rotates_without_restart_and_retains_last_good(tmp_path: Path):
    path = tmp_path / "validator-access.json"
    path.write_bytes(_signed_snapshot())
    path.chmod(0o644)
    key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    state = ValidatorAccessState(str(tmp_path / "validator-access.sqlite"))
    provider = SignedValidatorSnapshotProvider(
        str(path),
        {"cathedral-validator-access": key},
        network=NETWORK,
        netuid=NETUID,
        minimum_stake_rao=1_000,
        state=state,
    )

    first = provider.load(now=NOW)
    assert first is not None and VALIDATOR_HOTKEY in first.validators

    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(
        _signed_snapshot(
            validator_hotkey=OTHER_VALIDATOR_HOTKEY,
            uid=31,
            generated_at=NOW + timedelta(seconds=10),
            expires_at=NOW + timedelta(minutes=10),
            block=8_948_558,
            block_hash="0x" + "b" * 64,
        )
    )
    replacement.chmod(0o644)
    os.replace(replacement, path)
    second = provider.load(now=NOW + timedelta(seconds=10))
    assert second is not None and OTHER_VALIDATOR_HOTKEY in second.validators

    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    bad.chmod(0o644)
    os.replace(bad, path)
    assert provider.load(now=NOW + timedelta(seconds=20)) is second
    path.unlink()
    assert provider.load(now=NOW + timedelta(seconds=30)) is second
    assert provider.load(now=NOW + timedelta(minutes=11)) is None


def test_snapshot_provider_does_not_reverify_unchanged_file(tmp_path: Path, monkeypatch):
    path = tmp_path / "validator-access.json"
    path.write_bytes(_signed_snapshot())
    path.chmod(0o644)
    key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    calls = 0
    real_verify = access_module.verify_validator_access_snapshot

    def counting_verify(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(access_module, "verify_validator_access_snapshot", counting_verify)
    provider = SignedValidatorSnapshotProvider(
        str(path),
        {"cathedral-validator-access": key},
        network=NETWORK,
        netuid=NETUID,
        minimum_stake_rao=1_000,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
    )

    assert provider.load(now=NOW) is not None
    assert provider.load(now=NOW + timedelta(seconds=1)) is not None
    assert calls == 1


def test_snapshot_provider_rejects_durable_block_rollback(tmp_path: Path):
    path = tmp_path / "validator-access.json"
    path.write_bytes(_signed_snapshot())
    path.chmod(0o644)
    key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    state_path = str(tmp_path / "validator-access.sqlite")
    provider = SignedValidatorSnapshotProvider(
        str(path),
        {"cathedral-validator-access": key},
        network=NETWORK,
        netuid=NETUID,
        minimum_stake_rao=1_000,
        state=ValidatorAccessState(state_path),
    )
    accepted = provider.load(now=NOW)
    assert accepted is not None

    replacement = tmp_path / "rollback.json"
    replacement.write_bytes(
        _signed_snapshot(
            block=8_948_556,
            block_hash="0x" + "c" * 64,
            generated_at=NOW + timedelta(seconds=10),
        )
    )
    replacement.chmod(0o644)
    os.replace(replacement, path)
    assert provider.load(now=NOW + timedelta(seconds=10)) is accepted

    restarted = SignedValidatorSnapshotProvider(
        str(path),
        {"cathedral-validator-access": key},
        network=NETWORK,
        netuid=NETUID,
        minimum_stake_rao=1_000,
        state=ValidatorAccessState(state_path),
    )
    assert restarted.load(now=NOW + timedelta(seconds=10)) is None


def test_snapshot_state_accepts_only_semantically_identical_same_height_resign(
    tmp_path: Path,
):
    state = ValidatorAccessState(str(tmp_path / "validator-access.sqlite"))
    first = _snapshot()
    resigned = _snapshot(
        generated_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=11),
        verify_at=NOW + timedelta(minutes=1),
    )
    changed_authorization = _snapshot(
        stake_rao=3_000,
        generated_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=12),
        verify_at=NOW + timedelta(minutes=2),
    )
    changed_hash = _snapshot(
        block_hash="0x" + "b" * 64,
        generated_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=12),
        verify_at=NOW + timedelta(minutes=2),
    )

    assert first.digest != resigned.digest
    assert first.authorization_digest == resigned.authorization_digest
    assert changed_authorization.authorization_digest != first.authorization_digest
    assert state.accept_snapshot(first)
    assert state.accept_snapshot(resigned)
    assert not state.accept_snapshot(changed_authorization)
    assert not state.accept_snapshot(changed_hash)


def test_snapshot_state_migrates_legacy_row_without_weakening_same_height_gate(
    tmp_path: Path,
):
    path = tmp_path / "validator-access.sqlite"
    first = _snapshot()
    resigned = _snapshot(
        generated_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=11),
        verify_at=NOW + timedelta(minutes=1),
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE validator_snapshot_high_water (
                network TEXT NOT NULL,
                netuid INTEGER NOT NULL,
                block INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                snapshot_digest TEXT NOT NULL,
                PRIMARY KEY(network, netuid)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO validator_snapshot_high_water(
                network, netuid, block, block_hash, snapshot_digest
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (first.network, first.netuid, first.block, first.block_hash, first.digest),
        )
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)

    state = ValidatorAccessState(str(path))
    assert not state.accept_snapshot(resigned)
    assert state.accept_snapshot(first)
    assert state.accept_snapshot(resigned)


def test_fleet_manifest_keeps_axon_as_exact_singleton_then_adds_candidates():
    primary = "https://8.8.8.8:8081"
    assert singleton_fleet(public_endpoint=primary) == (primary,)

    endpoints = validate_fleet_document(
        {
            "schema": WORKER_FLEET_SCHEMA,
            "worker_hotkey": WORKER_HOTKEY,
            "endpoints": ["https://1.1.1.1:8081", primary],
        },
        worker_hotkey=WORKER_HOTKEY,
        public_endpoint=primary,
    )
    assert endpoints == (primary, "https://1.1.1.1:8081")
    assert fleet_response(WORKER_HOTKEY, endpoints)["endpoints"] == list(endpoints)

    with pytest.raises(ValidatorAccessError, match="port"):
        singleton_fleet(public_endpoint="https://8.8.8.8:0")


@pytest.mark.parametrize(
    "host",
    [
        "::ffff:8.8.8.8",
        "2002:0808:0808::",
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b::808:808",
        "64:ff9b:1::808:808",
        "::8.8.8.8",
    ],
)
def test_fleet_endpoint_rejects_every_ipv6_transition_form(
    host: str,
    monkeypatch,
):
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _address: True)

    with pytest.raises(ValidatorAccessError, match="globally routable"):
        singleton_fleet(public_endpoint=f"https://[{host}]:8081")


def test_remote_fleet_parser_requires_attested_chain_axon_first(monkeypatch):
    remote = RemoteMiner(
        "https://8.8.8.8:8081",
        WORKER_HOTKEY,
        validator_hotkey=VALIDATOR_HOTKEY,
        validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
    )
    remote._trusted_binding = _binding()  # noqa: SLF001 - parser boundary fixture
    monkeypatch.setattr(
        remote,
        "_post_tls",
        lambda *args, **kwargs: (
            {
                "schema": WORKER_FLEET_SCHEMA,
                "worker_hotkey": WORKER_HOTKEY,
                "endpoints": ["https://1.1.1.1:8081", "https://8.8.8.8:8081"],
            },
            _binding(),
        ),
    )

    with pytest.raises(RemoteError, match="chain axon first"):
        remote.fetch_fleet()


def _certificate_pair_bytes() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


def _tls_contexts(tmp_path: Path):
    certificate_pem, private_key_pem = _certificate_pair_bytes()
    certificate_path = tmp_path / "worker.crt"
    private_key_path = tmp_path / "worker.key"
    certificate_path.write_bytes(certificate_pem)
    private_key_path.write_bytes(private_key_pem)
    private_key_path.chmod(0o600)
    certificate_der = ssl.PEM_cert_to_DER_cert(certificate_pem.decode("ascii"))
    binding = tls_spki_binding(certificate_der)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(certificate_path, private_key_path)
    client = ssl.create_default_context(cafile=str(certificate_path))
    return server, client, binding


def test_signed_remote_discovers_fleet_and_runs_validation_work(tmp_path: Path, monkeypatch):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _address: True)
    current = datetime.now(UTC).replace(microsecond=0)
    state = ValidatorAccessState(str(tmp_path / "validator-access.sqlite"))
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(
            generated_at=current,
            expires_at=current + timedelta(minutes=10),
            verify_at=current,
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=state,
        signature_verifier=load_sr25519_verifier(),
    )

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    endpoints = (f"https://127.0.0.1:{port}", "https://1.1.1.1:8081")
    with WorkerServer(
        port=port,
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=endpoints,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
            validator_hotkey=VALIDATOR_HOTKEY,
            validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        remote.confirm_channel_binding(evidence)
        remote.confirm_signed_validator_access_required(evidence)
        assert remote.fetch_fleet() == endpoints
        seed = 7
        instance = _canonical_instance(seed)
        certificate = remote.do_sat_work(
            SatWorkItem(instance, seed, _compute_challenge_id(instance, seed))
        )
        assert certificate.assigned_hotkey == WORKER_HOTKEY

        unsigned = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
        )
        with pytest.raises(RemoteError, match="HTTP 401"):
            unsigned.fetch_evidence(os.urandom(32))
        unsigned._trusted_binding = binding  # noqa: SLF001 - negative auth boundary
        with pytest.raises(RemoteError, match="HTTP 401"):
            unsigned.do_sat_work(SatWorkItem(instance, seed, _compute_challenge_id(instance, seed)))
        with pytest.raises(RemoteError, match="HTTP 401"):
            unsigned.supports_customer_sat()


def test_signed_access_negative_control_rejects_an_unsigned_development_worker(
    tmp_path: Path,
):
    server_context, client_context, binding = _tls_contexts(tmp_path)

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.SEV_SNP,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
            validator_hotkey=VALIDATOR_HOTKEY,
            validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        remote.confirm_channel_binding(evidence)

        with pytest.raises(RemoteError, match="accepted an invalid validator signature"):
            remote.confirm_signed_validator_access_required(evidence)


def test_signed_client_without_bearer_cannot_bootstrap_bearer_only_worker(
    tmp_path: Path,
):
    server_context, client_context, binding = _tls_contexts(tmp_path)

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.SEV_SNP,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token="legacy-secret",
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
            validator_hotkey=VALIDATOR_HOTKEY,
            validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )
        with pytest.raises(RemoteError, match="HTTP 401"):
            remote.fetch_evidence(os.urandom(32))


def test_signed_access_negative_control_rejects_header_presence_without_verification(
    monkeypatch,
):
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"t" * 32)
    evidence = Evidence(
        kind=EvidenceKind.SEV_SNP,
        quote=b"quote",
        nonce=b"n" * 32,
        miner_hotkey=WORKER_HOTKEY,
        report_data_version=2,
        channel_binding=binding,
    )
    remote = RemoteMiner(
        "https://1.1.1.1:8081",
        WORKER_HOTKEY,
        validator_hotkey=VALIDATOR_HOTKEY,
        validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
    )
    remote._trusted_binding = binding  # noqa: SLF001 - isolated negative control

    def accepts_any_validator_header(
        _path,
        _payload_factory,
        *,
        expected_binding,
        include_auth,
        include_validator_auth=False,
        validator_signer_override=None,
        response_body_limit=None,
    ):
        assert expected_binding == binding
        assert response_body_limit == 1024
        _ = (include_auth, validator_signer_override)
        if include_validator_auth:
            return {"customer_sat": False}, binding
        raise RemoteError("worker returned HTTP 401", status_code=401)

    monkeypatch.setattr(remote, "_post_tls", accepts_any_validator_header)

    with pytest.raises(RemoteError, match="accepted an invalid validator signature"):
        remote.confirm_signed_validator_access_required(evidence)


def test_signed_remote_uses_singleton_only_for_legacy_fleet_404(tmp_path: Path):
    server_context, client_context, binding = _tls_contexts(tmp_path)

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
            validator_hotkey=VALIDATOR_HOTKEY,
            validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )
        evidence = remote.fetch_evidence(os.urandom(32))
        remote.confirm_channel_binding(evidence)

        assert remote.fetch_fleet() == (server.base_url,)


def test_signed_remote_never_treats_configured_worker_401_as_singleton(tmp_path: Path):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(
            generated_at=current,
            expires_at=current + timedelta(minutes=10),
            verify_at=current,
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        allow_public_bootstrap_evidence=True,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        public = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
        )
        evidence = public.fetch_evidence(os.urandom(32))
        public.confirm_channel_binding(evidence)
        qualified = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
            validator_hotkey=VALIDATOR_HOTKEY,
            validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )
        qualified_evidence = qualified.fetch_evidence(os.urandom(32))
        qualified.confirm_channel_binding(qualified_evidence)
        with pytest.raises(RemoteError, match="accepted an unsigned evidence request"):
            qualified.confirm_signed_validator_access_required(qualified_evidence)
        unqualified = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
            validator_hotkey=OTHER_VALIDATOR_HOTKEY,
            validator_signer=lambda message: sr25519.sign(OTHER_VALIDATOR_PAIR, message),
        )
        unqualified._trusted_binding = public._trusted_binding  # noqa: SLF001

        with pytest.raises(RemoteError, match="HTTP 401") as error:
            unqualified.fetch_fleet()
        assert error.value.status_code == 401


def test_public_legacy_audit_bridge_preserves_uid30_without_opening_customer_sat(
    tmp_path: Path,
):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(
            generated_at=current,
            expires_at=current + timedelta(minutes=10),
            verify_at=current,
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token="legacy-customer-token",
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        allow_noncanonical_sat=True,
        allow_public_legacy_audit=True,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        legacy = RemoteMiner(server.base_url, WORKER_HOTKEY, ssl_context=client_context)
        evidence = legacy.fetch_evidence(os.urandom(32))
        legacy.confirm_channel_binding(evidence)

        seed = 11
        canonical = _canonical_instance(seed)
        certificate = legacy.do_sat_work(
            SatWorkItem(canonical, seed, _compute_challenge_id(canonical, seed))
        )
        assert certificate.assigned_hotkey == WORKER_HOTKEY

        noncanonical = SatInstance(n_vars=1, clauses=[[1]])
        with pytest.raises(RemoteError, match="HTTP 401"):
            legacy.do_sat_work(
                SatWorkItem(
                    noncanonical,
                    seed,
                    _compute_challenge_id(noncanonical, seed),
                )
            )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        allow_public_legacy_audit=True,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        no_bearer = RemoteMiner(server.base_url, WORKER_HOTKEY, ssl_context=client_context)
        evidence = no_bearer.fetch_evidence(os.urandom(32))
        no_bearer.confirm_channel_binding(evidence)
        certificate = no_bearer.do_sat_work(
            SatWorkItem(canonical, seed, _compute_challenge_id(canonical, seed))
        )
        assert certificate.assigned_hotkey == WORKER_HOTKEY
        with pytest.raises(RemoteError, match="HTTP 401"):
            no_bearer.do_sat_work(
                SatWorkItem(
                    noncanonical,
                    seed,
                    _compute_challenge_id(noncanonical, seed),
                )
            )

    with pytest.raises(ValueError, match="customer SAT requires bearer"):
        WorkerServer(
            configured_hotkey=WORKER_HOTKEY,
            bearer_token=None,
            evidence_collector=evidence_collector,
            channel_binding=binding,
            tls_context=server_context,
            validator_authorizer=authorizer,
            fleet_endpoints=("https://8.8.8.8:8081",),
            allow_noncanonical_sat=True,
            allow_public_legacy_audit=True,
        )


def test_global_pool_still_bounds_signed_body_admission(
    tmp_path: Path,
):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _two_validator_snapshot(
            generated_at=current,
            expires_at=current + timedelta(minutes=10),
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )
    entered = threading.Event()
    release = threading.Event()
    first_errors: list[Exception] = []

    def evidence_collector(nonce, hotkey, **kwargs):
        entered.set()
        release.wait(5)
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        max_validator_challenge_concurrent=1,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def remote(hotkey, pair) -> RemoteMiner:
            return RemoteMiner(
                server.base_url,
                WORKER_HOTKEY,
                ssl_context=client_context,
                validator_hotkey=hotkey,
                validator_signer=lambda message: sr25519.sign(pair, message),
            )

        def first_request() -> None:
            try:
                remote(VALIDATOR_HOTKEY, VALIDATOR_PAIR).fetch_evidence(os.urandom(32))
            except Exception as exc:  # pragma: no cover - asserted below
                first_errors.append(exc)

        thread = threading.Thread(target=first_request)
        thread.start()
        assert entered.wait(2)
        with pytest.raises(RemoteError, match="HTTP 503"):
            remote(OTHER_VALIDATOR_HOTKEY, OTHER_VALIDATOR_PAIR).fetch_evidence(os.urandom(32))
        release.set()
        thread.join(2)
        assert not thread.is_alive()
        assert first_errors == []


def test_one_verified_validator_cannot_consume_every_signed_challenge_slot(
    tmp_path: Path,
):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    snapshot = _two_validator_snapshot(
        generated_at=current,
        expires_at=current + timedelta(minutes=10),
    )
    authorizer = ValidatorRequestAuthorizer(
        snapshot,
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )
    first_entered = threading.Event()
    release_first = threading.Event()
    collector_lock = threading.Lock()
    collector_calls = 0
    first_errors: list[Exception] = []

    def evidence_collector(nonce, hotkey, **kwargs):
        nonlocal collector_calls
        with collector_lock:
            collector_calls += 1
            call_number = collector_calls
        if call_number == 1:
            first_entered.set()
            release_first.wait(5)
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        max_challenge_concurrent=2,
        validator_max_concurrent=1,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def remote(hotkey, pair) -> RemoteMiner:
            return RemoteMiner(
                server.base_url,
                WORKER_HOTKEY,
                ssl_context=client_context,
                validator_hotkey=hotkey,
                validator_signer=lambda message: sr25519.sign(pair, message),
            )

        first_validator = remote(VALIDATOR_HOTKEY, VALIDATOR_PAIR)
        second_validator = remote(OTHER_VALIDATOR_HOTKEY, OTHER_VALIDATOR_PAIR)

        def hold_first_slot() -> None:
            try:
                first_validator.fetch_evidence(os.urandom(32))
            except Exception as exc:  # pragma: no cover - asserted below
                first_errors.append(exc)

        thread = threading.Thread(target=hold_first_slot)
        thread.start()
        assert first_entered.wait(2)

        with pytest.raises(RemoteError, match="HTTP 429"):
            remote(VALIDATOR_HOTKEY, VALIDATOR_PAIR).fetch_evidence(os.urandom(32))
        other_evidence = second_validator.fetch_evidence(os.urandom(32))
        assert other_evidence.miner_hotkey == WORKER_HOTKEY

        release_first.set()
        thread.join(2)
        assert not thread.is_alive()
        assert first_errors == []
        assert collector_calls == 2


def test_signed_body_stall_is_limited_before_global_challenge_admission(
    tmp_path: Path,
    monkeypatch,
):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _two_validator_snapshot(
            generated_at=current,
            expires_at=current + timedelta(minutes=10),
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )
    captured_limiters: list[ValidatorRequestLimiter] = []
    limiter_class = worker_module.ValidatorRequestLimiter

    def capture_limiter(**kwargs):
        limiter = limiter_class(**kwargs)
        captured_limiters.append(limiter)
        return limiter

    monkeypatch.setattr(worker_module, "ValidatorRequestLimiter", capture_limiter)

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        max_challenge_concurrent=2,
        validator_max_concurrent=1,
        timeout=5.0,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        assert len(captured_limiters) == 1
        limiter = captured_limiters[0]
        payload = canonical_json(
            {
                "assigned_hotkey": WORKER_HOTKEY,
                "channel_binding_digest_hex": binding.digest.hex(),
                "channel_binding_type": binding.binding_type.value,
                "nonce_hex": os.urandom(32).hex(),
                "report_data_version": 2,
            }
        )

        def open_stalled_request(hotkey, pair, nonce):
            header = build_validator_request_header(
                validator_hotkey=hotkey,
                worker_hotkey=WORKER_HOTKEY,
                network=NETWORK,
                netuid=NETUID,
                method="POST",
                path="/v1/evidence",
                body=payload,
                channel_binding=binding,
                nonce=nonce,
                issued_at=current,
                expires_at=current + timedelta(seconds=60),
                signer=lambda message: sr25519.sign(pair, message),
            )
            connection = client_context.wrap_socket(
                socket.create_connection((server.host, server.port), timeout=2.0),
                server_hostname="127.0.0.1",
            )
            connection.settimeout(2.0)
            request = (
                "POST /v1/evidence HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{server.port}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"{VALIDATOR_REQUEST_HEADER}: {header}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            connection.sendall(request)
            return connection

        first = open_stalled_request(VALIDATOR_HOTKEY, VALIDATOR_PAIR, b"a" * 32)
        try:
            deadline = time.monotonic() + 2.0
            while limiter.active_count(VALIDATOR_HOTKEY) != 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert limiter.active_count(VALIDATOR_HOTKEY) == 1

            refused = open_stalled_request(
                VALIDATOR_HOTKEY,
                VALIDATOR_PAIR,
                b"b" * 32,
            )
            try:
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = refused.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                assert b" 429 " in response.partition(b"\r\n")[0]
            finally:
                refused.close()

            other = RemoteMiner(
                server.base_url,
                WORKER_HOTKEY,
                ssl_context=client_context,
                validator_hotkey=OTHER_VALIDATOR_HOTKEY,
                validator_signer=lambda message: sr25519.sign(OTHER_VALIDATOR_PAIR, message),
            )
            evidence = other.fetch_evidence(os.urandom(32))
            assert evidence.miner_hotkey == WORKER_HOTKEY
        finally:
            first.close()


def test_fake_signed_header_on_unknown_path_never_occupies_validator_pool(
    tmp_path: Path,
):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(
            generated_at=current,
            expires_at=current + timedelta(minutes=10),
            verify_at=current,
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        max_challenge_concurrent=2,
        timeout=5.0,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stalled: list[ssl.SSLSocket] = []
        try:
            for _ in range(2):
                connection = client_context.wrap_socket(
                    socket.create_connection((server.host, server.port), timeout=2.0),
                    server_hostname="127.0.0.1",
                )
                connection.settimeout(2.0)
                connection.sendall(
                    (
                        "POST /not-a-worker-route HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{server.port}\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: 65536\r\n"
                        f"{VALIDATOR_REQUEST_HEADER}: not-a-signature\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                )
                stalled.append(connection)
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                assert b" 404 " in response.partition(b"\r\n")[0]

            validator = RemoteMiner(
                server.base_url,
                WORKER_HOTKEY,
                ssl_context=client_context,
                validator_hotkey=VALIDATOR_HOTKEY,
                validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
            )
            evidence = validator.fetch_evidence(os.urandom(32))
            assert evidence.miner_hotkey == WORKER_HOTKEY
        finally:
            for connection in stalled:
                connection.close()


def test_public_legacy_bridge_cannot_starve_signed_validator_control(
    tmp_path: Path,
    monkeypatch,
):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _address: True)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(
            generated_at=current,
            expires_at=current + timedelta(minutes=10),
            verify_at=current,
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )

    real_semaphore = threading.Semaphore
    created: list[object] = []

    class TrackingSemaphore:
        def __init__(self, value):
            self._inner = real_semaphore(value)
            self._active = 0
            self._condition = threading.Condition()
            created.append(self)

        def acquire(self, blocking=True):
            acquired = self._inner.acquire(blocking=blocking)
            if acquired:
                with self._condition:
                    self._active += 1
                    self._condition.notify_all()
            return acquired

        def release(self):
            with self._condition:
                self._active -= 1
                self._condition.notify_all()
            self._inner.release()

        def wait_for_active(self, expected, timeout):
            deadline = time.monotonic() + timeout
            with self._condition:
                while self._active != expected:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._condition.wait(remaining)
                return True

    monkeypatch.setattr(worker_module, "_Semaphore", TrackingSemaphore)

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    endpoints = (f"https://127.0.0.1:{port}",)
    with WorkerServer(
        port=port,
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=endpoints,
        allow_public_legacy_audit=True,
        max_challenge_concurrent=2,
        max_validator_challenge_concurrent=1,
        timeout=5.0,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        # Three semaphore classes; signed validator traffic has its own fair pool.
        assert len(created) == 3
        assert isinstance(server._validator_pool, worker_module._ValidatorPool)
        public_evidence_pool = created[1]

        validator = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
            validator_hotkey=VALIDATOR_HOTKEY,
            validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )
        evidence = validator.fetch_evidence(os.urandom(32))
        validator.confirm_channel_binding(evidence)

        stalled: list[ssl.SSLSocket] = []
        try:
            for _ in range(2):
                connection = client_context.wrap_socket(
                    socket.create_connection((server.host, server.port), timeout=2.0),
                    server_hostname="127.0.0.1",
                )
                connection.settimeout(2.0)
                connection.sendall(
                    (
                        "POST /v1/evidence HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{server.port}\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: 65536\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                )
                stalled.append(connection)
            assert public_evidence_pool.wait_for_active(2, 2.0)

            assert validator.fetch_fleet() == endpoints
        finally:
            for connection in stalled:
                connection.close()


THIRD_VALIDATOR_PAIR = sr25519.pair_from_seed(b"t" * 32)
THIRD_VALIDATOR_HOTKEY = _hotkey(THIRD_VALIDATOR_PAIR[0])


def _three_validator_snapshot(*, generated_at: datetime, expires_at: datetime):
    document = _snapshot_document(generated_at=generated_at, expires_at=expires_at)
    document["validators"] = [
        {"hotkey": hotkey, "uid": uid, "validator_permit": True, "stake_rao": 2_000}
        for hotkey, uid in (
            (VALIDATOR_HOTKEY, 30),
            (OTHER_VALIDATOR_HOTKEY, 31),
            (THIRD_VALIDATOR_HOTKEY, 32),
        )
    ]
    signing_public = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return verify_validator_access_snapshot(
        canonical_json(sign_validator_access_snapshot(document, SNAPSHOT_SEED)),
        {"cathedral-validator-access": signing_public},
        network=NETWORK,
        netuid=NETUID,
        required_minimum_stake_rao=1_000,
        now=generated_at,
    )


def test_two_validators_stalling_bodies_cannot_lock_out_a_third(tmp_path: Path):
    """Review finding W2: the signed class is shared, so permitted validators
    stalling their bodies used to turn every other validator away until the
    request deadline. A stalled body now yields its slot to a new validator."""
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _three_validator_snapshot(
            generated_at=current, expires_at=current + timedelta(minutes=10)
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        max_validator_challenge_concurrent=2,
        timeout=10.0,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        payload = canonical_json(
            {
                "assigned_hotkey": WORKER_HOTKEY,
                "channel_binding_digest_hex": binding.digest.hex(),
                "channel_binding_type": binding.binding_type.value,
                "nonce_hex": os.urandom(32).hex(),
                "report_data_version": 2,
            }
        )

        def stall(hotkey, pair, nonce):
            header = build_validator_request_header(
                validator_hotkey=hotkey,
                worker_hotkey=WORKER_HOTKEY,
                network=NETWORK,
                netuid=NETUID,
                method="POST",
                path="/v1/evidence",
                body=payload,
                channel_binding=binding,
                nonce=nonce,
                issued_at=current,
                expires_at=current + timedelta(seconds=60),
                signer=lambda message: sr25519.sign(pair, message),
            )
            connection = client_context.wrap_socket(
                socket.create_connection((server.host, server.port), timeout=5.0),
                server_hostname="127.0.0.1",
            )
            connection.sendall(
                (
                    "POST /v1/evidence HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{server.port}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"{VALIDATOR_REQUEST_HEADER}: {header}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            return connection

        pool = server._validator_pool
        stalled = [
            stall(VALIDATOR_HOTKEY, VALIDATOR_PAIR, b"a" * 32),
            stall(OTHER_VALIDATOR_HOTKEY, OTHER_VALIDATOR_PAIR, b"b" * 32),
        ]
        try:
            deadline = time.monotonic() + 3.0
            while pool.in_use != 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert pool.in_use == 2
            time.sleep(worker_module.VALIDATOR_BODY_STALL_SECONDS + 0.2)
            third = RemoteMiner(
                server.base_url,
                WORKER_HOTKEY,
                ssl_context=client_context,
                validator_hotkey=THIRD_VALIDATOR_HOTKEY,
                validator_signer=lambda message: sr25519.sign(THIRD_VALIDATOR_PAIR, message),
            )
            evidence = third.fetch_evidence(os.urandom(32))
            assert evidence.miner_hotkey == WORKER_HOTKEY
            assert pool.displaced_count >= 1
        finally:
            for connection in stalled:
                connection.close()


def _pool(now, **kwargs):
    return worker_module._ValidatorPool(
        1, stall_seconds=1.0, penalty_seconds=20.0, clock=lambda: now[0], **kwargs
    )


def test_a_request_past_its_body_is_never_displaced():
    now = [100.0]
    pool = _pool(now)
    a, b = socket.socketpair()
    try:
        slot = pool.admit(a, "v1")
        assert slot is not None
        now[0] += 0.5
        assert pool.admit(b, "v2") is None  # still inside the grace
        assert slot.mark_body_received() is True
        now[0] += 5.0
        assert pool.admit(b, "v2") is None  # body read: never displaced
        slot.release()
        assert pool.in_use == 0 and not pool.penalized("v1")
    finally:
        a.close()
        b.close()


def test_a_stalled_request_is_displaced_and_its_validator_benched():
    now = [100.0]
    pool = _pool(now)
    a, b = socket.socketpair()
    c, d = socket.socketpair()
    try:
        stalled = pool.admit(a, "attacker")
        now[0] += 1.5
        newcomer = pool.admit(c, "honest")
        assert newcomer is not None and pool.displaced_count == 1
        # A displaced request that finished reading just too late must stop.
        assert stalled.mark_body_received() is False
        stalled.release()  # owns nothing
        assert pool.in_use == 1
        assert pool.penalized("attacker")
        newcomer.release()
        assert pool.admit(b, "attacker") is None  # benched
        now[0] += 21.0
        assert pool.admit(b, "attacker") is not None  # served its time
    finally:
        for sock in (a, b, c, d):
            sock.close()


def test_leaving_without_a_body_benches_the_validator():
    # The adaptive attack: stall, then close just inside the grace, and repeat.
    now = [100.0]
    pool = _pool(now)
    a, b = socket.socketpair()
    try:
        slot = pool.admit(a, "attacker")
        now[0] += 0.95
        slot.release()  # closed before its body arrived
        assert pool.penalized("attacker")
        assert pool.admit(b, "attacker") is None
        assert pool.admit(b, "honest") is not None
    finally:
        a.close()
        b.close()


def test_the_grace_grows_with_the_declared_body():
    now = [100.0]
    pool = _pool(now)
    a, b = socket.socketpair()
    try:
        assert pool.admit(a, "far-validator", 64 * 1024) is not None  # grace 1 s + 2 s
        now[0] += 2.5
        assert pool.admit(b, "other") is None
        now[0] += 1.0
        assert pool.admit(b, "other") is not None
    finally:
        a.close()
        b.close()


def test_only_a_client_fault_after_the_body_benches():
    now = [100.0]
    pool = worker_module._ValidatorPool(3, penalty_seconds=20.0, clock=lambda: now[0])
    pairs = [socket.socketpair() for _ in range(3)]
    try:
        verified, refused, rejected = (
            pool.admit(a, hotkey) for (a, _b), hotkey in zip(pairs, ("ok", "server", "junk"))
        )
        for slot in (verified, refused, rejected):
            assert slot.mark_body_received() is True
        verified.mark_verified()
        rejected.mark_client_fault()  # e.g. the body is not the one signed
        now[0] += 5.0  # a slow finalize: no stall clock once the body is in
        for slot in (verified, refused, rejected):
            slot.release()
        assert not pool.penalized("ok")
        assert not pool.penalized("server")  # the worker refused: replay store, snapshot
        assert pool.penalized("junk")
    finally:
        for a, b in pairs:
            a.close()
            b.close()


def test_the_penalty_table_is_bounded():
    now = [100.0]
    pool = worker_module._ValidatorPool(
        1, penalty_seconds=20.0, max_penalized=3, clock=lambda: now[0]
    )
    sockets = [socket.socketpair() for _ in range(5)]
    try:
        for index, (a, _b) in enumerate(sockets):
            pool.admit(a, f"v{index}").release()
        assert len(pool._penalized_until) == 3
    finally:
        for a, b in sockets:
            a.close()
            b.close()


def test_the_body_arrival_ends_the_slow_charge():
    """Only pre-body time is slow. The charge is taken when the body arrives,
    so the time spent serving the request is never billed to the validator."""
    now = [100.0]
    pool = _pool(now)
    a, _b = socket.socketpair()
    c, _d = socket.socketpair()
    try:
        prompt = pool.admit(a, "prompt")
        now[0] += 0.05
        assert prompt.mark_body_received() is True
        prompt.mark_verified()
        now[0] += 10.0  # a long solve
        prompt.release()
        assert pool.slow_usage("prompt") == 0.0

        late = pool.admit(c, "late")
        now[0] += 0.9
        assert late.mark_body_received() is True
        charged = pool.slow_usage("late")
        # The grace is 1 s; its prompt fraction is free.
        assert charged == pytest.approx(0.9 - 1.0 * worker_module.VALIDATOR_PROMPT_GRACE_FRACTION)
        late.mark_verified()
        now[0] += 10.0
        late.release()
        assert pool.slow_usage("late") < charged  # draining, never charged again
    finally:
        for sock in (a, _b, c, _d):
            sock.close()


def test_the_slow_usage_table_is_bounded():
    now = [100.0]
    pool = worker_module._ValidatorPool(1, stall_seconds=1.0, max_penalized=3, clock=lambda: now[0])
    sockets = [socket.socketpair() for _ in range(5)]
    try:
        for index, (a, _b) in enumerate(sockets):
            slot = pool.admit(a, f"v{index}")
            now[0] += 0.9  # a valid body just inside the grace: charged, not benched
            assert slot.mark_body_received() is True
            slot.mark_verified()
            slot.release()
        assert len(pool._slow_usage) == 3
        assert "v4" in pool._slow_usage
        assert not any(pool.penalized(f"v{index}") for index in range(5))
    finally:
        for a, b in sockets:
            a.close()
            b.close()


def test_a_body_that_fails_its_signature_benches_the_validator(tmp_path: Path):
    """Sending a mismatched body at the end of the grace used to keep the slot,
    dodge the bench and leave the header replayable. A body the signature does
    not cover is a client fault, so it still benches even though a full-length
    body stops the stall clock."""
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _three_validator_snapshot(
            generated_at=current, expires_at=current + timedelta(minutes=10)
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )

    def evidence_collector(nonce, hotkey, **kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        timeout=5.0,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        signed_body = canonical_json({"nonce_hex": "00" * 32})
        header = build_validator_request_header(
            validator_hotkey=VALIDATOR_HOTKEY,
            worker_hotkey=WORKER_HOTKEY,
            network=NETWORK,
            netuid=NETUID,
            method="POST",
            path="/v1/evidence",
            body=signed_body,
            channel_binding=binding,
            nonce=b"x" * 32,
            issued_at=current,
            expires_at=current + timedelta(seconds=60),
            signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )

        def send(body: bytes) -> bytes:
            connection = client_context.wrap_socket(
                socket.create_connection((server.host, server.port), timeout=5.0),
                server_hostname="127.0.0.1",
            )
            try:
                connection.sendall(
                    (
                        "POST /v1/evidence HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{server.port}\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"{VALIDATOR_REQUEST_HEADER}: {header}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                    + body
                )
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                return response.partition(b"\r\n")[0]
            finally:
                connection.close()

        junk = b"x" * len(signed_body)
        assert b" 401 " in send(junk)
        assert server._validator_pool.penalized(VALIDATOR_HOTKEY)
        assert b" 429 " in send(signed_body)  # benched: the replay gets nowhere


def _three_validator_authorizer(tmp_path: Path, binding, current, **state_kwargs):
    return ValidatorRequestAuthorizer(
        _three_validator_snapshot(generated_at=current, expires_at=current + timedelta(minutes=10)),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite"), **state_kwargs),
        signature_verifier=load_sr25519_verifier(),
    )


def _evidence_server(authorizer, server_context, binding, **kwargs):
    def evidence_collector(nonce, hotkey, **collector_kwargs):
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=collector_kwargs["report_data_version"],
            channel_binding=collector_kwargs["channel_binding"],
        )

    return WorkerServer(
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=("https://8.8.8.8:8081",),
        **kwargs,
    )


def test_a_slow_finalize_does_not_displace_a_validator_that_sent_its_body(tmp_path: Path):
    """Review of W2: the stall clock used to run through finalize, a
    synchronous replay-store write. With finalize taking longer than the grace,
    a third validator arriving while the class was full displaced a validator
    that had already sent a complete, valid body: its nonce was consumed, it
    got no response, and it was benched."""
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = _three_validator_authorizer(tmp_path, binding, current)
    # The worker finalizes through finalize_result; slow that down, and count the
    # calls so the test fails if the worker ever stops going through it.
    original_finalize = authorizer.finalize_result
    slow_calls: list[float] = []

    def slow_finalize(*args, **kwargs):
        slow_calls.append(time.monotonic())
        time.sleep(1.5)
        return original_finalize(*args, **kwargs)

    authorizer.finalize_result = slow_finalize
    with _evidence_server(
        authorizer, server_context, binding, max_validator_challenge_concurrent=2, timeout=10.0
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        pool = server._validator_pool
        results: dict[str, object] = {}

        def fetch(name, hotkey, pair):
            miner = RemoteMiner(
                server.base_url,
                WORKER_HOTKEY,
                ssl_context=client_context,
                validator_hotkey=hotkey,
                validator_signer=lambda message: sr25519.sign(pair, message),
            )
            try:
                results[name] = miner.fetch_evidence(os.urandom(32))
            except RemoteError as exc:
                results[name] = exc

        first = [
            threading.Thread(target=fetch, args=("A", VALIDATOR_HOTKEY, VALIDATOR_PAIR)),
            threading.Thread(
                target=fetch, args=("B", OTHER_VALIDATOR_HOTKEY, OTHER_VALIDATOR_PAIR)
            ),
        ]
        for thread in first:
            thread.start()
        time.sleep(1.2)
        fetch("C", THIRD_VALIDATOR_HOTKEY, THIRD_VALIDATOR_PAIR)
        for thread in first:
            thread.join(timeout=10.0)
        assert len(slow_calls) >= 2  # A's and B's bodies went through the slow finalize
        for name in ("A", "B"):
            assert isinstance(results[name], Evidence), results[name]
            assert results[name].miner_hotkey == WORKER_HOTKEY
        assert pool.displaced_count == 0
        assert not pool.penalized(VALIDATOR_HOTKEY)
        assert not pool.penalized(OTHER_VALIDATOR_HOTKEY)
        # C found the class full of requests past their bodies and was turned
        # away (or, if it raced a release, served), never at A's expense.
        assert not pool.penalized(THIRD_VALIDATOR_HOTKEY)


class _SwitchableSnapshotProvider:
    def __init__(self, inner) -> None:
        self.inner = inner
        self.available = True

    @property
    def network(self) -> str:
        return self.inner.network

    @property
    def netuid(self) -> int:
        return self.inner.netuid

    def load(self, *, now):
        return self.inner.load(now=now) if self.available else None


@pytest.mark.parametrize(
    "refusal", ["replay-store-full", "replay-store-error", "snapshot-unavailable"]
)
def test_a_refusal_on_the_worker_side_does_not_bench_the_validator(tmp_path: Path, refusal: str):
    """Review of W2: every finalize refusal used to bench, so a full replay
    store (which an attacker can fill) turned into 20 s bans for honest
    validators. Only a client fault benches now."""
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = _three_validator_authorizer(
        tmp_path,
        binding,
        current,
        **({"max_replay_entries": 1} if refusal == "replay-store-full" else {}),
    )
    switchable = _SwitchableSnapshotProvider(authorizer.snapshot_provider)
    authorizer.snapshot_provider = switchable
    original_preauthorize = authorizer.preauthorize
    original_connect = authorizer.state._connect
    sabotaged = [False]

    def preauthorize(*args, **kwargs):
        # The envelope checks pass; the worker then fails before replay commit.
        result = original_preauthorize(*args, **kwargs)
        if sabotaged[0] and refusal == "snapshot-unavailable":
            switchable.available = False
        return result

    def failing_connect():
        if sabotaged[0]:
            raise sqlite3.OperationalError("disk I/O error")
        return original_connect()

    authorizer.preauthorize = preauthorize
    authorizer.state._connect = failing_connect
    with _evidence_server(authorizer, server_context, binding, timeout=5.0) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        pool = server._validator_pool

        def miner(hotkey, pair):
            return RemoteMiner(
                server.base_url,
                WORKER_HOTKEY,
                ssl_context=client_context,
                validator_hotkey=hotkey,
                validator_signer=lambda message: sr25519.sign(pair, message),
            )

        if refusal == "replay-store-full":
            # Another validator's accepted request fills the one-entry store.
            miner(OTHER_VALIDATOR_HOTKEY, OTHER_VALIDATOR_PAIR).fetch_evidence(os.urandom(32))
        else:
            sabotaged[0] = True
        with pytest.raises(RemoteError) as refused:
            miner(VALIDATOR_HOTKEY, VALIDATOR_PAIR).fetch_evidence(os.urandom(32))
        assert refused.value.status_code == 401
        _wait_released(pool)
        assert not pool.penalized(VALIDATOR_HOTKEY)
        # Not benched: the next request reaches finalize again (401 while the
        # fault lasts, never 429), and succeeds once the worker recovers.
        with pytest.raises(RemoteError) as again:
            miner(VALIDATOR_HOTKEY, VALIDATOR_PAIR).fetch_evidence(os.urandom(32))
        assert again.value.status_code == 401
        if refusal != "replay-store-full":
            sabotaged[0] = False
            switchable.available = True
            evidence = miner(VALIDATOR_HOTKEY, VALIDATOR_PAIR).fetch_evidence(os.urandom(32))
            assert evidence.miner_hotkey == WORKER_HOTKEY


def test_a_hotkey_over_its_slow_slot_budget_loses_its_grace():
    """Review of W2: a valid body sent just inside the grace was never
    displaced or benched, so two hotkeys doing it back to back held a class of
    two. Slow slot time now drains a per-hotkey budget; once over it, the
    hotkey's request still waiting for its body is displaced at once, without
    a bench. A prompt validator is never charged."""
    now = [100.0]
    pool = worker_module._ValidatorPool(
        1,
        penalty_seconds=20.0,
        slow_budget_seconds=2.0,
        slow_window_seconds=60.0,
        clock=lambda: now[0],
    )
    a, b = socket.socketpair()
    try:
        # A prompt validator sends many bodies within a tenth of its grace.
        for _ in range(200):
            slot = pool.admit(a, "prompt")
            now[0] += 0.09
            assert slot.mark_body_received() is True
            slot.release()
        assert pool.slow_usage("prompt") == 0.0
        slot = pool.admit(a, "prompt")
        now[0] += 0.5
        assert pool.admit(b, "other") is None  # inside its grace: kept
        slot.release()

        # A slow validator sends each valid body at 0.95 s of a 1 s grace.
        for _ in range(2):
            slot = pool.admit(a, "slow")
            now[0] += 0.95
            assert pool.admit(b, "other") is None  # still under budget
            assert slot.mark_body_received() is True
            slot.release()
        assert pool.slow_usage("slow") == pytest.approx(2 * 0.85, abs=0.05)  # less drain
        slot = pool.admit(a, "slow")
        now[0] += 0.05
        assert pool.admit(b, "other") is None  # within its prompt tenth
        now[0] += 0.45  # 1.7 + 0.4 charged is over the 2 s budget
        newcomer = pool.admit(b, "other")
        assert newcomer is not None and pool.displaced_count == 1
        assert slot.mark_body_received() is False  # displaced: must stop
        slot.release()
        assert not pool.penalized("slow")  # displaced for the budget, not benched
        newcomer.release()
        # The budget drains: after its window the hotkey has its grace back.
        now[0] += 120.0
        assert pool.slow_usage("slow") == 0.0
        slot = pool.admit(a, "slow")
        now[0] += 0.5
        assert pool.admit(b, "other") is None
        slot.release()
    finally:
        a.close()
        b.close()


def _evidence_request_body(binding) -> bytes:
    return canonical_json(
        {
            "nonce_hex": os.urandom(32).hex(),
            "assigned_hotkey": WORKER_HOTKEY,
            "report_data_version": 2,
            "channel_binding_type": binding.binding_type.value,
            "channel_binding_digest_hex": binding.digest.hex(),
        }
    )


def _evidence_header(binding, issued_at, hotkey, pair, body, nonce, lifetime=100):
    return build_validator_request_header(
        validator_hotkey=hotkey,
        worker_hotkey=WORKER_HOTKEY,
        network=NETWORK,
        netuid=NETUID,
        method="POST",
        path="/v1/evidence",
        body=body,
        channel_binding=binding,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=lifetime),
        signer=lambda message: sr25519.sign(pair, message),
    )


def _send_evidence(server, context, header, body, delay=0.0) -> bytes:
    """One raw signed request whose body follows its headers after delay."""
    try:
        connection = context.wrap_socket(
            socket.create_connection((server.host, server.port), timeout=5.0),
            server_hostname="127.0.0.1",
        )
    except OSError:
        return b""
    try:
        connection.sendall(
            (
                "POST /v1/evidence HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{server.port}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"{VALIDATOR_REQUEST_HEADER}: {header}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        if delay:
            time.sleep(delay)
        connection.sendall(body)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
        return response.partition(b"\r\n")[0]
    except OSError:
        return b""  # displaced: the worker shut the connection
    finally:
        connection.close()


def _wait_released(pool) -> None:
    """The 401 goes out before the handler releases its slot and benches."""
    deadline = time.monotonic() + 3.0
    while pool.in_use and time.monotonic() < deadline:
        time.sleep(0.01)
    assert pool.in_use == 0


def _without_early_replay_check(authorizer):
    authorizer.is_replay = lambda *args, **kwargs: False
    return authorizer


@pytest.mark.parametrize("early_check", [True, False], ids=["early-check", "finalize-only"])
def test_a_replayed_request_cannot_hold_a_slot(tmp_path: Path, early_check: bool):
    """Review of 514f220: a replay was refused only in finalize, which did not
    bench it, so resending one signed request held a slot for its whole
    lifetime. The early check now refuses it before a slot; a replay that gets
    past it (finalize-only here) is a client fault and benches."""
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = _three_validator_authorizer(tmp_path, binding, current)
    if not early_check:
        _without_early_replay_check(authorizer)
    with _evidence_server(authorizer, server_context, binding, timeout=5.0) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        pool = server._validator_pool
        body = _evidence_request_body(binding)
        header = _evidence_header(
            binding, current, VALIDATOR_HOTKEY, VALIDATOR_PAIR, body, b"r" * 32
        )
        assert b" 200 " in _send_evidence(server, client_context, header, body)
        _wait_released(pool)
        assert not pool.penalized(VALIDATOR_HOTKEY)
        assert b" 401 " in _send_evidence(server, client_context, header, body)
        _wait_released(pool)
        if early_check:
            assert not pool.penalized(VALIDATOR_HOTKEY)  # never held a slot
            assert b" 401 " in _send_evidence(server, client_context, header, body)
        else:
            assert pool.penalized(VALIDATOR_HOTKEY)
            assert b" 429 " in _send_evidence(server, client_context, header, body)


def test_a_request_that_expires_in_flight_benches(tmp_path: Path):
    """Review of 514f220: signing expires_at just ahead and sending the body
    after it was refused as expired without a bench."""
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = _three_validator_authorizer(tmp_path, binding, current)
    with _evidence_server(authorizer, server_context, binding, timeout=5.0) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        body = _evidence_request_body(binding)
        issued = datetime.now(UTC).replace(microsecond=0)
        header = _evidence_header(
            binding, issued, VALIDATOR_HOTKEY, VALIDATOR_PAIR, body, os.urandom(32), lifetime=2
        )
        delay = (issued + timedelta(seconds=2) - datetime.now(UTC)).total_seconds() + 0.2
        assert b" 401 " in _send_evidence(server, client_context, header, body, delay=delay)
        _wait_released(server._validator_pool)
        assert server._validator_pool.penalized(VALIDATOR_HOTKEY)


def _lockout_round(server, client_context, binding, current, attacker_request, seconds=6.0):
    """A and B loop attacker_request with each body at 0.95 s; C sends prompt
    fresh requests. Returns C's status lines."""
    stop = time.monotonic() + seconds

    def attack(hotkey, pair, tag):
        while time.monotonic() < stop:
            attacker_request(hotkey, pair, tag)

    attackers = [
        threading.Thread(target=attack, args=(hotkey, pair, tag), daemon=True)
        for hotkey, pair, tag in (
            (VALIDATOR_HOTKEY, VALIDATOR_PAIR, b"a"),
            (OTHER_VALIDATOR_HOTKEY, OTHER_VALIDATOR_PAIR, b"b"),
        )
    ]
    for thread in attackers:
        thread.start()
    time.sleep(0.3)
    third = []
    while time.monotonic() < stop - 0.5:
        body = _evidence_request_body(binding)
        header = _evidence_header(
            binding, current, THIRD_VALIDATOR_HOTKEY, THIRD_VALIDATOR_PAIR, body, os.urandom(32)
        )
        third.append(_send_evidence(server, client_context, header, body))
        time.sleep(0.25)
    for thread in attackers:
        thread.join(timeout=10.0)
    return third


@pytest.mark.parametrize("early_check", [True, False], ids=["early-check", "finalize-only"])
def test_two_replaying_validators_do_not_lock_out_a_third(tmp_path: Path, early_check: bool):
    """The reviewer's lockout: with a class of two, A and B resending one
    signed request each, body at 0.95 s, turned C away 27 of 27 times."""
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = _three_validator_authorizer(tmp_path, binding, current)
    if not early_check:
        _without_early_replay_check(authorizer)
    with _evidence_server(
        authorizer, server_context, binding, timeout=5.0, max_validator_challenge_concurrent=2
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        requests = {}
        for hotkey, pair, tag in (
            (VALIDATOR_HOTKEY, VALIDATOR_PAIR, b"a"),
            (OTHER_VALIDATOR_HOTKEY, OTHER_VALIDATOR_PAIR, b"b"),
        ):
            body = _evidence_request_body(binding)
            requests[hotkey] = (
                _evidence_header(binding, current, hotkey, pair, body, tag * 32),
                body,
            )

        def replay(hotkey, _pair, _tag):
            header, body = requests[hotkey]
            _send_evidence(server, client_context, header, body, delay=0.95)

        third = _lockout_round(server, client_context, binding, current, replay)
        # Finalize-only, A's and B's first replay still holds a slot until it
        # is refused and benched, about 2 s in; C is then served.
        served = sum(b" 200 " in line for line in third[10:])
        assert served >= len(third[10:]) * 3 // 4, third


def test_two_slow_fresh_validators_do_not_lock_out_a_third(tmp_path: Path):
    """The reviewer's second lockout, which predates the bench: fresh valid
    requests with each body at 0.95 s are never displaced or benched, so A and
    B held a class of two. Over the slow-slot budget they lose the grace."""
    server_context, client_context, binding = _tls_contexts(tmp_path)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = _three_validator_authorizer(tmp_path, binding, current)
    with _evidence_server(
        authorizer, server_context, binding, timeout=5.0, max_validator_challenge_concurrent=2
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        pool = server._validator_pool
        pool._slow_budget = 1.0  # the default 5 s would outlast a short test
        pool._slow_drain = 1.0 / 60.0

        def fresh(hotkey, pair, _tag):
            body = _evidence_request_body(binding)
            header = _evidence_header(binding, current, hotkey, pair, body, os.urandom(32))
            _send_evidence(server, client_context, header, body, delay=0.95)

        third = _lockout_round(server, client_context, binding, current, fresh, seconds=8.0)
        # A and B exceed the 1 s budget within about two requests each; from
        # then on C is admitted whenever it arrives.
        served = sum(b" 200 " in line for line in third[10:])
        assert served >= len(third[10:]) * 3 // 4, third
        assert pool.displaced_count > 0
        assert not pool.penalized(VALIDATOR_HOTKEY)
        assert not pool.penalized(OTHER_VALIDATOR_HOTKEY)
        assert not pool.penalized(THIRD_VALIDATOR_HOTKEY)
