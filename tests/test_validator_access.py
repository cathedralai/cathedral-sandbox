from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
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
NETUID = 39
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
) -> dict[str, object]:
    expires_at = expires_at or generated_at + timedelta(minutes=10)
    return {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": NETWORK,
        "netuid": NETUID,
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
    signing_public = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return verify_validator_access_snapshot(
        _signed_snapshot(**kwargs),
        {"cathedral-validator-access": signing_public},
        network=NETWORK,
        netuid=NETUID,
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
) -> str:
    return build_validator_request_header(
        validator_hotkey=validator_hotkey,
        worker_hotkey=WORKER_HOTKEY,
        network=NETWORK,
        netuid=NETUID,
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

    monkeypatch.setattr(worker_module.threading, "Semaphore", TrackingSemaphore)

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
        assert len(created) == 4
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
