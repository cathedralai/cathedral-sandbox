"""The worker serves a delegated central caller only when central access is configured."""

from __future__ import annotations

import base64
import http.client
import json
import socket
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import cathedral.validator_access as access_module
from cathedral import central_access as ca
from cathedral.validator_access import (
    VALIDATOR_REQUEST_HEADER,
    ValidatorAccessState,
    ValidatorRequestAuthorizer,
    load_sr25519_verifier,
)
from cathedral.worker import WorkerServer
from tests.test_validator_access import WORKER_HOTKEY, _snapshot, _tls_contexts

ROOT_SEED = b"r" * 32
CENTRAL_SEED = b"c" * 32
PATH = "/v1/capabilities"


def _public(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


ROOT_KEYS = {"cathedral-root-1": _public(ROOT_SEED)}


def _validator_authorizer(tmp_path: Path, binding) -> ValidatorRequestAuthorizer:
    current = datetime.now(UTC).replace(microsecond=0)
    return ValidatorRequestAuthorizer(
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


def _central_authorizer(tmp_path: Path, validator, binding) -> ca.CentralAccessAuthorizer:
    return ca.CentralAccessAuthorizer(
        ROOT_KEYS,
        worker_hotkey=WORKER_HOTKEY,
        network=validator.snapshot_provider.network,
        netuid=validator.snapshot_provider.netuid,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "central-access.sqlite")),
    )


def _header(validator, binding, *, nonce: bytes, path: str = PATH, body: bytes = b"{}") -> str:
    now = datetime.now(UTC).replace(microsecond=0)
    delegation = ca.sign_delegation(
        root_key_id="cathedral-root-1",
        root_seed=ROOT_SEED,
        central_key=_public(CENTRAL_SEED),
        routes=[PATH],
        network=validator.snapshot_provider.network,
        netuid=validator.snapshot_provider.netuid,
        sequence=1,
        issued_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=1),
    )
    return ca.build_central_request_header(
        delegation=delegation,
        central_seed=CENTRAL_SEED,
        worker_hotkey=WORKER_HOTKEY,
        network=validator.snapshot_provider.network,
        netuid=validator.snapshot_provider.netuid,
        method="POST",
        path=path,
        body=body,
        channel_binding=binding,
        nonce=nonce,
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(seconds=60),
    )


def _post(server, client_context, path, headers, body=b"{}"):
    connection = http.client.HTTPSConnection(
        "127.0.0.1", server.port, context=client_context, timeout=10
    )
    try:
        connection.request("POST", path, body=body, headers={"Content-Type": "application/json", **headers})
        response = connection.getresponse()
        return response.status, json.loads(response.read() or b"{}")
    finally:
        connection.close()


@pytest.fixture
def worker(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _address: True)
    server_context, client_context, binding = _tls_contexts(tmp_path)
    validator = _validator_authorizer(tmp_path, binding)

    def start(*, central: bool, **options):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        server = WorkerServer(
            port=port,
            configured_hotkey=WORKER_HOTKEY,
            channel_binding=binding,
            tls_context=server_context,
            validator_authorizer=validator,
            fleet_endpoints=(f"https://127.0.0.1:{port}",),
            central_authorizer=_central_authorizer(tmp_path, validator, binding) if central else None,
            **options,
        )
        server.__enter__()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    servers: list[WorkerServer] = []
    yield start, client_context, validator, binding
    for server in servers:
        server.__exit__(None, None, None)


def test_a_delegated_central_request_reads_capabilities_once(worker):
    start, client_context, validator, binding = worker
    server = start(central=True)
    header = _header(validator, binding, nonce=b"n" * 32)
    status, body = _post(server, client_context, PATH, {ca.CENTRAL_REQUEST_HEADER: header})
    assert status == 200
    assert "customer_sat" in body
    status, _ = _post(server, client_context, PATH, {ca.CENTRAL_REQUEST_HEADER: header})
    assert status == 401


def test_central_access_is_off_unless_configured(worker):
    start, client_context, validator, binding = worker
    server = start(central=False)
    header = _header(validator, binding, nonce=b"n" * 32)
    status, _ = _post(server, client_context, PATH, {ca.CENTRAL_REQUEST_HEADER: header})
    assert status == 401


@pytest.mark.parametrize(
    "case", ["route", "garbage", "duplicate", "with_validator_header", "body"]
)
def test_a_bad_central_request_is_refused(worker, case):
    start, client_context, validator, binding = worker
    server = start(central=True)
    header = _header(validator, binding, nonce=b"n" * 32)
    path, body = PATH, b"{}"
    headers: dict[str, str] | list = {ca.CENTRAL_REQUEST_HEADER: header}
    if case == "route":
        path = "/v1/evidence"
        headers = {ca.CENTRAL_REQUEST_HEADER: _header(validator, binding, nonce=b"m" * 32, path=path)}
    elif case == "garbage":
        headers = {ca.CENTRAL_REQUEST_HEADER: base64.b64encode(b"{}").decode()}
    elif case == "with_validator_header":
        headers[VALIDATOR_REQUEST_HEADER] = "x"
    elif case == "body":
        body = b'{"x":1}'
    if case == "duplicate":
        connection = http.client.HTTPSConnection("127.0.0.1", server.port, context=client_context, timeout=10)
        try:
            connection.putrequest("POST", PATH)
            connection.putheader(ca.CENTRAL_REQUEST_HEADER, header)
            connection.putheader(ca.CENTRAL_REQUEST_HEADER, header)
            connection.putheader("Content-Length", "2")
            connection.endheaders(b"{}")
            status = connection.getresponse().status
        finally:
            connection.close()
    else:
        status, _ = _post(server, client_context, path, headers, body)
    assert status == 401


def test_central_requests_are_rate_limited_per_key(worker):
    start, client_context, validator, binding = worker
    server = start(central=True, central_requests_per_window=1)
    first = _header(validator, binding, nonce=b"n" * 32)
    second = _header(validator, binding, nonce=b"m" * 32)
    assert _post(server, client_context, PATH, {ca.CENTRAL_REQUEST_HEADER: first})[0] == 200
    assert _post(server, client_context, PATH, {ca.CENTRAL_REQUEST_HEADER: second})[0] == 429


def test_central_access_requires_signed_validator_access_and_the_worker_key(tmp_path, monkeypatch):
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _address: True)
    server_context, _client, binding = _tls_contexts(tmp_path)
    validator = _validator_authorizer(tmp_path, binding)
    central = _central_authorizer(tmp_path, validator, binding)
    with pytest.raises(ValueError, match="signed validator access"):
        WorkerServer(
            configured_hotkey=WORKER_HOTKEY,
            channel_binding=binding,
            tls_context=server_context,
            central_authorizer=central,
        )
    other = type(binding)(binding.binding_type, b"z" * 32)
    mismatched = ca.CentralAccessAuthorizer(
        ROOT_KEYS,
        worker_hotkey=WORKER_HOTKEY,
        network=validator.snapshot_provider.network,
        netuid=validator.snapshot_provider.netuid,
        channel_binding=other,
        state=ValidatorAccessState(str(tmp_path / "other-central.sqlite")),
    )
    with pytest.raises(ValueError, match="worker TLS key"):
        WorkerServer(
            configured_hotkey=WORKER_HOTKEY,
            channel_binding=binding,
            tls_context=server_context,
            validator_authorizer=validator,
            fleet_endpoints=("https://1.1.1.1:8081",),
            central_authorizer=mismatched,
        )


def test_central_limiter_allows_one_in_flight_and_a_bounded_rate():
    clock = [0.0]
    limiter = ca.CentralRequestLimiter(requests_per_window=2, window_seconds=60, clock=lambda: clock[0])
    lease = limiter.acquire("central:a")
    assert lease is not None
    assert limiter.acquire("central:a") is None
    lease.release()
    lease.release()
    assert limiter.acquire("central:a") is not None
    clock[0] = 1.0
    assert limiter.acquire("central:a") is None
    with pytest.raises(ca.CentralAccessError):
        limiter.acquire("5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty")


def test_an_ungranted_route_is_refused_before_any_central_verification(tmp_path, monkeypatch):
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _address: True)
    server_context, client_context, binding = _tls_contexts(tmp_path)
    validator = _validator_authorizer(tmp_path, binding)
    calls: list[str] = []

    class Recording(ca.CentralAccessAuthorizer):
        def preauthorize(self, header, *, method, path, now):
            calls.append(path)
            return super().preauthorize(header, method=method, path=path, now=now)

    central = Recording(
        ROOT_KEYS,
        worker_hotkey=WORKER_HOTKEY,
        network=validator.snapshot_provider.network,
        netuid=validator.snapshot_provider.netuid,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "central-access.sqlite")),
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with WorkerServer(
        port=port,
        configured_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=validator,
        fleet_endpoints=(f"https://127.0.0.1:{port}",),
        central_authorizer=central,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        header = _header(validator, binding, nonce=b"n" * 32, path="/v1/sat-work")
        status, _ = _post(server, client_context, "/v1/sat-work", {ca.CENTRAL_REQUEST_HEADER: header})
        assert status == 401
        assert calls == []
        status, _ = _post(server, client_context, PATH, {ca.CENTRAL_REQUEST_HEADER: _header(validator, binding, nonce=b"m" * 32)})
        assert status == 200
        assert calls == [PATH]


_SIGNED_ACCESS_ARGS = [
    "--validator-access-snapshot", "/srv/cathedral/validator-access.json",
    "--validator-access-keys", "/srv/cathedral/keys.json",
    "--validator-access-keys-digest", "sha256:" + "cd" * 32,
    "--validator-access-state", "/var/lib/cathedral/validator-access.sqlite",
    "--validator-minimum-stake-rao", "1000",
    "--public-endpoint", "https://8.8.8.8:8081",
]
_CENTRAL_ARGS = [
    "--central-root-keys", "/etc/cathedral/central-root-keys.json",
    "--central-root-keys-digest", "sha256:" + "ab" * 32,
    "--central-access-state", "/var/lib/cathedral/central-access.sqlite",
]


@pytest.mark.parametrize(
    ("argv", "match"),
    [
        (_CENTRAL_ARGS[:2], "root keys, their pinned digest, and its own state"),
        (_CENTRAL_ARGS, "requires signed validator access"),
        (
            _SIGNED_ACCESS_ARGS
            + _CENTRAL_ARGS[:4]
            + ["--central-access-state", "/var/lib/cathedral/validator-access.sqlite"],
            "separate from validator access state",
        ),
    ],
)
def test_the_worker_cli_refuses_incomplete_or_shared_central_config(monkeypatch, argv, match):
    from cathedral.cli import build_parser, cmd_worker_serve

    monkeypatch.setenv("CATHEDRAL_WORKER_BEARER_TOKEN", "t" * 32)
    args = build_parser().parse_args(["worker", "serve", "--hotkey", "miner", *argv])
    with pytest.raises(ValueError, match=match):
        cmd_worker_serve(args)
