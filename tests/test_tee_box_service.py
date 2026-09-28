"""The T6a TEE box sandbox API: routes, caller keys, the customer lease, and the flag."""

from __future__ import annotations

import http.client
import io
import json
import os
import random
import tarfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import pytest
import sr25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cathedral.policy_registry import canonical_json
from cathedral.tee_box import (
    TEE_BOX_CALLER_NETWORK,
    FakeExecutor,
    Shape,
    TeeBoxSandboxApi,
    build_egress_policy,
    caller_authorizer,
    caller_snapshot_provider,
    sandbox_target_allowed,
)
from cathedral.tee_box.executor import ExecResult
from cathedral.validator_access import (
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
    ValidatorAccessError,
    ValidatorAccessState,
    ValidatorRequestAuthorizer,
    build_validator_request_header,
    load_sr25519_verifier,
    sign_validator_access_snapshot,
    verify_validator_access_snapshot,
)
from cathedral.worker import WorkerServer
from tests.test_validator_access import (
    OTHER_VALIDATOR_HOTKEY as OTHER,
    OTHER_VALIDATOR_PAIR as OTHER_PAIR,
    SNAPSHOT_SEED,
    VALIDATOR_HOTKEY as CALLER,
    VALIDATOR_PAIR as CALLER_PAIR,
    WORKER_HOTKEY,
    _hotkey,
    _tls_contexts,
)

NETUID = random.SystemRandom().randrange(1, 65536)
KEY_ID = "cathedral-control-plane"
STRANGER_PAIR = sr25519.pair_from_seed(b"x" * 32)
STRANGER = _hotkey(STRANGER_PAIR[0])
DIGEST = "sha256:" + "ab" * 32
BOX_IP = "34.120.1.2"
CAPACITY = Shape(8, 32768, 204800)
DEFAULT_SHAPE = Shape(2, 4096, 10240)
TRUSTED = {
    KEY_ID: ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
}


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _snapshot_bytes(
    *,
    callers: tuple[str, ...] = (CALLER, OTHER),
    generated_at: datetime | None = None,
    network: str = TEE_BOX_CALLER_NETWORK,
) -> bytes:
    generated_at = generated_at or _now() - timedelta(seconds=5)
    document = {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": network,
        "netuid": NETUID,
        "block": 1_000,
        "block_hash": "0x" + "c" * 64,
        "block_is_finalized": True,
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (generated_at + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minimum_stake_rao": 0,
        "validators": [
            {"hotkey": hotkey, "uid": uid, "validator_permit": True, "stake_rao": 0}
            for uid, hotkey in enumerate(sorted(callers))
        ],
        "signing_key_id": KEY_ID,
    }
    return canonical_json(sign_validator_access_snapshot(document, SNAPSHOT_SEED))


def _static_snapshot(network: str = TEE_BOX_CALLER_NETWORK, **kwargs):
    return verify_validator_access_snapshot(
        _snapshot_bytes(network=network, **kwargs),
        TRUSTED,
        network=network,
        netuid=NETUID,
        required_minimum_stake_rao=0,
    )


class _Clock:
    def __init__(self) -> None:
        self.value = 1_900_000_000.0

    def __call__(self) -> float:
        return self.value


def _api(tmp_path: Path, binding, *, snapshot=None, clock=None, executor=None):
    state = ValidatorAccessState(str(tmp_path / f"callers-{os.urandom(4).hex()}.sqlite"))
    authorizer = caller_authorizer(
        snapshot if snapshot is not None else _static_snapshot(),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=state,
        signature_verifier=load_sr25519_verifier(),
    )
    fake = executor or FakeExecutor()
    kwargs = {} if clock is None else {"clock": clock}
    api = TeeBoxSandboxApi(
        executor=fake,
        authorizer=authorizer,
        egress=build_egress_policy([BOX_IP]),
        capacity=CAPACITY,
        default_shape=DEFAULT_SHAPE,
        **kwargs,
    )
    return api, fake


def _header(
    binding,
    method: str,
    target: str,
    body: bytes = b"",
    *,
    hotkey=CALLER,
    pair=CALLER_PAIR,
    issued_at=None,
    lifetime=60,
    network=TEE_BOX_CALLER_NETWORK,
    nonce=None,
    target_allowed=sandbox_target_allowed,
) -> str:
    issued_at = issued_at or _now()
    return build_validator_request_header(
        validator_hotkey=hotkey,
        worker_hotkey=WORKER_HOTKEY,
        network=network,
        netuid=NETUID,
        method=method,
        path=target,
        body=body,
        channel_binding=binding,
        nonce=nonce or os.urandom(32),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=lifetime),
        signer=lambda message: sr25519.sign(pair, message),
        target_allowed=target_allowed,
    )


class _Box:
    """A worker with the sandbox API enabled, over real TLS."""

    def __init__(self, tmp_path: Path, **api_kwargs) -> None:
        server_context, self.client_context, self.binding = _tls_contexts(tmp_path)
        self.api, self.fake = _api(tmp_path, self.binding, **api_kwargs)
        self.server = WorkerServer(
            configured_hotkey=WORKER_HOTKEY,
            channel_binding=self.binding,
            tls_context=server_context,
            tee_box_api=self.api,
        )
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def raw(self, method: str, target: str, body: bytes = b"", headers=None):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.server.port, context=self.client_context, timeout=10
        )
        try:
            connection.request(
                method,
                target,
                body=body if body or method in {"POST", "PUT"} else None,
                headers=headers or {},
            )
            response = connection.getresponse()
            return response.status, response.getheader("Content-Type"), response.read()
        finally:
            connection.close()

    def call(self, method: str, target: str, body: bytes | dict | None = None, **signing):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        body = body or b""
        header = _header(self.binding, method, target, body, **signing)
        return self.raw(method, target, body, {"X-Cathedral-Validator-Request": header})

    def json(self, method: str, target: str, body=None, **signing):
        status, _type, raw = self.call(method, target, body, **signing)
        return status, json.loads(raw)

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture
def box(tmp_path: Path):
    instance = _Box(tmp_path)
    try:
        yield instance
    finally:
        instance.close()


def _lease_and_image(box: _Box, **signing) -> None:
    status, _ = box.json("POST", "/v1/lease", {"ttl_seconds": 600}, **signing)
    assert status == 200
    status, image = box.json(
        "POST",
        "/v1/images/import",
        {"digest": DIGEST, "reference": "registry.example/tasks/base"},
        **signing,
    )
    assert status == 200 and image["id"] == DIGEST


def _create(box: _Box, **extra) -> dict:
    status, view = box.json(
        "POST",
        "/v1/sandboxes",
        {
            "image_id": DIGEST,
            "network": "deny_all",
            "lifetime_seconds": 3600,
            **extra,
        },
    )
    assert status == 201, view
    return view


def test_every_v1_route_maps_to_the_executor(box: _Box):
    status, contract = box.json("GET", "/v1/box")
    assert status == 200
    assert contract["hardware"] == "standard"
    assert contract["max_exec_timeout_seconds"] == 14_400
    assert contract["exec_options"] == ["env", "user", "cwd", "timeout_seconds"]
    assert contract["lease"] == {
        "held": False,
        "held_by_caller": False,
        "expires_at": None,
        "draining": False,
    }

    _lease_and_image(box)
    assert box.json("GET", "/v1/lease")[1]["lease"]["holder"] == CALLER
    assert box.json("GET", f"/v1/images/{DIGEST}")[1]["reference"] == "registry.example/tasks/base"
    assert box.json("GET", "/v1/images/sha256:" + "0" * 64)[0] == 404

    view = _create(
        box,
        labels={"job": "j1", "trial_id": "t1"},
        env={"A": "1"},
        shape={"vcpus": 1, "memory_mib": 1024, "disk_mib": 2048},
    )
    sid = view["id"]
    assert view["hardware"] == "standard" and view["state"] == "running"
    assert box.fake.get(sid).spec.env == {"A": "1"}
    other = _create(box, labels={"job": "j2"})
    assert other["shape"] == DEFAULT_SHAPE.view()

    listing = box.json("GET", "/v1/sandboxes?label=job%3Dj1")[1]["sandboxes"]
    assert [row["id"] for row in listing] == [sid]
    assert len(box.json("GET", "/v1/sandboxes")[1]["sandboxes"]) == 2
    assert box.json("GET", f"/v1/sandboxes/{sid}")[1]["labels"]["trial_id"] == "t1"

    status, result = box.json(
        "POST",
        f"/v1/sandboxes/{sid}/exec",
        {
            "command": "echo hi",
            "timeout_seconds": 45,
            "env": {"X": "y"},
            "user": "root",
            "cwd": "/work",
        },
    )
    assert status == 200 and result["exit_code"] == 0 and result["stdout"] == "ok\n"
    _sid, request = box.fake.requests[-1]
    assert request.argv == ("/bin/sh", "-c", "echo hi")
    assert (request.env, request.user, request.cwd, request.timeout_seconds) == (
        {"X": "y"},
        "root",
        "/work",
        45,
    )

    status, started = box.json(
        "POST",
        f"/v1/sandboxes/{sid}/execs",
        {"command": ["sleep", "100"], "timeout_seconds": 14_400},
    )
    assert status == 200 and started["state"] == "running"
    exec_path = f"/v1/sandboxes/{sid}/execs/{started['exec_id']}"
    assert box.json("GET", exec_path + "?wait=1")[1]["state"] == "running"
    box.fake.finish(sid, started["exec_id"], ExecResult(0, b"done"))
    polled = box.json("GET", exec_path)[1]
    assert (polled["state"], polled["stdout"]) == ("exited", "done")

    status, process = box.json(
        "POST", f"/v1/sandboxes/{sid}/processes", {"cmd": "exec server", "cwd": "/srv", "env": {}}
    )
    assert status == 200
    stopped = box.json("DELETE", f"/v1/sandboxes/{sid}/processes/{process['exec_id']}")[1]
    assert stopped["state"] == "killed"

    target = f"/v1/sandboxes/{sid}/files?path={quote('/work/a b.txt', safe='')}&mode=384"
    assert box.call("PUT", target, b"\x00payload")[0] == 200
    status, content_type, data = box.call(
        "GET", f"/v1/sandboxes/{sid}/files?path={quote('/work/a b.txt', safe='')}"
    )
    assert (status, content_type, data) == (200, "application/octet-stream", b"\x00payload")
    stat = box.json("GET", f"/v1/sandboxes/{sid}/stat?path=/work/a%20b.txt")[1]
    assert stat == {
        "path": "/work/a b.txt",
        "is_dir": False,
        "is_file": True,
        "size": 8,
        "mode": 0o600,
    }
    assert box.json("GET", f"/v1/sandboxes/{sid}/stat?path=/work")[1]["is_dir"] is True
    assert box.json("GET", f"/v1/sandboxes/{sid}/stat?path=/missing")[0] == 404

    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        member = tarfile.TarInfo("sub/x.txt")
        member.size = 3
        tar.addfile(member, io.BytesIO(b"xyz"))
    assert box.call("PUT", f"/v1/sandboxes/{sid}/tar?path=/data", archive.getvalue())[0] == 200
    assert box.call("PUT", f"/v1/sandboxes/{sid}/tar?path=/", archive.getvalue())[0] == 400
    status, content_type, packed = box.call(
        "GET", f"/v1/sandboxes/{sid}/tar?path=/data&exclude=nothing"
    )
    assert (status, content_type) == (200, "application/gzip")
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as tar:
        assert tar.getnames() == ["sub/x.txt"]

    before = box.fake.get(sid).spec.expires_at
    extended = box.json("POST", f"/v1/sandboxes/{sid}/lifetime", {"extend_by_seconds": 600})[1]
    assert extended["expires_at"] == int(before + 600)
    assert (
        box.json(
            "POST",
            f"/v1/sandboxes/{sid}/lifetime",
            {"extend_by_seconds": 1, "lifetime_seconds": 60},
        )[0]
        == 400
    )

    assert box.json("DELETE", f"/v1/sandboxes/{sid}")[1] == {"id": sid, "deleted": True}
    assert box.json("GET", f"/v1/sandboxes/{sid}")[0] == 404
    assert box.json("DELETE", "/v1/lease")[1] == {"released": True, "draining": False}
    assert other["id"] in box.fake.deleted


def test_exec_limits_follow_the_standard_contract(box: _Box):
    _lease_and_image(box)
    sid = _create(box)["id"]
    assert (
        box.json("POST", f"/v1/sandboxes/{sid}/exec", {"command": "x", "timeout_seconds": 46})[0]
        == 400
    )
    assert (
        box.json("POST", f"/v1/sandboxes/{sid}/execs", {"command": "x", "timeout_seconds": 14_401})[
            0
        ]
        == 400
    )
    assert box.json("POST", f"/v1/sandboxes/{sid}/exec", {"command": "x", "user": "a b"})[0] == 400
    assert (
        box.json("POST", f"/v1/sandboxes/{sid}/exec", {"command": "x", "cwd": "relative"})[0] == 400
    )
    assert (
        box.json("POST", f"/v1/sandboxes/{sid}/exec", {"command": "x", "env": {"1BAD": "v"}})[0]
        == 400
    )
    assert box.json("POST", f"/v1/sandboxes/{sid}/exec", {"command": "x", "shell": True})[0] == 400
    # v1 has no snapshot, fork or port routes.
    for method, target in (
        ("POST", f"/v1/sandboxes/{sid}/snapshot"),
        ("POST", f"/v1/sandboxes/{sid}/ports"),
    ):
        with pytest.raises(ValidatorAccessError):
            _header(box.binding, method, target)


def test_one_customer_at_a_time_and_release_drains(box: _Box):
    _lease_and_image(box)
    first = _create(box)["id"]
    second = _create(box)["id"]
    busy = box.json("POST", "/v1/lease", {"ttl_seconds": 600}, hotkey=OTHER, pair=OTHER_PAIR)
    assert busy == (409, {"error": "the box is leased to another customer", "reason": "box_busy"})
    for method, target in (
        ("GET", "/v1/sandboxes"),
        ("GET", f"/v1/sandboxes/{first}"),
        ("DELETE", f"/v1/sandboxes/{first}"),
        ("DELETE", "/v1/lease"),
    ):
        assert box.json(method, target, hotkey=OTHER, pair=OTHER_PAIR)[1]["reason"] == "box_busy"
    assert (
        box.json(
            "POST",
            "/v1/sandboxes",
            {"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 60},
            hotkey=OTHER,
            pair=OTHER_PAIR,
        )[0]
        == 409
    )
    assert box.json("GET", "/v1/box", hotkey=OTHER, pair=OTHER_PAIR)[1]["lease"]["held"] is True
    assert box.fake.deleted == []

    assert box.json("DELETE", "/v1/lease")[1] == {"released": True, "draining": False}
    assert sorted(box.fake.deleted) == sorted([first, second])
    status, lease = box.json(
        "POST", "/v1/lease", {"ttl_seconds": 600}, hotkey=OTHER, pair=OTHER_PAIR
    )
    assert status == 200 and lease["lease"]["holder"] == OTHER
    assert box.json("GET", "/v1/sandboxes", hotkey=OTHER, pair=OTHER_PAIR)[1] == {"sandboxes": []}


def test_calls_without_a_lease_are_refused(tmp_path: Path):
    api, _fake = _api(tmp_path, _binding())
    response = api.handle("GET", "/v1/sandboxes", CALLER, b"")
    assert response.status == 409
    assert json.loads(response.body)["reason"] == "lease_required"


def _binding():
    from cathedral.common import ChannelBinding, ChannelBindingType

    return ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"\x07" * 32)


def _handle(api, method, target, caller=CALLER, body=None):
    raw = b"" if body is None else json.dumps(body).encode()
    response = api.handle(method, target, caller, raw)
    return response.status, json.loads(response.body)


def test_lease_expiry_drains_and_frees_the_box(tmp_path: Path):
    clock = _Clock()
    api, fake = _api(tmp_path, _binding(), clock=clock)
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 60})[0] == 200
    fake.import_image(DIGEST, "registry.example/tasks/base")
    status, view = _handle(
        api,
        "POST",
        "/v1/sandboxes",
        body={"image_id": DIGEST, "network": "internet", "lifetime_seconds": 3600},
    )
    assert status == 201
    clock.value += 59
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})[1]["reason"] == "box_busy"
    # Renewal keeps the holder and pushes the expiry.
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 60})[0] == 200
    clock.value += 59
    assert fake.deleted == []
    clock.value += 2
    status, lease = _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 120})
    assert status == 200 and lease["lease"]["holder"] == OTHER
    assert fake.deleted == [view["id"]]
    assert _handle(api, "GET", "/v1/sandboxes")[1]["reason"] == "box_busy"


def test_reaper_ends_an_expired_lease_without_a_call(tmp_path: Path):
    clock = _Clock()
    api, fake = _api(tmp_path, _binding(), clock=clock)
    _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 60})
    fake.import_image(DIGEST, "registry.example/tasks/base")
    sid = _handle(
        api,
        "POST",
        "/v1/sandboxes",
        body={"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 3600},
    )[1]["id"]
    clock.value += 61
    api.reap()
    assert fake.deleted == [sid] and api.lease.current() is None


def test_sandbox_lifetime_and_capacity_are_enforced(tmp_path: Path):
    clock = _Clock()
    api, fake = _api(tmp_path, _binding(), clock=clock)
    _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 86_400})
    fake.import_image(DIGEST, "registry.example/tasks/base")
    short = _handle(
        api,
        "POST",
        "/v1/sandboxes",
        body={"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 60},
    )[1]["id"]
    clock.value += 60
    assert _handle(api, "GET", f"/v1/sandboxes/{short}")[0] == 404
    assert fake.deleted == [short]

    big = {"vcpus": 8, "memory_mib": 32768, "disk_mib": 1024}
    assert (
        _handle(
            api,
            "POST",
            "/v1/sandboxes",
            body={"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 60, "shape": big},
        )[0]
        == 201
    )
    status, refusal = _handle(
        api,
        "POST",
        "/v1/sandboxes",
        body={"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 60},
    )
    assert (status, refusal["reason"]) == (409, "box_capacity_full")
    assert (
        _handle(
            api,
            "POST",
            "/v1/sandboxes",
            body={"image_id": "sha256:" + "1" * 64, "network": "deny_all", "lifetime_seconds": 60},
        )[0]
        == 404
    )
    assert (
        _handle(
            api,
            "POST",
            "/v1/sandboxes",
            body={"image_id": DIGEST, "network": "bridge", "lifetime_seconds": 60},
        )[0]
        == 400
    )
    assert (
        _handle(
            api,
            "POST",
            "/v1/sandboxes",
            body={"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 86_401},
        )[0]
        == 400
    )


def test_unsigned_unknown_expired_and_mismatched_callers_are_refused(box: _Box):
    _lease_and_image(box)
    assert box.raw("GET", "/v1/box")[0] == 401
    assert box.raw("GET", "/v1/box", headers={"X-Cathedral-Validator-Request": "junk"})[0] == 401
    # A key the snapshot does not list.
    assert box.call("GET", "/v1/box", hotkey=STRANGER, pair=STRANGER_PAIR)[0] == 401
    # A listed key's name with another key's signature.
    assert box.call("GET", "/v1/box", hotkey=CALLER, pair=OTHER_PAIR)[0] == 401
    # An expired request.
    assert box.call("GET", "/v1/box", issued_at=_now() - timedelta(minutes=5))[0] == 401
    # Signed for another network label (a validator-access envelope).
    assert box.call("GET", "/v1/box", network="finney")[0] == 401
    # Signed for one target, sent to another; and a query the signature did not cover.
    header = _header(box.binding, "GET", "/v1/lease")
    assert box.raw("GET", "/v1/box", headers={"X-Cathedral-Validator-Request": header})[0] == 401
    sid = _create(box)["id"]
    header = _header(box.binding, "GET", f"/v1/sandboxes/{sid}/files?path=/a")
    assert (
        box.raw(
            "GET",
            f"/v1/sandboxes/{sid}/files?path=/etc/shadow",
            headers={"X-Cathedral-Validator-Request": header},
        )[0]
        == 401
    )
    # A body the signature did not cover.
    body = json.dumps({"ttl_seconds": 600}).encode()
    header = _header(box.binding, "POST", "/v1/lease", body)
    assert (
        box.raw(
            "POST", "/v1/lease", b'{"ttl_seconds":900}', {"X-Cathedral-Validator-Request": header}
        )[0]
        == 401
    )
    # A replayed envelope.
    header = _header(box.binding, "GET", "/v1/box")
    assert box.raw("GET", "/v1/box", headers={"X-Cathedral-Validator-Request": header})[0] == 200
    assert box.raw("GET", "/v1/box", headers={"X-Cathedral-Validator-Request": header})[0] == 401
    # Unknown paths in the namespace are refused before any handler runs,
    # even under an envelope a permissive signer produced for them.
    assert box.raw("GET", "/v1/sandboxes/sbx-x/ports")[0] == 401
    for method, target in (("GET", f"/v1/sandboxes/{sid}/ports"), ("POST", "/v1/sandboxes/fork")):
        body = b"" if method == "GET" else b"{}"
        header = _header(box.binding, method, target, body, target_allowed=lambda _m, _p: True)
        status = box.raw(method, target, body, {"X-Cathedral-Validator-Request": header})[0]
        assert status == 401, (method, target)


def test_an_expired_caller_snapshot_refuses_every_call(tmp_path: Path):
    snapshot_path = tmp_path / "callers.json"
    snapshot_path.write_bytes(_snapshot_bytes())
    snapshot_path.chmod(0o644)
    state = ValidatorAccessState(str(tmp_path / "callers.sqlite"))
    provider = caller_snapshot_provider(
        str(snapshot_path), TRUSTED, netuid=NETUID, state=state, max_age_seconds=60
    )
    box = _Box(tmp_path, snapshot=provider)
    try:
        assert box.call("GET", "/v1/box")[0] == 200
        stale = tmp_path / "stale.json"
        stale.write_bytes(_snapshot_bytes(generated_at=_now() - timedelta(minutes=9)))
        stale.chmod(0o644)
        state2 = ValidatorAccessState(str(tmp_path / "stale.sqlite"))
        stale_provider = caller_snapshot_provider(
            str(stale), TRUSTED, netuid=NETUID, state=state2, max_age_seconds=60
        )
        assert stale_provider.load(now=datetime.now(UTC)) is None
    finally:
        box.close()
    box = _Box(tmp_path, snapshot=stale_provider)
    try:
        assert box.call("GET", "/v1/box")[0] == 401
    finally:
        box.close()


def test_validator_access_cannot_stand_in_for_caller_access(tmp_path: Path):
    state = ValidatorAccessState(str(tmp_path / "state.sqlite"))
    with pytest.raises(ValueError, match="control-plane network label"):
        caller_authorizer(
            _static_snapshot(network="finney"),
            worker_hotkey=WORKER_HOTKEY,
            channel_binding=_binding(),
            state=state,
            signature_verifier=load_sr25519_verifier(),
        )
    validator_routes = ValidatorRequestAuthorizer(
        _static_snapshot(),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=_binding(),
        state=state,
        signature_verifier=load_sr25519_verifier(),
    )
    with pytest.raises(ValueError, match="only sandbox API targets"):
        TeeBoxSandboxApi(
            executor=FakeExecutor(),
            authorizer=validator_routes,
            egress=build_egress_policy([BOX_IP]),
            capacity=CAPACITY,
            default_shape=DEFAULT_SHAPE,
        )
    # The default envelope builder still signs only the validator routes.
    with pytest.raises(ValidatorAccessError, match="unsupported"):
        build_validator_request_header(
            validator_hotkey=CALLER,
            worker_hotkey=WORKER_HOTKEY,
            network="finney",
            netuid=NETUID,
            method="GET",
            path="/v1/box",
            body=b"",
            channel_binding=_binding(),
            nonce=b"n" * 32,
            issued_at=_now(),
            expires_at=_now() + timedelta(seconds=30),
            signer=lambda message: sr25519.sign(CALLER_PAIR, message),
        )
    assert not sandbox_target_allowed("POST", "/v1/fleet")
    assert not sandbox_target_allowed("GET", "/v1/sandboxes/sbx-" + "0" * 24 + "/files?p=a b")


def test_flag_off_means_no_sandbox_routes(tmp_path: Path):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    with WorkerServer(
        configured_hotkey=WORKER_HOTKEY, channel_binding=binding, tls_context=server_context
    ) as server:
        # Serve first: shutdown() on exit waits for a started serve loop.
        threading.Thread(target=server.serve_forever, daemon=True).start()
        handler = server._server.RequestHandlerClass
        assert not any(hasattr(handler, name) for name in ("do_GET", "do_PUT", "do_DELETE"))
        for method, target in (
            ("POST", "/v1/sandboxes"),
            ("POST", "/v1/lease"),
            ("GET", "/v1/box"),
            ("DELETE", "/v1/lease"),
        ):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", server.port, context=client_context, timeout=10
            )
            connection.request(method, target, body=b"{}" if method == "POST" else None)
            status = connection.getresponse().status
            connection.close()
            assert status in {404, 501}, (method, target, status)


def test_the_sandbox_api_requires_the_attested_listener(tmp_path: Path):
    server_context, _client, binding = _tls_contexts(tmp_path)
    api, _fake = _api(tmp_path, binding)
    with pytest.raises(ValueError, match="attested worker TLS"):
        WorkerServer(configured_hotkey=WORKER_HOTKEY, tee_box_api=api)
    (tmp_path / "other").mkdir()
    other_context, _c, other_binding = _tls_contexts(tmp_path / "other")
    with pytest.raises(ValueError, match="bind the worker TLS key"):
        WorkerServer(
            configured_hotkey=WORKER_HOTKEY,
            channel_binding=other_binding,
            tls_context=other_context,
            tee_box_api=api,
        )


def _one_sandbox(api, caller=CALLER, ttl=60):
    assert _handle(api, "POST", "/v1/lease", caller, {"ttl_seconds": ttl})[0] == 200
    return _handle(
        api,
        "POST",
        "/v1/sandboxes",
        caller,
        {"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 3600},
    )[1]["id"]


def _draining(api, caller=OTHER):
    status, body = _handle(api, "POST", "/v1/lease", caller, {"ttl_seconds": 60})
    return status == 409 and body["reason"] == "box_draining"


def test_a_failed_drain_keeps_the_box_unleasable_until_the_delete_succeeds(tmp_path: Path):
    clock = _Clock()
    api, fake = _api(tmp_path, _binding(), clock=clock)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    leftover = _one_sandbox(api)
    fake.delete_fails = True
    assert _handle(api, "DELETE", "/v1/lease")[1] == {"released": True, "draining": True}
    # Nobody gets the box while the old customer's sandbox may still run:
    # not another customer, not the old one again.
    for _ in range(3):
        assert _draining(api) and _draining(api, CALLER)
        api.reap()
    assert _handle(api, "GET", "/v1/sandboxes", CALLER)[1]["reason"] == "box_draining"
    assert _handle(api, "GET", "/v1/box", OTHER)[1]["lease"]["draining"] is True
    assert fake.get(leftover) is not None and fake.deleted == []
    # The reaper retries; once the delete works the box can change hands.
    fake.delete_fails = False
    api.reap()
    assert fake.deleted == [leftover] and not api.lease.draining
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})[0] == 200
    assert _handle(api, "GET", "/v1/sandboxes", OTHER)[1] == {"sandboxes": []}


def test_an_expired_lease_with_a_stuck_sandbox_stays_draining(tmp_path: Path):
    clock = _Clock()
    api, fake = _api(tmp_path, _binding(), clock=clock)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    stuck = _one_sandbox(api)
    fake.delete_fails = True
    clock.value += 61
    api.reap()
    assert api.lease.current() is None and _draining(api)
    fake.delete_fails = False
    # Ordinary calls space their retries; the next one after the gap drains.
    assert _draining(api)
    clock.value += 2
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})[0] == 200
    assert fake.deleted == [stuck]


def test_an_untracked_container_blocks_the_hand_over(tmp_path: Path):
    # A container the table lost (a timed-out create, an earlier process)
    # may belong to the old customer, so the sweep must clear it first.
    api, fake = _api(tmp_path, _binding(), clock=_Clock())
    fake.import_image(DIGEST, "registry.example/tasks/base")
    sid = _one_sandbox(api)
    fake.orphans.add("cathsbx-sbx-" + "9" * 24)
    fake.orphans_stuck = True
    assert _handle(api, "DELETE", "/v1/lease")[1] == {"released": True, "draining": True}
    assert fake.deleted == [sid] and _draining(api)
    fake.orphans_stuck = False
    api.reap()  # the reaper's tick
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})[0] == 200
    assert fake.orphans == set()


def _fresh(tmp_path: Path, fake: FakeExecutor):
    clock = _Clock()
    api, _ = _api(tmp_path, _binding(), clock=clock, executor=fake)
    return api, clock


def test_a_restarted_box_refuses_leases_until_a_sweep_removes_leftovers(tmp_path: Path):
    # A container an earlier process left running (its table is gone).
    fake = FakeExecutor()
    fake.orphans.add("cathsbx-sbx-" + "5" * 24)
    fake.orphans_stuck = True
    api, clock = _fresh(tmp_path, fake)
    assert api.lease.draining
    assert _draining(api, CALLER) and _draining(api, OTHER)
    assert _handle(api, "GET", "/v1/sandboxes")[1]["reason"] == "box_draining"
    for _ in range(3):
        api.reap()
        clock.value += 5
        assert _draining(api)
    fake.orphans_stuck = False
    api.reap()
    assert fake.orphans == set() and not api.lease.draining
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})[0] == 200


def test_a_restarted_box_with_a_clean_daemon_is_leasable_after_the_first_sweep(tmp_path: Path):
    fake = FakeExecutor()
    api, _clock = _fresh(tmp_path, fake)
    assert api.lease.draining  # nothing is known until the first sweep
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 60})[0] == 200


def test_a_sweep_that_fails_keeps_the_box_draining(tmp_path: Path):
    fake = FakeExecutor()
    fake.sweep_fails = True  # the container daemon is down
    api, clock = _fresh(tmp_path, fake)
    for _ in range(3):
        api.reap()
        clock.value += 5
        assert _draining(api) and api.lease.draining
    fake.sweep_fails = False
    clock.value += 5
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 60})[0] == 200


def test_an_unsigned_caller_gets_no_body_read(box: _Box):
    # Refused on its headers alone: the declared body is never awaited.
    connection = http.client.HTTPSConnection(
        "127.0.0.1", box.server.port, context=box.client_context, timeout=10
    )
    try:
        connection.putrequest("PUT", "/v1/sandboxes/sbx-" + "0" * 24 + "/files?path=/a")
        connection.putheader("Content-Length", "1000000")
        connection.endheaders()
        assert connection.getresponse().status == 401
    finally:
        connection.close()


def test_numeric_query_values_must_be_short_ascii_decimals(tmp_path: Path):
    api, fake = _api(tmp_path, _binding(), clock=_Clock())
    fake.import_image(DIGEST, "registry.example/tasks/base")
    sid = _one_sandbox(api, ttl=600)
    eid = _handle(api, "POST", f"/v1/sandboxes/{sid}/execs", body={"command": "x"})[1]["exec_id"]
    for value in (quote("\u00b2"), quote("\u0663"), "9" * 4301, "-1", "99999"):
        status = api.handle("GET", f"/v1/sandboxes/{sid}/execs/{eid}?wait={value}", CALLER, b"")
        assert status.status == 400, value
        status = api.handle("PUT", f"/v1/sandboxes/{sid}/files?path=/a&mode={value}", CALLER, b"")
        assert status.status == 400, value
    assert api.handle("GET", f"/v1/sandboxes/{sid}/execs/{eid}?wait=25", CALLER, b"").status == 200


def test_the_worker_sweeps_leftover_containers_when_it_starts(tmp_path: Path):
    # Containers a previous worker process left behind are removed without
    # waiting for a call.
    fake = FakeExecutor()
    fake.orphans.add("cathsbx-sbx-" + "7" * 24)
    box = _Box(tmp_path, executor=fake)
    try:
        deadline = time.monotonic() + 5
        while fake.orphans and time.monotonic() < deadline:
            time.sleep(0.01)
        assert fake.orphans == set()
    finally:
        box.close()
