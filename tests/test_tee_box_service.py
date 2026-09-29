"""The TEE box sandbox API: routes, central callers, the customer lease, and the flag."""

from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import os
import random
import tarfile
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cathedral import central_access as ca
from cathedral.policy_registry import canonical_json
from cathedral.tee_box import (
    FakeExecutor,
    Shape,
    TeeBoxSandboxApi,
    build_egress_policy,
    route_scope,
)
from cathedral.tee_box.boot import BootGuard, rtmr_extend
from cathedral.tee_box.executor import ExecResult
from cathedral.worker import WorkerServer
from tests.test_validator_access import WORKER_HOTKEY, _tls_contexts

NETWORK = "finney"
NETUID = random.SystemRandom().randrange(1, 65536)
ROOT_KEY_ID = "cathedral-root-1"
ROOT_SEED = b"r" * 32
OTHER_ROOT_SEED = b"o" * 32
CENTRAL_SEED = b"c" * 32
OTHER_CENTRAL_SEED = b"d" * 32
STRANGER_SEED = b"x" * 32
DIGEST = "sha256:" + "ab" * 32
BOX_IP = "34.120.1.2"
CAPACITY = Shape(8, 32768, 204800)
DEFAULT_SHAPE = Shape(2, 4096, 10240)
ALL_SCOPES = sorted(ca.TEE_BOX_CENTRAL_SCOPES)
CENTRAL_HEADER = ca.CENTRAL_REQUEST_HEADER


def _public(seed: bytes) -> bytes:
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _caller(seed: bytes) -> str:
    return "central:" + hashlib.sha256(_public(seed)).hexdigest()


ROOT_KEYS = {ROOT_KEY_ID: _public(ROOT_SEED)}
CALLER = _caller(CENTRAL_SEED)
OTHER = _caller(OTHER_CENTRAL_SEED)


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _delegation(
    *,
    central_seed: bytes = CENTRAL_SEED,
    routes=ALL_SCOPES,
    root_seed: bytes = ROOT_SEED,
    sequence: int = 5,
    issued_at: datetime | None = None,
    lifetime: timedelta = timedelta(hours=1),
    netuid: int = NETUID,
) -> dict[str, object]:
    issued_at = issued_at or _now() - timedelta(minutes=5)
    return ca.sign_delegation(
        root_key_id=ROOT_KEY_ID,
        root_seed=root_seed,
        central_key=_public(central_seed),
        routes=routes,
        network=NETWORK,
        netuid=netuid,
        sequence=sequence,
        issued_at=issued_at,
        expires_at=issued_at + lifetime,
    )


def _revocations(
    sequence: int = 1, revoked=(), seed: bytes = ROOT_SEED, issued_at: datetime | None = None
) -> dict[str, object]:
    return ca.sign_revocations(
        root_key_id=ROOT_KEY_ID,
        root_seed=seed,
        sequence=sequence,
        issued_at=issued_at or _now(),
        revoked=list(revoked),
    )


def _delegation_digest(delegation: dict[str, object]) -> str:
    return ca.verify_delegation(
        delegation, ROOT_KEYS, network=NETWORK, netuid=NETUID, now=_now()
    ).digest


class _Clock:
    def __init__(self) -> None:
        self.value = 1_900_000_000.0

    def __call__(self) -> float:
        return self.value


def _authorizer(tmp_path: Path, binding, root_keys=ROOT_KEYS) -> ca.CentralAccessAuthorizer:
    state = ca.open_central_access_state(str(tmp_path / f"central-{os.urandom(4).hex()}.sqlite"))
    return ca.CentralAccessAuthorizer(
        root_keys,
        worker_hotkey=WORKER_HOTKEY,
        network=NETWORK,
        netuid=NETUID,
        channel_binding=binding,
        state=state,
    )


def _push_revocations(api: TeeBoxSandboxApi, document=None) -> None:
    # Signed "now" on the API's own clock, which some tests replace.
    issued_at = datetime.fromtimestamp(int(api._clock()), UTC)  # noqa: SLF001
    body = canonical_json(document if document is not None else _revocations(issued_at=issued_at))
    response = api.handle("POST", "/v1/box/revocations", CALLER, body)
    assert response.status == 200, response.body


BOOTED_AT = 1_899_990_000


class _FakeRtmr:
    """RTMR3 of a fake TD: extends as TDG.MR.RTMR.EXTEND does."""

    def __init__(self) -> None:
        self.value = bytes(48)
        self.extends: list[bytes] = []
        self.fail: Exception | None = None
        self.fail_after_landing = False
        self.unreadable = False

    def read(self) -> bytes:
        if self.unreadable:
            raise OSError("no such file")
        return self.value

    def extend(self, digest: bytes) -> None:
        self.extends.append(digest)
        if self.fail is not None and not self.fail_after_landing:
            raise self.fail
        self.value = rtmr_extend(self.value, digest)
        if self.fail is not None:
            raise self.fail


class _BootIds:
    """An injectable kernel boot id and RTMR3; ``relaunch`` stands for a new boot."""

    def __init__(self) -> None:
        self.value = str(uuid.uuid4())
        self.rtmr = _FakeRtmr()

    def __call__(self) -> str:
        return self.value

    def relaunch(self) -> None:
        self.value = str(uuid.uuid4())
        self.rtmr = _FakeRtmr()


class _CurrentRtmr:
    """Follows ``boot_ids.rtmr``, which a relaunch replaces."""

    def __init__(self, boot_ids: _BootIds) -> None:
        self.boot_ids = boot_ids

    def read(self) -> bytes:
        return self.boot_ids.rtmr.read()

    def extend(self, digest: bytes) -> None:
        self.boot_ids.rtmr.extend(digest)


def _boot(boot_ids=None, marker=None, clock=None) -> BootGuard:
    kwargs = {} if clock is None else {"clock": clock}
    boot_ids = boot_ids or _BootIds()
    return BootGuard(
        None if marker is None else str(marker),
        rtmr=_CurrentRtmr(boot_ids),
        read_boot_id=boot_ids,
        read_booted_at=lambda: BOOTED_AT,
        **kwargs,
    )


def _api(
    tmp_path: Path, binding, *, clock=None, executor=None, ready=True, boot_ids=None, marker=None
):
    fake = executor or FakeExecutor()
    kwargs = {} if clock is None else {"clock": clock}
    api = TeeBoxSandboxApi(
        executor=fake,
        authorizer=_authorizer(tmp_path, binding),
        egress=build_egress_policy([BOX_IP]),
        capacity=CAPACITY,
        default_shape=DEFAULT_SHAPE,
        boot=_boot(boot_ids, marker, clock),
        **kwargs,
    )
    if ready:
        _push_revocations(api)
    return api, fake


def _header(
    binding,
    method: str,
    target: str,
    body: bytes = b"",
    *,
    central_seed: bytes = CENTRAL_SEED,
    delegation: dict[str, object] | None = None,
    issued_at: datetime | None = None,
    lifetime: int = 60,
    nonce: bytes | None = None,
    worker_hotkey: str = WORKER_HOTKEY,
) -> str:
    issued_at = issued_at or _now()
    return ca.build_central_request_header(
        delegation=delegation if delegation is not None else _delegation(central_seed=central_seed),
        central_seed=central_seed,
        worker_hotkey=worker_hotkey,
        network=NETWORK,
        netuid=NETUID,
        method=method,
        path=target,
        body=body,
        channel_binding=binding,
        nonce=nonce or os.urandom(32),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=lifetime),
    )


class _Box:
    """A worker with the sandbox API enabled, over real TLS."""

    def __init__(self, tmp_path: Path, *, ready: bool = True, **api_kwargs) -> None:
        server_context, self.client_context, self.binding = _tls_contexts(tmp_path)
        self.boot_ids = api_kwargs.setdefault("boot_ids", _BootIds())
        self.api, self.fake = _api(tmp_path, self.binding, ready=False, **api_kwargs)
        self.server = WorkerServer(
            configured_hotkey=WORKER_HOTKEY,
            channel_binding=self.binding,
            tls_context=server_context,
            tee_box_api=self.api,
        )
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        if ready:
            status, _type, raw = self.call(
                "POST", "/v1/box/revocations", canonical_json(_revocations())
            )
            assert status == 200, raw

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
        return self.raw(method, target, body, {CENTRAL_HEADER: header})

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
    assert contract["boot"] == {
        "boot_id": box.boot_ids.value,
        "booted_at": BOOTED_AT,
        "consumed": False,
        "consumed_by_caller": False,
        "needs_relaunch": False,
        "last_released_at": None,
        "rtmr3": "00" * 48,
        "rtmr3_extended": False,
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
    assert box.json("DELETE", "/v1/lease")[1] == {
        "released": True,
        "draining": False,
        "needs_relaunch": True,
    }
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
        assert route_scope(method, target) is None
        assert box.call(method, target, b"{}")[0] == 401


def test_one_customer_at_a_time_and_release_drains(box: _Box):
    _lease_and_image(box)
    first = _create(box)["id"]
    second = _create(box)["id"]
    busy = box.json("POST", "/v1/lease", {"ttl_seconds": 600}, central_seed=OTHER_CENTRAL_SEED)
    assert busy == (409, {"error": "the box is leased to another customer", "reason": "box_busy"})
    for method, target in (
        ("GET", "/v1/sandboxes"),
        ("GET", f"/v1/sandboxes/{first}"),
        ("DELETE", f"/v1/sandboxes/{first}"),
        ("DELETE", "/v1/lease"),
    ):
        assert box.json(method, target, central_seed=OTHER_CENTRAL_SEED)[1]["reason"] == "box_busy"
    assert (
        box.json(
            "POST",
            "/v1/sandboxes",
            {"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 60},
            central_seed=OTHER_CENTRAL_SEED,
        )[0]
        == 409
    )
    assert box.json("GET", "/v1/box", central_seed=OTHER_CENTRAL_SEED)[1]["lease"]["held"] is True
    assert box.fake.deleted == []

    assert box.json("DELETE", "/v1/lease")[1] == {
        "released": True,
        "draining": False,
        "needs_relaunch": True,
    }
    assert sorted(box.fake.deleted) == sorted([first, second])
    # The next customer waits for the VM to be relaunched (decision 1).
    refused = box.json("POST", "/v1/lease", {"ttl_seconds": 600}, central_seed=OTHER_CENTRAL_SEED)
    assert refused == (
        409,
        {
            "error": "another customer used this boot; the VM must be relaunched first",
            "reason": "relaunch_required",
        },
    )
    box.boot_ids.relaunch()
    status, lease = box.json(
        "POST", "/v1/lease", {"ttl_seconds": 600}, central_seed=OTHER_CENTRAL_SEED
    )
    assert status == 200 and lease["lease"]["holder"] == OTHER
    assert box.json("GET", "/v1/sandboxes", central_seed=OTHER_CENTRAL_SEED)[1] == {"sandboxes": []}


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
    boot_ids = _BootIds()
    api, fake = _api(tmp_path, _binding(), clock=clock, boot_ids=boot_ids)
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
    # Expired and drained, but another customer still needs a relaunch.
    status, refused = _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 120})
    assert (status, refused["reason"]) == (409, "relaunch_required")
    assert fake.deleted == [view["id"]]
    boot_ids.relaunch()
    status, lease = _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 120})
    assert status == 200 and lease["lease"]["holder"] == OTHER
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
    assert box.raw("GET", "/v1/box", headers={CENTRAL_HEADER: "junk"})[0] == 401
    # A central key the root never delegated to, signing under another key's delegation.
    assert (
        box.call("GET", "/v1/box", central_seed=STRANGER_SEED, delegation=_delegation())[0] == 401
    )
    # A delegation the pinned root did not sign.
    stranger = _delegation(central_seed=STRANGER_SEED, root_seed=OTHER_ROOT_SEED)
    assert box.call("GET", "/v1/box", central_seed=STRANGER_SEED, delegation=stranger)[0] == 401
    # An expired request, and a request under an expired delegation.
    assert box.call("GET", "/v1/box", issued_at=_now() - timedelta(minutes=5))[0] == 401
    expired = _delegation(issued_at=_now() - timedelta(hours=3))
    assert box.call("GET", "/v1/box", delegation=expired)[0] == 401
    # A delegation for another subnet, and a request for another worker.
    other_subnet = _delegation(netuid=(NETUID % 65_535) + 1)
    assert box.call("GET", "/v1/box", delegation=other_subnet)[0] == 401
    other_worker = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
    assert box.call("GET", "/v1/box", worker_hotkey=other_worker)[0] == 401
    # Signed for one target, sent to another; and a query the signature did not cover.
    header = _header(box.binding, "GET", "/v1/lease")
    assert box.raw("GET", "/v1/box", headers={CENTRAL_HEADER: header})[0] == 401
    sid = _create(box)["id"]
    header = _header(box.binding, "GET", f"/v1/sandboxes/{sid}/files?path=/a")
    assert (
        box.raw(
            "GET",
            f"/v1/sandboxes/{sid}/files?path=/etc/shadow",
            headers={CENTRAL_HEADER: header},
        )[0]
        == 401
    )
    # Signed for one method, sent with another.
    header = _header(box.binding, "GET", f"/v1/sandboxes/{sid}")
    assert box.raw("DELETE", f"/v1/sandboxes/{sid}", headers={CENTRAL_HEADER: header})[0] == 401
    # A body the signature did not cover.
    body = json.dumps({"ttl_seconds": 600}).encode()
    header = _header(box.binding, "POST", "/v1/lease", body)
    assert box.raw("POST", "/v1/lease", b'{"ttl_seconds":900}', {CENTRAL_HEADER: header})[0] == 401
    # A replayed request.
    header = _header(box.binding, "GET", "/v1/box")
    assert box.raw("GET", "/v1/box", headers={CENTRAL_HEADER: header})[0] == 200
    assert box.raw("GET", "/v1/box", headers={CENTRAL_HEADER: header})[0] == 401
    # Two central headers, or a validator header beside one.
    header = _header(box.binding, "GET", "/v1/box")
    assert (
        box.raw(
            "GET",
            "/v1/box",
            headers={CENTRAL_HEADER: header, "X-Cathedral-Validator-Request": "x"},
        )[0]
        == 401
    )
    # Unknown paths in the namespace are refused before any handler runs,
    # even under a validly signed central request.
    assert box.raw("GET", "/v1/sandboxes/sbx-x/ports")[0] == 401
    for method, target in (("GET", f"/v1/sandboxes/{sid}/ports"), ("POST", "/v1/sandboxes/fork")):
        body = b"" if method == "GET" else b"{}"
        assert box.call(method, target, body)[0] == 401, (method, target)
    assert box.fake.get(sid) is not None


def test_a_bad_request_signature_is_refused(box: _Box):
    header = _header(box.binding, "GET", "/v1/box")
    document = json.loads(base64.b64decode(header))
    document["nonce_hex"] = "ab" * 32
    tampered = base64.b64encode(canonical_json(document)).decode("ascii")
    assert box.raw("GET", "/v1/box", headers={CENTRAL_HEADER: tampered})[0] == 401
    # Signed by the root key itself instead of the delegated central key.
    header = _header(
        box.binding, "GET", "/v1/box", central_seed=ROOT_SEED, delegation=_delegation()
    )
    assert box.raw("GET", "/v1/box", headers={CENTRAL_HEADER: header})[0] == 401


# One request per route, each with the scope it needs.
_SCOPED_ROUTES = (
    ("tee-box:box", "GET", "/v1/box", None),
    ("tee-box:lease", "GET", "/v1/lease", None),
    ("tee-box:lease", "POST", "/v1/lease", {"ttl_seconds": 600}),
    (
        "tee-box:image-import",
        "POST",
        "/v1/images/import",
        {"digest": DIGEST, "reference": "registry.example/tasks/base"},
    ),
    ("tee-box:image-import", "GET", f"/v1/images/{DIGEST}", None),
    (
        "tee-box:create",
        "POST",
        "/v1/sandboxes",
        {"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 3600},
    ),
    ("tee-box:list", "GET", "/v1/sandboxes", None),
    ("tee-box:get", "GET", "/v1/sandboxes/{sid}", None),
    ("tee-box:lifetime", "POST", "/v1/sandboxes/{sid}/lifetime", {"extend_by_seconds": 60}),
    ("tee-box:exec", "POST", "/v1/sandboxes/{sid}/exec", {"command": "true"}),
    ("tee-box:exec", "POST", "/v1/sandboxes/{sid}/execs", {"command": "true"}),
    ("tee-box:files", "PUT", "/v1/sandboxes/{sid}/files?path=/a", b"x"),
    ("tee-box:files", "GET", "/v1/sandboxes/{sid}/files?path=/a", None),
    ("tee-box:files", "GET", "/v1/sandboxes/{sid}/stat?path=/a", None),
    ("tee-box:files", "GET", "/v1/sandboxes/{sid}/tar?path=/", None),
    ("tee-box:delete", "DELETE", "/v1/sandboxes/{sid}", None),
    ("tee-box:lease", "DELETE", "/v1/lease", None),
)


def test_every_route_needs_exactly_its_scope(box: _Box):
    from cathedral.tee_box import ROUTE_SCOPES, route_scope

    assert frozenset(ROUTE_SCOPES.values()) == ca.TEE_BOX_CENTRAL_SCOPES
    assert ca.TEE_BOX_CENTRAL_SCOPES <= ca.CENTRAL_ROUTES
    sid = None
    for scope, method, template, body in _SCOPED_ROUTES:
        target = template.format(sid=sid)
        assert route_scope(method, target) == scope, (method, target)
        raw = (
            body if isinstance(body, bytes) else b"" if body is None else json.dumps(body).encode()
        )
        others = sorted(ca.TEE_BOX_CENTRAL_SCOPES - {scope})
        # Every scope but this one: refused before any handler runs.
        wrong = _delegation(routes=others)
        assert box.call(method, target, raw, delegation=wrong)[0] == 401, (method, target)
        # A /v1/capabilities delegation does not reach the sandbox API.
        path_only = _delegation(routes=["/v1/capabilities"])
        assert box.call(method, target, raw, delegation=path_only)[0] == 401
        # This scope alone: served.
        status, _type, answer = box.call(
            method, target, raw, delegation=_delegation(routes=[scope])
        )
        assert status in {200, 201}, (method, target, status, answer)
        if template == "/v1/sandboxes" and method == "POST":
            sid = json.loads(answer)["id"]


def test_scoped_requests_do_not_open_the_path_routes(tmp_path: Path):
    # A scope names TEE box routes only: it is no path route, and a scoped
    # request never passes as a POST to /v1/capabilities.
    binding = _binding()
    authorizer = _authorizer(tmp_path, binding)
    now = datetime.now(UTC)
    header = _header(binding, "POST", "tee-box:box", b"{}")
    with pytest.raises(ca.CentralAccessError, match="target does not match"):
        authorizer.preauthorize(header, method="POST", path="tee-box:box", now=now)
    header = _header(binding, "GET", "/v1/box")
    with pytest.raises(ca.CentralAccessError, match="scope is unknown"):
        authorizer.preauthorize(header, method="GET", path="/v1/box", now=now, scope="/v1/box")
    with pytest.raises(ca.CentralAccessError, match="target does not match"):
        authorizer.preauthorize(
            _header(binding, "PATCH", "/v1/box"),
            method="PATCH",
            path="/v1/box",
            now=now,
            scope="tee-box:box",
        )


def test_a_revoked_delegation_is_refused_on_every_route(box: _Box):
    delegation = _delegation()
    assert box.call("GET", "/v1/box", delegation=delegation)[0] == 200
    revoked = _revocations(2, [_delegation_digest(delegation)])
    assert box.call("POST", "/v1/box/revocations", canonical_json(revoked))[0] == 200
    for method, target in (("GET", "/v1/box"), ("POST", "/v1/lease"), ("GET", "/v1/sandboxes")):
        body = b'{"ttl_seconds":600}' if method == "POST" else b""
        assert box.call(method, target, body, delegation=delegation)[0] == 401
    # A fresh delegation to the same central key is served again.
    assert box.call("GET", "/v1/box", delegation=_delegation(sequence=6))[0] == 200


def test_no_route_but_box_is_served_before_a_revocation_list_is_pushed(tmp_path: Path):
    box = _Box(tmp_path, ready=False)
    try:
        status, contract = box.json("GET", "/v1/box")
        assert status == 200
        assert contract["revocations"] == {
            "pushed": False,
            "sequence": 0,
            "issued_at": None,
            "fresh": False,
        }
        for method, target, body in (
            ("POST", "/v1/lease", {"ttl_seconds": 600}),
            ("GET", "/v1/sandboxes", None),
            ("POST", "/v1/images/import", {"digest": DIGEST, "reference": "r.example/a/b"}),
        ):
            status, refusal = box.json(method, target, body)
            assert (status, refusal["reason"]) == (409, "revocation_list_required")
        # Lists the pinned root did not sign, or not canonical, are refused.
        status, refusal = box.json(
            "POST", "/v1/box/revocations", canonical_json(_revocations(seed=OTHER_ROOT_SEED))
        )
        assert (status, refusal["reason"]) == (409, "revocations_refused")
        assert (
            box.json("POST", "/v1/box/revocations", json.dumps(_revocations(), indent=1).encode())[
                0
            ]
            == 400
        )
        assert box.json("GET", "/v1/box")[1]["revocations"]["pushed"] is False
        # A signed list opens the box; the same list may be pushed again, an older one not.
        signed = _now()
        pushed = canonical_json(_revocations(3, issued_at=signed))
        assert box.json("POST", "/v1/box/revocations", pushed)[1] == {
            "sequence": 3,
            "issued_at": int(signed.timestamp()),
        }
        assert box.json("POST", "/v1/box/revocations", pushed)[0] == 200
        status, refusal = box.json("POST", "/v1/box/revocations", canonical_json(_revocations(2)))
        assert (status, refusal["reason"]) == (409, "revocations_refused")
        assert box.json("POST", "/v1/lease", {"ttl_seconds": 600})[0] == 200
        assert box.json("GET", "/v1/box")[1]["revocations"] == {
            "pushed": True,
            "sequence": 3,
            "issued_at": int(signed.timestamp()),
            "fresh": True,
        }
    finally:
        box.close()


def test_the_sandbox_api_needs_a_central_authorizer(tmp_path: Path):
    from cathedral.validator_access import ValidatorAccessState

    with pytest.raises(ValueError, match="central access authorizer"):
        TeeBoxSandboxApi(
            executor=FakeExecutor(),
            authorizer=ValidatorAccessState(str(tmp_path / "state.sqlite")),
            egress=build_egress_policy([BOX_IP]),
            capacity=CAPACITY,
            default_shape=DEFAULT_SHAPE,
            boot=_boot(),
        )


def test_the_flag_configured_central_authorizer_cannot_serve_the_sandbox_api(tmp_path: Path):
    from tests.test_central_access_worker import _validator_authorizer

    server_context, _client, binding = _tls_contexts(tmp_path)
    api, _fake = _api(tmp_path, binding)
    with pytest.raises(ValueError, match="must not share the flag-configured one"):
        WorkerServer(
            configured_hotkey=WORKER_HOTKEY,
            channel_binding=binding,
            tls_context=server_context,
            validator_authorizer=_validator_authorizer(tmp_path, binding),
            fleet_endpoints=("https://127.0.0.1:1",),
            tee_box_api=api,
            central_authorizer=api.authorizer,
        )


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
    boot_ids = _BootIds()
    api, fake = _api(tmp_path, _binding(), clock=clock, boot_ids=boot_ids)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    leftover = _one_sandbox(api)
    fake.delete_fails = True
    assert _handle(api, "DELETE", "/v1/lease")[1] == {
        "released": True,
        "draining": True,
        "needs_relaunch": True,
    }
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})[1]["reason"] == (
        "relaunch_required"
    )
    # Even after a relaunch (simulated in process), the drain still gates.
    boot_ids.relaunch()
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
    boot_ids = _BootIds()
    api, fake = _api(tmp_path, _binding(), clock=clock, boot_ids=boot_ids)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    stuck = _one_sandbox(api)
    fake.delete_fails = True
    clock.value += 61
    api.reap()
    assert api.lease.current() is None and _draining(api, CALLER)
    boot_ids.relaunch()
    assert _draining(api)
    fake.delete_fails = False
    # Ordinary calls space their retries; the next one after the gap drains.
    assert _draining(api)
    clock.value += 2
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})[0] == 200
    assert fake.deleted == [stuck]


def test_an_untracked_container_blocks_the_hand_over(tmp_path: Path):
    # A container the table lost (a timed-out create, an earlier process)
    # may belong to the old customer, so the sweep must clear it first.
    boot_ids = _BootIds()
    api, fake = _api(tmp_path, _binding(), clock=_Clock(), boot_ids=boot_ids)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    sid = _one_sandbox(api)
    fake.orphans.add("cathsbx-sbx-" + "9" * 24)
    fake.orphans_stuck = True
    assert _handle(api, "DELETE", "/v1/lease")[1] == {
        "released": True,
        "draining": True,
        "needs_relaunch": True,
    }
    boot_ids.relaunch()
    assert fake.deleted == [sid] and _draining(api) and _draining(api, CALLER)
    fake.orphans_stuck = False
    api.reap()  # the reaper's tick
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})[0] == 200
    assert fake.orphans == set()


def _fresh(tmp_path: Path, fake: FakeExecutor):
    clock = _Clock()
    api, _ = _api(tmp_path, _binding(), clock=clock, executor=fake, ready=False)
    # Mark the list pushed without a call: any call would run the first sweep.
    api._revocations_issued_at = clock.value  # noqa: SLF001
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


def test_an_expiry_found_under_the_create_lock_never_runs_the_drain_there():
    # Review of 5b1f5ea: a lease expiring between the route's require and the
    # create's locked require ran the drain while holding the lease lock, so a
    # hung daemon blocked every caller instead of refusing them as draining.
    from cathedral.tee_box.lease import CustomerLease, LeaseDraining

    now = [1000.0]
    drains: list[str] = []

    def drain(holder: str) -> bool:
        drains.append(holder)
        return True

    lease = CustomerLease(drain, clock=lambda: now[0])
    lease.retry_drain()  # a fresh box starts draining until its first clean sweep
    assert not lease.draining
    lease.acquire("customer-a", 60)
    drains.clear()
    now[0] += 61  # the lease expires
    with lease.locked():
        with pytest.raises(LeaseDraining):
            lease.require_locked("customer-a")
    assert drains == []  # nothing drained while the lock was held
    assert lease.draining
    lease.retry_drain()  # the drain runs later, outside the lock
    assert drains == ["customer-a"] and not lease.draining


class _DenyAllExecutor(FakeExecutor):
    """An executor whose egress table is down: deny_all only, with the error reported."""

    @property
    def network_modes(self) -> tuple[str, ...]:
        return ("deny_all",)

    def egress_status(self):
        return {"enforced": False, "error": "nft apply failed"}


def test_the_box_reports_egress_enforcement_and_refuses_internet_without_it(tmp_path: Path):
    api, fake = _api(tmp_path, _binding(), executor=_DenyAllExecutor())
    status, contract = _handle(api, "GET", "/v1/box")
    assert status == 200
    assert contract["network_modes"] == ["deny_all"]
    assert contract["egress"]["enforced"] is False
    assert contract["egress"]["enforcement_error"] == "nft apply failed"
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 60})[0] == 200
    fake.import_image(DIGEST, "registry.example/tasks/base")
    status, refusal = _handle(
        api,
        "POST",
        "/v1/sandboxes",
        body={"image_id": DIGEST, "network": "internet", "lifetime_seconds": 600},
    )
    assert (status, refusal["reason"]) == (409, "network_unavailable")
    assert fake.list() == ()


class _LapsedExecutor(FakeExecutor):
    def exec(self, sandbox_id, request):
        from cathedral.tee_box.executor import NetworkLapsed

        raise NetworkLapsed("lapsed")


def test_a_lapsed_sandbox_call_is_refused_with_its_reason(tmp_path: Path):
    api, fake = _api(tmp_path, _binding(), executor=_LapsedExecutor())
    fake.import_image(DIGEST, "registry.example/tasks/base")
    sid = _one_sandbox(api)
    status, refusal = _handle(api, "POST", f"/v1/sandboxes/{sid}/exec", body={"command": "true"})
    assert (status, refusal["reason"]) == (409, "sandbox_network_lapsed")


class _SlowReapExecutor(FakeExecutor):
    """A docker-bound reaper stuck on a slow daemon; the egress check still runs."""

    def __init__(self) -> None:
        super().__init__()
        self.release = threading.Event()
        self.checks = 0

    def sweep(self) -> int:
        self.release.wait(30)
        return 0

    def check_egress(self) -> int:
        self.checks += 1
        return 0


def test_the_egress_check_runs_on_its_own_thread(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("cathedral.worker.TEE_BOX_EGRESS_CHECK_INTERVAL_SECONDS", 0.05)
    executor = _SlowReapExecutor()
    box = _Box(tmp_path, executor=executor)
    try:
        deadline = time.monotonic() + 10
        while executor.checks < 5 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert executor.checks >= 5, "the egress check waited behind the reaper"
    finally:
        executor.release.set()
        box.close()


def test_a_revoked_delegation_cannot_reopen_a_relaunched_box_with_a_stale_list(tmp_path: Path):
    # Review of 5f7d355: after a relaunch the central state is empty, so any
    # root-signed list passed the sequence check. A stolen delegation revoked
    # under list 2 pushed the older list 1 and reopened every route.
    delegation = _delegation()
    list_one = _revocations(1, issued_at=_now() - timedelta(hours=30))
    list_two = _revocations(2, [_delegation_digest(delegation)])
    for name in ("before", "relaunched"):
        (tmp_path / name).mkdir(mode=0o700)
    before = _Box(tmp_path / "before", ready=False)
    try:
        assert before.call("POST", "/v1/box/revocations", canonical_json(list_two))[0] == 200
        assert before.call("GET", "/v1/box", delegation=delegation)[0] == 401
    finally:
        before.close()
    relaunched = _Box(tmp_path / "relaunched", ready=False)
    try:
        status, refusal = relaunched.json(
            "POST", "/v1/box/revocations", canonical_json(list_one), delegation=delegation
        )
        assert (status, refusal["reason"]) == (409, "revocations_stale")
        contract = relaunched.json("GET", "/v1/box", delegation=delegation)[1]
        assert contract["revocations"]["pushed"] is False
        status, refusal = relaunched.json(
            "POST", "/v1/lease", {"ttl_seconds": 600}, delegation=delegation
        )
        assert (status, refusal["reason"]) == (409, "revocation_list_required")
        # The current list closes the delegation for good.
        assert relaunched.call("POST", "/v1/box/revocations", canonical_json(list_two))[0] == 200
        assert relaunched.call("GET", "/v1/box", delegation=delegation)[0] == 401
    finally:
        relaunched.close()


@pytest.mark.parametrize(
    "issued_at",
    [
        lambda now: now - timedelta(seconds=24 * 3600 + 1),
        lambda now: now + timedelta(seconds=16),
    ],
)
def test_a_stale_or_future_list_is_refused(tmp_path: Path, issued_at):
    clock = _Clock()
    api, _fake = _api(tmp_path, _binding(), clock=clock, ready=False)
    now = datetime.fromtimestamp(clock.value, UTC)
    response = api.handle(
        "POST",
        "/v1/box/revocations",
        CALLER,
        canonical_json(_revocations(issued_at=issued_at(now))),
    )
    assert (response.status, json.loads(response.body)["reason"]) == (409, "revocations_stale")
    assert api.authorizer.revocations_sequence == 0  # never installed
    # At the bounds, a list is fresh.
    for edge in (now - timedelta(seconds=24 * 3600), now + timedelta(seconds=15)):
        body = canonical_json(_revocations(2, issued_at=edge))
        assert api.handle("POST", "/v1/box/revocations", CALLER, body).status == 200


def test_the_gate_closes_when_the_pushed_list_goes_stale(tmp_path: Path):
    from cathedral.tee_box.service import MAX_REVOCATIONS_AGE_SECONDS

    assert MAX_REVOCATIONS_AGE_SECONDS == ca.MAX_DELEGATION_SECONDS
    clock = _Clock()
    api, _fake = _api(tmp_path, _binding(), clock=clock)  # pushes a list signed now
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 60})[0] == 200
    clock.value += MAX_REVOCATIONS_AGE_SECONDS
    assert _handle(api, "GET", "/v1/lease")[0] == 200
    clock.value += 1
    status, refusal = _handle(api, "GET", "/v1/sandboxes")
    assert (status, refusal["reason"]) == (409, "revocation_list_stale")
    status, contract = _handle(api, "GET", "/v1/box")
    assert status == 200
    assert contract["revocations"]["pushed"] is True
    assert contract["revocations"]["fresh"] is False
    # The same list again is still stale; a freshly signed one reopens the box.
    stale = canonical_json(_revocations(issued_at=datetime.fromtimestamp(1_900_000_000, UTC)))
    assert api.handle("POST", "/v1/box/revocations", CALLER, stale).status == 409
    fresh = canonical_json(_revocations(2, issued_at=datetime.fromtimestamp(int(clock.value), UTC)))
    assert api.handle("POST", "/v1/box/revocations", CALLER, fresh).status == 200
    assert _handle(api, "GET", "/v1/box")[1]["revocations"]["fresh"] is True
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 60})[0] == 200


def test_the_gate_follows_the_signed_issued_at_not_the_push_time(tmp_path: Path):
    # A list signed 23 h ago is fresh when pushed, and goes stale about 1 h
    # later, not 24 h after the push.
    clock = _Clock()
    api, _fake = _api(tmp_path, _binding(), clock=clock, ready=False)
    signed = datetime.fromtimestamp(int(clock.value) - 23 * 3600, UTC)
    body = canonical_json(_revocations(issued_at=signed))
    assert api.handle("POST", "/v1/box/revocations", CALLER, body).status == 200
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 7200})[0] == 200
    clock.value += 3600 + 1
    status, refusal = _handle(api, "GET", "/v1/lease")
    assert (status, refusal["reason"]) == (409, "revocation_list_stale")
