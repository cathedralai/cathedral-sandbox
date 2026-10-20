"""Room networks: guests with a network are spread over several Docker bridges.

One Linux bridge takes at most 1,024 ports. In the 2026-10-20 load test a room
host stopped at 1,023 guests ("exchange full"). The fake docker CLI models the
port limit per network with the ``bridge_ports`` behaviour.
"""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, NetworkSpec, Resources
from cathedral.sandbox_guest import DockerGuestProvider, RoomNetworkPool
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    f = install(tmp_path, monkeypatch)
    f.add_image("alpine:3.20")
    return f


def _pool_env(monkeypatch, *, count: int = 2, size: int = 2, subnets: str = "", bridge_prefix: str = "") -> None:
    monkeypatch.setenv("CATHEDRAL_ROOM_NETWORKS", str(count))
    monkeypatch.setenv("CATHEDRAL_ROOM_NETWORK_SIZE", str(size))
    monkeypatch.setenv("CATHEDRAL_ROOM_NETWORK_PREFIX", "room-net")
    if subnets:
        monkeypatch.setenv("CATHEDRAL_ROOM_NETWORK_SUBNETS", subnets)
    if bridge_prefix:
        monkeypatch.setenv("CATHEDRAL_ROOM_NETWORK_BRIDGE_PREFIX", bridge_prefix)


def _create(provider, mode: str = "public", digest: str = "b"):
    req = CreateSandboxRequest(
        image=ImageSource(image="alpine:3.20"),
        resources=Resources(vcpu=1, memory_gib=1, disk_gib=5),
        network=NetworkSpec(mode=mode),
    )
    return provider.create(req, api_key="k", idempotency=None, body_digest=digest)


def _members(fake: FakeDocker) -> dict[str, int]:
    return {name: len(net["containers"]) for name, net in fake.networks.items()}


def test_pool_off_keeps_default_bridge(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        doc = _create(provider)
        run = fake.calls_of("run")[-1]
        assert "--network" not in run
        assert doc["guest"]["network_name"] is None
        assert fake.calls_of("network", "create") == []
    finally:
        provider.close()


def test_networks_are_created_with_subnet_and_bridge_name(fake: FakeDocker, monkeypatch) -> None:
    _pool_env(monkeypatch, subnets="10.213.8.0/22,10.213.12.0/22", bridge_prefix="rmbr")
    provider = DockerGuestProvider()
    try:
        _create(provider)
        creates = fake.calls_of("network", "create")
        assert [c[-1] for c in creates] == ["room-net-0", "room-net-1"]
        assert "10.213.8.0/22" in creates[0] and "com.docker.network.bridge.name=rmbr1" in creates[1]
    finally:
        provider.close()


def test_existing_network_is_reused_and_counted(fake: FakeDocker, monkeypatch) -> None:
    _pool_env(monkeypatch, count=1, size=2)
    fake.set(bridge_ports=2)
    # A network left by an earlier API process, with one guest still attached.
    import subprocess

    subprocess.run(["docker", "network", "create", "room-net-0"], check=True, capture_output=True)
    fake.add_container("c" * 64, name="old", labels={})
    subprocess.run(["docker", "network", "connect", "room-net-0", "c" * 64], check=True)
    provider = DockerGuestProvider()
    try:
        _create(provider)
        assert fake.calls_of("network", "create") == [["network", "create", "room-net-0"]]  # only ours above
        with pytest.raises(SandboxOpError) as exc:
            _create(provider, digest="c")
        assert exc.value.code == "network_capacity_exhausted"
    finally:
        provider.close()


def test_full_network_moves_to_next(fake: FakeDocker, monkeypatch) -> None:
    _pool_env(monkeypatch, count=2, size=2)
    fake.set(bridge_ports=2)
    provider = DockerGuestProvider()
    try:
        docs = [_create(provider, digest=str(i)) for i in range(4)]
        assert _members(fake)["room-net-0"] == 2
        assert _members(fake)["room-net-1"] == 2
        assert {d["guest"]["network_name"] for d in docs} == {"room-net-0", "room-net-1"}
        assert all(d["state"] == "running" for d in docs)
    finally:
        provider.close()


def test_all_networks_full_is_a_clear_503_not_a_500(fake: FakeDocker, monkeypatch) -> None:
    _pool_env(monkeypatch, count=2, size=1)
    provider = DockerGuestProvider()
    app = SandboxApplication(provider)
    try:
        body = json.dumps({"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}).encode()
        for _ in range(2):
            assert app.dispatch("POST", "/v1/sandboxes", {"Authorization": "Bearer k"}, body).status == 202
        runs_before = len(fake.calls_of("run"))
        resp = app.dispatch("POST", "/v1/sandboxes", {"Authorization": "Bearer k"}, body)
        assert resp.status == 503
        assert json.loads(resp.body)["error"]["code"] == "network_capacity_exhausted"
        assert resp.headers.get("Retry-After") == "10"
        assert len(fake.calls_of("run")) == runs_before  # no docker run was tried
        quota = json.loads(app.dispatch("GET", "/v1/quota", {"Authorization": "Bearer k"}, b"").body)
        assert quota["usage"]["resident_sandboxes"] == 2  # the refused create holds nothing
        assert quota["room_networks"]["used"] == 2 and quota["room_networks"]["capacity"] == 2
    finally:
        provider.close()


def test_network_none_uses_no_port(fake: FakeDocker, monkeypatch) -> None:
    _pool_env(monkeypatch, count=1, size=1)
    provider = DockerGuestProvider()
    try:
        _create(provider)
        for i in range(3):
            doc = _create(provider, mode="none", digest=str(i))
            assert doc["guest"]["network_name"] is None
            assert fake.calls_of("run")[-1][fake.calls_of("run")[-1].index("--network") + 1] == "none"
        assert provider.room_networks()["used"] == 1
    finally:
        provider.close()


def test_delete_frees_a_port(fake: FakeDocker, monkeypatch) -> None:
    _pool_env(monkeypatch, count=1, size=1)
    provider = DockerGuestProvider()
    try:
        doc = _create(provider)
        with pytest.raises(SandboxOpError):
            _create(provider, digest="c")
        provider.delete(doc["id"])
        assert provider.room_networks()["used"] == 0
        again = _create(provider, digest="d")
        assert again["guest"]["network_name"] == "room-net-0"
    finally:
        provider.close()


def test_port_held_until_container_is_confirmed_gone(fake: FakeDocker, monkeypatch) -> None:
    _pool_env(monkeypatch, count=1, size=1)
    provider = DockerGuestProvider()
    try:
        doc = _create(provider)
        cid = doc["guest"]["container_id"]
        fake.set(rm_fail={cid: 1})
        provider.delete(doc["id"])  # rm fails once: record stays "deleting"
        assert provider.room_networks()["used"] == 1
        provider.sweep()  # retry succeeds
        assert provider.room_networks()["used"] == 0
    finally:
        provider.close()


def test_failed_docker_run_releases_the_port(fake: FakeDocker, monkeypatch) -> None:
    _pool_env(monkeypatch, count=1, size=1)
    fake.set(run_fail_images=["alpine:3.20"])
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as exc:
            _create(provider)
        assert exc.value.code == "guest_start_failed"
        assert provider.room_networks()["used"] == 0
    finally:
        provider.close()


def test_switch_to_none_and_back_moves_the_port(fake: FakeDocker, monkeypatch) -> None:
    from cathedral.sandbox_api import NetworkPatch

    _pool_env(monkeypatch, count=1, size=1)
    provider = DockerGuestProvider()
    try:
        doc = _create(provider)
        provider.set_network(doc["id"], NetworkPatch(mode="none"))
        assert provider.room_networks()["used"] == 0
        provider.set_network(doc["id"], NetworkPatch(mode="public"))
        assert provider.room_networks()["used"] == 1
        assert ["network", "connect", "room-net-0", doc["guest"]["container_id"]] in fake.calls
    finally:
        provider.close()


def test_pool_settings_are_checked() -> None:
    with pytest.raises(ValueError):
        RoomNetworkPool(count=2, subnets=("10.0.0.0/22",))
    assert RoomNetworkPool(count=1, size=5000).size == 1023
