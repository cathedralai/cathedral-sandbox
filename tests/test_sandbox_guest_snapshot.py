"""DockerGuestProvider snapshot and fork against a fake docker CLI.

Defects from run 5 (2026-10-20):
1. a fork from a snapshot this host does not have started the default image;
2. a snapshot could not leave its host (no push to a registry);
3. snapshot size_bytes measured only the /work archive.
"""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

RES = Resources(vcpu=1, memory_gib=1, disk_gib=5)
AUTH = {"username": "robot", "password": "s3cret-token"}


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    return docker


@pytest.fixture
def provider(fake):
    p = DockerGuestProvider()
    yield p
    p.close()


def _source(provider) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES)
    return provider.create(req, api_key="k", idempotency=None, body_digest="src")["id"]


def _fork(provider, ref: str, digest: str = "fork"):
    return provider.create(CreateSandboxRequest(snapshot_id=ref, resources=RES), api_key="k", idempotency=None, body_digest=digest)


def _snapshot(provider, sid: str, **kw) -> dict:
    return provider.get_operation(provider.snapshot(sid, **kw))["result"]


# ---------------------------------------------------------------- defect 1
def test_fork_of_unknown_snapshot_is_404_and_starts_nothing(fake, provider) -> None:
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, "snap_000000000000")
    assert (err.value.code, err.value.http_status) == ("snapshot_not_found", 404)
    assert fake.calls_of("run") == []
    assert provider.quota()["usage"]["resident_sandboxes"] == 0


def test_fork_by_name_uses_the_committed_image(fake, provider) -> None:
    sid = _source(provider)
    result = _snapshot(provider, sid, name="busy")
    doc = _fork(provider, "busy")
    assert doc["guest"]["image"] == f"cathedral-snap-{result['snapshot_id']}:latest"


def test_fork_of_snapshot_without_committed_image_is_409(fake, provider) -> None:
    sid = _source(provider)
    snap_id = _snapshot(provider, sid)["snapshot_id"]
    state = fake.state
    state["images"].remove(f"cathedral-snap-{snap_id}:latest")  # for example pruned by an operator
    fake._save(state)  # noqa: SLF001
    runs_before = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, snap_id)
    assert (err.value.code, err.value.http_status) == ("snapshot_image_missing", 409)
    assert len(fake.calls_of("run")) == runs_before


def test_unknown_snapshot_over_http_is_a_json_404(fake, provider) -> None:
    app = SandboxApplication(provider)
    body = json.dumps({"snapshot_id": "snap_000000000000"}).encode()
    response = app.dispatch("POST", "/v1/sandboxes", {"Authorization": "Bearer k"}, body)
    assert response.status == 404
    assert json.loads(response.body)["error"]["code"] == "snapshot_not_found"


def test_named_snapshot_is_not_committed_again(fake, provider) -> None:
    sid = _source(provider)
    _snapshot(provider, sid, name="busy")
    _snapshot(provider, sid, name="busy")
    assert len(fake.calls_of("commit")) == 1


# ---------------------------------------------------------------- defect 3
def test_snapshot_sizes_name_each_part(fake, provider) -> None:
    # Run 5: a 3.64 MB commit layer was reported as 259 bytes (the /work archive).
    image = "cathedral-snap-snap_aaaaaaaaaaaa:latest"
    fake.add_image(image)
    fake.set(image_sizes={"alpine:3.20": 100_000_000, image: 103_640_000})
    sizes = provider._snapshot_sizes("snap_aaaaaaaaaaaa", image, "alpine:3.20", 259)  # noqa: SLF001
    assert sizes["layer_size_bytes"] == 3_640_000
    assert sizes["image_size_bytes"] == 103_640_000
    assert sizes["work_archive_bytes"] == 259
    assert sizes["size_bytes"] == 3_640_259


def test_snapshot_result_and_list_carry_the_real_sizes(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    sizes = {"alpine:3.20": 100_000_000}
    real_commit = provider._client.commit  # noqa: SLF001

    def commit(container_id, image_name):
        out = real_commit(container_id, image_name)
        sizes[image_name] = 103_640_000
        fake.set(image_sizes=sizes)
        return out

    monkeypatch.setattr(provider._client, "commit", commit)  # noqa: SLF001
    result = _snapshot(provider, sid)
    assert result["layer_size_bytes"] == 3_640_000
    assert result["image_size_bytes"] == 103_640_000
    assert result["size_bytes"] == 3_640_000 + result["work_archive_bytes"]
    (listed,) = provider.list_snapshots()
    assert listed["size_bytes"] == result["size_bytes"]
    assert listed["layer_size_bytes"] == 3_640_000


# ---------------------------------------------------------------- defect 2 (hotel side)
def test_push_snapshot_tags_and_pushes_with_a_one_call_login(fake, provider) -> None:
    sid = _source(provider)
    snap_id = _snapshot(provider, sid)["snapshot_id"]
    out = provider.push_snapshot(snap_id, image="ghcr.io/acme/forks:md230", registry_auth=AUTH)
    assert out["image"] == "ghcr.io/acme/forks:md230"
    assert out["includes_work"] is False
    assert fake.calls_of("tag") == [["tag", f"cathedral-snap-{snap_id}:latest", "ghcr.io/acme/forks:md230"]]
    (pushed,) = fake.state["pushed"]
    assert pushed["auth"]["auths"]["ghcr.io"]["password"] == AUTH["password"]
    # The password is never on the docker command line.
    assert not any(AUTH["password"] in " ".join(c) for c in fake.calls)


def test_push_of_unknown_snapshot_is_404(fake, provider) -> None:
    with pytest.raises(SandboxOpError) as err:
        provider.push_snapshot("snap_000000000000", image="ghcr.io/acme/forks:x")
    assert err.value.code == "snapshot_not_found"


def test_push_route_over_http(fake, provider) -> None:
    app = SandboxApplication(provider)
    sid = _source(provider)
    snap_id = _snapshot(provider, sid)["snapshot_id"]
    body = json.dumps({"image": "ghcr.io/acme/forks:a", "registry_auth": AUTH}).encode()
    response = app.dispatch("POST", f"/v1/snapshots/{snap_id}/push", {"Authorization": "Bearer k"}, body)
    assert response.status == 200, response.body
    assert json.loads(response.body)["image"] == "ghcr.io/acme/forks:a"


def test_delete_snapshot_removes_its_image(fake, provider) -> None:
    sid = _source(provider)
    snap_id = _snapshot(provider, sid)["snapshot_id"]
    assert provider.delete_snapshot(snap_id) is True
    assert f"cathedral-snap-{snap_id}:latest" not in fake.state["images"]
    with pytest.raises(SandboxOpError):
        _fork(provider, snap_id)
