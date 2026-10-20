"""DockerGuestProvider create path against a fake docker CLI (no daemon needed).

Defects from the 2026-10-20 pool qualification run:
1. every create ran docker pull;
2. a pull failure left a ghost sandbox that held quota.

"""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, PrefetchRequest, Resources
from cathedral.sandbox_guest import DockerGuestProvider, mirror_ref
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    return install(tmp_path, monkeypatch)


def _req(image: str = "alpine:3.20", **over) -> CreateSandboxRequest:
    values = {"image": ImageSource(image=image), "resources": Resources(vcpu=1, memory_gib=1, disk_gib=5)}
    values.update(over)
    return CreateSandboxRequest(**values)


def _create(provider, image="alpine:3.20", key=None, digest="b", **over):
    return provider.create(_req(image, **over), api_key="k", idempotency=key, body_digest=digest)


def _resident(provider) -> int:
    return provider.quota()["usage"]["resident_sandboxes"]


# ---------------------------------------------------------------- D1: pull policy
def test_second_create_of_same_image_does_not_pull(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        _create(provider)
        _create(provider, digest="c")
        assert fake.calls_of("pull") == [["pull", "alpine:3.20"]]
    finally:
        provider.close()


def test_image_already_local_is_not_pulled(fake: FakeDocker) -> None:
    fake.add_image("alpine:3.20")
    provider = DockerGuestProvider()
    try:
        _create(provider)
        assert fake.calls_of("pull") == []
    finally:
        provider.close()


def test_prefetch_always_refreshes(fake: FakeDocker) -> None:
    fake.add_image("alpine:3.20")
    provider = DockerGuestProvider()
    try:
        provider.prefetch(PrefetchRequest(images=("alpine:3.20",)))
        assert fake.calls_of("pull") == [["pull", "alpine:3.20"]]
    finally:
        provider.close()


def test_pull_policy_always_restores_old_behaviour(fake: FakeDocker, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_PULL_POLICY", "always")
    fake.add_image("alpine:3.20")
    provider = DockerGuestProvider()
    try:
        _create(provider)
        assert len(fake.calls_of("pull")) == 1
    finally:
        provider.close()


def test_image_pulled_with_credentials_is_pulled_again(fake: FakeDocker) -> None:
    # A cached private image must not skip the registry credential check.
    provider = DockerGuestProvider()
    try:
        auth = {"username": "u", "password": "p"}
        request = CreateSandboxRequest(
            image=ImageSource(image="ghcr.io/acme/private:1", registry_auth=auth),
            resources=Resources(vcpu=1, memory_gib=1, disk_gib=5),
        )
        provider.create(request, api_key="k", idempotency=None, body_digest="1")
        _create(provider, image="ghcr.io/acme/private:1", digest="2")
        assert len(fake.calls_of("pull")) == 2
    finally:
        provider.close()


def test_registry_mirror_is_used_for_docker_hub(fake: FakeDocker, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_REGISTRY_MIRROR", "mirror.gcr.io")
    provider = DockerGuestProvider()
    try:
        _create(provider)
        assert fake.calls_of("pull") == [["pull", "mirror.gcr.io/library/alpine:3.20"]]
        assert fake.calls_of("tag") == [["tag", "mirror.gcr.io/library/alpine:3.20", "alpine:3.20"]]
    finally:
        provider.close()


def test_registry_mirror_failure_falls_back_to_direct_pull(fake: FakeDocker, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_REGISTRY_MIRROR", "mirror.gcr.io")
    fake.set(pull_fail=["mirror.gcr.io/library/alpine:3.20"])
    provider = DockerGuestProvider()
    try:
        _create(provider)
        assert [c[-1] for c in fake.calls_of("pull")] == ["mirror.gcr.io/library/alpine:3.20", "alpine:3.20"]
    finally:
        provider.close()


@pytest.mark.parametrize(
    ("image", "want"),
    [
        ("alpine:3.20", "m.io/library/alpine:3.20"),
        ("docker.io/library/alpine:3.20", "m.io/library/alpine:3.20"),
        ("acme/tool:1", "m.io/acme/tool:1"),
        ("ghcr.io/acme/tool:1", None),
        ("localhost:5000/x:1", None),
        ("alpine@sha256:" + "a" * 64, None),
    ],
)
def test_mirror_ref(image: str, want: str | None) -> None:
    assert mirror_ref("m.io/", image) == want


# ---------------------------------------------------------------- D2: pull failure
def test_pull_failure_releases_record_and_quota(fake: FakeDocker) -> None:
    fake.set(pull_fail=["acme/missing:1"])
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as err:
            _create(provider, image="acme/missing:1")
        assert err.value.code == "image_pull_failed" and err.value.http_status == 502
        assert provider.list(labels=[], state=None) == []
        assert _resident(provider) == 0
        assert fake.calls_of("run") == []
    finally:
        provider.close()


def test_pull_failure_returns_stable_json_error_over_http(fake: FakeDocker) -> None:
    fake.set(pull_fail=["acme/missing:1"])
    provider = DockerGuestProvider()
    app = SandboxApplication(provider)
    try:
        body = json.dumps({"image": "acme/missing:1"}).encode()
        resp = app.dispatch("POST", "/v1/sandboxes", {"Authorization": "Bearer k"}, body)
        assert resp.status == 502
        assert json.loads(resp.body)["error"]["code"] == "image_pull_failed"
        quota = json.loads(app.dispatch("GET", "/v1/quota", {"Authorization": "Bearer k"}, b"").body)
        assert quota["usage"]["resident_sandboxes"] == 0
    finally:
        provider.close()


def test_idempotent_retry_after_pull_failure_creates_again(fake: FakeDocker) -> None:
    fake.set(pull_fail=["acme/flaky:1"])
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError):
            _create(provider, image="acme/flaky:1", key="retry-key-0001")
        fake.set(pull_fail=[])
        doc = _create(provider, image="acme/flaky:1", key="retry-key-0001")
        assert doc["guest"]["container_id"]
        assert provider.get(doc["id"])["state"] == "running"
    finally:
        provider.close()
