"""Image prefetch with an optional registry login, against a fake docker CLI.

Run 5 (2026-10-20): prefetch had no registry login, so a host could not pull
a private image before a job.
"""

from __future__ import annotations

import json
import os

import pytest

from cathedral.sandbox_api import PrefetchRequest
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

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


def test_prefetch_with_registry_login_uses_a_temp_config_that_is_deleted(fake, provider) -> None:
    op = provider.prefetch(PrefetchRequest(images=("ghcr.io/acme/private:1",), registry_auth=AUTH))
    (entry,) = fake.state["pull_auth"]
    assert entry["auth"]["auths"]["ghcr.io"] == AUTH
    assert not os.path.exists(entry["config_dir"])
    assert not any(AUTH["password"] in " ".join(c) for c in fake.calls)
    (pulled,) = provider.get_operation(op)["result"]["images"]
    assert pulled["ref"] == "ghcr.io/acme/private:1" and pulled["size_bytes"] == 1234


def test_prefetch_without_login_still_works(fake, provider) -> None:
    provider.prefetch(PrefetchRequest(images=("alpine:3.20",)))
    assert fake.calls_of("pull") == [["pull", "alpine:3.20"]]
    assert "pull_auth" not in fake.state


def test_prefetch_request_hides_the_password() -> None:
    req = PrefetchRequest(images=("ghcr.io/acme/private:1",), registry_auth=AUTH)
    assert AUTH["password"] not in repr(req)


def test_prefetch_route_passes_the_login(fake, provider) -> None:
    app = SandboxApplication(provider)
    body = json.dumps({"images": ["ghcr.io/acme/private:1"], "registry_auth": AUTH}).encode()
    response = app.dispatch("POST", "/v1/images/prefetch", {"Authorization": "Bearer k"}, body)
    assert response.status == 202, response.body
    assert fake.state["pull_auth"][0]["auth"]["auths"]["ghcr.io"] == AUTH
    assert AUTH["password"] not in response.body.decode()


def test_prefetch_route_rejects_a_bad_login(fake, provider) -> None:
    app = SandboxApplication(provider)
    body = json.dumps({"images": ["alpine:3.20"], "registry_auth": {"username": "u"}}).encode()
    response = app.dispatch("POST", "/v1/images/prefetch", {"Authorization": "Bearer k"}, body)
    assert response.status == 400
    assert json.loads(response.body)["error"]["code"] == "invalid_registry_auth"
