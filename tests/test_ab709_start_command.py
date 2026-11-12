"""AB#709: allowlisted image start commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError
from cathedral.start_commands import (
    StartCommandsError,
    image_config_argv,
    load_start_commands,
    start_command_sha256,
)
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_docker_cli import FakeDocker, install

RES = Resources(vcpu=1, memory_gib=1, disk_gib=5)
DIGEST = "sha256:" + "ab" * 32
SERVICE = ["long-service", "--foreground"]


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    return install(tmp_path, monkeypatch)


@pytest.fixture
def allowlist(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "start_commands.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [{"image_digest": DIGEST, "argv": SERVICE, "note": "test"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CATHEDRAL_START_COMMANDS_PATH", str(path))
    return path


def _listed_image(fake: FakeDocker, ref: str = "svc:1") -> str:
    fake.add_image(ref, image_id=DIGEST)
    fake.set_image_config(ref, cmd=SERVICE, repo_digest=f"example.com/{ref}@{DIGEST}")
    return ref


def _create(provider: DockerGuestProvider, image: str, **kwargs):
    request = CreateSandboxRequest(
        image=ImageSource(image=image),
        resources=RES,
        **kwargs,
    )
    return provider.create(request, api_key="k", idempotency=None, body_digest="d")


def test_default_create_still_runs_sleep_infinity(fake: FakeDocker, allowlist: Path) -> None:  # noqa: ARG001
    fake.add_image("alpine:3.20")
    provider = DockerGuestProvider()
    try:
        doc = _create(provider, "alpine:3.20")
        run = [c for c in fake.calls_of("run") if c[-1] == "infinity"][-1]
        assert "sleep" in run and doc["start_command"] is None
    finally:
        provider.close()


def test_start_image_runs_the_listed_argv(fake: FakeDocker, allowlist: Path) -> None:
    image = _listed_image(fake)
    provider = DockerGuestProvider()
    try:
        doc = _create(provider, image, start_image=True)
        run = fake.calls_of("run")[-1]
        # start:image uses the image ENTRYPOINT+CMD (image_default); docker argv
        # ends at the inspected immutable Id — never the mutable tag (AB#709 HOLD).
        assert run[-1] == DIGEST
        assert image not in run
        assert "sleep" not in run
        assert doc["start_command"] == list(SERVICE)
        assert doc["start_command_sha256"] == start_command_sha256(SERVICE)
    finally:
        provider.close()


def test_start_image_pins_run_when_tag_moves_after_inspect(fake: FakeDocker, allowlist: Path) -> None:
    """Retag after allowlist inspect must not change which image docker runs."""
    image = _listed_image(fake)
    evil = "sha256:" + "ef" * 32
    provider = DockerGuestProvider()
    real_start = provider._client.create_and_start

    def retag_then_start(**kwargs):
        # Mutable tag now points at a different image with a different CMD.
        fake.add_image("evil:1", image_id=evil)
        fake.set_image_id(image, evil)
        fake.set_image_config(image, cmd=["evil-bin"], repo_digest=f"evil@{evil}")
        return real_start(**kwargs)

    provider._client.create_and_start = retag_then_start  # type: ignore[method-assign]
    try:
        doc = _create(provider, image, start_image=True)
        run = fake.calls_of("run")[-1]
        assert run[-1] == DIGEST
        assert evil not in run
        assert doc["start_command"] == list(SERVICE)
    finally:
        provider.close()


def test_wrong_argv_is_refused(fake: FakeDocker, allowlist: Path) -> None:
    image = _listed_image(fake)
    fake.set_image_config(image, cmd=["other"], repo_digest=f"x@{DIGEST}")
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as err:
            _create(provider, image, start_image=True)
        assert err.value.code == "start_command_not_allowed"
        assert fake.containers == {}
    finally:
        provider.close()


def test_unlisted_digest_is_refused(fake: FakeDocker, allowlist: Path) -> None:
    fake.add_image("other:1")
    other_digest = "sha256:" + "cd" * 32
    fake.set_image_config("other:1", cmd=SERVICE, repo_digest=f"other:1@{other_digest}")
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as err:
            _create(provider, "other:1", start_image=True)
        assert err.value.code == "start_command_not_allowed"
        assert fake.containers == {}
    finally:
        provider.close()


def test_image_without_cmd_is_unavailable(fake: FakeDocker, allowlist: Path) -> None:
    fake.add_image("empty:1", image_id=DIGEST)
    fake.set_image_config("empty:1", entrypoint=None, cmd=None, repo_digest=f"x@{DIGEST}")
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as err:
            _create(provider, "empty:1", start_image=True)
        assert err.value.code == "start_command_unavailable"
    finally:
        provider.close()


def test_start_conflict_is_refused() -> None:
    from cathedral.sandbox_api import SandboxContractError
    from cathedral.sandbox_server import _create_request

    with pytest.raises(SandboxContractError) as err:
        _create_request(
            {
                "image": "alpine:3.20",
                "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5},
                "start": "image",
                "entrypoint": ["false"],
            }
        )
    assert err.value.code == "start_conflict"


def test_malformed_allowlist_refuses_provider_startup(tmp_path, monkeypatch, fake: FakeDocker) -> None:  # noqa: ARG001
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    monkeypatch.setenv("CATHEDRAL_START_COMMANDS_PATH", str(bad))
    with pytest.raises(SandboxOpError) as err:
        DockerGuestProvider()
    assert err.value.code == "runtime_unavailable"


@pytest.mark.parametrize(
    "doc,match",
    [
        ('{"version": 2, "entries": []}', "version must be 1"),
        ('{"version": 1, "entries": [{"image_digest": "sha256:abc", "argv": ["x"]}]}', "image_digest"),
        ('{"version": 1, "entries": [{"image_digest": "' + DIGEST + '", "argv": []}]}', "argv must"),
    ],
)
def test_allowlist_validation_fail_closed(doc: str, match: str, tmp_path: Path) -> None:
    path = tmp_path / "start_commands.json"
    path.write_text(doc, encoding="utf-8")
    with pytest.raises(StartCommandsError, match=match):
        load_start_commands(path)


def test_image_config_argv_merges_entrypoint_and_cmd() -> None:
    assert image_config_argv({"Config": {"Entrypoint": ["/bin/sh", "-c"], "Cmd": ["echo"]}}) == (
        "/bin/sh",
        "-c",
        "echo",
    )


def test_start_commands_json_ships_with_cathedral() -> None:
    path = Path(__file__).resolve().parents[1] / "cathedral" / "start_commands.json"
    assert path.is_file()
    load_start_commands(path)
