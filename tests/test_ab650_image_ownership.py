"""AB#650 part 2: per-guest hotel image ownership (Gate S.1).

Same hotel API key, two broker guests: guest A cannot boot guest B's snapshot
image (by tag, alias, or immutable id). Option A refuses hotel builds.
"""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_owner import owner_id
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

RES = Resources(vcpu=1, memory_gib=1, disk_gib=5)
KEY = "hotel-key"


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    # Ownership on; Option A refuse for sealed-shared build paths under test.
    monkeypatch.setenv("CATHEDRAL_IMAGE_OWNERS_PATH", str(tmp_path / "image-owners.json"))
    monkeypatch.setenv("CATHEDRAL_SHARED_HOTEL_BUILDS", "refuse")
    return docker


@pytest.fixture
def provider(fake):
    p = DockerGuestProvider()
    yield p
    p.close()


def _owner(guest: str) -> str:
    return owner_id(KEY, guest)


def _create(provider, *, guest: str, image: str = "alpine:3.20", digest: str = "d", **over):
    req = CreateSandboxRequest(
        image=ImageSource(image=image),
        resources=RES,
        labels={"broker_guest": guest},
        **over,
    )
    return provider.create(req, api_key=KEY, idempotency=None, body_digest=digest, owner=_owner(guest))


def _snapshot(provider, sid: str) -> dict:
    return provider.get_operation(provider.snapshot(sid))["result"]


def test_owner_can_fork_own_snapshot(fake, provider) -> None:
    sid = _create(provider, guest="ga", digest="1")["id"]
    snap = _snapshot(provider, sid)
    fork = provider.create(
        CreateSandboxRequest(snapshot_id=snap["snapshot_id"], resources=RES),
        api_key=KEY,
        idempotency=None,
        body_digest="fork",
        owner=_owner("ga"),
    )
    assert fork["guest"]["image"] == snap["image"]


def test_foreign_snapshot_id_is_not_found(fake, provider) -> None:
    sid = _create(provider, guest="ga", digest="1")["id"]
    snap = _snapshot(provider, sid)
    with pytest.raises(SandboxOpError) as err:
        provider.create(
            CreateSandboxRequest(snapshot_id=snap["snapshot_id"], resources=RES),
            api_key=KEY,
            idempotency=None,
            body_digest="x",
            owner=_owner("gb"),
        )
    assert (err.value.code, err.value.http_status) == ("snapshot_not_found", 404)


def test_foreign_snapshot_image_name_is_not_owned(fake, provider) -> None:
    sid = _create(provider, guest="ga", digest="1")["id"]
    snap = _snapshot(provider, sid)
    image = snap["image"]
    with pytest.raises(SandboxOpError) as err:
        _create(provider, guest="gb", image=image, digest="x")
    assert (err.value.code, err.value.http_status) == ("image_not_owned", 403)
    assert fake.calls_of("run")  # ga's create ran; gb must not start a room from B's image
    # No additional successful room for gb: only ga's container remains.
    assert sum(1 for c in fake.containers.values() if c["status"] == "running") == 1


def test_foreign_image_id_is_not_owned(fake, provider) -> None:
    sid = _create(provider, guest="ga", digest="1")["id"]
    snap = _snapshot(provider, sid)
    image_id = provider._image_id_of(snap["image"])  # noqa: SLF001
    assert image_id and image_id.startswith("sha256:")
    with pytest.raises(SandboxOpError) as err:
        _create(provider, guest="gb", image=image_id, digest="x")
    assert (err.value.code, err.value.http_status) == ("image_not_owned", 403)


def test_foreign_alias_is_not_owned(fake, provider) -> None:
    sid = _create(provider, guest="ga", digest="1")["id"]
    snap = _snapshot(provider, sid)
    alias = "ab650.invalid/proof/alias:1"
    fake.add_image(alias, alias_of=snap["image"])
    with pytest.raises(SandboxOpError) as err:
        _create(provider, guest="gb", image=alias, digest="x")
    assert (err.value.code, err.value.http_status) == ("image_not_owned", 403)


def test_two_guests_may_share_a_registry_image_after_each_pull(fake, provider) -> None:
    a = _create(provider, guest="ga", image="alpine:3.20", digest="1")
    b = _create(provider, guest="gb", image="alpine:3.20", digest="2")
    assert a["id"] != b["id"]
    # First create pulls; second authorizes with its own pull (refresh).
    assert len(fake.calls_of("pull")) >= 2


def test_shared_hotel_build_route_is_refused(fake, provider) -> None:
    with pytest.raises(SandboxOpError) as err:
        provider.build_image("FROM alpine:3.20\n")
    assert (err.value.code, err.value.http_status) == ("shared_hotel_build_refused", 403)


def test_inline_build_create_is_refused(fake, provider) -> None:
    from cathedral.sandbox_api import BuildSpec

    with pytest.raises(SandboxOpError) as err:
        provider.create(
            CreateSandboxRequest(
                build=BuildSpec(dockerfile="FROM alpine:3.20\n", context_multipart=True),
                resources=RES,
            ),
            api_key=KEY,
            idempotency=None,
            body_digest="b",
            owner=_owner("ga"),
        )
    assert (err.value.code, err.value.http_status) == ("shared_hotel_build_refused", 403)


def test_http_foreign_alias_returns_image_not_owned(fake, provider) -> None:
    sid = _create(provider, guest="ga", digest="1")["id"]
    snap = _snapshot(provider, sid)
    alias = "ab650.invalid/proof/http:1"
    fake.add_image(alias, alias_of=snap["image"])
    app = SandboxApplication(provider)
    body = json.dumps({"image": alias, "labels": {"broker_guest": "gb"}}).encode()
    response = app.dispatch(
        "POST",
        "/v1/sandboxes",
        {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "gb"},
        body,
    )
    assert response.status == 403
    assert json.loads(response.body)["error"]["code"] == "image_not_owned"


def test_idempotency_is_scoped_per_guest(fake, provider) -> None:
    a = provider.create(
        CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES),
        api_key=KEY,
        idempotency="same",
        body_digest="SAME",
        owner=_owner("ga"),
    )
    b = provider.create(
        CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES),
        api_key=KEY,
        idempotency="same",
        body_digest="SAME",
        owner=_owner("gb"),
    )
    assert a["id"] != b["id"]
