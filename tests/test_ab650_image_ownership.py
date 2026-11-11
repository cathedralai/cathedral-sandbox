"""AB#650 part 2: per-guest hotel image ownership (Gate S.1).

Same hotel API key, two broker guests: guest A cannot boot guest B's snapshot
image (by tag, alias, or immutable id). Option A refuses hotel builds.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_image_owners import ImageOwnerStore
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


# ---------------------------------------------------------------- the owner table on disk
# Found on the canary, 11 Nov 2026: the hotel API could not write in the table's
# directory, every new grant answered 503, and the failed grant stayed in memory.
# Tests cannot switch users, so a read-only directory stands in for "the
# directory belongs to someone else".

IMAGE_ID = "sha256:" + "a" * 64
needs_file_modes = pytest.mark.skipif(os.geteuid() == 0, reason="root writes in a read-only directory")


@contextmanager
def _read_only(directory: Path):
    directory.chmod(0o500)
    try:
        yield
    finally:
        directory.chmod(0o700)


@pytest.fixture
def owners_dir(fake, tmp_path, monkeypatch) -> Path:
    """The table in a directory of its own, the layout install.sh makes on a hotel."""
    directory = tmp_path / "image-owners"
    directory.mkdir(mode=0o700)
    monkeypatch.setenv("CATHEDRAL_IMAGE_OWNERS_PATH", str(directory / "image-owners.json"))
    return directory


@pytest.fixture
def hotel(owners_dir):
    p = DockerGuestProvider()
    yield p
    p.close()


def _live_sandboxes(provider) -> list[str]:
    with provider._inner._lock:  # noqa: SLF001
        return [sid for sid, rec in provider._inner._sandboxes.items() if rec.state not in ("deleting", "deleted")]  # noqa: SLF001


@needs_file_modes
def test_grant_fails_in_a_read_only_store_directory(owners_dir) -> None:
    store = ImageOwnerStore()
    with _read_only(owners_dir):
        with pytest.raises(SandboxOpError) as err:
            store.grant(IMAGE_ID, _owner("ga"), provenance="registry", ref="alpine:3.20")
    assert (err.value.code, err.value.http_status) == ("image_owner_store_failed", 503)
    assert list(owners_dir.iterdir()) == []


@needs_file_modes
def test_failed_grant_leaves_nothing_in_memory(owners_dir) -> None:
    store = ImageOwnerStore()
    with _read_only(owners_dir):
        with pytest.raises(SandboxOpError):
            store.grant(IMAGE_ID, _owner("ga"), provenance="snapshot", ref="cathedral-snap-x:latest")
        assert store.owns(IMAGE_ID, _owner("ga")) is False
        assert store.provenance(IMAGE_ID) is None
        with pytest.raises(SandboxOpError) as err:
            store.require(IMAGE_ID, _owner("ga"))
    assert (err.value.code, err.value.http_status) == ("image_not_owned", 403)


@needs_file_modes
def test_retry_after_a_failed_grant_is_still_refused(fake, owners_dir, hotel) -> None:
    with _read_only(owners_dir):
        for attempt in ("1", "2"):
            with pytest.raises(SandboxOpError) as err:
                _create(hotel, guest="ga", image="alpine:3.20", digest=attempt)
            assert (err.value.code, err.value.http_status) == ("image_owner_store_failed", 503), attempt
        image_id = hotel._image_id_of("alpine:3.20")  # noqa: SLF001
        assert image_id and image_id.startswith("sha256:")
        with pytest.raises(SandboxOpError) as err:
            _create(hotel, guest="ga", image=image_id, digest="3")
        assert (err.value.code, err.value.http_status) == ("image_not_owned", 403)
    assert _live_sandboxes(hotel) == []
    assert not any(c["status"] == "running" for c in fake.containers.values())
    assert list(owners_dir.iterdir()) == []


@needs_file_modes
def test_failed_snapshot_grant_removes_image_and_record(fake, owners_dir, hotel) -> None:
    sid = _create(hotel, guest="ga", digest="1")["id"]
    with _read_only(owners_dir):
        with pytest.raises(SandboxOpError) as err:
            hotel.snapshot(sid)
    assert (err.value.code, err.value.http_status) == ("image_owner_store_failed", 503)
    assert hotel.list_snapshots(owner=_owner("ga")) == []
    assert not [ref for ref in fake.state["images"] if ref.startswith("cathedral-snap-")]
    assert fake.calls_of("image", "rm")


@needs_file_modes
def test_failed_drop_owner_keeps_the_grant(owners_dir) -> None:
    store = ImageOwnerStore()
    store.grant(IMAGE_ID, _owner("ga"), provenance="snapshot", ref="cathedral-snap-x:latest")
    with _read_only(owners_dir):
        with pytest.raises(SandboxOpError) as err:
            store.drop_owner(IMAGE_ID, _owner("ga"))
        assert (err.value.code, err.value.http_status) == ("image_owner_store_failed", 503)
        # Memory still matches the file: the grant is in both.
        assert store.owns(IMAGE_ID, _owner("ga")) is True
    assert ImageOwnerStore().owns(IMAGE_ID, _owner("ga")) is True


@needs_file_modes
def test_store_refuses_to_start_when_directory_is_not_writable(owners_dir) -> None:
    with _read_only(owners_dir):
        with pytest.raises(RuntimeError) as err:
            ImageOwnerStore()
        with pytest.raises(RuntimeError):
            DockerGuestProvider()
    assert str(owners_dir / "image-owners.json") in str(err.value)
    assert "not writable" in str(err.value)
    assert list(owners_dir.iterdir()) == []


def test_grant_survives_a_new_store_instance(owners_dir) -> None:
    ImageOwnerStore().grant(IMAGE_ID, _owner("ga"), provenance="snapshot", ref="cathedral-snap-x:latest")
    again = ImageOwnerStore()
    assert again.owns(IMAGE_ID, _owner("ga")) is True
    assert again.owns(IMAGE_ID, _owner("gb")) is False
    assert again.provenance(IMAGE_ID) == "snapshot"
    assert sorted(p.name for p in owners_dir.iterdir()) == ["image-owners.json"]
