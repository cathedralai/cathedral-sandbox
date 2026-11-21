"""AB#860: the hotel lists each owner's cached images and keeps pinned ones.

GET /v1/images is scoped by owner (hotel key + broker guest, AB#650) and
joins the owner's grants with what Docker holds now. A prefetch with
"pin": true records the images in the pins file the image GC reads, under
the broker's per-owner cap (X-Pin-Max-Bytes) and the hotel's own ceiling.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_owner import owner_hash, owner_id
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import install

KEY = "hotel-key"
ROOT = Path(__file__).resolve().parents[1]
MIB = 1 << 20


@pytest.fixture
def env(tmp_path, monkeypatch):
    fake = install(tmp_path, monkeypatch)
    monkeypatch.setenv("CATHEDRAL_IMAGE_PINS_PATH", str(tmp_path / "gc" / "pins.json"))
    monkeypatch.setenv("CATHEDRAL_IMAGE_GC_STATE", str(tmp_path / "gc" / "state.json"))
    monkeypatch.setenv("CATHEDRAL_IMAGE_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ROOM_IMAGE_PIN_MAX_PCT", raising=False)
    fake.set(image_sizes={"alpine:3.20": 8 * MIB, "busybox:1": 4 * MIB, "ghcr.io/acme/big:1": 64 * MIB})
    provider = DockerGuestProvider()
    yield fake, provider, SandboxApplication(provider), tmp_path
    provider.close()


def call(app, method, path, guest, body=None, headers=None):
    h = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": guest, **(headers or {})}
    raw = json.dumps(body).encode() if body is not None else b""
    resp = app.dispatch(method, path, h, raw)
    return resp.status, (json.loads(resp.body) if resp.body else None)


def prefetch(app, guest, images, *, pin=None, cap=None):
    body = {"images": images}
    if pin is not None:
        body["pin"] = pin
    headers = {"X-Pin-Max-Bytes": str(cap)} if cap is not None else None
    return call(app, "POST", "/v1/images/prefetch", guest, body, headers)


def listed(app, guest):
    status, doc = call(app, "GET", "/v1/images", guest)
    assert status == 200, doc
    return {e["ref"]: e for e in doc["images"]}


def test_list_shows_only_the_callers_images_with_docker_facts(env) -> None:
    fake, _provider, app, _ = env
    assert prefetch(app, "ga", ["alpine:3.20", "busybox:1"])[0] == 202
    assert prefetch(app, "gb", ["alpine:3.20"])[0] == 202
    a = listed(app, "ga")
    assert sorted(a) == ["alpine:3.20", "busybox:1"]
    assert a["alpine:3.20"]["size_bytes"] == 8 * MIB and a["alpine:3.20"]["digest"].startswith("alpine:3.20@sha256:")
    assert a["alpine:3.20"]["pinned"] is False and a["alpine:3.20"]["last_used_at"] is None
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", a["busybox:1"]["image_id"])
    # gb pulled alpine only: busybox, ga's image, is not in its list.
    assert sorted(listed(app, "gb")) == ["alpine:3.20"]
    # Another guest with nothing pulled sees nothing.
    assert listed(app, "gc") == {}


def test_a_granted_image_docker_no_longer_holds_is_not_listed(env) -> None:
    fake, provider, app, _ = env
    prefetch(app, "ga", ["alpine:3.20", "busybox:1"])
    provider._client.run(["docker", "image", "rm", "busybox:1"])  # noqa: SLF001 the image GC removed it
    assert sorted(listed(app, "ga")) == ["alpine:3.20"]


def test_last_used_comes_from_the_gc_state_when_readable(env) -> None:
    _fake, provider, app, tmp = env
    prefetch(app, "ga", ["alpine:3.20"])
    iid = provider._image_id_of("alpine:3.20")  # noqa: SLF001
    state = tmp / "gc" / "state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"images": {iid: {"first_seen": 1.0, "last_used": 1763700000.0}}}))
    assert listed(app, "ga")["alpine:3.20"]["last_used_at"] == "2025-11-21T04:40:00Z"
    state.write_text("{broken")
    assert listed(app, "ga")["alpine:3.20"]["last_used_at"] is None


def test_the_list_route_does_not_shadow_one_image_lookup(env) -> None:
    _fake, _provider, app, _ = env
    prefetch(app, "ga", ["alpine:3.20"])
    status, doc = call(app, "GET", "/v1/images/alpine:3.20", "ga")
    assert status == 200 and doc["ref"] == "alpine:3.20" and doc["cached"] is True
    status, doc = call(app, "GET", "/v1/images", "ga")
    assert status == 200 and doc["count"] == 1


def test_pin_records_the_image_and_echoes_it(env) -> None:
    _fake, provider, app, tmp = env
    status, doc = prefetch(app, "ga", ["alpine:3.20"], pin=True, cap=100 * MIB)
    assert status == 202, doc
    assert doc["result"]["pinned"] == ["alpine:3.20"]
    pins = json.loads((tmp / "gc" / "pins.json").read_text())
    (entry,) = pins["pins"]
    assert entry["ref"] == "alpine:3.20" and entry["size_bytes"] == 8 * MIB
    assert entry["owner"] == owner_hash(owner_id(KEY, "ga")) and entry["image_id"] == provider._image_id_of("alpine:3.20")  # noqa: SLF001
    assert listed(app, "ga")["alpine:3.20"]["pinned"] is True
    # gb also pulled alpine; ga's pin is not gb's.
    prefetch(app, "gb", ["alpine:3.20"])
    assert listed(app, "gb")["alpine:3.20"]["pinned"] is False
    # A prefetch without pin has no echo.
    status, doc = prefetch(app, "ga", ["busybox:1"])
    assert status == 202 and "pinned" not in doc["result"]


def test_pin_over_the_owner_cap_is_507_and_pins_nothing(env) -> None:
    _fake, _provider, app, tmp = env
    assert prefetch(app, "ga", ["alpine:3.20"], pin=True, cap=10 * MIB)[0] == 202
    status, doc = prefetch(app, "ga", ["busybox:1"], pin=True, cap=10 * MIB)  # 8 + 4 > 10
    assert status == 507 and doc["error"]["code"] == "pin_cap_exceeded"
    assert [p["ref"] for p in json.loads((tmp / "gc" / "pins.json").read_text())["pins"]] == ["alpine:3.20"]
    # Another owner's pins do not count against ga's cap.
    assert prefetch(app, "gb", ["busybox:1"], pin=True, cap=5 * MIB)[0] == 202
    # Pinning the same image again does not count it twice.
    assert prefetch(app, "ga", ["alpine:3.20"], pin=True, cap=10 * MIB)[0] == 202


def test_pin_over_the_hotel_ceiling_is_507_whatever_the_owner_cap(env, monkeypatch) -> None:
    _fake, _provider, app, tmp = env
    import shutil

    total = shutil.disk_usage(tmp).total
    # A ceiling of about 70 MiB: two owners' pins share it.
    monkeypatch.setenv("ROOM_IMAGE_PIN_MAX_PCT", repr(100 * 70 * MIB / total))
    assert prefetch(app, "ga", ["ghcr.io/acme/big:1"], pin=True, cap=1 << 40)[0] == 202
    status, doc = prefetch(app, "gb", ["alpine:3.20"], pin=True, cap=1 << 40)  # 64 + 8 > 70
    assert status == 507 and doc["error"]["code"] == "pin_cap_exceeded" and "hotel" in doc["error"]["message"]


def test_a_hotel_ceiling_of_zero_turns_pins_off(env, monkeypatch) -> None:
    """Review observation on #642: ROOM_IMAGE_PIN_MAX_PCT=0 means no pins, not the default 50."""
    _fake, _provider, app, _tmp = env
    monkeypatch.setenv("ROOM_IMAGE_PIN_MAX_PCT", "0")
    status, doc = prefetch(app, "ga", ["alpine:3.20"], pin=True, cap=1 << 40)
    assert status == 507 and doc["error"]["code"] == "pin_cap_exceeded"


def test_unpin_removes_only_the_callers_pin(env) -> None:
    _fake, _provider, app, tmp = env
    prefetch(app, "ga", ["ghcr.io/acme/big:1"], pin=True, cap=1 << 30)
    status, doc = call(app, "DELETE", "/v1/images/pins/ghcr.io%2Facme%2Fbig:1", "gb")
    assert status == 404 and doc["error"]["code"] == "pin_not_found"
    status, doc = call(app, "DELETE", "/v1/images/pins/ghcr.io%2Facme%2Fbig:1", "ga")
    assert status == 200 and doc == {"ref": "ghcr.io/acme/big:1", "pinned": False}
    assert json.loads((tmp / "gc" / "pins.json").read_text())["pins"] == []
    assert listed(app, "ga")["ghcr.io/acme/big:1"]["pinned"] is False


def test_pin_must_be_a_boolean_and_the_cap_a_number(env) -> None:
    _fake, _provider, app, _ = env
    assert prefetch(app, "ga", ["alpine:3.20"], pin="yes")[0] == 400
    status, doc = call(app, "POST", "/v1/images/prefetch", "ga", {"images": ["alpine:3.20"], "pin": True}, {"X-Pin-Max-Bytes": "lots"})
    assert status == 400 and doc["error"]["code"] == "invalid_pin_cap"


def test_a_hotel_without_a_pins_file_pulls_and_does_not_echo(env, monkeypatch) -> None:
    _fake, _provider, _app, _ = env
    monkeypatch.delenv("CATHEDRAL_IMAGE_PINS_PATH")
    provider = DockerGuestProvider()
    try:
        status, doc = prefetch(SandboxApplication(provider), "ga", ["alpine:3.20"], pin=True, cap=1 << 30)
        assert status == 202 and "pinned" not in doc["result"]
    finally:
        provider.close()


def test_the_kit_feeds_the_pins_file_to_the_gc_and_the_api() -> None:
    install_sh = (ROOT / "room-kit" / "install.sh").read_text()
    assert "--keep-file /var/lib/pool-room-$ROOM_ID-image-gc/pins.json" in install_sh
    # The API makes the GC state directory, so pins work before the first GC run.
    assert "StateDirectory=pool-room pool-room-$ROOM_ID-image-gc" in install_sh
    assert "ROOM_IMAGE_PIN_MAX_PCT" in install_sh.split("ROOM_KEYS=", 1)[1].splitlines()[0]
    profile = (ROOT / "room-kit" / "profiles" / "v1.sh").read_text()
    for line in (
        "CATHEDRAL_IMAGE_PINS_PATH=/var/lib/pool-room-$ROOM_ID-image-gc/pins.json",
        "CATHEDRAL_IMAGE_GC_STATE=/var/lib/pool-room-$ROOM_ID-image-gc/state.json",
        "CATHEDRAL_IMAGE_DATA_DIR=$ROOM_DATA_DIR",
        "ROOM_IMAGE_PIN_MAX_PCT=${ROOM_IMAGE_PIN_MAX_PCT:-50}",
    ):
        assert line in profile
