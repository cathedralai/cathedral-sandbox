"""room-kit/room_image_gc.py: LRU cleanup of unused images (AB#819).

A fake Docker stands in for the room daemon; fill is a function of what is left.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("room_image_gc", ROOT / "room-kit" / "room_image_gc.py")
gc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gc)

HOUR = 3600.0
NOW = 1_000_000.0


def image(iid: str, tag: str | None, size_gb: float, digest: bool = True, labels: dict | None = None) -> dict:
    repo = (tag or "x").split(":")[0]
    return {"Id": iid, "RepoTags": [tag] if tag else [], "RepoDigests": [f"{repo}@sha256:{iid}"] if digest else [],
            "Size": int(size_gb * 1e9), "Config": {"Labels": labels}}


class FakeDocker:
    def __init__(self, images: list[dict], used: set[str] = frozenset(), refuse: set[str] = frozenset()) -> None:
        self.images = {i["Id"]: i for i in images}
        self.used = set(used)
        self.refuse = set(refuse)
        self.removed: list[str] = []

    def image_ids(self) -> list[str]:
        return sorted(self.images)

    def inspect_images(self, ids: list[str]) -> list[dict]:
        return [self.images[i] for i in ids]

    def used_image_ids(self) -> set[str]:
        return set(self.used)

    def remove(self, ref: str) -> tuple[bool, str]:
        for iid, img in list(self.images.items()):
            if ref in img["RepoTags"] or ref in img["RepoDigests"]:
                if iid in self.refuse:
                    return False, "conflict: unable to remove repository reference (must force) - container is using its referenced image"
                self.removed.append(ref)
                img["RepoTags"] = [t for t in img["RepoTags"] if t != ref]
                img["RepoDigests"] = [d for d in img["RepoDigests"] if d != ref]
                if not img["RepoTags"] and not img["RepoDigests"]:
                    del self.images[iid]
                return True, ""
        return False, "Error: No such image: " + ref

    def fill(self, total_gb: float = 100.0, other_gb: float = 0.0):
        return lambda _path: 100.0 * (other_gb + sum(i["Size"] for i in self.images.values()) / 1e9) / total_gb


def args(tmp_path: Path, **kw) -> argparse.Namespace:
    base = {"sock": "/s", "data_dir": "/d", "state": str(tmp_path / "state.json"), "high_pct": 85.0, "low_pct": 70.0,
            "min_idle_minutes": 60.0, "keep": ["alpine:3.20"], "keep_file": None, "dry_run": False, "off": False}
    base.update(kw)
    return argparse.Namespace(**base)


def seen(tmp_path: Path, **ages_h: float) -> None:
    """Pre-seed the state: each image first seen ages_h hours before NOW."""
    (tmp_path / "state.json").write_text(json.dumps({"images": {k: {"first_seen": NOW - v * HOUR} for k, v in ages_h.items()}}))


def test_below_the_high_mark_nothing_is_removed_but_use_is_noted(tmp_path: Path) -> None:
    d = FakeDocker([image("a", "swe/a:1", 10), image("b", "swe/b:1", 10)], used={"b"})
    seen(tmp_path, a=5, b=5)
    gc.run_once(args(tmp_path), d, fill=d.fill(other_gb=50), now=NOW)  # 70%
    assert d.removed == []
    st = json.loads((tmp_path / "state.json").read_text())["images"]
    assert st["b"]["last_used"] == NOW and "last_used" not in st["a"]


def test_only_unused_idle_registry_images_go_least_recently_used_first_until_the_low_mark(tmp_path: Path) -> None:
    d = FakeDocker([
        image("run", "swe/running:1", 10),                                    # a container uses it
        image("snap", "reg/snap:1", 10, labels={"cathedral.sandbox.owner": "g1"}),  # a room snapshot, pushed
        image("build", "cathedral-build-1:latest", 10, digest=False),         # a local build
        image("young", "swe/young:1", 10),                                    # pulled 10 minutes ago
        image("probe", "alpine:3.20", 1),                                     # the keep list
        image("old", "swe/old:1", 10),                                        # unused for 9 h
        image("mid", "swe/mid:1", 10),                                        # unused for 5 h
        image("new", "swe/new:1", 10),                                        # unused for 2 h
    ], used={"run"})
    seen(tmp_path, run=9, snap=9, build=9, young=10 / 60, probe=9, old=9, mid=5, new=2)
    # 71 GB of images + 20 GB of room disks on 100 GB: 91%. Below 70% needs 3 images gone.
    gc.run_once(args(tmp_path), d, fill=d.fill(other_gb=20), now=NOW)
    assert [r.split("@")[0].split(":")[0] for r in d.removed[::2]] == ["swe/old", "swe/mid", "swe/new"]
    assert set(d.images) == {"run", "snap", "build", "young", "probe"}
    st = json.loads((tmp_path / "state.json").read_text())["images"]
    assert set(st) == set(d.images)


def test_an_image_used_recently_is_younger_than_its_first_sight(tmp_path: Path) -> None:
    d = FakeDocker([image("a", "swe/a:1", 30), image("b", "swe/b:1", 30)], used=set())
    (tmp_path / "state.json").write_text(json.dumps({"images": {
        "a": {"first_seen": NOW - 20 * HOUR, "last_used": NOW - 30 * 60},  # used 30 min ago: stays
        "b": {"first_seen": NOW - 3 * HOUR}}}))
    gc.run_once(args(tmp_path), d, fill=d.fill(other_gb=30), now=NOW)  # 90%
    assert set(d.images) == {"a"}


def test_a_new_image_is_only_noted_on_its_first_run(tmp_path: Path) -> None:
    d = FakeDocker([image("a", "swe/a:1", 90)])
    gc.run_once(args(tmp_path), d, fill=d.fill(), now=NOW)  # 90%, but first seen now
    assert d.removed == []
    gc.run_once(args(tmp_path), d, fill=d.fill(), now=NOW + 61 * 60)
    assert "a" not in d.images


def test_a_refused_removal_keeps_the_image_and_goes_on(tmp_path: Path) -> None:
    d = FakeDocker([image("a", "swe/a:1", 30), image("b", "swe/b:1", 30)], refuse={"a"})
    seen(tmp_path, a=9, b=5)
    gc.run_once(args(tmp_path), d, fill=d.fill(other_gb=30), now=NOW)
    assert set(d.images) == {"a"}


def test_every_reference_goes_never_forced(tmp_path: Path) -> None:
    img = image("a", "swe/a:1", 90)
    img["RepoTags"].append("swe/a:latest")
    d = FakeDocker([img])
    seen(tmp_path, a=9)
    gc.run_once(args(tmp_path), d, fill=d.fill(), now=NOW)
    assert d.removed == ["swe/a:1", "swe/a:latest", "swe/a@sha256:a"] and d.images == {}


def test_dry_run_removes_nothing(tmp_path: Path) -> None:
    d = FakeDocker([image("a", "swe/a:1", 90)])
    seen(tmp_path, a=9)
    gc.run_once(args(tmp_path, dry_run=True), d, fill=d.fill(), now=NOW)
    assert d.removed == []


def test_off_and_bad_marks(tmp_path: Path) -> None:
    common = ["--sock", "/nonexistent", "--data-dir", str(tmp_path), "--state", str(tmp_path / "s.json")]
    assert gc.main([*common, "--off"]) == 0
    assert not (tmp_path / "s.json").exists()
    assert gc.main([*common, "--high-pct", "60", "--low-pct", "70"]) == 2


@pytest.mark.parametrize("bad", ["", "{not json", '{"images": []}'])
def test_a_broken_state_file_starts_over(tmp_path: Path, bad: str) -> None:
    (tmp_path / "state.json").write_text(bad)
    d = FakeDocker([image("a", "swe/a:1", 90)])
    gc.run_once(args(tmp_path), d, fill=d.fill(), now=NOW)
    assert d.removed == []  # first seen now
    assert "a" in json.loads((tmp_path / "state.json").read_text())["images"]


def pins(tmp_path: Path, *entries: dict) -> str:
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"version": 1, "pins": list(entries)}))
    return str(path)


def test_pinned_images_are_kept_like_the_keep_list(tmp_path: Path, capsys) -> None:
    """AB#860: refs and image ids in the pins file stay; the GC logs once that pins hold the volume up."""
    d = FakeDocker([image("old", "swe/old:1", 30), image("mid", "swe/mid:1", 30), image("new", "swe/new:1", 30)])
    seen(tmp_path, old=9, mid=5, new=2)
    keep_file = pins(tmp_path, {"ref": "swe/old:1", "owner": "o1"}, {"ref": "gone:1", "image_id": "mid", "owner": "o2"})
    gc.run_once(args(tmp_path, keep_file=keep_file), d, fill=d.fill(other_gb=20), now=NOW)  # 110%, 80% after
    assert set(d.images) == {"old", "mid"}
    out = capsys.readouterr().out
    assert out.count("pinned images keep") == 1


def test_a_pin_keeps_the_image_it_counted_not_what_a_moved_tag_names(tmp_path: Path) -> None:
    """Review HOLD on #642: a pin with an image id keeps only that id. The tag
    re-pulled as another, larger image is not pinned and can go."""
    d = FakeDocker([image("small", "swe/app@sha256:aa", 10), image("big", "swe/app:latest", 90)])
    seen(tmp_path, small=9, big=9)
    keep_file = pins(tmp_path, {"ref": "swe/app:latest", "image_id": "small", "owner": "o1"})
    gc.run_once(args(tmp_path, keep_file=keep_file), d, fill=d.fill(), now=NOW)
    assert set(d.images) == {"small"}


@pytest.mark.parametrize("bad", ["", "{not json", '{"pins": {}}', '{"pins": [1, "x"]}', None])
def test_a_missing_or_broken_pins_file_keeps_nothing_extra_and_gc_goes_on(tmp_path: Path, bad, capsys) -> None:
    path = tmp_path / "pins.json"
    if bad is not None:
        path.write_text(bad)
    d = FakeDocker([image("a", "swe/a:1", 90)])
    seen(tmp_path, a=9)
    assert gc.run_once(args(tmp_path, keep_file=str(path)), d, fill=d.fill(), now=NOW) == 0
    assert d.images == {}
    out = capsys.readouterr().out
    assert out.count("pins file") == (0 if bad is None else 1)


def test_keep_file_is_a_cli_option(tmp_path: Path) -> None:
    common = ["--sock", "/nonexistent", "--data-dir", str(tmp_path), "--state", str(tmp_path / "s.json")]
    assert gc.main([*common, "--keep-file", str(tmp_path / "pins.json"), "--off"]) == 0
