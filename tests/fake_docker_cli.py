"""A fake ``docker`` CLI for DockerGuestProvider tests that need no daemon.

``install(tmp_path, monkeypatch)`` writes an executable ``docker`` script, puts it
first on PATH and returns a :class:`FakeDocker` handle. The script keeps its state
in a JSON file under a file lock, so parallel ``docker`` processes see one daemon.

The handle sets behaviour (failures, delays, hangs) and reads back state and the
call log. Only the commands DockerGuestProvider uses are modelled.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = r'''
import fcntl, json, os, sys, time, uuid

STATE = os.environ["FAKE_DOCKER_STATE"]
LOCK = STATE + ".lock"


class Locked:
    def __enter__(self):
        self.fh = open(LOCK, "a+")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        with open(STATE) as f:
            self.state = json.load(f)
        return self.state

    def __exit__(self, *exc):
        with open(STATE + ".tmp", "w") as f:
            json.dump(self.state, f)
        os.replace(STATE + ".tmp", STATE)
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


def find(state, ref):
    for cid, c in state["containers"].items():
        if cid == ref or cid.startswith(ref) or c["name"] == ref:
            return cid
    return None


def main(argv):
    with Locked() as st:
        st["calls"].append(argv)
        b = st["behaviour"]
    cmd = argv[0] if argv else ""

    if cmd == "info":
        fmt = argv[argv.index("--format") + 1] if "--format" in argv else ""
        if "Runtimes" in fmt:
            print(json.dumps({r: {} for r in b.get("runtimes", ["runc"])}))
        elif "DefaultRuntime" in fmt:
            print(b.get("default_runtime", "runc"))
        else:
            print("27.0.0-fake")
        return 0

    if cmd == "image" and argv[1] == "inspect":
        ref = argv[-1]
        with Locked() as st:
            present = ref in st["images"]
        if not present:
            print(f"Error: No such image: {ref}", file=sys.stderr)
            return 1
        fmt = argv[argv.index("--format") + 1]
        if fmt == "{{.Id}}":
            print("sha256:" + "ab" * 32)
        else:
            print(json.dumps({"Id": "sha256:" + "ab" * 32, "Size": 1234, "RepoDigests": [ref + "@sha256:" + "cd" * 32]}))
        return 0

    if cmd == "pull":
        ref = argv[-1]
        if b.get("pull_delay"):
            time.sleep(b["pull_delay"])
        if ref in b.get("pull_fail", []):
            print(f"Error response from daemon: pull access denied for {ref}", file=sys.stderr)
            return 1
        with Locked() as st:
            if ref not in st["images"]:
                st["images"].append(ref)
        print(f"Status: Downloaded newer image for {ref}")
        return 0

    if cmd == "tag":
        with Locked() as st:
            if argv[1] not in st["images"]:
                print(f"Error: No such image: {argv[1]}", file=sys.stderr)
                return 1
            st["images"].append(argv[2])
        return 0

    if cmd == "run":
        name = argv[argv.index("--name") + 1]
        labels = {}
        for i, part in enumerate(argv):
            if part == "--label":
                k, _, v = argv[i + 1].partition("=")
                labels[k] = v
        with Locked() as st:
            if any(c["name"] == name for c in st["containers"].values()):
                print(
                    f'docker: Error response from daemon: Conflict. The container name "/{name}" is already in use.',
                    file=sys.stderr,
                )
                return 125
            cid = uuid.uuid4().hex + uuid.uuid4().hex
            fail = "--storage-opt" in argv and b.get("reject_storage_opt")
            fail = fail or any(img in argv for img in b.get("run_fail_images", []))
            st["containers"][cid] = {
                "name": name,
                "labels": labels,
                "status": "created" if fail else "running",
                "argv": argv,
            }
        if fail:
            print("docker: Error response from daemon: start failed.", file=sys.stderr)
            return 125
        print(cid)
        return 0

    if cmd == "rm":
        ref = argv[-1]
        with Locked() as st:
            st["rm_active"] = st.get("rm_active", 0) + 1
            st["rm_max_active"] = max(st.get("rm_max_active", 0), st["rm_active"])
            cid = find(st, ref)
            key = cid or ref
            seen = st["rm_seen"].get(key, 0)
            st["rm_seen"][key] = seen + 1
            hang = seen < b.get("rm_hang", {}).get(key, 0)
            fail = seen < b.get("rm_fail", {}).get(key, 0)
        try:
            if hang:
                time.sleep(30)  # longer than any test timeout; the caller kills us
                return 1
            if b.get("rm_delay"):
                time.sleep(b["rm_delay"])
            if fail:
                print(f"Error response from daemon: removal of container {ref} is already in progress", file=sys.stderr)
                return 1
            with Locked() as st:
                cid = find(st, ref)
                if cid is None:
                    print(f"Error response from daemon: No such container: {ref}", file=sys.stderr)
                    return 1
                del st["containers"][cid]
                st["removed"].append(cid)
            print(ref)
            return 0
        finally:
            with Locked() as st:
                st["rm_active"] -= 1

    if cmd == "ps":
        flt = argv[argv.index("--filter") + 1]
        _, _, kv = flt.partition("=")
        k, _, v = kv.partition("=")
        with Locked() as st:
            for cid, c in st["containers"].items():
                if c["labels"].get(k) == v:
                    print(f"{cid} {c['labels'].get('cathedral.sandbox.id', '')}")
        return 0

    if cmd in ("exec", "inspect", "network", "pause", "unpause", "commit", "build"):
        return 0

    print(f"fake docker: unsupported command {argv}", file=sys.stderr)
    return 2


sys.exit(main(sys.argv[1:]))
'''


class FakeDocker:
    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path

    def _load(self) -> dict[str, Any]:
        return json.loads(self.state_path.read_text())

    def _save(self, state: dict[str, Any]) -> None:
        self.state_path.write_text(json.dumps(state))

    def set(self, **behaviour: Any) -> None:
        state = self._load()
        state["behaviour"].update(behaviour)
        self._save(state)

    def add_image(self, ref: str) -> None:
        state = self._load()
        state["images"].append(ref)
        self._save(state)

    def add_container(self, cid: str, *, name: str, labels: dict[str, str]) -> None:
        state = self._load()
        state["containers"][cid] = {"name": name, "labels": labels, "status": "running", "argv": []}
        self._save(state)

    @property
    def state(self) -> dict[str, Any]:
        return self._load()

    @property
    def containers(self) -> dict[str, dict[str, Any]]:
        return self._load()["containers"]

    @property
    def calls(self) -> list[list[str]]:
        return self._load()["calls"]

    def calls_of(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]


def install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    script = bindir / "docker"
    script.write_text(f"#!{sys.executable}\n" + _SCRIPT)
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    state_path = tmp_path / "fake-docker-state.json"
    state_path.write_text(
        json.dumps(
            {
                "behaviour": {},
                "images": [],
                "containers": {},
                "calls": [],
                "removed": [],
                "rm_seen": {},
                "rm_active": 0,
                "rm_max_active": 0,
            }
        )
    )
    monkeypatch.setenv("FAKE_DOCKER_STATE", str(state_path))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    for name in (
        "CATHEDRAL_SANDBOX_KEYS",
        "CATHEDRAL_SANDBOX_REVOKED_KEYS",
        "CATHEDRAL_SANDBOX_QUOTA",
        "CATHEDRAL_SANDBOX_OWNER",
        "CATHEDRAL_SANDBOX_IMAGE_ALLOWLIST",
        "CATHEDRAL_SANDBOX_REGISTRY_MIRROR",
        "CATHEDRAL_SANDBOX_PULL_POLICY",
        "CATHEDRAL_DOCKER_RUNTIME",
        "CATHEDRAL_DIND_RUNTIME",
        "CATHEDRAL_DIND_DOCKERD_ARGS",
        "CATHEDRAL_DIND_ENV",
    ):
        monkeypatch.delenv(name, raising=False)
    return FakeDocker(state_path)
