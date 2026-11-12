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


def image_id_for(ref, b):
    """Same Id inspect would return for ref (default hash or override / alias)."""
    import hashlib
    ids = b.get("image_ids") or {}
    aliases = b.get("image_aliases") or {}
    image_id = ids.get(ref)
    if not image_id:
        image_id = "sha256:" + hashlib.sha256(ref.encode()).hexdigest()
    if ref in aliases and aliases[ref] in ids:
        image_id = ids[aliases[ref]]
    elif ref in aliases:
        image_id = "sha256:" + hashlib.sha256(aliases[ref].encode()).hexdigest()
    return image_id


def main(argv):
    with Locked() as st:
        st["calls"].append(argv)
        b = st["behaviour"]
    cmd = argv[0] if argv else ""

    if cmd == "info":
        fmt = argv[argv.index("--format") + 1] if "--format" in argv else ""
        if "Runtimes" in fmt:
            rts = b.get("runtimes", ["runc"])
            print(json.dumps(rts if isinstance(rts, dict) else {r: {} for r in rts}))
        elif "DefaultRuntime" in fmt:
            print(b.get("default_runtime", "runc"))
        else:
            print("27.0.0-fake")
        return 0

    if cmd == "images":
        import fnmatch

        pattern = None
        if "--filter" in argv:
            flt = argv[argv.index("--filter") + 1]
            if flt.startswith("reference="):
                pattern = flt[len("reference="):]
        with Locked() as st:
            for ref in st["images"]:
                if pattern is None or fnmatch.fnmatch(ref, pattern) or fnmatch.fnmatch(ref.split(":")[0], pattern):
                    print(ref)
        return 0

    if cmd == "image" and argv[1] == "inspect":
        ref = argv[-1]
        with Locked() as st:
            present = ref in st["images"]
            # Distinct immutable ids per ref so ownership tests can prove an
            # ID-based boundary (AB#650). Operators may override via behaviour.
            image_id = image_id_for(ref, b)
        if not present:
            print(f"Error: No such image: {ref}", file=sys.stderr)
            return 1
        fmt = argv[argv.index("--format") + 1]
        if fmt == "{{.Id}}":
            print(image_id)
        else:
            size = b.get("image_sizes", {}).get(ref, 1234)
            digests = b.get("image_digests", {}).get(ref)
            if digests is None:
                digests = [ref + "@sha256:" + "cd" * 32]
            cfg = (b.get("image_configs") or {}).get(ref, {})
            config = {
                "Entrypoint": cfg.get("Entrypoint"),
                "Cmd": cfg.get("Cmd"),
            }
            print(json.dumps({"Id": image_id, "Size": size, "RepoDigests": digests, "Config": config}))
        return 0

    if cmd == "image" and argv[1] == "rm":
        with Locked() as st:
            if argv[-1] in st["images"]:
                st["images"].remove(argv[-1])
        return 0

    if cmd == "commit":
        with Locked() as st:
            if find(st, argv[-2]) is None:
                print(f"Error response from daemon: No such container: {argv[-2]}", file=sys.stderr)
                return 1
            if argv[-1] not in st["images"]:
                st["images"].append(argv[-1])
        return 0

    if cmd == "push":
        ref = argv[-1]
        config = os.environ.get("DOCKER_CONFIG")
        auth = None
        if config:
            with open(os.path.join(config, "config.json")) as f:
                auth = json.load(f)
        with Locked() as st:
            present = ref in st["images"]
            st.setdefault("pushed", []).append({"ref": ref, "auth": auth})
        if not present:
            print(f"An image does not exist locally with the tag: {ref}", file=sys.stderr)
            return 1
        if ref in b.get("push_fail", []):
            print(f"denied: permission to push {ref}", file=sys.stderr)
            return 1
        return 0

    if cmd == "pull":
        ref = argv[-1]
        config = os.environ.get("DOCKER_CONFIG")
        if config:
            with open(os.path.join(config, "config.json")) as f:
                auth = json.load(f)
            with Locked() as st:
                st.setdefault("pull_auth", []).append({"ref": ref, "auth": auth, "config_dir": config})
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
            if argv[2] not in st["images"]:
                st["images"].append(argv[2])
            st.setdefault("behaviour", {}).setdefault("image_aliases", {})[argv[2]] = argv[1]
            ids = st["behaviour"].setdefault("image_ids", {})
            if argv[1] in ids:
                ids[argv[2]] = ids[argv[1]]
        return 0

    if cmd == "network" and argv[1] == "create":
        name = argv[-1]
        opts = [argv[i + 1] for i, p in enumerate(argv) if p == "-o"]
        subnet = argv[argv.index("--subnet") + 1] if "--subnet" in argv else None
        with Locked() as st:
            nets = st.setdefault("networks", {"bridge": {"containers": []}})
            if name in nets:
                print(f"Error response from daemon: network with name {name} already exists", file=sys.stderr)
                return 1
            nets[name] = {"containers": [], "opts": opts, "subnet": subnet}
        print(uuid.uuid4().hex)
        return 0

    if cmd == "network" and argv[1] == "inspect":
        name = argv[-1]
        with Locked() as st:
            net = st.setdefault("networks", {"bridge": {"containers": []}}).get(name)
        if net is None:
            print(f"Error response from daemon: network {name} not found", file=sys.stderr)
            return 1
        print(len(net["containers"]))
        return 0

    if cmd == "network" and argv[1] in ("connect", "disconnect"):
        net_name, ref = argv[-2], argv[-1]
        with Locked() as st:
            nets = st.setdefault("networks", {"bridge": {"containers": []}})
            cid = find(st, ref)
            if net_name == "none":
                return 0
            if net_name not in nets or cid is None:
                print(f"Error response from daemon: network {net_name} not found", file=sys.stderr)
                return 1
            members = nets[net_name]["containers"]
            if argv[1] == "connect":
                if len(members) >= b.get("bridge_ports", 1 << 30):
                    print("Error response from daemon: adding interface to bridge failed: exchange full", file=sys.stderr)
                    return 1
                if cid not in members:
                    members.append(cid)
            elif cid in members:
                members.remove(cid)
        return 0

    if cmd == "run" and "--rm" in argv and any(p.startswith("cathedral.workspace.op=") for p in argv):
        # Workspace helper (#305): do the copy on the host paths of the -v mounts.
        import shutil
        op = next(p for p in argv if p.startswith("cathedral.workspace.op=")).split("=", 1)[1]
        vols = {}
        for i, part in enumerate(argv):
            if part == "-v":
                src, dst = argv[i + 1].split(":")[:2]
                vols[dst] = src
        with Locked() as st:
            st.setdefault("helpers", []).append(argv)
        if b.get("helper_fail"):
            print("cp: write error: No space left on device", file=sys.stderr)
            return 1
        dst = vols["/dst"]
        if op in ("replace", "clear"):
            for entry in os.scandir(dst):
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path)
                else:
                    os.unlink(entry.path)
        if op in ("copy", "replace"):
            shutil.copytree(vols["/src"], dst, symlinks=True, dirs_exist_ok=True)
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
            # Match the tag or its inspected Id — docker run is pinned to Id (AB#709).
            fail = fail or any(
                img in argv or image_id_for(img, b) in argv
                for img in b.get("run_fail_images", [])
            )
            net_name = argv[argv.index("--network") + 1] if "--network" in argv else "bridge"
            nets = st.setdefault("networks", {"bridge": {"containers": []}})
            net_error = None
            if net_name != "none" and not fail:
                if net_name not in nets:
                    net_error = f"docker: Error response from daemon: network {net_name} not found."
                elif len(nets[net_name]["containers"]) >= b.get("bridge_ports", 1 << 30):
                    net_error = ("docker: Error response from daemon: failed to set up container networking: "
                                 "adding interface to bridge failed: exchange full")
                else:
                    nets[net_name]["containers"].append(cid)
            fail = fail or net_error is not None
            # exit_at_once: {argv token: exit code}. The container starts and
            # its entrypoint ends at once; docker run -d still prints the id.
            exited = next((code for tok, code in b.get("exit_at_once", {}).items() if tok in argv), None)
            st["containers"][cid] = {
                "name": name,
                "labels": labels,
                "status": "created" if fail else ("exited" if exited is not None else "running"),
                "exit_code": exited,
                "argv": argv,
            }
        if fail:
            print(net_error or "docker: Error response from daemon: start failed.", file=sys.stderr)
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
                for net in st.setdefault("networks", {}).values():
                    if cid in net["containers"]:
                        net["containers"].remove(cid)
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

    if cmd == "exec" and b.get("exec_model"):
        # The guest command is everything after the container id.
        with Locked() as st:
            ids = set(st["containers"])
        rest = argv[1:]
        for i, part in enumerate(rest):
            if part in ids:
                rest = rest[i + 1:]
                break
        form = b.get("timeout_form", "gnu")
        if rest[:1] == ["timeout"]:
            # BusyBox: timeout [-s SIG] [-t SECS] PROG; GNU: timeout [-k N] SECS PROG.
            opts = rest[1:]
            if opts[:2] == ["-s", "KILL"]:
                opts = opts[2:]
            busybox = opts[:1] == ["-t"]
            if form == "none":
                print("sh: timeout: not found", file=sys.stderr)
                return 127
            if busybox != (form == "busybox"):
                print("timeout: invalid usage", file=sys.stderr)
                return 125 if form == "gnu" else 1
            rest = rest[3:] if busybox else rest[2:]
        if rest[:1] == ["bash"] and b.get("no_bash"):
            print("exec: \"bash\": executable file not found in $PATH", file=sys.stderr)
            return 127
        if rest == ["true"]:
            return 0
        line = " ".join(rest)
        for rule in b.get("exec_rules", []):
            if rule["contains"] in line:
                if rule.get("append"):
                    with open(rule["append"], "a") as f:
                        f.write("ran\n")
                print(rule.get("stdout", ""), end="")
                if rule.get("sleep"):
                    time.sleep(rule["sleep"])
                if rule.get("kill_container"):
                    # A room killed by the host cgroup: the container ends and docker exec gives 128.
                    # inspect_lag: docker still says running (OOMKilled already true) for that many inspects.
                    with Locked() as st:
                        for c in st["containers"].values():
                            c.update(exit_code=rule.get("container_exit", 137), oom_killed=rule.get("oom_killed", True))
                            if rule.get("inspect_lag"):
                                c["dying_inspects"] = rule["inspect_lag"]
                            else:
                                c["status"] = "exited"
                if rule.get("oom_kill_process"):
                    # The host OOM killer ended one process; the room runs on, docker records the OOM.
                    with Locked() as st:
                        for c in st["containers"].values():
                            c["oom_killed"] = True
                return rule.get("exit", 0)
        return 0

    if cmd == "exec" and "info" in argv:
        print("27.0.0-fake")  # inner dockerd of a DinD guest is ready
        return 0

    if cmd == "inspect" and "--format" in argv and ".State.Running" in argv[argv.index("--format") + 1]:
        # The state probe of exit_code_if_stopped: "true 0" while the
        # container runs, "false <code>" once its entrypoint ended.
        with Locked() as st:
            cid = find(st, argv[-1])
            c = st["containers"].get(cid) if cid else None
            if c is not None and c.get("dying_inspects"):
                c["dying_inspects"] -= 1
                if not c["dying_inspects"]:
                    c["status"] = "exited"
                c = {**c, "status": "running"}
        if c is None:
            print(f"Error: No such object: {argv[-1]}", file=sys.stderr)
            return 1
        extra = f" {'true' if c.get('oom_killed') else 'false'}" if "OOMKilled" in argv[argv.index("--format") + 1] else ""
        print((f"false {c.get('exit_code') or 0}" if c.get("status") == "exited" else "true 0") + extra)
        return 0

    if cmd == "save":
        with Locked() as st:
            st.setdefault("saved", []).append(argv[-1])
        return 1 if b.get("save_fail") else 0

    if cmd == "build":
        tag = argv[argv.index("-t") + 1]
        context = argv[-1]
        with Locked() as st:
            st.setdefault("builds", []).append({"tag": tag, "files": sorted(os.listdir(context))})
            if tag not in st["images"] and not b.get("build_fail"):
                st["images"].append(tag)
        if b.get("build_fail"):
            print("failed to solve: process did not complete successfully", file=sys.stderr)
            return 1
        return 0

    if cmd in ("exec", "inspect", "network", "pause", "unpause"):
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

    def add_image(self, ref: str, *, image_id: str | None = None, alias_of: str | None = None) -> None:
        state = self._load()
        if ref not in state["images"]:
            state["images"].append(ref)
        if image_id:
            state.setdefault("behaviour", {}).setdefault("image_ids", {})[ref] = image_id
        if alias_of:
            state.setdefault("behaviour", {}).setdefault("image_aliases", {})[ref] = alias_of
        self._save(state)

    def set_image_id(self, ref: str, image_id: str) -> None:
        state = self._load()
        state.setdefault("behaviour", {}).setdefault("image_ids", {})[ref] = image_id
        self._save(state)

    def set_image_config(
        self,
        ref: str,
        *,
        entrypoint: list[str] | None = None,
        cmd: list[str] | None = None,
        repo_digest: str | None = None,
    ) -> None:
        state = self._load()
        behaviour = state.setdefault("behaviour", {})
        behaviour.setdefault("image_configs", {})[ref] = {
            "Entrypoint": entrypoint,
            "Cmd": cmd,
        }
        if repo_digest is not None:
            behaviour.setdefault("image_digests", {})[ref] = [repo_digest]
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
    def networks(self) -> dict[str, dict[str, Any]]:
        return self._load().get("networks", {"bridge": {"containers": []}})

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
        "CATHEDRAL_ROOM_NETWORKS",
        "CATHEDRAL_ROOM_NETWORK_SIZE",
        "CATHEDRAL_ROOM_NETWORK_PREFIX",
        "CATHEDRAL_ROOM_NETWORK_SUBNETS",
        "CATHEDRAL_ROOM_NETWORK_BRIDGE_PREFIX",
        "CATHEDRAL_ROOM_NETWORK_DNS",
        "CATHEDRAL_ROOM_EGRESS_SOCKET",
        "CATHEDRAL_WORKSPACE_ROOT",
        "CATHEDRAL_WORKSPACE_MAX_PER_OWNER",
        "CATHEDRAL_WORKSPACE_MAX_VERSIONS",
        "CATHEDRAL_WORKSPACE_HELPER_IMAGE",
        "CATHEDRAL_WORKSPACE_MOUNT_CHECK",
        "CATHEDRAL_IMAGE_OWNERS_PATH",
        "CATHEDRAL_SHARED_HOTEL_BUILDS",
    ):
        monkeypatch.delenv(name, raising=False)
    # AB#650 ownership store: isolated per test under tmp_path.
    monkeypatch.setenv("CATHEDRAL_IMAGE_OWNERS_PATH", str(tmp_path / "image-owners.json"))
    monkeypatch.setenv("CATHEDRAL_SHARED_HOTEL_BUILDS", "allow")
    return FakeDocker(state_path)
