"""AB#789 HOLD fixes: the guest volume agent against a stubbed restic (runs in CI with no restic).

Covers: no mount after a failed restore or a repo-id mismatch, backup exit status, resend after a lost
registry answer, bearer auth on the front routes, verify_chain and lease-at-head on attach, the
password never leaving the restic environment, and the receipts front staying up when volumes fail.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import volume_agent as va
from cathedral import volume_chain as vc
from cathedral import volume_subtoken as vs

NOW = 1_800_000_000
REPO_ID = "f" * 64
SECRET = os.urandom(32)
ROOT = Path(__file__).resolve().parents[1]


class StubRestic:
    """Answers the agent's restic calls; records argv and env. Set the fields to make a call fail."""

    def __init__(self, repo_id: str = REPO_ID):
        self.repo_id = repo_id
        self.exists = False
        self.restore_code = 0
        self.backup_code = 0
        self.snapshots = 0
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, env: dict, *args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
        argv = list(args)
        self.calls.append((argv, dict(env)))
        verb = [a for a in argv if not a.startswith("-")][0]

        def done(code=0, out=""):
            return subprocess.CompletedProcess(argv, code, out, "")

        if verb == "cat":
            return done(0, json.dumps({"id": self.repo_id})) if self.exists else done(1)
        if verb == "init":
            self.exists = True
            return done()
        if verb == "restore":
            return done(self.restore_code)
        if verb == "backup":
            self.snapshots += 1
            summary = {"message_type": "summary", "snapshot_id": f"{self.snapshots:064x}"}
            return done(self.backup_code, json.dumps(summary) + "\n")
        raise AssertionError(f"unexpected restic call {argv}")

    def verbs(self) -> list[str]:
        return [[a for a in argv if not a.startswith("-")][0] for argv, _ in self.calls]


class Client:
    """The API's holder routes over the in-memory registry; can lose the answer to a commit."""

    def __init__(self, registry, registry_key):
        self.registry, self.registry_key = registry, registry_key
        self.commits: list[dict] = []
        self.lose_next_answer = False
        self.posts = 0

    def subtoken(self, volume_id, request_doc):
        lease = self.registry.volumes[volume_id].lease.doc
        return vs.issue(self.registry_key, lease, prefix=vs.volume_prefix(volume_id), source_ip="127.0.0.1",
                        ttl_seconds=600, now=lambda: NOW)

    def commit(self, volume_id, commit_doc):
        self.posts += 1
        head = self.registry.accept(commit_doc)
        if commit_doc not in self.commits:
            self.commits.append(commit_doc)
        if self.lose_next_answer:
            self.lose_next_answer = False
            raise va.RegistryError(502, "registry_unreachable")
        return head


class World:
    def __init__(self, monkeypatch, tmp_path):
        monkeypatch.setattr(va, "restic_version", lambda restic: va.RESTIC_VERSION)
        self.tmp = tmp_path
        self.registry_key = Ed25519PrivateKey.generate()
        self.registry = vc.VolumeRegistry(self.registry_key, now=lambda: NOW)
        self.keys = [vc.public_b64(self.registry_key)]
        self.client = Client(self.registry, self.registry_key)
        self.restic = StubRestic()
        self.registry.create("vol1", "owner")

    def host(self, name: str):
        key = Ed25519PrivateKey.generate()
        binding = {"schema": vc.SEALED_BINDING_SCHEMA, "hotel": name,
                   "receipt_key_ed25519_b64": vc.public_b64(key), "measurement": "m-" + name}
        signer = va.HolderSigner(key, binding, self.keys, now=lambda: NOW)
        keys = va.VolumeKeys(signer)
        keys.install(va.seal_volume_key(keys.install_key_document(), binding, volume_id="vol1", key_id="k1",
                                        secret=SECRET))
        agent = va.VolumeAgent(signer, keys, self.client, "http://127.0.0.1:9", "restic",
                               str(self.tmp / name / "cache"))
        agent._restic = self.restic
        return agent

    def grant(self, agent):
        volume = self.registry.volumes["vol1"]
        return {"volume": volume.doc, "commits": list(self.client.commits), "head": volume.head_doc,
                "lease": self.registry.grant("vol1", agent.signer.binding)}

    def release(self):
        self.registry.release("vol1", self.registry.volumes["vol1"].lease.statement["lease_id"])

    def head_generation(self) -> int:
        return self.registry.head("vol1")["statement"]["generation"]

    def at_generation_one(self):
        """Host a writes generation 1 and hands the lease back."""
        a = self.host("a")
        a.attach(self.grant(a), str(self.tmp / "a" / "ws"))
        assert a.commit("vol1")["statement"]["generation"] == 1
        self.release()
        return a


@pytest.fixture
def world(monkeypatch, tmp_path):
    return World(monkeypatch, tmp_path)


def test_commit_refused_after_failed_restore(world):
    world.at_generation_one()
    b = world.host("b")
    world.restic.restore_code = 1
    with pytest.raises(vc.VolumeRefused, match="restore_failed"):
        b.attach(world.grant(b), str(world.tmp / "b" / "ws"))
    assert "vol1" not in b.mounts
    backups = world.restic.verbs().count("backup")
    with pytest.raises(vc.VolumeRefused, match="volume_not_attached"):
        b.commit("vol1")
    # The empty workspace was never backed up nor signed; the head is still generation 1.
    assert world.restic.verbs().count("backup") == backups
    assert world.head_generation() == 1


def test_commit_refused_after_repo_id_mismatch(world):
    world.at_generation_one()
    b = world.host("b")
    world.restic.repo_id = "e" * 64  # storage swapped in another repo
    with pytest.raises(vc.VolumeRefused, match="restic_repo_not_the_committed_one"):
        b.attach(world.grant(b), str(world.tmp / "b" / "ws"))
    assert "restore" not in world.restic.verbs()[-1:]
    with pytest.raises(vc.VolumeRefused, match="volume_not_attached"):
        b.commit("vol1")
    assert world.head_generation() == 1


def test_failed_reattach_drops_the_old_mount(world):
    a = world.at_generation_one()
    world.restic.restore_code = 1
    with pytest.raises(vc.VolumeRefused, match="restore_failed"):
        a.attach(world.grant(a), str(world.tmp / "a" / "ws"))
    with pytest.raises(vc.VolumeRefused, match="volume_not_attached"):
        a.commit("vol1")


def test_successful_restore_then_commit(world):
    world.at_generation_one()
    b = world.host("b")
    attached = b.attach(world.grant(b), str(world.tmp / "b" / "ws"))
    assert attached["restored"]["generation"] == 1
    assert b.commit("vol1")["statement"]["generation"] == 2


def test_backup_exit_3_is_not_committed(world):
    a = world.host("a")
    a.attach(world.grant(a), str(world.tmp / "a" / "ws"))
    world.restic.backup_code = 3  # snapshot stored, some files unreadable
    with pytest.raises(vc.VolumeRefused, match="backup_failed"):
        a.commit("vol1")
    assert world.client.posts == 0
    assert world.head_generation() == 0


def test_lost_answer_resends_the_landed_commit(world):
    a = world.host("a")
    a.attach(world.grant(a), str(world.tmp / "a" / "ws"))
    world.client.lose_next_answer = True
    with pytest.raises(va.RegistryError):
        a.commit("vol1")
    assert world.head_generation() == 1  # it landed; the answer was lost
    head = a.commit("vol1")
    assert head["statement"]["generation"] == 1
    assert world.restic.verbs().count("backup") == 1  # the same commit, not a fresh backup
    assert a.commit("vol1")["statement"]["generation"] == 2  # and the mount carries on


def test_definite_refusal_clears_the_pending_commit(world):
    a = world.host("a")
    a.attach(world.grant(a), str(world.tmp / "a" / "ws"))

    def refuse(volume_id, commit_doc):
        raise va.RegistryError(409, "lease_expired")

    world.client.commit = refuse
    with pytest.raises(va.RegistryError):
        a.commit("vol1")
    assert a.mounts["vol1"]["pending"] is None


def test_unreachable_registry_is_a_registry_error(monkeypatch):
    import urllib.error

    def down(*args, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(va.urllib.request, "urlopen", down)
    with pytest.raises(va.RegistryError) as exc:
        va.RegistryClient("http://127.0.0.1:9").commit("vol1", {})
    assert exc.value.status == 502


def test_verify_chain_on_attach_restores_nothing(world):
    world.at_generation_one()
    b = world.host("b")
    grant = world.grant(b)
    other = Ed25519PrivateKey.generate()
    forged_head = vc.sign_statement(other, grant["head"]["statement"])
    for bad, code in ((dict(grant, head=forged_head), "head_not_signed_by_registry"),
                      (dict(grant, commits=[]), "chain_not_at_head")):
        calls = len(world.restic.calls)
        with pytest.raises(vc.VolumeRefused, match=code):
            b.attach(bad, str(world.tmp / "b" / "ws"))
        assert len(world.restic.calls) == calls  # restic never ran
        assert "vol1" not in b.mounts


def test_attach_refuses_a_lease_not_at_head(world):
    a = world.host("a")
    grant0 = world.grant(a)
    a.attach(grant0, str(world.tmp / "a" / "ws"))
    a.commit("vol1")
    volume = world.registry.volumes["vol1"]
    # The generation 0 lease with the generation 1 chain: restoring would fork the head.
    stale = {"volume": volume.doc, "commits": list(world.client.commits), "head": volume.head_doc,
             "lease": grant0["lease"]}
    a.mounts.clear()
    with pytest.raises(vc.VolumeRefused, match="lease_not_at_head"):
        a.attach(stale, str(world.tmp / "a" / "ws"))
    assert "vol1" not in a.mounts


def test_front_routes_need_the_bearer(world):
    a = world.host("a")
    front = va.FrontRoutes(a, str(world.tmp / "ws"))
    body = json.dumps({"volume_id": "vol1", "workspace": "w", "grant": world.grant(a)}).encode()
    for path in va.FrontRoutes.PATHS[1:]:
        assert front.handle(path, "POST", body, authorized=False) == (401, {"error": "unauthorized"})
    assert world.restic.calls == [] and a.mounts == {}
    status, doc = front.handle("/room/volume-key-install-key", "GET", None, authorized=False)
    assert status == 200 and doc["statement"]["schema"] == va.KEY_INSTALL_SCHEMA
    assert front.handle("/room/volume-attach", "POST", body, authorized=True)[0] == 200


def test_password_stays_in_the_restic_environment(world):
    a = world.at_generation_one()
    password = a.keys.password("vol1")
    assert password == SECRET.hex()
    b = world.host("b")
    front = va.FrontRoutes(b, str(world.tmp / "front"))
    answers = [front.handle("/room/volume-key-install-key", "GET", None, True),
               front.handle("/room/volume-attach", "POST",
                            json.dumps({"grant": world.grant(b), "workspace": "w"}).encode(), True),
               front.handle("/room/volume-commit", "POST", b'{"volume_id": "vol1"}', True),
               front.handle("/room/volume-commit", "POST", b'{"volume_id": "nope"}', True),
               front.handle("/room/volume-lease-request", "POST", b'{"volume_id": "vol1"}', True)]
    world.release()
    c = world.host("c")
    world.restic.restore_code = 1
    answers.append(va.FrontRoutes(c, str(world.tmp / "front-c")).handle(
        "/room/volume-attach", "POST", json.dumps({"grant": world.grant(c), "workspace": "w"}).encode(), True))
    assert answers[-1] == (409, {"error": "restore_failed"})
    text = json.dumps(answers) + json.dumps(world.client.commits) + repr(b.mounts) + repr(c.mounts)
    assert password not in text and SECRET.hex() not in text
    for argv, env in world.restic.calls:
        assert password not in " ".join(argv)
        assert password not in env["RESTIC_REPOSITORY"]
        assert env["RESTIC_PASSWORD"] == password


def _load_receipts():
    spec = importlib.util.spec_from_file_location("room_receipts", ROOT / "room-kit" / "room_receipts.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["room_receipts"] = mod
    spec.loader.exec_module(mod)
    return mod


class Ledger:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.sealed = True
        self.binding = {"schema": vc.SEALED_BINDING_SCHEMA, "receipt_key_ed25519_b64": vc.public_b64(self.key),
                        "measurement": "m"}


def _env(tmp_path, restic: str) -> dict:
    return {"ROOM_VOLUMES": "1", "ROOM_VOLUME_REGISTRY_KEYS": vc.public_b64(Ed25519PrivateKey.generate()),
            "ROOM_VOLUME_REGISTRY_URL": "http://127.0.0.1:9", "ROOM_VOLUME_GATEWAY_URL": "http://127.0.0.1:9",
            "ROOM_VOLUME_RESTIC": restic, "ROOM_VOLUME_CACHE_DIR": str(tmp_path / "cache")}


def _fake_restic(tmp_path, version: str) -> str:
    path = tmp_path / f"restic-{version}"
    path.write_text(f"#!/bin/sh\necho 'restic {version} compiled with go1.24 on linux/amd64'\n")
    path.chmod(0o755)
    return str(path)


def test_receipts_front_keeps_serving_when_volumes_fail(tmp_path, monkeypatch):
    rr = _load_receipts()
    ledger = Ledger()
    assert rr.start_volumes(ledger, {}) is None
    # restic not the pinned version
    assert rr.start_volumes(ledger, _env(tmp_path, _fake_restic(tmp_path, "0.17.0"))) is None
    # no registry keys (RuntimeError) and no URLs (KeyError)
    assert rr.start_volumes(ledger, dict(_env(tmp_path, "x"), ROOM_VOLUME_REGISTRY_KEYS="")) is None
    assert rr.start_volumes(ledger, {"ROOM_VOLUMES": "1", "ROOM_VOLUME_REGISTRY_KEYS": "k"}) is None
    # an API tarball without the agent (de28030)
    import cathedral
    monkeypatch.delattr(cathedral, "volume_agent")
    monkeypatch.setitem(sys.modules, "cathedral.volume_agent", None)
    assert rr.start_volumes(ledger, _env(tmp_path, _fake_restic(tmp_path, va.RESTIC_VERSION))) is None
    monkeypatch.undo()
    volumes = rr.start_volumes(ledger, _env(tmp_path, _fake_restic(tmp_path, va.RESTIC_VERSION)))
    assert isinstance(volumes, va.FrontRoutes)
