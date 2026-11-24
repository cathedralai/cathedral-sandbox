"""AB#825: volume commits on a timer, with the registry-signed head kept as each commit's receipt."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import volume_agent as va
from cathedral import volume_chain as vc
from cathedral import volume_gateway as vg
from cathedral import volume_subtoken as vs
from tests import test_ab789_volume_agent as real
from tests.test_ab789_volume_agent_stubbed import Ledger, World, _env, _fake_restic, _load_receipts


def _attached(monkeypatch, tmp_path):
    world = World(monkeypatch, tmp_path)
    agent = world.host("a")
    workspace = tmp_path / "a" / "ws"
    agent.attach(world.grant(agent), str(workspace))
    return world, agent, workspace, va.CommitTimer(agent, 60, now=lambda: 1_800_000_000)


def test_tick_commits_changed_workspaces_and_keeps_the_signed_head(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    (workspace / "notes.txt").write_text("one")
    timer.tick()
    status = timer.snapshot()["vol1"]
    assert status["generation"] == 1 and world.head_generation() == 1
    # The receipt is the registry's signed head of this exact commit.
    head = vc._check_signed(status["receipt"], vc.HEAD_SCHEMA, world.keys, "bad")
    assert head["head_sha256"] == vc.statement_sha256(world.client.commits[-1])
    # Nothing changed: no backup, no new generation, the receipt stays.
    backups = world.restic.verbs().count("backup")
    timer.tick()
    assert world.restic.verbs().count("backup") == backups and world.head_generation() == 1
    assert timer.snapshot()["vol1"]["receipt"] == status["receipt"]
    (workspace / "notes.txt").write_text("two, longer")
    timer.tick()
    assert timer.snapshot()["vol1"]["generation"] == 2 and world.head_generation() == 2


def test_a_write_during_the_backup_is_committed_next_tick(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    stub = world.restic

    def backup_while_writing(env, *args, cwd=None):
        if "backup" in args:
            (workspace / "late.txt").write_text("written during the backup")
        return stub(env, *args, cwd=cwd)

    agent._restic = backup_while_writing
    timer.tick()
    agent._restic = stub
    timer.tick()
    assert world.head_generation() == 2


def test_restored_workspace_is_not_recommitted(monkeypatch, tmp_path):
    world = World(monkeypatch, tmp_path)
    world.at_generation_one()
    b = world.host("b")
    workspace = tmp_path / "b" / "ws"
    workspace.mkdir(parents=True)
    (workspace / "restored.txt").write_text("as restored")
    b.attach(world.grant(b), str(workspace))
    timer = va.CommitTimer(b, 60)
    timer.tick()
    assert world.head_generation() == 1 and "receipt" not in timer.snapshot()["vol1"]


def test_lost_answer_is_resent_next_tick(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    world.client.lose_next_answer = True
    timer.tick()
    assert timer.snapshot()["vol1"]["last_error"] == "registry_unreachable"
    assert "vol1" in agent.mounts
    backups = world.restic.verbs().count("backup")
    timer.tick()
    status = timer.snapshot()["vol1"]
    assert status["generation"] == 1 and "last_error" not in status
    assert world.restic.verbs().count("backup") == backups  # the same commit, not a fresh backup


def test_pending_commit_is_resent_even_if_nothing_changed_since(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    world.client.lose_next_answer = True
    timer.tick()
    # The workspace now matches the last fingerprint, but the commit's answer is still owed.
    mount = agent.mounts["vol1"]
    mount["fingerprint"] = va.workspace_fingerprint(mount["target"])
    timer.tick()
    assert timer.snapshot()["vol1"]["generation"] == 1 and mount["pending"] is None


class Refusing:
    def __init__(self, inner, status, code):
        self.inner, self.status, self.code = inner, status, code

    def subtoken(self, volume_id, request_doc):
        return self.inner.subtoken(volume_id, request_doc)

    def commit(self, volume_id, commit_doc):
        raise va.RegistryError(self.status, self.code)


def test_shredded_volume_is_detached_and_its_key_dropped(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    agent.registry = Refusing(world.client, 410, "volume_shredded")
    timer.tick()
    status = timer.snapshot()["vol1"]
    assert status["last_error"] == "volume_shredded" and status["detached"] is True
    assert "vol1" not in agent.mounts and "vol1" not in agent.keys.passwords
    calls = len(world.restic.calls)
    timer.tick()
    assert len(world.restic.calls) == calls


def test_lease_moved_elsewhere_detaches_but_keeps_key(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    agent.registry = Refusing(world.client, 409, "lease_not_current")
    timer.tick()
    assert "vol1" not in agent.mounts and "vol1" in agent.keys.passwords


def test_other_refusals_keep_the_volume_attached(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    agent.registry = Refusing(world.client, 409, "lease_expired")
    timer.tick()
    assert "vol1" in agent.mounts and timer.snapshot()["vol1"]["last_error"] == "lease_expired"


def test_refusal_never_detaches_a_mount_attached_after_it(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    agent.registry = Refusing(world.client, 409, "lease_not_current")
    real = agent.commit_if_changed
    replacement = dict(agent.mounts["vol1"], lease={"new": True})

    def commit_then_reattach(volume_id):
        try:
            return real(volume_id)
        finally:
            # The refused commit already let go of the lock: a re-attach publishes a new mount now.
            assert volume_id not in agent.mounts
            agent.mounts[volume_id] = replacement

    monkeypatch.setattr(agent, "commit_if_changed", commit_then_reattach)
    timer.tick()
    assert agent.mounts["vol1"] is replacement and timer.snapshot()["vol1"]["detached"] is True


def test_fingerprint_handles_non_utf8_names(tmp_path):
    name = os.fsdecode(b"bad-\xff-name")
    (tmp_path / name).write_text("x")
    first = va.workspace_fingerprint(str(tmp_path))
    (tmp_path / name).write_text("changed")
    assert first and va.workspace_fingerprint(str(tmp_path)) != first


def test_one_volume_crashing_does_not_stop_the_others(monkeypatch, tmp_path):
    world, agent, workspace, timer = _attached(monkeypatch, tmp_path)
    agent.mounts["vol0"] = dict(agent.mounts["vol1"])
    real = agent.commit_if_changed

    def commit_if_changed(volume_id):
        if volume_id == "vol0":
            raise ZeroDivisionError
        return real(volume_id)

    monkeypatch.setattr(agent, "commit_if_changed", commit_if_changed)
    timer.tick()
    snapshot = timer.snapshot()
    assert snapshot["vol0"]["last_error"] == "ZeroDivisionError" and snapshot["vol1"]["generation"] == 1


def test_timer_thread_runs_and_stops(monkeypatch, tmp_path):
    world, agent, workspace, _ = _attached(monkeypatch, tmp_path)
    timer = va.CommitTimer(agent, 0.05).start()
    deadline = time.monotonic() + 10
    while world.head_generation() < 1 and time.monotonic() < deadline:
        time.sleep(0.02)
    timer.stop()
    assert world.head_generation() == 1 and not timer._thread.is_alive()
    off = va.CommitTimer(agent, 0).start()
    assert off._thread is None


@pytest.mark.parametrize("value,expected", [(None, 300), ("", 300), ("0", 0), ("30", 30), ("86400", 86400)])
def test_commit_seconds_accepts(value, expected):
    assert va.commit_seconds(value) == expected


@pytest.mark.parametrize("value", ["29", "86401", "-5", "abc", "1.5"])
def test_commit_seconds_refuses(value):
    with pytest.raises(RuntimeError):
        va.commit_seconds(value)


def test_front_serves_status_and_bad_interval_keeps_volumes_off(monkeypatch, tmp_path):
    rr = _load_receipts()
    env = _env(tmp_path, _fake_restic(tmp_path, va.RESTIC_VERSION))
    assert rr.start_volumes(Ledger(), dict(env, ROOM_VOLUME_COMMIT_SECONDS="5")) is None
    routes = rr.start_volumes(Ledger(), dict(env, ROOM_VOLUME_COMMIT_SECONDS="0"))
    assert routes.timer.interval == 0 and routes.timer._thread is None
    assert "/room/volume-status" in routes.PATHS
    assert routes.handle("/room/volume-status", "GET", None, False) == (401, {"error": "unauthorized"})
    assert routes.handle("/room/volume-status", "POST", b"{}", True)[0] == 405
    status, body = routes.handle("/room/volume-status", "GET", None, True)
    assert status == 200 and body == {"interval_seconds": 0, "volumes": {}}
    json.dumps(body)


def test_install_carries_the_interval_into_the_unit():
    install = (Path(__file__).resolve().parents[1] / "room-kit" / "install.sh").read_text()
    keys_line = next(line for line in install.splitlines() if line.startswith("ROOM_KEYS="))
    assert " ROOM_VOLUME_COMMIT_SECONDS" in keys_line
    assert "Environment=ROOM_VOLUME_COMMIT_SECONDS=${ROOM_VOLUME_COMMIT_SECONDS:-}" in install


@pytest.mark.skipif(real._restic() is None, reason="pinned restic 0.19.1 not available")
def test_timer_with_pinned_restic_then_restore_on_another_host(tmp_path, monkeypatch):
    registry_key = Ed25519PrivateKey.generate()
    registry = vc.VolumeRegistry(registry_key, now=lambda: real.NOW)
    keys = [vc.public_b64(registry_key)]
    monkeypatch.setattr(vs.time, "time", lambda: real.NOW)
    server, _ = vg.serve(tmp_path / "store", keys[0])
    gateway = f"http://127.0.0.1:{server.server_address[1]}"
    client = real.InMemoryRegistryClient(registry, registry_key)
    secret = os.urandom(32)

    def host(name):
        boot = real.Boot(name, keys)
        boot.keys.install(va.seal_volume_key(boot.keys.install_key_document(), boot.binding, volume_id="vol1",
                                             key_id="k1", secret=secret))
        return boot, va.VolumeAgent(boot.signer, boot.keys, client, gateway, real._restic(),
                                    str(tmp_path / name / "cache"))

    def grant(boot):
        volume = registry.volumes["vol1"]
        return {"volume": volume.doc, "commits": list(client.commits), "head": volume.head_doc,
                "lease": registry.grant("vol1", boot.binding)}

    try:
        registry.create("vol1", "owner")
        a, agent_a = host("a")
        work_a = tmp_path / "a" / "ws"
        agent_a.attach(grant(a), str(work_a))
        timer_a = va.CommitTimer(agent_a, 60)
        (work_a / "notes.txt").write_text("tick one\n")
        timer_a.tick()
        timer_a.tick()  # unchanged: no commit
        assert registry.head("vol1")["statement"]["generation"] == 1
        (work_a / "notes.txt").write_text("tick two, changed\n")
        timer_a.tick()
        receipt = timer_a.snapshot()["vol1"]["receipt"]
        assert receipt == registry.head("vol1") and receipt["statement"]["generation"] == 2
        registry.release("vol1", registry.volumes["vol1"].lease.statement["lease_id"])
        b, agent_b = host("b")
        work_b = tmp_path / "b" / "ws"
        assert agent_b.attach(grant(b), str(work_b))["restored"]["generation"] == 2
        assert (work_b / "notes.txt").read_text() == "tick two, changed\n"
        timer_b = va.CommitTimer(agent_b, 60)
        timer_b.tick()  # a fresh restore is not a change
        assert registry.head("vol1")["statement"]["generation"] == 2
    finally:
        server.shutdown()
