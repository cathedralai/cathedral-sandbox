"""AB#789 / AB#395: concurrent attach and commit on the same volume (sandbox #716 P1).

The receipts front is a ThreadingHTTPServer, so /room/volume-attach and /room/volume-commit can run
at the same time. Ported from Review bot's restore-boundary reproduction. Real chain, signatures and
in-memory registry; stubbed restic, no network.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import volume_agent as va
from cathedral import volume_chain as vc

_spec = importlib.util.spec_from_file_location("ab789_volume_helpers",
                                               Path(__file__).with_name("test_ab789_volume_agent.py"))
helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(helpers)


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    registry = vc.VolumeRegistry(key, now=lambda: helpers.NOW)
    registry_keys = [vc.public_b64(key)]
    first, second = helpers.Boot("first", registry_keys), helpers.Boot("second", registry_keys)
    genesis = registry.create("vol1", "owner")
    lease = registry.grant("vol1", first.binding)
    seed = first.signer.sign_commit(lease, generation=1, parent_sha256=vc.statement_sha256(genesis),
                                    restic_repo_id="repo1", restic_snapshot_id="a" * 64)
    registry.accept(seed)
    registry.release("vol1", lease["statement"]["lease_id"])
    client = helpers.InMemoryRegistryClient(registry, key)
    client.commits.append(seed)
    volume = registry.volumes["vol1"]
    grant = {"volume": volume.doc, "commits": list(client.commits), "head": volume.head_doc,
             "lease": registry.grant("vol1", second.binding)}
    second.keys.install(va.seal_volume_key(second.keys.install_key_document(), second.binding,
                                           volume_id="vol1", key_id="synthetic", secret=b"x" * 32))
    monkeypatch.setattr(va, "restic_version", lambda _: va.RESTIC_VERSION)
    agent = va.VolumeAgent(second.signer, second.keys, client, "http://127.0.0.1:1", "stubbed", str(tmp_path))
    control = {"fail": False, "block": False}
    entered, release = threading.Event(), threading.Event()

    def restic(env, *args, cwd=None):
        if "config" in args:
            return subprocess.CompletedProcess(args, 0, json.dumps({"id": "repo1"}), "")
        if "restore" in args:
            entered.set()
            if control["block"]:
                assert release.wait(5), "test restore barrier timed out"
            return subprocess.CompletedProcess(args, int(control["fail"]), "", "injected restore failure")
        if "backup" in args:
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"message_type": "summary", "snapshot_id": "b" * 64}), "")
        raise AssertionError(args)

    monkeypatch.setattr(agent, "_restic", restic)
    return agent, registry, grant, str(tmp_path / "workspace"), control, entered, release


@pytest.mark.parametrize("reattach", [False, True])
def test_commit_during_restore_cannot_advance_head(prepared, reattach):
    agent, registry, grant, target, control, entered, release = prepared
    if reattach:
        agent.attach(grant, target)
        entered.clear()
    control["block"] = True
    errors = []
    commit_started, commit_finished = threading.Event(), threading.Event()

    def attach():
        try:
            agent.attach(grant, target)
        except BaseException as exc:
            errors.append(exc)

    def commit():
        commit_started.set()
        try:
            agent.commit("vol1")
        except vc.VolumeRefused:
            pass
        except BaseException as exc:
            errors.append(exc)
        finally:
            commit_finished.set()

    attacher, committer = threading.Thread(target=attach), threading.Thread(target=commit)
    attacher.start()
    try:
        assert entered.wait(5), "restore did not start"
        committer.start()
        assert commit_started.wait(5)
        commit_finished.wait(0.1)
        assert registry.head("vol1")["statement"]["generation"] == 1, "commit advanced while restore was blocked"
    finally:
        release.set()
        attacher.join(5)
        if committer.ident is not None:
            committer.join(5)
    assert not attacher.is_alive() and not committer.is_alive()
    assert not errors


def test_commit_already_in_backup_cannot_publish_after_failed_reattach(prepared, monkeypatch):
    """A commit holding the previous mount must not publish a partial restore.

    Hold the commit inside backup, re-attach with a restore that partially overwrites the workspace
    and fails, then release the backup. Generation 2 may only be accepted if its backup read the
    complete workspace, which means the commit finished before the re-attach touched it.
    """
    agent, registry, grant, target, control, _, _ = prepared
    agent.attach(grant, target)
    workspace_file = Path(target) / "customer.txt"
    workspace_file.write_text("complete workspace")
    captured = []
    original = agent._restic
    backup_entered, release_backup, restore_failed = threading.Event(), threading.Event(), threading.Event()
    errors = []

    def restic(env, *args, cwd=None):
        if "backup" in args:
            backup_entered.set()
            assert release_backup.wait(5), "backup barrier timed out"
            captured.append(workspace_file.read_text())
        result = original(env, *args, cwd=cwd)
        if "restore" in args and result.returncode:
            workspace_file.write_text("partial restore")
            restore_failed.set()
        return result

    monkeypatch.setattr(agent, "_restic", restic)

    def commit():
        try:
            agent.commit("vol1")
        except vc.VolumeRefused:
            pass
        except BaseException as exc:
            errors.append(exc)

    def reattach():
        try:
            agent.attach(grant, target)
        except vc.VolumeRefused:
            pass
        except BaseException as exc:
            errors.append(exc)

    committer, attacher = threading.Thread(target=commit), threading.Thread(target=reattach)
    committer.start()
    try:
        assert backup_entered.wait(5)
        control["fail"] = True
        attacher.start()
        restore_failed.wait(0.1)
    finally:
        release_backup.set()
        committer.join(5)
        if attacher.ident is not None:
            attacher.join(5)
    assert not committer.is_alive() and not attacher.is_alive()
    assert not errors
    assert restore_failed.is_set(), "the re-attach never ran its restore"
    generation = registry.head("vol1")["statement"]["generation"]
    if captured != ["complete workspace"]:
        assert generation == 1, "in-flight backup published after a failed overlapping restore"
    # The failed re-attach leaves no mount, so nothing more can be committed from the partial workspace.
    with pytest.raises(vc.VolumeRefused, match="volume_not_attached"):
        agent.commit("vol1")
    assert registry.head("vol1")["statement"]["generation"] == generation
