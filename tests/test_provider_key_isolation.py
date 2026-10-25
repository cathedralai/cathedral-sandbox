"""One hotel API key must not see or use another key's snapshots, replayed
creates or usage. The shipped hotel runs one key, so these are the
provider's own contract; a second key on a hotel must not break it."""
from __future__ import annotations

import pytest

from cathedral.sandbox_api import ApiKey, CreateSandboxRequest, FileGet, ImageSource, QuotaLimits, Resources
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError


@pytest.fixture
def p():
    provider = InMemorySandboxProvider(
        keys=[ApiKey(key="alice", project="a"), ApiKey(key="bob", project="b")],
        limits=QuotaLimits(running_sandboxes=100, vcpu=200, memory_gib=400),
        require_known_keys=True,
    )
    try:
        yield provider
    finally:
        provider.close()


def _req(**over) -> CreateSandboxRequest:
    values = {"image": ImageSource(image="repo/tool:latest"), "resources": Resources(vcpu=1, memory_gib=2, disk_gib=5)}
    values.update(over)
    return CreateSandboxRequest(**values)


def _snap(p, sandbox_id, **kw) -> str:
    return p.get_operation(p.snapshot(sandbox_id, **kw))["result"]["snapshot_id"]


def test_a_snapshot_cannot_be_forked_by_another_key(p) -> None:
    sa = p.create(_req(), api_key="alice", idempotency=None, body_digest="a")["id"]
    p.write_file(sa, "/work/secret.txt", b"ALICE-TOPSECRET", None)
    snap_id = _snap(p, sa, name="base")
    fork = Resources(vcpu=1, memory_gib=2, disk_gib=5)
    for ref in ("base", snap_id):
        with pytest.raises(SandboxOpError) as err:
            p.create(CreateSandboxRequest(snapshot_id=ref, resources=fork), api_key="bob", idempotency=None, body_digest="b")
        assert err.value.code == "snapshot_not_found"
    # Alice still can, by name and by id.
    sb = p.create(CreateSandboxRequest(snapshot_id="base", resources=fork), api_key="alice", idempotency=None, body_digest="c")["id"]
    assert p.read_file(sb, FileGet(path="/work/secret.txt"))[0] == b"ALICE-TOPSECRET"


def test_snapshot_list_delete_and_names_are_per_key(p) -> None:
    sa = p.create(_req(), api_key="alice", idempotency=None, body_digest="a")["id"]
    sb = p.create(_req(), api_key="bob", idempotency=None, body_digest="b")["id"]
    p.authorize("alice")
    alice_snap = _snap(p, sa, name="base", labels={"team": "alice"})
    p.authorize("bob")
    assert [s["snapshot_id"] for s in p.list_snapshots()] == []
    assert p.delete_snapshot(alice_snap) is False
    # The name "base" is Bob's own namespace: get-or-create must not hand him Alice's.
    bob_snap = _snap(p, sb, name="base")
    assert bob_snap != alice_snap
    assert {s["snapshot_id"] for s in p.list_snapshots()} == {bob_snap}
    p.authorize("alice")
    assert {s["snapshot_id"] for s in p.list_snapshots()} == {alice_snap}
    assert p.delete_snapshot(alice_snap) is True


def test_idempotency_keys_are_per_key(p) -> None:
    da = p.create(_req(labels={"job": "alice-secret-name"}), api_key="alice", idempotency="shared-1", body_digest="SAME")
    db = p.create(_req(labels={"job": "alice-secret-name"}), api_key="bob", idempotency="shared-1", body_digest="SAME")
    assert db["id"] != da["id"]
    p.authorize("bob")
    assert p.get(db["id"])["id"] == db["id"]
    # A replay by the same key still works.
    again = p.create(_req(labels={"job": "alice-secret-name"}), api_key="alice", idempotency="shared-1", body_digest="SAME")
    assert again["id"] == da["id"]


def test_usage_is_scoped_to_the_caller(p) -> None:
    p.create(_req(labels={"job": "alice-job"}), api_key="alice", idempotency=None, body_digest="a")
    p.create(_req(labels={"job": "bob-job"}), api_key="bob", idempotency=None, body_digest="b")
    p.authorize("bob")
    groups = p.usage(group_by="label.job", labels=[])["groups"]
    assert "bob-job" in groups and "alice-job" not in groups
