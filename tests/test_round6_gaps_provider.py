"""Review round 6 (reader P): per-key usage and snapshot bookkeeping of PR #312
that no test guarded (in-memory provider). Each test failed on 22e7824."""
from __future__ import annotations

import os
import time

import pytest

from cathedral.sandbox_api import ApiKey, CreateSandboxRequest, ImageSource, QuotaLimits, Resources
from cathedral.sandbox_provider import InMemorySandboxProvider


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


# ---------------------------------------------------------------- O12: usage per key

def test_usage_hides_another_key_s_deleted_sandboxes_and_snapshots(p) -> None:
    # A deleted sandbox bills from its log tombstone and a snapshot from its
    # record; both were summed into every caller's usage and cost.
    sa = p.create(_req(labels={"job": "alice-job"}), api_key="alice", idempotency=None, body_digest="a")["id"]
    p.write_file(sa, "/work/big.bin", os.urandom(4 << 20), None)  # a snapshot with a visible GiB-month cost
    p.get_operation(p.snapshot(sa))
    p.delete(sa)
    p.authorize("alice")
    own = p.usage(group_by="label.job", labels=[])
    assert "alice-job" in own["groups"] and own["snapshot_gib_months"] > 0 and own["total_cost_usd"] > 0
    p.authorize("bob")
    other = p.usage(group_by="label.job", labels=[])
    assert "alice-job" not in other["groups"]
    assert other["snapshot_gib_months"] == 0 and other["snapshot_cost_usd"] == 0 and other["total_cost_usd"] == 0


# ---------------------------------------------------------------- O15: owner entry dropped at expiry

def test_an_expired_snapshot_leaves_no_owner_entry(p) -> None:
    # Bookkeeping: the owner map must follow the snapshot map, or every
    # expired snapshot leaves an entry behind for the life of the process.
    sa = p.create(_req(), api_key="alice", idempotency=None, body_digest="a")["id"]
    snap = p.get_operation(p.snapshot(sa, ttl_seconds=1))["result"]["snapshot_id"]
    assert p._snapshot_owner[snap] == "alice"  # noqa: SLF001
    time.sleep(1.1)
    assert p.list_snapshots() == []  # the expiry sweep ran
    assert snap not in p._snapshot_owner  # noqa: SLF001
    assert set(p._snapshot_owner) == set(p._snapshots)  # noqa: SLF001
