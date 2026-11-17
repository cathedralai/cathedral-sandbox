"""AB#398: the registry writes every head to the volume log, shreds with a receipt,
and prune runs only with a delete-scoped prune token.

Done line parts covered here: each head appears in an append-only log, shred
returns a receipt and a restore after shred fails, prune works with a
delete-scoped token only. The commit timer needs the guest volume agent
(AB#789) and is not here.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral import volume_chain as vc
from cathedral import volume_log as vl
from cathedral import volume_subtoken as st

T0 = 1_800_000_000
PREFIX = "volumes/vol-1/"
RUNNER_IP = "198.51.100.5"


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def binding(key: Ed25519PrivateKey) -> dict:
    return {"schema": vc.SEALED_BINDING_SCHEMA, "hotel": "hotel-a", "boot_id": "b1",
            "receipt_key_ed25519_b64": vc.public_b64(key), "measurement": "aa" * 48}


@pytest.fixture
def world():
    clock = Clock()
    key = Ed25519PrivateKey.generate()
    registry = vc.VolumeRegistry(key, now=clock, lease_seconds=600)
    volume_doc = registry.create("vol-1", "customer-1")
    holder = Ed25519PrivateKey.generate()
    lease = registry.grant("vol-1", binding(holder))
    return clock, registry, volume_doc, holder, lease


def commit_next(registry, holder, lease, snapshot: str) -> dict:
    head = registry.head("vol-1")["statement"]
    return vc.make_commit(holder, lease, generation=head["generation"] + 1, parent_sha256=head["head_sha256"],
                          restic_repo_id="repo-1", restic_snapshot_id=snapshot)


def refused(code: str, fn, *args, **kwargs):
    with pytest.raises(vc.VolumeRefused) as exc:
        fn(*args, **kwargs)
    assert exc.value.code == code


def log_keys(registry) -> dict[str, bytes]:
    return {registry.log_signing_key_id: registry.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}


class KeyService:
    def __init__(self, result=True, error: Exception | None = None):
        self.calls: list[str] = []
        self.result = result
        self.error = error

    def __call__(self, key_id: str):
        self.calls.append(key_id)
        if self.error is not None:
            raise self.error
        return self.result


# --- head log -----------------------------------------------------------------


def test_each_accepted_head_is_logged(world):
    _, registry, _, holder, lease = world
    assert registry.log_entries() == []
    commits = []
    for snap in ("s1", "s2", "s3"):
        doc = commit_next(registry, holder, lease, snap)
        registry.accept(doc)
        commits.append(doc)
    log = registry.log_entries()
    heads = vl.verify_log(log)
    assert [e["generation"] for e in log] == [1, 2, 3]
    assert all(e["kind"] == vl.KIND_HEAD and e["volume_id"] == "vol-1" for e in log)
    assert [e["commit_receipt_sha256"] for e in log] == ["sha256:" + vc.statement_sha256(d) for d in commits]
    assert heads["vol-1"].manifest_sha256 == vc.manifest_sha256(commits[-1]["statement"])
    assert log[0]["logged_at"] == "2027-01-15T08:00:00Z"


def test_log_only_grows_and_resend_does_not_append(world):
    _, registry, _, holder, lease = world
    doc = commit_next(registry, holder, lease, "s1")
    registry.accept(doc)
    before = registry.log_entries()
    registry.accept(doc)  # exact resend
    assert registry.log_entries() == before
    registry.accept(commit_next(registry, holder, lease, "s2"))
    vl.verify_extends(before, registry.log_entries())


def test_refused_commit_leaves_log_unchanged(world):
    _, registry, _, holder, lease = world
    registry.accept(commit_next(registry, holder, lease, "s1"))
    before = registry.log_entries()
    stale = vc.make_commit(holder, lease, generation=1, parent_sha256="00" * 32,
                           restic_repo_id="repo-1", restic_snapshot_id="s9")
    refused("generation_not_next", registry.accept, stale)
    assert registry.log_entries() == before


def test_volume_id_the_log_cannot_hold_is_refused_at_create(world):
    _, registry, *_ = world
    refused("bad_volume_id", registry.create, "vol.1", "customer-1")
    refused("bad_volume_id", registry.create, "vol 1", "customer-1")


def test_restoring_guest_checks_the_logged_head(world):
    clock, registry, volume_doc, holder, lease = world
    commits = []
    for snap in ("s1", "s2"):
        doc = commit_next(registry, holder, lease, snap)
        registry.accept(doc)
        commits.append(doc)
    head = vc.verify_chain(volume_doc, commits, registry.head("vol-1"), [registry.public_b64])
    log = registry.log_entries()
    vl.check_restore(log, volume_id="vol-1", generation=head["generation"],
                     manifest_sha256=vc.manifest_sha256(head))
    with pytest.raises(vl.VolumeLogError, match="not_latest_head"):
        vl.check_restore(log, volume_id="vol-1", generation=1,
                         manifest_sha256=vc.manifest_sha256(commits[0]["statement"]))


# --- shred --------------------------------------------------------------------


def shredded_world(world):
    clock, registry, volume_doc, holder, lease = world
    commits = []
    for snap in ("s1", "s2"):
        doc = commit_next(registry, holder, lease, snap)
        registry.accept(doc)
        commits.append(doc)
    final_head = registry.head("vol-1")
    keys = KeyService()
    clock.t += 30
    receipt = registry.shred("vol-1", key_id="vk:vol-1", destroy_key=keys)
    return registry, volume_doc, holder, lease, commits, final_head, keys, receipt


def test_shred_returns_a_receipt_that_matches_the_log(world):
    registry, _, _, _, commits, _, keys, receipt = shredded_world(world)
    assert keys.calls == ["vk:vol-1"]
    log = registry.log_entries()
    assert log[-1]["kind"] == vl.KIND_SHRED
    assert log[-1]["commit_receipt_sha256"] == "sha256:" + vc.statement_sha256(commits[-1])
    vl.verify_shred_receipt(receipt, public_keys_by_id=log_keys(registry), entries=log)
    assert receipt["final_generation"] == 2
    assert receipt["key_id"] == "vk:vol-1"
    assert receipt["shredded_at"] == "2027-01-15T08:00:30Z"
    assert receipt["signing_key_id"].startswith("registry:")


def test_restore_after_shred_fails(world):
    registry, volume_doc, _, _, commits, final_head, _, _ = shredded_world(world)
    # The chain alone still verifies (storage still holds it); the log refuses the restore.
    head = vc.verify_chain(volume_doc, commits, final_head, [registry.public_b64])
    with pytest.raises(vl.VolumeLogError, match="volume_shredded"):
        vl.check_restore(registry.log_entries(), volume_id="vol-1", generation=head["generation"],
                         manifest_sha256=vc.manifest_sha256(head))
    refused("volume_shredded", registry.head, "vol-1")


def test_nothing_moves_after_shred(world):
    registry, _, holder, lease, commits, _, _, _ = shredded_world(world)
    log = registry.log_entries()
    refused("volume_shredded", registry.accept, commits[-1])  # resend of the final commit
    refused("volume_shredded", registry.accept, vc.make_commit(
        holder, lease, generation=3, parent_sha256=vc.statement_sha256(commits[-1]),
        restic_repo_id="repo-1", restic_snapshot_id="s3"))
    refused("volume_shredded", registry.grant, "vol-1", binding(holder))
    refused("volume_shredded", registry.shred, "vol-1", key_id="vk:vol-1", destroy_key=KeyService())
    assert registry.log_entries() == log


def test_bad_key_id_never_touches_the_key(world):
    _, registry, _, holder, lease = world
    registry.accept(commit_next(registry, holder, lease, "s1"))
    keys = KeyService()
    refused("bad_key_id", registry.shred, "vol-1", key_id="k/1", destroy_key=keys)
    refused("bad_key_id", registry.shred, "vol-1", key_id=None, destroy_key=keys)
    assert keys.calls == []


def test_volume_with_no_commit_has_nothing_to_shred(world):
    _, registry, *_ = world
    keys = KeyService()
    refused("nothing_to_shred", registry.shred, "vol-1", key_id="vk:vol-1", destroy_key=keys)
    assert keys.calls == []


@pytest.mark.parametrize("keys", [KeyService(error=RuntimeError("unknown key")), KeyService(result=None),
                                  KeyService(result=1)])
def test_key_service_refusal_logs_nothing_and_a_retry_works(world, keys):
    _, registry, _, holder, lease = world
    registry.accept(commit_next(registry, holder, lease, "s1"))
    before = registry.log_entries()
    refused("key_not_destroyed", registry.shred, "vol-1", key_id="vk:vol-1", destroy_key=keys)
    assert registry.log_entries() == before
    # The lease ended before the key was touched; the volume is still live and the holder re-grants.
    refused("lease_expired", registry.accept, commit_next(registry, holder, lease, "s2"))
    lease2 = registry.grant("vol-1", binding(holder))
    registry.accept(commit_next(registry, holder, lease2, "s2"))
    receipt = registry.shred("vol-1", key_id="vk:vol-1", destroy_key=KeyService())
    assert receipt["final_generation"] == 2


# --- prune token --------------------------------------------------------------


def prune_call(registry, token, **kw):
    args = dict(op="delete", key=PREFIX + "data/ab", source_ip=RUNNER_IP, now=lambda: T0 + 10)
    args.update(kw)
    return st.authorize_prune(token, registry.public_b64, **args)


def prune_token(registry, **kw):
    args = dict(prefix=PREFIX, source_ip=RUNNER_IP, ttl_seconds=300)
    args.update(kw)
    return registry.issue_prune_token("vol-1", **args)


def test_prune_token_runs_restic_prune(world):
    _, registry, *_ = world
    token = prune_token(registry)
    for op in ("delete", "get", "put", "list"):
        assert prune_call(registry, token, op=op)["volume_id"] == "vol-1"


def test_only_the_prune_token_deletes(world):
    _, registry, _, _, lease = world
    guest = st.issue(registry.key, lease, prefix=PREFIX, source_ip="203.0.113.7", ttl_seconds=300, now=lambda: T0)
    refused("op_not_allowed", st.authorize, guest, registry.public_b64, op="delete", key=PREFIX + "x",
            source_ip="203.0.113.7", now=lambda: T0 + 10)
    # Neither token passes the other's check.
    refused("wrong_schema", prune_call, registry, guest)
    refused("wrong_schema", st.authorize, prune_token(registry), registry.public_b64, op="delete",
            key=PREFIX + "x", source_ip=RUNNER_IP, now=lambda: T0 + 10)
    # A guest token relabelled as a prune token does not verify.
    relabelled = {**guest, "statement": {**guest["statement"], "schema": st.PRUNE_SCHEMA}}
    refused("bad_signature", prune_call, registry, relabelled)


def test_prune_token_limits(world):
    _, registry, *_ = world
    token = prune_token(registry, ttl_seconds=10_000)
    assert token["statement"]["expires_at"] == T0 + st.MAX_TTL_SECONDS
    refused("token_expired", prune_call, registry, token, now=lambda: T0 + st.MAX_TTL_SECONDS)
    refused("outside_prefix", prune_call, registry, token, key="volumes/vol-2/data/ab")
    refused("outside_prefix", prune_call, registry, token, key=PREFIX + "../vol-2/x")
    refused("wrong_source_ip", prune_call, registry, token, source_ip="203.0.113.7")
    refused("op_not_allowed", prune_call, registry, token, op="head")
    forged = {**token, "statement": {**token["statement"], "prefix": "volumes/"}}
    refused("bad_signature", prune_call, registry, forged)
    foreign = st.issue_prune(Ed25519PrivateKey.generate(), volume_id="vol-1", prefix=PREFIX,
                             source_ip=RUNNER_IP, ttl_seconds=60, now=lambda: T0)
    refused("bad_signature", prune_call, registry, foreign)
    refused("volume_unknown", registry.issue_prune_token, "vol-9", prefix=PREFIX, source_ip=RUNNER_IP,
            ttl_seconds=60)
    refused("bad_ttl", prune_token, registry, ttl_seconds=0)
    refused("bad_prefix", prune_token, registry, prefix="volumes/vol-1")


def test_prune_token_still_issued_after_shred(world):
    registry, *_ = shredded_world(world)
    assert prune_call(registry, prune_token(registry))["volume_id"] == "vol-1"
