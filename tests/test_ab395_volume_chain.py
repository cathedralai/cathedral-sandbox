"""AB#395: the signed generation chain of a volume synced from a sealed guest.

Done line, second half: a commit not signed by the lease holder is rejected at
head + 1. The first half (restore on another host from a restic repo) needs two
live sealed hotels; here "another host" is a fresh verifier that has only the
registry's public key and what storage hands back.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import volume_chain as vc


class Clock:
    def __init__(self, t: float = 1_800_000_000):
        self.t = t

    def __call__(self) -> float:
        return self.t


def binding(key: Ed25519PrivateKey, measurement: str = "aa" * 48) -> dict:
    return {"schema": vc.SEALED_BINDING_SCHEMA, "hotel": "hotel-a", "boot_id": "b1",
            "receipt_key_ed25519_b64": vc.public_b64(key), "measurement": measurement}


@pytest.fixture
def world():
    clock = Clock()
    registry_key = Ed25519PrivateKey.generate()
    registry = vc.VolumeRegistry(registry_key, now=clock, lease_seconds=600)
    volume_doc = registry.create("vol-1", "customer-1")
    holder = Ed25519PrivateKey.generate()
    lease = registry.grant("vol-1", binding(holder))
    return clock, registry, volume_doc, holder, lease


def commit_next(registry, holder, lease, snapshot: str, **overrides) -> dict:
    head = registry.head("vol-1")["statement"]
    fields = {"generation": head["generation"] + 1, "parent_sha256": head["head_sha256"],
              "restic_repo_id": "repo-1", "restic_snapshot_id": snapshot}
    fields.update(overrides)
    return vc.make_commit(holder, lease, **fields)


def refused(code: str, fn, *args):
    with pytest.raises(vc.VolumeRefused) as exc:
        fn(*args)
    assert exc.value.code == code


def test_chain_restores_on_a_fresh_verifier(world):
    _, registry, volume_doc, holder, lease = world
    commits = []
    for snap in ("s1", "s2", "s3"):
        doc = commit_next(registry, holder, lease, snap)
        head = registry.accept(doc)
        commits.append(doc)
    assert head["statement"]["generation"] == 3
    restored = vc.verify_chain(volume_doc, commits, head, [registry.public_b64])
    assert restored["restic_snapshot_id"] == "s3"
    assert restored["lease"]["statement"]["holder_measurement"] == "aa" * 48


def test_empty_volume_verifies_to_none(world):
    _, registry, volume_doc, _, _ = world
    assert vc.verify_chain(volume_doc, [], registry.head("vol-1"), [registry.public_b64]) is None


def test_commit_not_signed_by_lease_holder_is_refused_at_head_plus_one(world):
    _, registry, _, holder, lease = world
    registry.accept(commit_next(registry, holder, lease, "s1"))
    before = registry.head("vol-1")
    stranger = Ed25519PrivateKey.generate()
    forged = commit_next(registry, stranger, lease, "evil")
    assert forged["statement"]["generation"] == before["statement"]["generation"] + 1
    refused("signature_not_lease_holder", registry.accept, forged)
    assert registry.head("vol-1") == before


def test_registry_signature_on_a_commit_is_not_the_holders(world):
    _, registry, _, _, lease = world
    refused("signature_not_lease_holder", registry.accept, commit_next(registry, registry.key, lease, "s1"))


def test_receipt_style_signature_without_label_is_refused(world):
    _, registry, _, holder, lease = world
    doc = commit_next(registry, holder, lease, "s1")
    doc["signature_b64"] = vc.b64(holder.sign(vc.canonical(doc["statement"])))
    refused("signature_not_lease_holder", registry.accept, doc)


@pytest.mark.parametrize("override,code", [
    ({"generation": 0}, "generation_not_next"),
    ({"generation": 2}, "generation_not_next"),
    ({"generation": True}, "generation_not_next"),
    ({"parent_sha256": "00" * 32}, "parent_not_head"),
    ({"restic_repo_id": ""}, "bad_restic_repo_id"),
    ({"restic_snapshot_id": None}, "bad_restic_snapshot_id"),
])
def test_bad_commits_leave_head_unchanged(world, override, code):
    _, registry, _, holder, lease = world
    before = registry.head("vol-1")
    refused(code, registry.accept, commit_next(registry, holder, lease, "s1", **override))
    assert registry.head("vol-1") == before


def test_stale_generation_after_advance_is_refused(world):
    _, registry, _, holder, lease = world
    first = commit_next(registry, holder, lease, "s1")
    registry.accept(first)
    registry.accept(commit_next(registry, holder, lease, "s2"))
    refused("generation_not_next", registry.accept, first)


def test_exact_resend_of_head_commit_returns_same_head(world):
    _, registry, _, holder, lease = world
    doc = commit_next(registry, holder, lease, "s1")
    head = registry.accept(doc)
    assert registry.accept(doc) == head


def test_tampered_commit_is_refused(world):
    _, registry, _, holder, lease = world
    doc = commit_next(registry, holder, lease, "s1")
    doc["statement"]["restic_snapshot_id"] = "other"
    refused("signature_not_lease_holder", registry.accept, doc)


def test_expired_and_released_leases_cannot_commit(world):
    clock, registry, _, holder, lease = world
    clock.t += 601
    refused("lease_expired", registry.accept, commit_next(registry, holder, lease, "s1"))
    clock.t -= 601
    registry.release("vol-1", lease["statement"]["lease_id"])
    refused("lease_expired", registry.accept, commit_next(registry, holder, lease, "s1"))


def test_live_lease_blocks_another_holder_and_renewal_keeps_identity(world):
    clock, registry, _, holder, lease = world
    other = Ed25519PrivateKey.generate()
    refused("lease_held", registry.grant, "vol-1", binding(other))
    clock.t += 300
    renewed = registry.grant("vol-1", binding(holder))
    for k in ("lease_id", "lease_seq", "base_generation", "base_sha256"):
        assert renewed["statement"][k] == lease["statement"][k]
    clock.t += 400  # past the first expiry, inside the renewed one
    # A commit carrying the pre-renewal lease document is still the current lease.
    registry.accept(commit_next(registry, holder, lease, "s1"))


def test_superseded_lease_cannot_commit_and_handover_verifies(world):
    clock, registry, volume_doc, holder, lease = world
    commits = [commit_next(registry, holder, lease, "s1")]
    registry.accept(commits[0])
    clock.t += 601
    # Another host (a new boot, so a new receipt key) takes the volume over.
    second = Ed25519PrivateKey.generate()
    lease2 = registry.grant("vol-1", binding(second, "bb" * 48))
    assert lease2["statement"]["lease_seq"] == 2
    assert lease2["statement"]["base_generation"] == 1
    late = commit_next(registry, holder, lease, "late")
    refused("lease_not_current", registry.accept, late)
    commits.append(commit_next(registry, second, lease2, "s2"))
    head = registry.accept(commits[1])
    assert vc.verify_chain(volume_doc, commits, head, [registry.public_b64])["restic_snapshot_id"] == "s2"


def test_lease_signed_by_untrusted_key_is_refused(world):
    _, registry, _, holder, lease = world
    rogue = Ed25519PrivateKey.generate()
    forged_lease = vc.sign_statement(rogue, lease["statement"])
    refused("lease_not_signed_by_registry", registry.accept, commit_next(registry, holder, forged_lease, "s1"))


def test_grant_requires_a_sealed_binding(world):
    _, registry, _, _, _ = world
    registry.release("vol-1", registry.volumes["vol-1"].lease.statement["lease_id"])
    key = Ed25519PrivateKey.generate()
    level1 = dict(binding(key), schema="cathedral_hotel_binding_v1")
    refused("binding_not_sealed", registry.grant, "vol-1", level1)
    refused("bad_public_key", registry.grant, "vol-1", dict(binding(key), receipt_key_ed25519_b64="nope"))
    refused("volume_unknown", registry.grant, "vol-2", binding(key))


def _chain(world, n=3):
    _, registry, volume_doc, holder, lease = world
    commits = []
    for i in range(n):
        doc = commit_next(registry, holder, lease, f"s{i + 1}")
        registry.accept(doc)
        commits.append(doc)
    return registry, volume_doc, commits, registry.head("vol-1")


def test_restore_refuses_a_prefix_short_of_the_signed_head(world):
    registry, volume_doc, commits, head = _chain(world)
    refused("chain_not_at_head", vc.verify_chain, volume_doc, commits[:2], head, [registry.public_b64])


def test_restore_refuses_a_gap_and_a_reorder(world):
    registry, volume_doc, commits, head = _chain(world)
    refused("generation_not_next", vc.verify_chain, volume_doc, [commits[0], commits[2]], head, [registry.public_b64])
    refused("generation_not_next", vc.verify_chain, volume_doc, [commits[1], commits[0], commits[2]], head,
            [registry.public_b64])


def test_restore_refuses_a_former_holders_offline_commit(world):
    clock, registry, volume_doc, holder, lease = world
    commits = [commit_next(registry, holder, lease, "s1")]
    head = registry.accept(commits[0])
    clock.t += 601
    # The registry never accepted this one, so no signed head names it.
    late = commit_next(registry, holder, lease, "late")
    refused("chain_not_at_head", vc.verify_chain, volume_doc, commits + [late], head, [registry.public_b64])


def test_restore_refuses_untrusted_registry_and_wrong_volume(world):
    registry, volume_doc, commits, head = _chain(world, 1)
    rogue = vc.public_b64(Ed25519PrivateKey.generate())
    refused("volume_not_signed_by_registry", vc.verify_chain, volume_doc, commits, head, [rogue])
    other = registry.create("vol-2", "customer-1")
    refused("head_wrong_volume", vc.verify_chain, other, commits, head, [registry.public_b64])


def test_restore_refuses_a_commit_by_a_key_other_than_its_lease_holder(world):
    registry, volume_doc, commits, head = _chain(world, 1)
    stranger = Ed25519PrivateKey.generate()
    forged = vc.sign_statement(stranger, commits[0]["statement"])
    refused("signature_not_lease_holder", vc.verify_chain, volume_doc, [forged], head, [registry.public_b64])


def test_restore_of_old_leases_does_not_check_expiry(world):
    clock, registry, volume_doc, holder, lease = world
    commits = [commit_next(registry, holder, lease, "s1")]
    head = registry.accept(commits[0])
    clock.t += 10 ** 6
    assert vc.verify_chain(volume_doc, commits, head, [registry.public_b64])["restic_snapshot_id"] == "s1"
