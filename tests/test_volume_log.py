"""AB#398: the volume head log, checkpoints and shred receipts."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import volume_log as vl

T = "2026-11-13T12:00:00Z"


def _digest(n: int) -> str:
    return "sha256:" + f"{n:064x}"


def _keypair() -> tuple[bytes, bytes]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


def _head(log, volume_id, generation, manifest):
    return vl.append_entry(
        log,
        kind=vl.KIND_HEAD,
        volume_id=volume_id,
        generation=generation,
        manifest_sha256=_digest(manifest),
        commit_receipt_sha256=_digest(1000 + manifest),
        logged_at=T,
    )


def _shred(log, volume_id, generation, manifest):
    return vl.append_entry(
        log,
        kind=vl.KIND_SHRED,
        volume_id=volume_id,
        generation=generation,
        manifest_sha256=_digest(manifest),
        commit_receipt_sha256=_digest(2000 + manifest),
        logged_at=T,
    )


@pytest.fixture
def log():
    entries = _head([], "vol-a", 1, 1)
    entries = _head(entries, "vol-b", 1, 10)
    entries = _head(entries, "vol-a", 2, 2)
    return entries


def test_chain_and_latest_heads(log):
    heads = vl.verify_log(log)
    assert heads["vol-a"].generation == 2
    assert heads["vol-a"].manifest_sha256 == _digest(2)
    assert heads["vol-b"].generation == 1
    assert log[0]["prev_entry_sha256"] == vl.ZERO_SHA256
    assert log[2]["prev_entry_sha256"] == vl.entry_sha256(log[1])


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_sha256", _digest(99)),
        ("generation", 3),
        ("volume_id", "vol-c"),
        ("logged_at", "2026-11-13T12:00:01Z"),
        ("commit_receipt_sha256", _digest(99)),
    ],
)
def test_editing_an_old_entry_breaks_the_chain(log, field, value):
    log[1][field] = value
    with pytest.raises(vl.VolumeLogError, match="broken_chain:2|generation_not_next"):
        vl.verify_log(log)


def test_seq_gap_and_extra_field(log):
    gapped = copy.deepcopy(log)
    gapped[2]["seq"] = 5
    with pytest.raises(vl.VolumeLogError, match="seq_gap:2"):
        vl.verify_log(gapped)
    extra = copy.deepcopy(log)
    extra[0]["note"] = "x"
    with pytest.raises(vl.VolumeLogError, match="fields:entry"):
        vl.verify_log(extra)


def test_bool_is_not_an_integer(log):
    log[0]["generation"] = True
    with pytest.raises(vl.VolumeLogError, match="invalid:generation"):
        vl.verify_log(log)


@pytest.mark.parametrize("generation", [1, 2, 4])
def test_generation_must_be_head_plus_one(log, generation):
    with pytest.raises(vl.VolumeLogError, match="generation_not_next:3"):
        _head(log, "vol-a", generation, 50)


def test_first_head_is_generation_one():
    with pytest.raises(vl.VolumeLogError, match="generation_not_next:0"):
        _head([], "vol-a", 2, 1)


def test_shred_is_terminal_and_names_the_current_head(log):
    with pytest.raises(vl.VolumeLogError, match="shred_not_current_head"):
        _shred(log, "vol-a", 1, 1)
    with pytest.raises(vl.VolumeLogError, match="shred_not_current_head"):
        _shred(log, "vol-a", 2, 99)
    with pytest.raises(vl.VolumeLogError, match="shred_not_current_head"):
        _shred(log, "vol-z", 1, 1)
    shredded = _shred(log, "vol-a", 2, 2)
    assert vl.verify_log(shredded)["vol-a"].shredded
    with pytest.raises(vl.VolumeLogError, match="entry_after_shred:4"):
        _head(shredded, "vol-a", 3, 3)
    with pytest.raises(vl.VolumeLogError, match="entry_after_shred:4"):
        _shred(shredded, "vol-a", 2, 2)
    # Other volumes carry on.
    assert vl.verify_log(_head(shredded, "vol-b", 2, 11))["vol-b"].generation == 2


def test_restore_only_latest_head(log):
    head = vl.check_restore(log, volume_id="vol-a", generation=2, manifest_sha256=_digest(2))
    assert head.entry_sha256 == vl.entry_sha256(log[2])
    with pytest.raises(vl.VolumeLogError, match="not_latest_head"):
        vl.check_restore(log, volume_id="vol-a", generation=1, manifest_sha256=_digest(1))
    with pytest.raises(vl.VolumeLogError, match="manifest_mismatch"):
        vl.check_restore(log, volume_id="vol-a", generation=2, manifest_sha256=_digest(1))
    with pytest.raises(vl.VolumeLogError, match="unknown_volume"):
        vl.check_restore(log, volume_id="vol-z", generation=1, manifest_sha256=_digest(1))


def test_restore_after_shred_fails(log):
    shredded = _shred(log, "vol-a", 2, 2)
    with pytest.raises(vl.VolumeLogError, match="volume_shredded"):
        vl.check_restore(shredded, volume_id="vol-a", generation=2, manifest_sha256=_digest(2))


def test_rollback_by_truncating_or_rewriting_is_visible(log):
    newer = _head(log, "vol-a", 3, 3)
    vl.verify_extends(log, newer)
    vl.verify_extends(log, log)
    with pytest.raises(vl.VolumeLogError, match="log_shrank"):
        vl.verify_extends(newer, log)
    # A rewritten history that is valid on its own still fails against the old copy.
    forked = _head(log[:2], "vol-a", 2, 77)
    forked = _head(forked, "vol-a", 3, 3)
    vl.verify_log(forked)
    with pytest.raises(vl.VolumeLogError, match="log_rewritten:2"):
        vl.verify_extends(log, forked)


def test_checkpoint(log):
    private, public = _keypair()
    _, other = _keypair()
    cp = vl.sign_checkpoint(log, log_key_id="log-1", issued_at=T, private_key=private)
    vl.verify_checkpoint(cp, public_keys_by_id={"log-1": public}, entries=log)
    with pytest.raises(vl.VolumeLogError, match="bad_signature"):
        vl.verify_checkpoint(cp, public_keys_by_id={"log-1": other})
    with pytest.raises(vl.VolumeLogError, match="unknown_signing_key"):
        vl.verify_checkpoint(cp, public_keys_by_id={})
    with pytest.raises(vl.VolumeLogError, match="checkpoint_mismatch"):
        vl.verify_checkpoint(cp, public_keys_by_id={"log-1": public}, entries=log[:2])
    tampered = dict(cp, size=2)
    with pytest.raises(vl.VolumeLogError, match="bad_signature"):
        vl.verify_checkpoint(tampered, public_keys_by_id={"log-1": public})


def test_shred_receipt(log):
    private, public = _keypair()
    _, other = _keypair()
    with pytest.raises(vl.VolumeLogError, match="not_shredded"):
        vl.sign_shred_receipt(
            log, volume_id="vol-a", key_id="k1", shredded_at=T,
            signing_key_id="guest-1", private_key=private,
        )
    shredded = _shred(log, "vol-a", 2, 2)
    receipt = vl.sign_shred_receipt(
        shredded, volume_id="vol-a", key_id="k1", shredded_at=T,
        signing_key_id="guest-1", private_key=private,
    )
    assert receipt["final_generation"] == 2
    assert receipt["log_entry_sha256"] == vl.entry_sha256(shredded[3])
    keys = {"guest-1": public}
    vl.verify_shred_receipt(receipt, public_keys_by_id=keys, entries=shredded)
    with pytest.raises(vl.VolumeLogError, match="bad_signature"):
        vl.verify_shred_receipt(receipt, public_keys_by_id={"guest-1": other})
    with pytest.raises(vl.VolumeLogError, match="bad_signature"):
        vl.verify_shred_receipt(dict(receipt, final_generation=1), public_keys_by_id=keys)
    # A log that does not hold the shred (rolled back to before it) fails the receipt.
    with pytest.raises(vl.VolumeLogError, match="shred_not_in_log"):
        vl.verify_shred_receipt(receipt, public_keys_by_id=keys, entries=log)
