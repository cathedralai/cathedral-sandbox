"""Append-only log of sealed volume heads, signed checkpoints and shred receipts.

The format half of AB#398 (Decision 6, 4 Nov): every committed volume head is
an entry in a hash-chained public log, so a Cathedral-side rollback (serving an
older head, or rewriting the log) is visible to anyone who kept an earlier copy
or checkpoint. A crypto-shred is a terminal log entry plus a signed receipt;
after it, `check_restore` refuses the volume.

Pure functions only: no I/O, no publishing, no wiring. The volume agent, the
commit timer, the lease and the scoped tokens come from AB#395. The
`commit_receipt_sha256` field binds an entry to the 395 commit receipt (the
one signed by the lease holder); this module treats it as an opaque digest.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.policy_registry import PolicyRegistryError, canonical_json

ENTRY_SCHEMA = "cathedral_volume_log_entry_v1"
CHECKPOINT_SCHEMA = "cathedral_volume_log_checkpoint_v1"
SHRED_SCHEMA = "cathedral_volume_shred_receipt_v1"

KIND_HEAD = "head"
KIND_SHRED = "shred"

ZERO_SHA256 = "sha256:" + "0" * 64
MAX_INT = 2**53 - 1  # exact in a browser and in JSON readers that use doubles

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VOLUME_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")

_ENTRY_FIELDS = frozenset(
    {
        "schema",
        "seq",
        "prev_entry_sha256",
        "kind",
        "volume_id",
        "generation",
        "manifest_sha256",
        "commit_receipt_sha256",
        "logged_at",
    }
)
_CHECKPOINT_FIELDS = frozenset(
    {"schema", "size", "last_entry_sha256", "log_key_id", "issued_at", "signature"}
)
_SHRED_FIELDS = frozenset(
    {
        "schema",
        "volume_id",
        "key_id",
        "final_generation",
        "final_manifest_sha256",
        "log_entry_sha256",
        "shredded_at",
        "signing_key_id",
        "signature",
    }
)


class VolumeLogError(ValueError):
    """A log, checkpoint, receipt or restore check failed. The message is a stable code."""


@dataclass(frozen=True)
class VolumeHead:
    volume_id: str
    generation: int
    manifest_sha256: str
    entry_sha256: str
    shredded: bool


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------


def _int(value: object, label: str, minimum: int) -> int:
    # bool is an int subclass; a JSON true must not pass as 1.
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= MAX_INT:
        raise VolumeLogError(f"invalid:{label}")
    return value


def _match(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise VolumeLogError(f"invalid:{label}")
    return value


def _exact_fields(doc: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(doc, Mapping):
        raise VolumeLogError(f"invalid:{label}")
    if set(doc) != fields:
        raise VolumeLogError(f"fields:{label}")
    return doc


def _canonical(doc: Mapping[str, Any]) -> bytes:
    try:
        return canonical_json(dict(doc))
    except PolicyRegistryError as exc:
        raise VolumeLogError("non_canonical") from exc


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sign(unsigned: Mapping[str, Any], private_key: bytes) -> dict[str, Any]:
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(_canonical(unsigned))
    signed = dict(unsigned)
    signed["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def _verify_signature(doc: Mapping[str, Any], public_key: bytes) -> None:
    signature = doc.get("signature")
    if not isinstance(signature, Mapping) or set(signature) != {"algorithm", "value_base64"}:
        raise VolumeLogError("missing_signature")
    if signature["algorithm"] != "ed25519":
        raise VolumeLogError("bad_signature_algorithm")
    value = signature["value_base64"]
    if not isinstance(value, str):
        raise VolumeLogError("bad_signature_encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VolumeLogError("bad_signature_encoding") from exc
    unsigned = {k: v for k, v in doc.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw, _canonical(unsigned))
    except (InvalidSignature, ValueError) as exc:
        raise VolumeLogError("bad_signature") from exc


# ---------------------------------------------------------------------------
# Log entries
# ---------------------------------------------------------------------------


def entry_sha256(entry: Mapping[str, Any]) -> str:
    return _digest(_canonical(entry))


def _check_entry_shape(entry: object) -> Mapping[str, Any]:
    doc = _exact_fields(entry, _ENTRY_FIELDS, "entry")
    if doc["schema"] != ENTRY_SCHEMA:
        raise VolumeLogError("wrong_schema:entry")
    _int(doc["seq"], "seq", 0)
    _match(doc["prev_entry_sha256"], _DIGEST_RE, "prev_entry_sha256")
    if doc["kind"] not in (KIND_HEAD, KIND_SHRED):
        raise VolumeLogError("invalid:kind")
    _match(doc["volume_id"], _VOLUME_ID_RE, "volume_id")
    _int(doc["generation"], "generation", 1)
    _match(doc["manifest_sha256"], _DIGEST_RE, "manifest_sha256")
    _match(doc["commit_receipt_sha256"], _DIGEST_RE, "commit_receipt_sha256")
    _match(doc["logged_at"], _TIME_RE, "logged_at")
    return doc


def verify_log(entries: Sequence[Mapping[str, Any]]) -> dict[str, VolumeHead]:
    """Check the whole chain and the per-volume rules; return the latest head per volume.

    Rules: seq runs 0, 1, 2 with no gap; each entry names the hash of the one
    before (the zero hash at seq 0); a volume's first head is generation 1 and
    each later head is exactly the previous plus one (the AB#395 head+1 rule,
    so a repeated or skipped generation, which is how a fork or a rollback
    would show, is refused); a shred names the volume's current head and is
    the volume's last entry.
    """
    heads: dict[str, VolumeHead] = {}
    prev = ZERO_SHA256
    for index, raw in enumerate(entries):
        entry = _check_entry_shape(raw)
        if entry["seq"] != index:
            raise VolumeLogError(f"seq_gap:{index}")
        if entry["prev_entry_sha256"] != prev:
            raise VolumeLogError(f"broken_chain:{index}")
        digest = entry_sha256(entry)
        volume_id = entry["volume_id"]
        current = heads.get(volume_id)
        if current is not None and current.shredded:
            raise VolumeLogError(f"entry_after_shred:{index}")
        if entry["kind"] == KIND_HEAD:
            expected = 1 if current is None else current.generation + 1
            if entry["generation"] != expected:
                raise VolumeLogError(f"generation_not_next:{index}")
            heads[volume_id] = VolumeHead(
                volume_id, entry["generation"], entry["manifest_sha256"], digest, False
            )
        else:
            if (
                current is None
                or entry["generation"] != current.generation
                or entry["manifest_sha256"] != current.manifest_sha256
            ):
                raise VolumeLogError(f"shred_not_current_head:{index}")
            heads[volume_id] = VolumeHead(
                volume_id, current.generation, current.manifest_sha256, digest, True
            )
        prev = digest
    return heads


def last_entry_sha256(entries: Sequence[Mapping[str, Any]]) -> str:
    return entry_sha256(entries[-1]) if entries else ZERO_SHA256


def append_entry(
    entries: Sequence[Mapping[str, Any]],
    *,
    kind: str,
    volume_id: str,
    generation: int,
    manifest_sha256: str,
    commit_receipt_sha256: str,
    logged_at: str,
) -> list[dict[str, Any]]:
    """Return a new list: the verified log plus one entry. Refuses an entry that breaks a rule."""
    verify_log(entries)
    entry = {
        "schema": ENTRY_SCHEMA,
        "seq": len(entries),
        "prev_entry_sha256": last_entry_sha256(entries),
        "kind": kind,
        "volume_id": volume_id,
        "generation": generation,
        "manifest_sha256": manifest_sha256,
        "commit_receipt_sha256": commit_receipt_sha256,
        "logged_at": logged_at,
    }
    extended = [dict(e) for e in entries] + [entry]
    verify_log(extended)
    return extended


def verify_extends(
    old_entries: Sequence[Mapping[str, Any]], new_entries: Sequence[Mapping[str, Any]]
) -> None:
    """The new log must hold the old one as its exact prefix.

    This is the rollback check for a reader who kept an earlier copy: a log
    that dropped, reordered or rewrote an entry fails here.
    """
    verify_log(old_entries)
    verify_log(new_entries)
    if len(new_entries) < len(old_entries):
        raise VolumeLogError("log_shrank")
    for index, old in enumerate(old_entries):
        if entry_sha256(old) != entry_sha256(new_entries[index]):
            raise VolumeLogError(f"log_rewritten:{index}")


def check_restore(
    entries: Sequence[Mapping[str, Any]],
    *,
    volume_id: str,
    generation: int,
    manifest_sha256: str,
) -> VolumeHead:
    """Allow a restore only of the volume's latest logged head, and never after a shred."""
    head = verify_log(entries).get(volume_id)
    if head is None:
        raise VolumeLogError("unknown_volume")
    if head.shredded:
        raise VolumeLogError("volume_shredded")
    if generation != head.generation:
        raise VolumeLogError("not_latest_head")
    if manifest_sha256 != head.manifest_sha256:
        raise VolumeLogError("manifest_mismatch")
    return head


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------


def sign_checkpoint(
    entries: Sequence[Mapping[str, Any]], *, log_key_id: str, issued_at: str, private_key: bytes
) -> dict[str, Any]:
    verify_log(entries)
    unsigned = {
        "schema": CHECKPOINT_SCHEMA,
        "size": len(entries),
        "last_entry_sha256": last_entry_sha256(entries),
        "log_key_id": _match(log_key_id, _KEY_ID_RE, "log_key_id"),
        "issued_at": _match(issued_at, _TIME_RE, "issued_at"),
    }
    return _sign(unsigned, private_key)


def verify_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    public_keys_by_id: Mapping[str, bytes],
    entries: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    """Check the signature; with `entries`, check the log has exactly this size and last hash."""
    doc = _exact_fields(checkpoint, _CHECKPOINT_FIELDS, "checkpoint")
    if doc["schema"] != CHECKPOINT_SCHEMA:
        raise VolumeLogError("wrong_schema:checkpoint")
    _int(doc["size"], "size", 0)
    _match(doc["last_entry_sha256"], _DIGEST_RE, "last_entry_sha256")
    key_id = _match(doc["log_key_id"], _KEY_ID_RE, "log_key_id")
    _match(doc["issued_at"], _TIME_RE, "issued_at")
    public_key = public_keys_by_id.get(key_id)
    if public_key is None:
        raise VolumeLogError("unknown_signing_key")
    _verify_signature(doc, public_key)
    if entries is not None:
        verify_log(entries)
        if len(entries) != doc["size"] or last_entry_sha256(entries) != doc["last_entry_sha256"]:
            raise VolumeLogError("checkpoint_mismatch")


# ---------------------------------------------------------------------------
# Shred receipts
# ---------------------------------------------------------------------------


def sign_shred_receipt(
    entries: Sequence[Mapping[str, Any]],
    *,
    volume_id: str,
    key_id: str,
    shredded_at: str,
    signing_key_id: str,
    private_key: bytes,
) -> dict[str, Any]:
    """Sign a receipt for the volume's shred entry. The log must already hold it."""
    head = verify_log(entries).get(volume_id)
    if head is None or not head.shredded:
        raise VolumeLogError("not_shredded")
    unsigned = {
        "schema": SHRED_SCHEMA,
        "volume_id": volume_id,
        "key_id": _match(key_id, _KEY_ID_RE, "key_id"),
        "final_generation": head.generation,
        "final_manifest_sha256": head.manifest_sha256,
        "log_entry_sha256": head.entry_sha256,
        "shredded_at": _match(shredded_at, _TIME_RE, "shredded_at"),
        "signing_key_id": _match(signing_key_id, _KEY_ID_RE, "signing_key_id"),
    }
    return _sign(unsigned, private_key)


def verify_shred_receipt(
    receipt: Mapping[str, Any],
    *,
    public_keys_by_id: Mapping[str, bytes],
    entries: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    """Check the signature; with `entries`, check the log's shred entry is the one named."""
    doc = _exact_fields(receipt, _SHRED_FIELDS, "shred_receipt")
    if doc["schema"] != SHRED_SCHEMA:
        raise VolumeLogError("wrong_schema:shred_receipt")
    volume_id = _match(doc["volume_id"], _VOLUME_ID_RE, "volume_id")
    _match(doc["key_id"], _KEY_ID_RE, "key_id")
    _int(doc["final_generation"], "final_generation", 1)
    _match(doc["final_manifest_sha256"], _DIGEST_RE, "final_manifest_sha256")
    _match(doc["log_entry_sha256"], _DIGEST_RE, "log_entry_sha256")
    _match(doc["shredded_at"], _TIME_RE, "shredded_at")
    signer = _match(doc["signing_key_id"], _KEY_ID_RE, "signing_key_id")
    public_key = public_keys_by_id.get(signer)
    if public_key is None:
        raise VolumeLogError("unknown_signing_key")
    _verify_signature(doc, public_key)
    if entries is not None:
        head = verify_log(entries).get(volume_id)
        if (
            head is None
            or not head.shredded
            or head.entry_sha256 != doc["log_entry_sha256"]
            or head.generation != doc["final_generation"]
            or head.manifest_sha256 != doc["final_manifest_sha256"]
        ):
            raise VolumeLogError("shred_not_in_log")
