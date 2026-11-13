"""Signed generation chain of an encrypted volume synced from a sealed guest (AB#395, phase 1).

A volume is an encrypted restic repo that a sealed guest writes and another sealed
guest may later restore. The storage and the host are not trusted, so the volume's
history is a chain of signed statements:

- volume: the registry (control plane) creates it; its digest is the parent of
  generation 1.
- lease: the registry grants one guest boot the right to write. The lease names
  that boot's receipt key (receipt_key_ed25519_b64 of its sealed binding, which the
  attested REPORT_DATA commits to), the binding digest and the measurement.
- commit: the lease holder signs one restic snapshot at generation head + 1 with
  its receipt key. The registry accepts it only from the current, unexpired lease,
  only at head + 1 and only on top of the head digest (Decision 6, 4 Nov).
- head: on every accept the registry signs the new head. A restoring guest checks
  the whole chain against a registry-signed head, so storage that hands back an
  older prefix, or commits a former holder signed after its lease ended, is caught.

Every statement is signed over a fixed label and its canonical JSON. A receipt
signed by the same receipt key (room_receipts.py signs canonical(statement) with
no label) is never a valid commit.

The SNP report behind a binding is checked by the existing verifier
(verify_receipts.py) before grant() is called; grant() checks that the binding it
is given is a sealed binding and names the holder key.

This module is the contract. VolumeRegistry keeps state in memory; the control
plane's persistent registry, the guest's volume agent, restic and the storage
sub-tokens are later phases (docs/SEALED_DATA_VOLUME.md).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VOLUME_SCHEMA = "cathedral_volume_v1"
LEASE_SCHEMA = "cathedral_volume_lease_v1"
COMMIT_SCHEMA = "cathedral_volume_commit_v1"
HEAD_SCHEMA = "cathedral_volume_head_v1"
SEALED_BINDING_SCHEMA = "cathedral_sealed_hotel_binding_v1"

LABELS = {
    VOLUME_SCHEMA: b"cathedral.volume.v1\n",
    LEASE_SCHEMA: b"cathedral.volume-lease.v1\n",
    COMMIT_SCHEMA: b"cathedral.volume-commit.v1\n",
    HEAD_SCHEMA: b"cathedral.volume-head.v1\n",
}

DEFAULT_LEASE_SECONDS = 900
MAX_ID_LENGTH = 128


class VolumeRefused(Exception):
    """A volume statement refused. The code is short and stable."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def public_b64(key: Ed25519PrivateKey) -> str:
    return b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def statement_sha256(doc: dict) -> str:
    return sha(canonical(doc["statement"]))


def sign_statement(key: Ed25519PrivateKey, statement: dict) -> dict:
    """A signed document: the statement, the signer's public key and the signature over label + canonical."""
    label = LABELS[statement["schema"]]
    return {
        "statement": statement,
        "signer_ed25519_b64": public_b64(key),
        "signature_b64": b64(key.sign(label + canonical(statement))),
    }


def _public_key(value) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(value, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError, binascii.Error):
        raise VolumeRefused("bad_public_key") from None


def _check_signed(doc, schema: str, allowed_signers: Iterable[str] | None, code: str) -> dict:
    """Return the statement of a signed document of this schema whose signer is allowed and whose signature holds."""
    if not isinstance(doc, dict) or not isinstance(doc.get("statement"), dict):
        raise VolumeRefused("malformed")
    statement = doc["statement"]
    if statement.get("schema") != schema:
        raise VolumeRefused("wrong_schema")
    signer = doc.get("signer_ed25519_b64")
    if allowed_signers is not None and signer not in set(allowed_signers):
        raise VolumeRefused(code)
    try:
        signature = base64.b64decode(doc.get("signature_b64", ""), validate=True)
        _public_key(signer).verify(signature, LABELS[schema] + canonical(statement))
    except (TypeError, ValueError, binascii.Error, InvalidSignature, VolumeRefused):
        raise VolumeRefused(code) from None
    return statement


def _ident(value, code: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ID_LENGTH or not value.isprintable():
        raise VolumeRefused(code)
    return value


def make_commit(holder_key: Ed25519PrivateKey, lease_doc: dict, *, generation: int, parent_sha256: str,
                restic_repo_id: str, restic_snapshot_id: str, committed_at: int | None = None) -> dict:
    """What the lease holder (the volume agent, through the receipt key) signs for one snapshot."""
    lease = lease_doc["statement"]
    statement = {
        "schema": COMMIT_SCHEMA,
        "volume_id": lease["volume_id"],
        "generation": generation,
        "parent_sha256": parent_sha256,
        "restic_repo_id": restic_repo_id,
        "restic_snapshot_id": restic_snapshot_id,
        "lease": lease_doc,
        "committed_at": int(time.time()) if committed_at is None else committed_at,
    }
    return sign_statement(holder_key, statement)


@dataclass
class _Lease:
    statement: dict
    doc: dict
    expires_at: int
    released: bool = False


@dataclass
class _Volume:
    doc: dict
    genesis_sha256: str
    generation: int
    head_sha256: str
    head_doc: dict
    lease_seq: int = 0
    lease: _Lease | None = None


class VolumeRegistry:
    """The registry's contract, in memory. One live lease per volume; the head moves only on an accepted commit."""

    def __init__(self, key: Ed25519PrivateKey, *, now: Callable[[], float] = time.time,
                 lease_seconds: int = DEFAULT_LEASE_SECONDS):
        self.key = key
        self.public_b64 = public_b64(key)
        self.now = now
        self.lease_seconds = lease_seconds
        self.lock = threading.Lock()
        self.volumes: dict[str, _Volume] = {}

    def _t(self) -> int:
        return int(self.now())

    def _head(self, volume_id: str, generation: int, head_sha256: str, lease: dict | None) -> dict:
        return sign_statement(self.key, {
            "schema": HEAD_SCHEMA,
            "volume_id": volume_id,
            "generation": generation,
            "head_sha256": head_sha256,
            "lease_id": lease["lease_id"] if lease else None,
            "lease_seq": lease["lease_seq"] if lease else 0,
            "issued_at": self._t(),
        })

    def create(self, volume_id: str, owner: str) -> dict:
        """Create a volume. Returns the signed volume statement; its digest is the parent of generation 1."""
        _ident(volume_id, "bad_volume_id")
        _ident(owner, "bad_owner")
        with self.lock:
            if volume_id in self.volumes:
                raise VolumeRefused("volume_exists")
            doc = sign_statement(self.key, {"schema": VOLUME_SCHEMA, "volume_id": volume_id, "owner": owner,
                                            "created_at": self._t()})
            genesis = statement_sha256(doc)
            self.volumes[volume_id] = _Volume(doc=doc, genesis_sha256=genesis, generation=0, head_sha256=genesis,
                                              head_doc=self._head(volume_id, 0, genesis, None))
            return doc

    def _volume(self, volume_id) -> _Volume:
        volume = self.volumes.get(volume_id) if isinstance(volume_id, str) else None
        if volume is None:
            raise VolumeRefused("volume_unknown")
        return volume

    def _live(self, lease: _Lease | None) -> bool:
        return lease is not None and not lease.released and self._t() < lease.expires_at

    def grant(self, volume_id: str, binding: dict) -> dict:
        """Grant (or renew) the write lease to the boot this sealed binding names.

        The caller has already verified the binding's SNP report. A live lease of
        another key is refused; the same key renews and keeps lease_id and lease_seq.
        A reboot is a new receipt key, so it needs the old lease to end first.
        """
        if not isinstance(binding, dict) or binding.get("schema") != SEALED_BINDING_SCHEMA:
            raise VolumeRefused("binding_not_sealed")
        holder = binding.get("receipt_key_ed25519_b64")
        _public_key(holder)
        measurement = binding.get("measurement")
        if not isinstance(measurement, str) or not measurement:
            raise VolumeRefused("binding_not_sealed")
        binding_sha256 = sha(canonical(binding))
        with self.lock:
            volume = self._volume(volume_id)
            now = self._t()
            current = volume.lease
            if self._live(current):
                if current.statement["holder_receipt_key_ed25519_b64"] != holder:
                    raise VolumeRefused("lease_held")
                statement = dict(current.statement, issued_at=now, expires_at=now + self.lease_seconds)
            else:
                volume.lease_seq += 1
                statement = {
                    "schema": LEASE_SCHEMA,
                    "volume_id": volume_id,
                    "lease_id": str(uuid.uuid4()),
                    "lease_seq": volume.lease_seq,
                    "holder_receipt_key_ed25519_b64": holder,
                    "holder_binding_sha256": binding_sha256,
                    "holder_measurement": measurement,
                    "base_generation": volume.generation,
                    "base_sha256": volume.head_sha256,
                    "issued_at": now,
                    "expires_at": now + self.lease_seconds,
                }
            doc = sign_statement(self.key, statement)
            volume.lease = _Lease(statement=statement, doc=doc, expires_at=statement["expires_at"])
            return doc

    def release(self, volume_id: str, lease_id: str) -> None:
        """End a lease early (holder done, or an operator revoking a crashed holder)."""
        with self.lock:
            volume = self._volume(volume_id)
            if volume.lease is None or volume.lease.statement["lease_id"] != lease_id:
                raise VolumeRefused("lease_not_current")
            volume.lease.released = True

    def head(self, volume_id: str) -> dict:
        with self.lock:
            return self._volume(volume_id).head_doc

    def volume(self, volume_id: str) -> dict:
        with self.lock:
            return self._volume(volume_id).doc

    def accept(self, commit_doc: dict) -> dict:
        """Accept one commit at head + 1 from the current lease holder. Returns the new signed head.

        An exact resend of the commit already at the head returns the same head, so a
        holder that lost the answer can tell success from losing a race.
        """
        if not isinstance(commit_doc, dict) or not isinstance(commit_doc.get("statement"), dict):
            raise VolumeRefused("malformed")
        commit = commit_doc["statement"]
        if commit.get("schema") != COMMIT_SCHEMA:
            raise VolumeRefused("wrong_schema")
        with self.lock:
            volume = self._volume(commit.get("volume_id"))
            lease = _check_signed(commit.get("lease"), LEASE_SCHEMA, [self.public_b64], "lease_not_signed_by_registry")
            current = volume.lease
            if current is None or lease.get("volume_id") != commit["volume_id"] or any(
                lease.get(k) != current.statement[k]
                for k in ("volume_id", "lease_id", "lease_seq", "holder_receipt_key_ed25519_b64")
            ):
                raise VolumeRefused("lease_not_current")
            if not self._live(current):
                raise VolumeRefused("lease_expired")
            _check_signed(commit_doc, COMMIT_SCHEMA, [current.statement["holder_receipt_key_ed25519_b64"]],
                          "signature_not_lease_holder")
            digest = statement_sha256(commit_doc)
            if digest == volume.head_sha256:
                return volume.head_doc
            generation = commit.get("generation")
            if type(generation) is not int or generation != volume.generation + 1:
                raise VolumeRefused("generation_not_next")
            if commit.get("parent_sha256") != volume.head_sha256:
                raise VolumeRefused("parent_not_head")
            _ident(commit.get("restic_repo_id"), "bad_restic_repo_id")
            _ident(commit.get("restic_snapshot_id"), "bad_restic_snapshot_id")
            volume.generation = generation
            volume.head_sha256 = digest
            volume.head_doc = self._head(commit["volume_id"], generation, digest, current.statement)
            return volume.head_doc


def verify_chain(volume_doc: dict, commits: list[dict], head_doc: dict, registry_keys: Iterable[str]) -> dict | None:
    """What a restoring guest runs on data from untrusted storage.

    Returns the head commit's statement (the snapshot to restore), or None for a
    volume with no commit yet. Raises VolumeRefused. Lease expiry is not checked
    against the present: every lease in an old chain has ended by restore time.
    """
    keys = list(registry_keys)
    volume = _check_signed(volume_doc, VOLUME_SCHEMA, keys, "volume_not_signed_by_registry")
    head = _check_signed(head_doc, HEAD_SCHEMA, keys, "head_not_signed_by_registry")
    volume_id = volume["volume_id"]
    if head.get("volume_id") != volume_id:
        raise VolumeRefused("head_wrong_volume")
    parent = statement_sha256(volume_doc)
    last_lease: dict | None = None
    statement = None
    for generation, doc in enumerate(commits, start=1):
        if not isinstance(doc, dict) or not isinstance(doc.get("statement"), dict):
            raise VolumeRefused("malformed")
        lease = _check_signed(doc["statement"].get("lease"), LEASE_SCHEMA, keys, "lease_not_signed_by_registry")
        statement = _check_signed(doc, COMMIT_SCHEMA, [lease.get("holder_receipt_key_ed25519_b64")],
                                  "signature_not_lease_holder")
        if statement.get("volume_id") != volume_id or lease.get("volume_id") != volume_id:
            raise VolumeRefused("wrong_volume")
        if statement.get("generation") != generation:
            raise VolumeRefused("generation_not_next")
        if statement.get("parent_sha256") != parent:
            raise VolumeRefused("parent_not_head")
        new_lease = last_lease is None or lease.get("lease_id") != last_lease.get("lease_id")
        if new_lease:
            # A new lease starts at the head it was granted on, with a higher sequence.
            if last_lease is not None and not lease.get("lease_seq", 0) > last_lease.get("lease_seq", 0):
                raise VolumeRefused("lease_out_of_order")
            if lease.get("base_generation") != generation - 1 or lease.get("base_sha256") != parent:
                raise VolumeRefused("lease_not_at_base")
        elif lease.get("lease_seq") != last_lease.get("lease_seq"):
            raise VolumeRefused("lease_out_of_order")
        last_lease = lease
        parent = statement_sha256(doc)
    if head.get("generation") != len(commits) or head.get("head_sha256") != parent:
        raise VolumeRefused("chain_not_at_head")
    return statement
