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
from datetime import datetime, timezone
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from cathedral import volume_log

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
    head_commit_sha256: str | None = None
    key_id: str | None = None
    shredded: bool = False
    shred_pending: bool = False
    shred_pending_key_id: str | None = None
    shred_receipt: dict | None = None


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
        # AB#398: every accepted head and every shred, in order (volume_log format).
        # In memory like the rest of this contract; where it is published is open.
        self.log: list[dict] = []
        self.log_signing_key_id = "registry:" + sha(self.key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw))[:16]

    def _t(self) -> int:
        return int(self.now())

    def _iso(self) -> str:
        return datetime.fromtimestamp(self._t(), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

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

    def create(self, volume_id: str, owner: str, *, key_id: str | None = None) -> dict:
        """Create a volume. Returns the signed volume statement; its digest is the parent of generation 1.

        key_id, when known at create, is the volume's key; shred refuses any other.
        """
        _ident(volume_id, "bad_volume_id")
        if not volume_log.VOLUME_ID_RE.fullmatch(volume_id):
            raise VolumeRefused("bad_volume_id")  # the head log could not record it
        _ident(owner, "bad_owner")
        if key_id is not None:
            _key_id(key_id)
        with self.lock:
            if volume_id in self.volumes:
                raise VolumeRefused("volume_exists")
            doc = sign_statement(self.key, {"schema": VOLUME_SCHEMA, "volume_id": volume_id, "owner": owner,
                                            "created_at": self._t()})
            genesis = statement_sha256(doc)
            self.volumes[volume_id] = _Volume(doc=doc, genesis_sha256=genesis, generation=0, head_sha256=genesis,
                                              head_doc=self._head(volume_id, 0, genesis, None), key_id=key_id)
            return doc

    def bind_key(self, volume_id: str, key_id: str) -> None:
        """Record the volume's key id once (when the key is released after create). shred refuses any other."""
        _key_id(key_id)
        with self.lock:
            volume = self._volume(volume_id)
            if volume.key_id is not None and volume.key_id != key_id:
                raise VolumeRefused("key_already_bound")
            volume.key_id = key_id

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
            _not_shredded(volume)
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
            volume = self._volume(volume_id)
            _not_shredded(volume)
            return volume.head_doc

    def issue_prune_token(self, volume_id: str, *, source_ip: str, ttl_seconds: int) -> dict:
        """A delete-scoped prune token for the control plane's prune runner (AB#398). Also valid after a shred."""
        from cathedral import volume_subtoken  # imports this module

        with self.lock:
            self._volume(volume_id)
        return volume_subtoken.issue_prune(self.key, volume_id=volume_id, source_ip=source_ip,
                                           ttl_seconds=ttl_seconds, now=self.now)

    def log_entries(self) -> list[dict]:
        with self.lock:
            return [dict(entry) for entry in self.log]

    def volume(self, volume_id: str) -> dict:
        with self.lock:
            return self._volume(volume_id).doc

    def accept(self, commit_doc: dict) -> dict:
        """Accept one commit at head + 1 from the current lease holder. Returns the new signed head.

        An exact resend of the commit already at the head returns the same head, so a
        holder that lost the answer can tell success from losing a race. That replay
        is checked against the commit's own lease, so it holds after the lease has
        expired, been released or been handed over, as long as the head has not moved.
        """
        if not isinstance(commit_doc, dict) or not isinstance(commit_doc.get("statement"), dict):
            raise VolumeRefused("malformed")
        commit = commit_doc["statement"]
        if commit.get("schema") != COMMIT_SCHEMA:
            raise VolumeRefused("wrong_schema")
        with self.lock:
            volume = self._volume(commit.get("volume_id"))
            _not_shredded(volume)
            lease = _check_signed(commit.get("lease"), LEASE_SCHEMA, [self.public_b64], "lease_not_signed_by_registry")
            # Authenticate against the embedded lease first, so a resend of the
            # accepted head commit is answered even after that lease expired or
            # was handed over: the holder must be able to learn its write landed.
            _check_signed(commit_doc, COMMIT_SCHEMA, [lease.get("holder_receipt_key_ed25519_b64")],
                          "signature_not_lease_holder")
            digest = statement_sha256(commit_doc)
            if digest == volume.head_sha256:
                return volume.head_doc
            current = volume.lease
            if current is None or lease.get("volume_id") != commit["volume_id"] or any(
                lease.get(k) != current.statement[k]
                for k in ("volume_id", "lease_id", "lease_seq", "holder_receipt_key_ed25519_b64")
            ):
                raise VolumeRefused("lease_not_current")
            if not self._live(current):
                raise VolumeRefused("lease_expired")
            generation = commit.get("generation")
            if type(generation) is not int or generation != volume.generation + 1:
                raise VolumeRefused("generation_not_next")
            if commit.get("parent_sha256") != volume.head_sha256:
                raise VolumeRefused("parent_not_head")
            _ident(commit.get("restic_repo_id"), "bad_restic_repo_id")
            _ident(commit.get("restic_snapshot_id"), "bad_restic_snapshot_id")
            # Build the log entry before moving the head, so a refused append leaves both unchanged.
            try:
                extended = volume_log.append_entry(
                    self.log, kind=volume_log.KIND_HEAD, volume_id=commit["volume_id"], generation=generation,
                    manifest_sha256=manifest_sha256(commit), commit_receipt_sha256="sha256:" + digest,
                    logged_at=self._iso())
            except volume_log.VolumeLogError:
                raise VolumeRefused("log_refused") from None
            self.log = extended
            volume.generation = generation
            volume.head_sha256 = digest
            volume.head_commit_sha256 = "sha256:" + digest
            volume.head_doc = self._head(commit["volume_id"], generation, digest, current.statement)
            return volume.head_doc

    def shred(self, volume_id: str, *, key_id: str, destroy_key: Callable[[str, str], object]) -> dict:
        """Crypto-shred a volume: destroy its key, log a terminal shred entry, return a signed receipt.

        destroy_key(volume_id, key_id) is the key service's call (AB#392). It must raise
        on an unknown key or a key that is not this volume's, be idempotent (a key it
        already destroyed counts as destroyed) and return True only once the key is
        gone; any other return is a refusal. The registry also refuses (before the key
        is touched) a key_id other than the one recorded for the volume at create or
        bind_key, and a retry of a pending shred with a key_id other than the pending
        one (shred_key_mismatch). The receipt attests that the key service confirmed
        destroying key_id.

        Everything is checked and the log entry built before the key is touched. The
        lease ends and the volume freezes (shred_pending: no grant, accept or head)
        before destroy_key runs, and stays frozen if the key service refuses or the
        answer is lost, so no commit can land on a key that may be gone. Retrying shred
        finishes it. A resend after success, with the same key_id, returns the same
        receipt. Held under the lock throughout.
        """
        with self.lock:
            volume = self._volume(volume_id)
            if volume.shredded:
                if volume.shred_receipt is not None and volume.shred_receipt["key_id"] == key_id:
                    return volume.shred_receipt
                raise VolumeRefused("volume_shredded")
            if volume.generation < 1 or volume.head_commit_sha256 is None:
                raise VolumeRefused("nothing_to_shred")
            _key_id(key_id)
            if volume.shred_pending and volume.shred_pending_key_id != key_id:
                raise VolumeRefused("shred_key_mismatch")
            if volume.key_id is None:
                raise VolumeRefused("key_not_bound")
            if volume.key_id != key_id:
                raise VolumeRefused("shred_key_mismatch")
            shredded_at = self._iso()
            try:
                extended = volume_log.append_entry(
                    self.log, kind=volume_log.KIND_SHRED, volume_id=volume_id, generation=volume.generation,
                    manifest_sha256=volume_log.verify_log(self.log)[volume_id].manifest_sha256,
                    commit_receipt_sha256=volume.head_commit_sha256, logged_at=shredded_at)
            except (volume_log.VolumeLogError, KeyError):
                raise VolumeRefused("log_refused") from None
            if volume.lease is not None:
                volume.lease.released = True
            volume.shred_pending = True
            volume.shred_pending_key_id = key_id
            try:
                destroyed = destroy_key(volume_id, key_id)
            except Exception:
                destroyed = False
            if destroyed is not True:
                raise VolumeRefused("key_not_destroyed")
            receipt = volume_log.sign_shred_receipt(
                extended, volume_id=volume_id, key_id=key_id, shredded_at=shredded_at,
                signing_key_id=self.log_signing_key_id,
                private_key=self.key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
            self.log = extended
            volume.shredded = True
            volume.shred_pending = False
            volume.shred_receipt = receipt
            return receipt


def _key_id(key_id) -> str:
    if not isinstance(key_id, str) or not volume_log.KEY_ID_RE.fullmatch(key_id):
        raise VolumeRefused("bad_key_id")
    return key_id


def _not_shredded(volume: _Volume) -> None:
    if volume.shredded:
        raise VolumeRefused("volume_shredded")
    if volume.shred_pending:
        raise VolumeRefused("shred_pending")


def manifest_sha256(commit: dict) -> str:
    """The head log's manifest digest of a commit statement: the restic repo and snapshot it names.

    A restoring guest recomputes it from the head commit verify_chain returns and passes it
    to volume_log.check_restore.
    """
    return "sha256:" + sha(canonical({"restic_repo_id": commit["restic_repo_id"],
                                      "restic_snapshot_id": commit["restic_snapshot_id"]}))


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
