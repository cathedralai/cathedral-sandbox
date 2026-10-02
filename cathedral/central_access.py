"""Signed central access to an opted-in miner worker.

This implements steps 1 and 2 of docs/CENTRAL_POOL_ACCESS.md. An offline Ed25519 root
signs a short-lived delegation naming one online central key and the routes it
may call. The central key signs each request over the route, the body hash, a
nonce, and the worker's own TLS channel binding, as validator requests are
bound. The worker verifies the chain against root keys it pinned by digest and
records the nonce in its own replay state, separate from validator requests.
The highest delegation sequence accepted is kept in that same state file, so a
restarted worker still refuses an older delegation.

The worker admits a central caller only when the miner passes the three
--central-* flags (worker serve, serve-snp, serve-gpu, serve-g4, develop and
migrate). Step 2 has no revocation-list fetch yet: nothing calls
install_revocations, so a compromised delegation is bounded only by its expiry,
at most MAX_DELEGATION_SECONDS (24 hours), until the fetch lands.

A delegation grants path routes, which are POST only, or route scopes. The TEE
box sandbox API (docs/TEE_BOX_SERVICE.md) maps each of its requests to one of
TEE_BOX_CENTRAL_SCOPES and passes it to ``preauthorize``; the request then
signs its method and full target, and the delegation must grant the scope. The
TEE box builds its own authorizer from the root keys in measured state
(cathedral/tee_box/measured_root.py), never from the --central-* flags.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import sqlite3
import stat
import threading
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.admission_policy import AdmissionPolicyError, load_policy_keys
from cathedral.common import ChannelBinding
from cathedral.policy_registry import (
    PolicyRegistryError,
    canonical_json,
    canonical_signed_bytes,
    parse_registry_json,
)
from cathedral.validator_access import (
    MAX_NETUID,
    MAX_REQUEST_FUTURE_SKEW_SECONDS,
    MAX_REQUEST_HEADER_BYTES,
    MAX_REQUEST_LIFETIME_SECONDS,
    ValidatorAccessError,
    ValidatorAccessState,
    bittensor_account_id,
    canonical_utc,
)

CENTRAL_DELEGATION_SCHEMA = "cathedral_central_delegation_v1"
CENTRAL_REQUEST_SCHEMA = "cathedral_central_request_v1"
CENTRAL_REVOCATIONS_SCHEMA = "cathedral_central_revocations_v1"
CENTRAL_REQUEST_HEADER = "X-Cathedral-Central-Request"

MAX_DELEGATION_SECONDS = 24 * 60 * 60
MAX_CENTRAL_REPLAY_ENTRIES = 1024
MAX_REVOKED_DELEGATIONS = 4096
MAX_REVOCATIONS_FILE_BYTES = 512 * 1024
MAX_CENTRAL_CONCURRENT = 2
DEFAULT_CENTRAL_REQUESTS_PER_WINDOW = 60
DEFAULT_CENTRAL_RATE_WINDOW_SECONDS = 60.0
MAX_CENTRAL_CALLERS = 16
# Route scopes of the TEE box sandbox API. Each names a group of its method and
# path templates (cathedral/tee_box/service.py maps them); scoped requests may
# use any of SCOPED_METHODS, while the path routes stay POST only.
TEE_BOX_CENTRAL_SCOPES = frozenset(
    {
        "tee-box:box",
        "tee-box:lease",
        "tee-box:revocations",
        "tee-box:image-import",
        "tee-box:create",
        "tee-box:list",
        "tee-box:get",
        "tee-box:lifetime",
        "tee-box:delete",
        "tee-box:exec",
        "tee-box:files",
    }
)
SCOPED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})
CENTRAL_ROUTES = frozenset({"/v1/capabilities"}) | TEE_BOX_CENTRAL_SCOPES

_DELEGATION_KEYS = frozenset(
    {
        "schema",
        "root_key_id",
        "central_key_base64",
        "routes",
        "network",
        "netuid",
        "sequence",
        "issued_at",
        "expires_at",
        "signature",
    }
)
_REQUEST_KEYS = frozenset(
    {
        "schema",
        "delegation",
        "worker_hotkey",
        "network",
        "netuid",
        "method",
        "path",
        "body_sha256",
        "channel_binding_type",
        "channel_binding_digest_hex",
        "nonce_hex",
        "issued_at",
        "expires_at",
        "signature",
    }
)
_REVOCATIONS_KEYS = frozenset(
    {"schema", "root_key_id", "sequence", "issued_at", "revoked", "signature"}
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_HEX_32_RE = re.compile(r"[0-9a-f]{64}")
_KEY_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_NETWORK_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
# Ed25519 public keys. ``cryptography`` takes any 32 bytes as a public key, and
# OpenSSL does not refuse a small-order one when it verifies: under such a key,
# a signature whose R is the identity and whose S is zero verifies for any
# message. Every key this module parses must therefore decode to a curve point
# (RFC 8032 section 5.1.3) with a canonical y below p, and must not be one of
# the eight small-order points. Those are the points with the y values below,
# in either sign: the same blocklist as libsodium's ge25519_has_small_order.
_ED25519_P = 2**255 - 19
_ED25519_D = -121665 * pow(121666, -1, _ED25519_P) % _ED25519_P
_ED25519_SMALL_ORDER_Y = frozenset(
    {
        0,  # the two points of order 4
        1,  # the identity
        _ED25519_P - 1,  # order 2
        # the four points of order 8
        2707385501144840649318225287225658788936804267575313519463743609750303402022,
        55188659117513257062467267217118295137698188065244968500265048394206261417927,
    }
)


class CentralAccessError(ValueError):
    """A central delegation, request, or revocation list was refused."""


def check_ed25519_public_key(key: object, label: str) -> bytes:
    """Return ``key`` if it is a usable Ed25519 public key, else refuse it.

    It must be 32 bytes encoding a curve point with a canonical y, and not a
    small-order point, whose holder need not know a private key to sign.
    """

    if not isinstance(key, bytes) or len(key) != 32:
        raise CentralAccessError(f"{label} must be a 32-byte Ed25519 public key")
    y = int.from_bytes(key, "little") & ((1 << 255) - 1)
    if y >= _ED25519_P:
        raise CentralAccessError(f"{label} is not a canonical Ed25519 point")
    if y in _ED25519_SMALL_ORDER_Y:
        raise CentralAccessError(f"{label} is a small-order Ed25519 point")
    # x^2 = (y^2 - 1) / (d y^2 + 1). It is zero only for y = 1 or p - 1, both
    # refused above, so the point exists, in either sign, when x^2 is a square.
    y_squared = y * y % _ED25519_P
    x_squared = (y_squared - 1) * pow(_ED25519_D * y_squared + 1, -1, _ED25519_P) % _ED25519_P
    if pow(x_squared, (_ED25519_P - 1) // 2, _ED25519_P) != 1:
        raise CentralAccessError(f"{label} is not an Ed25519 point")
    return key


@dataclass(frozen=True)
class CentralDelegation:
    digest: str
    root_key_id: str
    central_key: bytes
    routes: frozenset[str]
    sequence: int
    expires_at: datetime


@dataclass(frozen=True)
class PreauthorizedCentralRequest:
    delegation_digest: str
    delegation_sequence: int
    caller: str
    nonce_hex: str
    body_sha256: str
    expires_at: datetime


class CentralAccessState(ValidatorAccessState):
    """The central replay store, plus the durable delegation high-water.

    It is a ValidatorAccessState on its own file, so the replay floor, clock
    and lock rules are the validator store's, and the file also records the
    highest delegation sequence ever accepted.
    """

    def _initialize(self) -> None:
        super()._initialize()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS central_delegation_high_water (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    sequence INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS central_revocations (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    sequence INTEGER NOT NULL,
                    document BLOB NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def delegation_high_water(self) -> int | None:
        """The highest accepted delegation sequence, 0 if none, None on failure."""

        if self.closed:
            return None
        try:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT sequence FROM central_delegation_high_water WHERE singleton = 1"
                ).fetchone()
            finally:
                connection.close()
        except (sqlite3.Error, ValidatorAccessError):
            return None
        return 0 if row is None else int(row[0])

    def raise_delegation_high_water(self, sequence: int) -> int | None:
        """Durably raise the high-water to ``sequence``; return it, None on failure."""

        if self.closed:
            return None
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO central_delegation_high_water(singleton, sequence)
                    VALUES (1, ?)
                    ON CONFLICT(singleton) DO UPDATE SET
                        sequence = MAX(sequence, excluded.sequence)
                    """,
                    (sequence,),
                )
                row = connection.execute(
                    "SELECT sequence FROM central_delegation_high_water WHERE singleton = 1"
                ).fetchone()
                connection.commit()
            finally:
                connection.close()
        except (sqlite3.Error, ValidatorAccessError):
            return None
        return int(row[0])

    def stored_revocations(self) -> tuple[int, bytes] | None:
        """The revocation list in force as (sequence, canonical JSON).

        ``(0, b"")`` means none was ever installed; None means the store failed.
        """

        if self.closed:
            return None
        try:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT sequence, document FROM central_revocations WHERE singleton = 1"
                ).fetchone()
            finally:
                connection.close()
        except (sqlite3.Error, ValidatorAccessError):
            return None
        return (0, b"") if row is None else (int(row[0]), bytes(row[1]))

    def store_revocations(self, sequence: int, document: bytes) -> tuple[int, bytes] | None:
        """Keep ``document`` only if its sequence is higher; return what is stored.

        A list with the same sequence as the stored one never replaces it, so
        the caller compares what comes back. None means the store failed.
        """

        if self.closed:
            return None
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO central_revocations(singleton, sequence, document)
                    VALUES (1, ?, ?)
                    ON CONFLICT(singleton) DO UPDATE SET
                        sequence = excluded.sequence,
                        document = excluded.document
                    WHERE excluded.sequence > central_revocations.sequence
                    """,
                    (sequence, document),
                )
                row = connection.execute(
                    "SELECT sequence, document FROM central_revocations WHERE singleton = 1"
                ).fetchone()
                connection.commit()
            finally:
                connection.close()
        except (sqlite3.Error, ValidatorAccessError):
            return None
        return int(row[0]), bytes(row[1])


def open_central_access_state(path: str) -> CentralAccessState:
    """Open the central replay store on its own path, with the central cap."""

    try:
        return CentralAccessState(path, max_replay_entries=MAX_CENTRAL_REPLAY_ENTRIES)
    except ValidatorAccessError as exc:
        raise CentralAccessError(f"central access state is unusable: {exc}") from exc


def load_central_root_keys(path: str, *, pinned_digest: str) -> dict[str, bytes]:
    """Load the root public keys whose whole file matches the miner's pin."""

    if not isinstance(pinned_digest, str) or _DIGEST_RE.fullmatch(pinned_digest) is None:
        raise CentralAccessError("central root key digest must be sha256 plus 64 hex")
    try:
        keys = load_policy_keys(path, production_mode=True, pinned_digest=pinned_digest)
    except (AdmissionPolicyError, PolicyRegistryError) as exc:
        raise CentralAccessError(f"central root keys are unusable: {exc}") from exc
    for key_id, key in keys.items():
        if _KEY_ID_RE.fullmatch(key_id) is None:
            raise CentralAccessError("central root key id is not canonical")
        check_ed25519_public_key(key, f"central root key {key_id}")
    return keys


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise CentralAccessError(f"{label} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CentralAccessError(f"{label} must be canonical UTC time") from exc


def _utc(moment: datetime) -> str:
    try:
        return canonical_utc(moment)
    except ValidatorAccessError as exc:
        raise CentralAccessError(str(exc)) from exc


def _check_now(now: datetime) -> datetime:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise CentralAccessError("central verification time must be UTC")
    return now


def _check_subnet(network: object, netuid: object) -> tuple[str, int]:
    if not isinstance(network, str) or _NETWORK_RE.fullmatch(network) is None:
        raise CentralAccessError("network must be a bounded lowercase name")
    if isinstance(netuid, bool) or not isinstance(netuid, int) or not 0 <= netuid <= MAX_NETUID:
        raise CentralAccessError("netuid must be an integer within the subnet range")
    return network, netuid


def _b64(value: object, size: int, label: str) -> bytes:
    if not isinstance(value, str) or not value.isascii():
        raise CentralAccessError(f"{label} is not canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CentralAccessError(f"{label} is not canonical base64") from exc
    if len(decoded) != size or base64.b64encode(decoded).decode("ascii") != value:
        raise CentralAccessError(f"{label} must be {size} bytes of canonical base64")
    return decoded


def _verify_ed25519(document: Mapping[str, object], public_key: bytes, label: str) -> None:
    signature = document.get("signature")
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise CentralAccessError(f"{label} signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise CentralAccessError(f"{label} signature algorithm is unsupported")
    raw = _b64(signature["value_base64"], 64, f"{label} signature")
    check_ed25519_public_key(public_key, f"{label} signing key")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw, canonical_signed_bytes(document))
    except (InvalidSignature, ValueError) as exc:
        raise CentralAccessError(f"{label} signature verification failed") from exc


def _sign_ed25519(document: dict[str, object], seed: bytes) -> dict[str, object]:
    if "signature" in document:
        raise CentralAccessError("an unsigned document must not carry a signature")
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise CentralAccessError("Ed25519 private key seed must be 32 bytes")
    value = Ed25519PrivateKey.from_private_bytes(seed).sign(canonical_json(document))
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(value).decode("ascii"),
    }
    return document


def _root_key(document: Mapping[str, object], root_keys: Mapping[str, bytes], label: str) -> bytes:
    key_id = document.get("root_key_id")
    if not isinstance(key_id, str) or key_id not in root_keys:
        raise CentralAccessError(f"{label} names an untrusted root key")
    return root_keys[key_id]


def _delegation_digest(document: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(canonical_signed_bytes(document)).hexdigest()


def sign_delegation(
    *,
    root_key_id: str,
    root_seed: bytes,
    central_key: bytes,
    routes: Sequence[str],
    network: str,
    netuid: int,
    sequence: int,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, object]:
    """Offline tooling: the root delegates the given routes to one central key."""

    document: dict[str, object] = {
        "schema": CENTRAL_DELEGATION_SCHEMA,
        "root_key_id": root_key_id,
        "central_key_base64": base64.b64encode(central_key).decode("ascii"),
        "routes": sorted(set(routes)),
        "network": network,
        "netuid": netuid,
        "sequence": sequence,
        "issued_at": _utc(issued_at),
        "expires_at": _utc(expires_at),
    }
    _check_delegation_fields(document)
    return _sign_ed25519(document, root_seed)


def _check_delegation_fields(
    document: Mapping[str, object],
) -> tuple[bytes, frozenset[str], int, datetime, datetime]:
    if document.get("schema") != CENTRAL_DELEGATION_SCHEMA:
        raise CentralAccessError("central delegation schema is unsupported")
    key_id = document.get("root_key_id")
    if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
        raise CentralAccessError("central delegation root key id is not canonical")
    central_key = check_ed25519_public_key(
        _b64(document.get("central_key_base64"), 32, "central key"), "central key"
    )
    routes = document.get("routes")
    if (
        not isinstance(routes, list)
        or not routes
        or any(not isinstance(route, str) for route in routes)
        or routes != sorted(set(routes))
        or any(route not in CENTRAL_ROUTES for route in routes)
    ):
        raise CentralAccessError(
            "central delegation routes must be a sorted subset of central routes"
        )
    _check_subnet(document.get("network"), document.get("netuid"))
    sequence = document.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence < 1 << 63:
        raise CentralAccessError("central delegation sequence must be a positive integer")
    issued_at = _time(document.get("issued_at"), "delegation issued_at")
    expires_at = _time(document.get("expires_at"), "delegation expires_at")
    if not issued_at < expires_at:
        raise CentralAccessError("central delegation validity window is invalid")
    if expires_at - issued_at > timedelta(seconds=MAX_DELEGATION_SECONDS):
        raise CentralAccessError("central delegation validity window is too long")
    return central_key, frozenset(routes), sequence, issued_at, expires_at


def verify_delegation(
    document: object,
    root_keys: Mapping[str, bytes],
    *,
    network: str,
    netuid: int,
    now: datetime,
) -> CentralDelegation:
    """Verify one root-signed delegation for this worker's subnet at ``now``."""

    now = _check_now(now)
    if not isinstance(document, dict) or frozenset(document) != _DELEGATION_KEYS:
        raise CentralAccessError("central delegation fields are invalid")
    central_key, routes, sequence, issued_at, expires_at = _check_delegation_fields(document)
    if (document["network"], document["netuid"]) != (network, netuid):
        raise CentralAccessError("central delegation subnet does not match")
    _verify_ed25519(
        document, _root_key(document, root_keys, "central delegation"), "central delegation"
    )
    if issued_at > now + timedelta(seconds=MAX_REQUEST_FUTURE_SKEW_SECONDS):
        raise CentralAccessError("central delegation was issued too far in the future")
    if not now < expires_at:
        raise CentralAccessError("central delegation has expired")
    return CentralDelegation(
        digest=_delegation_digest(document),
        root_key_id=str(document["root_key_id"]),
        central_key=central_key,
        routes=routes,
        sequence=sequence,
        expires_at=expires_at,
    )


def sign_revocations(
    *,
    root_key_id: str,
    root_seed: bytes,
    sequence: int,
    issued_at: datetime,
    revoked: Sequence[str],
) -> dict[str, object]:
    """Offline tooling: the root withdraws delegations by digest."""

    document: dict[str, object] = {
        "schema": CENTRAL_REVOCATIONS_SCHEMA,
        "root_key_id": root_key_id,
        "sequence": sequence,
        "issued_at": _utc(issued_at),
        "revoked": sorted(set(revoked)),
    }
    return _sign_ed25519(document, root_seed)


def verify_revocations(
    document: object,
    root_keys: Mapping[str, bytes],
    *,
    minimum_sequence: int,
) -> tuple[int, frozenset[str]]:
    """Verify a revocation list no older than ``minimum_sequence``."""

    if not isinstance(document, dict) or frozenset(document) != _REVOCATIONS_KEYS:
        raise CentralAccessError("central revocation list fields are invalid")
    if document["schema"] != CENTRAL_REVOCATIONS_SCHEMA:
        raise CentralAccessError("central revocation list schema is unsupported")
    sequence = document["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence < 1 << 63:
        raise CentralAccessError("central revocation list sequence must be a positive integer")
    if sequence < minimum_sequence:
        raise CentralAccessError("central revocation list is older than the one in force")
    _time(document["issued_at"], "revocation list issued_at")
    revoked = document["revoked"]
    if (
        not isinstance(revoked, list)
        or len(revoked) > MAX_REVOKED_DELEGATIONS
        or any(not isinstance(item, str) or _DIGEST_RE.fullmatch(item) is None for item in revoked)
        or revoked != sorted(set(revoked))
    ):
        raise CentralAccessError(
            "central revocation list entries must be sorted delegation digests"
        )
    _verify_ed25519(
        document,
        _root_key(document, root_keys, "central revocation list"),
        "central revocation list",
    )
    return sequence, frozenset(revoked)


def build_central_request_header(
    *,
    delegation: Mapping[str, object],
    central_seed: bytes,
    worker_hotkey: str,
    network: str,
    netuid: int,
    method: str,
    path: str,
    body: bytes,
    channel_binding: ChannelBinding,
    nonce: bytes,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    """Central-side: sign one request for one worker, route, body and TLS key."""

    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise CentralAccessError("central request nonce must be 32 bytes")
    if not isinstance(body, bytes):
        raise CentralAccessError("central request body must be bytes")
    document: dict[str, object] = {
        "schema": CENTRAL_REQUEST_SCHEMA,
        "delegation": dict(delegation),
        "worker_hotkey": worker_hotkey,
        "network": network,
        "netuid": netuid,
        "method": method,
        "path": path,
        "body_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
        "channel_binding_type": channel_binding.binding_type.value,
        "channel_binding_digest_hex": channel_binding.digest.hex(),
        "nonce_hex": nonce.hex(),
        "issued_at": _utc(issued_at),
        "expires_at": _utc(expires_at),
    }
    encoded = canonical_json(_sign_ed25519(document, central_seed))
    if len(encoded) > MAX_REQUEST_HEADER_BYTES:
        raise CentralAccessError("central request header exceeds its size limit")
    return base64.b64encode(encoded).decode("ascii")


class CentralAccessAuthorizer:
    """Worker-side verifier for central requests, with its own replay state.

    ``state`` must be a CentralAccessState on its own path, so central
    requests never share the validator replay budget, holding at most
    MAX_CENTRAL_REPLAY_ENTRIES nonces; open_central_access_state builds one.
    The delegation high-water is read from it at start, and every request is
    checked against the stored value, raised in the same transaction, so
    workers that share one state file honour each other's newer delegations.

    The revocation list in force is persisted in ``state`` and restored at
    start, so a restart never drops it, and a list older than it, or a
    different list under the same sequence, is refused. ``revocations_path``
    names a local file the operator keeps current; it is re-read before a
    request whenever it changes, and while it is missing or unusable every
    central request is refused.
    """

    def __init__(
        self,
        root_keys: Mapping[str, bytes],
        *,
        worker_hotkey: str,
        network: str,
        netuid: int,
        channel_binding: ChannelBinding,
        state: CentralAccessState,
        revocations_path: str | None = None,
    ) -> None:
        if not root_keys:
            raise CentralAccessError("central access requires at least one pinned root key")
        for key_id, key in root_keys.items():
            check_ed25519_public_key(key, f"central root key {key_id}")
        bittensor_account_id(worker_hotkey)
        self.network, self.netuid = _check_subnet(network, netuid)
        if not isinstance(channel_binding, ChannelBinding):
            raise CentralAccessError("central access requires the worker channel binding")
        if not isinstance(state, CentralAccessState):
            raise CentralAccessError("central access requires durable replay state")
        if state.max_replay_entries > MAX_CENTRAL_REPLAY_ENTRIES:
            raise CentralAccessError("central replay state exceeds the central replay cap")
        self.root_keys = dict(root_keys)
        self.worker_hotkey = worker_hotkey
        self.channel_binding = channel_binding
        self.state = state
        self._lock = threading.Lock()
        self._revoked: frozenset[str] = frozenset()
        self._revocations_sequence = 0
        high_water = state.delegation_high_water()
        if high_water is None:
            raise CentralAccessError("central delegation high-water is unreadable")
        self._delegation_high_water = high_water
        stored = state.stored_revocations()
        if stored is None:
            raise CentralAccessError("central revocation list in force is unreadable")
        if stored[0]:
            try:
                document = parse_registry_json(stored[1])
            except ValueError as exc:
                raise CentralAccessError("stored central revocation list is invalid") from exc
            self._revocations_sequence, self._revoked = verify_revocations(
                document, self.root_keys, minimum_sequence=stored[0]
            )
        self._revocations_path = revocations_path
        self._revocations_file: tuple[int, int, int, int] | None = None
        self._revocations_file_error: str | None = None
        if revocations_path is not None:
            with self._lock:
                self._refresh_revocations_locked()
            if self._revocations_file_error is not None:
                raise CentralAccessError(self._revocations_file_error)

    def install_revocations(self, document: object) -> None:
        """Replace the revocation set with a newer or equal signed list."""

        with self._lock:
            self._install_revocations_locked(document)

    def _install_revocations_locked(self, document: object) -> None:
        sequence, revoked = verify_revocations(
            document, self.root_keys, minimum_sequence=self._revocations_sequence
        )
        if sequence == self._revocations_sequence and revoked != self._revoked:
            raise CentralAccessError("central revocation list changed without a new sequence")
        stored = self.state.store_revocations(sequence, canonical_json(document))
        if stored is None:
            raise CentralAccessError("central revocation list could not be persisted")
        if stored[0] != sequence:
            raise CentralAccessError("central revocation list is older than the one in force")
        try:
            stored_sequence, stored_revoked = verify_revocations(
                parse_registry_json(stored[1]), self.root_keys, minimum_sequence=sequence
            )
        except ValueError as exc:
            raise CentralAccessError("stored central revocation list is invalid") from exc
        if (stored_sequence, stored_revoked) != (sequence, revoked):
            raise CentralAccessError("central revocation list changed without a new sequence")
        self._revocations_sequence = sequence
        self._revoked = revoked

    def _refresh_revocations_locked(self) -> None:
        """Install the operator's revocation file if it changed since last read.

        Any failure is remembered for that exact file, so requests are refused
        until the file is replaced, without re-parsing it on every request.
        """

        path = self._revocations_path
        if path is None:
            return
        try:
            # O_NONBLOCK: opening a FIFO for reading would otherwise wait for a
            # writer, holding the lock, and hang startup or every request. The
            # fstat below then refuses anything but a regular file.
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError:
            self._revocations_file = None
            self._revocations_file_error = "central revocation list file is unavailable"
            return
        try:
            metadata = os.fstat(descriptor)
            identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            )
            if identity == self._revocations_file:
                return
            self._revocations_file = identity
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or not 1 <= metadata.st_size <= MAX_REVOCATIONS_FILE_BYTES
            ):
                self._revocations_file_error = (
                    "central revocation list file must be a bounded regular file "
                    "that only its owner can write"
                )
                return
            with os.fdopen(os.dup(descriptor), "rb") as handle:
                raw = handle.read(MAX_REVOCATIONS_FILE_BYTES + 1)
        finally:
            os.close(descriptor)
        try:
            if len(raw) > MAX_REVOCATIONS_FILE_BYTES:
                raise ValueError("it grew past its size limit while being read")
            document = parse_registry_json(raw)
            if raw.rstrip(b"\n") != canonical_json(document):
                raise ValueError("not canonical")
            self._install_revocations_locked(document)
        except (ValueError, CentralAccessError) as exc:
            self._revocations_file_error = f"central revocation list file is unusable: {exc}"
            return
        self._revocations_file_error = None

    @property
    def revocations_sequence(self) -> int:
        """The sequence of the revocation list in force, 0 if none."""

        with self._lock:
            return self._revocations_sequence

    def preauthorize(
        self,
        header: object,
        *,
        method: str,
        path: str,
        now: datetime,
        scope: str | None = None,
    ) -> PreauthorizedCentralRequest:
        """Check everything but the body, before the body is read.

        With no ``scope``, ``path`` must be a path route the delegation grants
        and the method POST. With a ``scope`` from TEE_BOX_CENTRAL_SCOPES, the
        caller has already mapped ``method`` and ``path`` (the full target) to
        that scope, and the delegation must grant it.
        """

        now = _check_now(now)
        if scope is not None and scope not in TEE_BOX_CENTRAL_SCOPES:
            raise CentralAccessError("central route scope is unknown")
        with self._lock:
            self._refresh_revocations_locked()
            if self._revocations_file_error is not None:
                raise CentralAccessError(self._revocations_file_error)
        if (
            not isinstance(header, str)
            or not header
            or not header.isascii()
            or len(header) > MAX_REQUEST_HEADER_BYTES * 2
        ):
            raise CentralAccessError("central request header is invalid")
        try:
            encoded = base64.b64decode(header, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CentralAccessError("central request header is invalid") from exc
        if len(encoded) > MAX_REQUEST_HEADER_BYTES:
            raise CentralAccessError("central request header is too large")
        try:
            document = parse_registry_json(encoded)
        except ValueError as exc:
            raise CentralAccessError("central request is not valid JSON") from exc
        if encoded != canonical_json(document):
            raise CentralAccessError("central request must be canonical JSON")
        if frozenset(document) != _REQUEST_KEYS:
            raise CentralAccessError("central request fields are invalid")
        if document["schema"] != CENTRAL_REQUEST_SCHEMA:
            raise CentralAccessError("central request schema is unsupported")

        delegation = verify_delegation(
            document["delegation"],
            self.root_keys,
            network=self.network,
            netuid=self.netuid,
            now=now,
        )
        with self._lock:
            if delegation.digest in self._revoked:
                raise CentralAccessError("central delegation has been revoked")
            if delegation.sequence < self._delegation_high_water:
                raise CentralAccessError("central delegation is older than one already accepted")

        if scope is None:
            method_allowed = method == "POST" and path not in TEE_BOX_CENTRAL_SCOPES
            granted = path
        else:
            method_allowed = method in SCOPED_METHODS
            granted = scope
        if not method_allowed or document["method"] != method or document["path"] != path:
            raise CentralAccessError("central request target does not match")
        if granted not in delegation.routes:
            raise CentralAccessError("central delegation does not grant this route")
        if document["worker_hotkey"] != self.worker_hotkey:
            raise CentralAccessError("central request worker does not match")
        if (document["network"], document["netuid"]) != (self.network, self.netuid):
            raise CentralAccessError("central request subnet does not match")
        if document["channel_binding_type"] != self.channel_binding.binding_type.value:
            raise CentralAccessError("central request channel type does not match")
        if document["channel_binding_digest_hex"] != self.channel_binding.digest.hex():
            raise CentralAccessError("central request channel key does not match")
        body_sha256 = document["body_sha256"]
        if not isinstance(body_sha256, str) or _DIGEST_RE.fullmatch(body_sha256) is None:
            raise CentralAccessError("central request body digest is invalid")
        nonce_hex = document["nonce_hex"]
        if not isinstance(nonce_hex, str) or _HEX_32_RE.fullmatch(nonce_hex) is None:
            raise CentralAccessError("central request nonce is invalid")
        issued_at = _time(document["issued_at"], "request issued_at")
        expires_at = _time(document["expires_at"], "request expires_at")
        if not issued_at < expires_at:
            raise CentralAccessError("central request validity window is invalid")
        if expires_at - issued_at > timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS):
            raise CentralAccessError("central request validity window is too long")
        if issued_at > now + timedelta(seconds=MAX_REQUEST_FUTURE_SKEW_SECONDS):
            raise CentralAccessError("central request was issued too far in the future")
        if not now < expires_at:
            raise CentralAccessError("central request has expired")
        if expires_at > delegation.expires_at:
            raise CentralAccessError("central request outlives its delegation")

        _verify_ed25519(document, delegation.central_key, "central request")
        with self._lock:
            # Another worker may share this state file and have accepted a
            # newer delegation, so the stored high-water is read in the same
            # transaction that raises it, and never trusted from memory alone.
            stored = self.state.raise_delegation_high_water(delegation.sequence)
            if stored is None:
                raise CentralAccessError("central delegation high-water could not be recorded")
            self._delegation_high_water = max(self._delegation_high_water, stored)
            if delegation.sequence < self._delegation_high_water:
                raise CentralAccessError("central delegation is older than one already accepted")
        return PreauthorizedCentralRequest(
            delegation_digest=delegation.digest,
            delegation_sequence=delegation.sequence,
            caller="central:" + hashlib.sha256(delegation.central_key).hexdigest(),
            nonce_hex=nonce_hex,
            body_sha256=body_sha256,
            expires_at=expires_at,
        )

    def finalize(self, request: PreauthorizedCentralRequest, *, body: bytes, now: datetime) -> str:
        """Check the body and record the nonce; return the caller identity."""

        now = _check_now(now)
        if not isinstance(request, PreauthorizedCentralRequest):
            raise CentralAccessError("preauthorized central request is invalid")
        if not isinstance(body, bytes):
            raise CentralAccessError("central request body must be bytes")
        body_sha256 = "sha256:" + hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(request.body_sha256, body_sha256):
            raise CentralAccessError("central request body does not match")
        if not now < request.expires_at:
            raise CentralAccessError("central request has expired")
        with self._lock:
            if request.delegation_digest in self._revoked:
                raise CentralAccessError("central delegation has been revoked")
            stored = self.state.delegation_high_water()
            if stored is None:
                raise CentralAccessError("central delegation high-water is unreadable")
            self._delegation_high_water = max(self._delegation_high_water, stored)
            if request.delegation_sequence < self._delegation_high_water:
                raise CentralAccessError("central delegation is older than one already accepted")
        if not self.state.check_and_record_request(
            request.caller, request.nonce_hex, now=now, expires_at=request.expires_at
        ):
            raise CentralAccessError("central request was replayed or replay state failed")
        return request.caller


class CentralRequestLease:
    """One admitted central request, released exactly once by the worker."""

    def __init__(self, limiter: CentralRequestLimiter, caller: str) -> None:
        self._limiter = limiter
        self._caller = caller
        self._released = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._limiter._release(self._caller)


class CentralRequestLimiter:
    """Per central key: one request in flight and a bounded rate, few keys."""

    def __init__(
        self,
        *,
        requests_per_window: int = DEFAULT_CENTRAL_REQUESTS_PER_WINDOW,
        window_seconds: float = DEFAULT_CENTRAL_RATE_WINDOW_SECONDS,
        max_callers: int = MAX_CENTRAL_CALLERS,
        clock=time.monotonic,
    ) -> None:
        if (
            isinstance(requests_per_window, bool)
            or not isinstance(requests_per_window, int)
            or not 1 <= requests_per_window <= 10_000
        ):
            raise CentralAccessError("central request rate is out of range")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not 0 < window_seconds <= 3600
        ):
            raise CentralAccessError("central rate window is out of range")
        if (
            isinstance(max_callers, bool)
            or not isinstance(max_callers, int)
            or not 1 <= max_callers <= 256
        ):
            raise CentralAccessError("central caller count is out of range")
        self.requests_per_window = requests_per_window
        self.window_seconds = float(window_seconds)
        self.max_callers = max_callers
        self._clock = clock
        self._lock = threading.Lock()
        self._in_flight: dict[str, int] = {}
        self._recent: dict[str, deque[float]] = {}

    def acquire(self, caller: str) -> CentralRequestLease | None:
        if not isinstance(caller, str) or not caller.startswith("central:"):
            raise CentralAccessError("central limiter needs a central caller identity")
        now = self._clock()
        with self._lock:
            recent = self._recent.get(caller)
            if recent is None:
                if len(self._recent) >= self.max_callers:
                    idle = [
                        key
                        for key, times in self._recent.items()
                        if not self._in_flight.get(key)
                        and (not times or now - times[-1] >= self.window_seconds)
                    ]
                    if not idle:
                        return None
                    for key in idle:
                        self._recent.pop(key, None)
                        self._in_flight.pop(key, None)
                recent = self._recent.setdefault(caller, deque())
            while recent and now - recent[0] >= self.window_seconds:
                recent.popleft()
            if self._in_flight.get(caller, 0) >= 1 or len(recent) >= self.requests_per_window:
                return None
            recent.append(now)
            self._in_flight[caller] = self._in_flight.get(caller, 0) + 1
        return CentralRequestLease(self, caller)

    def _release(self, caller: str) -> None:
        with self._lock:
            count = self._in_flight.get(caller, 0)
            if count <= 1:
                self._in_flight.pop(caller, None)
            else:
                self._in_flight[caller] = count - 1
