"""Qualified validator access and bounded worker-fleet discovery.

The measured worker does not query Bittensor. An operator captures a finalized
validator view outside the guest, signs the bounded snapshot with an Ed25519
artifact key, and places that public artifact beside the worker. The worker
then authenticates each protected request with the validator's Bittensor
sr25519 hotkey.

The two signatures prove different facts:

* the snapshot signature says which hotkeys had a validator permit and enough
  stake at one finalized block;
* the request signature says one of those hotkeys authorized this exact HTTP
  body for this worker and this attested TLS key.

Neither fact admits a machine or grants weight. Every discovered endpoint must
still pass fresh hardware, channel, uniqueness, and work verification.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import stat
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.common import ChannelBinding, is_globally_routable
from cathedral.policy_registry import (
    MAX_SQLITE_INTEGER,
    canonical_json,
    canonical_signed_bytes,
    parse_registry_json,
)

VALIDATOR_ACCESS_SNAPSHOT_SCHEMA = "cathedral_validator_access_snapshot_v1"
VALIDATOR_REQUEST_SCHEMA = "cathedral_validator_request_v1"
WORKER_FLEET_SCHEMA = "cathedral_worker_fleet_v1"
VALIDATOR_REQUEST_HEADER = "X-Cathedral-Validator-Request"

MAX_VALIDATORS = 256
MAX_FLEET_ENDPOINTS = 32
MAX_FLEET_FILE_BYTES = 64 * 1024
MAX_SNAPSHOT_BYTES = 256 * 1024
MAX_REQUEST_HEADER_BYTES = 8 * 1024
MAX_REQUEST_LIFETIME_SECONDS = 120
MAX_REQUEST_FUTURE_SKEW_SECONDS = 15
MAX_REPLAY_ENTRIES = 4096
DEFAULT_SNAPSHOT_MAX_AGE_SECONDS = 3600
MAX_SNAPSHOT_VALIDITY_SECONDS = 3600
DEFAULT_VALIDATOR_MAX_CONCURRENT = 1
DEFAULT_VALIDATOR_REQUESTS_PER_WINDOW = 120
DEFAULT_VALIDATOR_RATE_WINDOW_SECONDS = 60.0
MAX_NETUID = 65_535
MAX_UID = 65_535
MAX_STAKE_RAO = MAX_SQLITE_INTEGER
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.IPv6Network("64:ff9b:1::/48")
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")

_SS58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,128}$")
_NETWORK_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_SNAPSHOT_KEYS = frozenset(
    {
        "schema",
        "network",
        "netuid",
        "block",
        "block_hash",
        "block_is_finalized",
        "generated_at",
        "expires_at",
        "minimum_stake_rao",
        "validators",
        "signing_key_id",
        "signature",
    }
)
_VALIDATOR_KEYS = frozenset({"hotkey", "uid", "validator_permit", "stake_rao"})
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_REQUEST_KEYS = frozenset(
    {
        "schema",
        "validator_hotkey",
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
_PROTECTED_PATHS = frozenset({"/v1/fleet", "/v1/evidence", "/v1/sat-work", "/v1/capabilities"})
_FLEET_KEYS = frozenset({"schema", "worker_hotkey", "endpoints"})

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {character: index for index, character in enumerate(_BASE58_ALPHABET)}
_SS58_PREFIX = b"SS58PRE"
_BITTENSOR_SS58_FORMAT = 42
_PREFLIGHT_ADDRESS = "5Cvzb5veKov4TMvd5JVgecHYSphjGU3Dh4N2MGPPCoUJ7cZV"
_PREFLIGHT_MESSAGE = b"cathedral-enroll-verifier-preflight-v1"
_PREFLIGHT_SIGNATURE_B64 = (
    "ThgZ+GzZKIBrOALGgrh3pVkAi84HnQrjp7b6mq1aIWpGWW0DtEUFymbyQJhYpZRD+OaS6UDE9VBPHcqSeRcDjw=="
)


class ValidatorAccessError(ValueError):
    """A validator snapshot, request, or fleet manifest is not trustworthy."""


class RequestSigner(Protocol):
    """The validator's existing Bittensor hotkey signing operation."""

    def __call__(self, message: bytes) -> bytes: ...


class SignatureVerifier(Protocol):
    """Verify one Bittensor sr25519 signature."""

    def __call__(self, signature: bytes, message: bytes, public_key: bytes) -> bool: ...


class ValidatorSnapshotProvider(Protocol):
    """A cheap-to-poll source of the current verified qualification view."""

    network: str
    netuid: int

    def load(self, *, now: datetime) -> "ValidatorAccessSnapshot | None": ...


class ValidatorAccessState:
    """Durable snapshot high-water and accepted-request replay state."""

    def __init__(self, path: str, *, max_replay_entries: int = MAX_REPLAY_ENTRIES) -> None:
        if not isinstance(path, str) or not path or path == ":memory:":
            raise ValidatorAccessError("validator access requires a durable state path")
        if (
            isinstance(max_replay_entries, bool)
            or not isinstance(max_replay_entries, int)
            or not 0 < max_replay_entries <= MAX_REPLAY_ENTRIES
        ):
            raise ValidatorAccessError("replay cache size is invalid")
        self.path = os.path.abspath(path)
        self.max_replay_entries = max_replay_entries
        self._prepare_path()
        self._initialize()

    def _prepare_path(self) -> None:
        target = Path(self.path)
        try:
            parent_metadata = target.parent.lstat()
        except OSError as exc:
            raise ValidatorAccessError(
                "validator access state parent must be owner-controlled"
            ) from exc
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or parent_metadata.st_mode & 0o022
        ):
            raise ValidatorAccessError("validator access state parent must be owner-controlled")
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    target,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
            except FileExistsError:
                return self._prepare_path()
            try:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise ValidatorAccessError("validator access state must be an owner-only file")

    def _connect(self) -> sqlite3.Connection:
        self._prepare_path()
        connection = sqlite3.connect(self.path, timeout=2.0)
        connection.execute("PRAGMA busy_timeout = 2000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            os.chmod(self.path, 0o600)
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS validator_snapshot_high_water (
                    network TEXT NOT NULL,
                    netuid INTEGER NOT NULL,
                    block INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL,
                    authorization_digest TEXT NOT NULL,
                    PRIMARY KEY(network, netuid)
                )
                """
            )
            high_water_columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(validator_snapshot_high_water)")
            }
            if "authorization_digest" not in high_water_columns:
                # An older row proves only the full signed document digest.
                # Leave its semantic digest unknown until that exact document
                # is observed again. A changed same-height document remains
                # fail-closed until the semantic authorization is known.
                connection.execute(
                    "ALTER TABLE validator_snapshot_high_water ADD COLUMN authorization_digest TEXT"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS validator_request_replays (
                    validator_hotkey TEXT NOT NULL,
                    nonce_hex TEXT NOT NULL,
                    expires_at_epoch INTEGER NOT NULL,
                    PRIMARY KEY(validator_hotkey, nonce_hex)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS validator_request_clock_high_water (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    observed_at_epoch INTEGER NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def accept_snapshot(self, snapshot: "ValidatorAccessSnapshot") -> bool:
        """Accept freshness-only re-signs while rejecting rollback or equivocation."""

        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT block, block_hash, snapshot_digest, authorization_digest
                    FROM validator_snapshot_high_water
                    WHERE network = ? AND netuid = ?
                    """,
                    (snapshot.network, snapshot.netuid),
                ).fetchone()
                if row is not None:
                    (
                        current_block,
                        current_hash,
                        current_digest,
                        current_authorization_digest,
                    ) = row
                    if snapshot.block < current_block:
                        connection.rollback()
                        return False
                    if snapshot.block == current_block:
                        if snapshot.block_hash != current_hash:
                            connection.rollback()
                            return False
                        if current_authorization_digest is None:
                            # A pre-migration row has no independently stored
                            # semantic authorization. Re-observing its exact
                            # signed document safely backfills that digest, but
                            # a changed same-height document stays fail-closed.
                            if snapshot.digest != current_digest:
                                connection.rollback()
                                return False
                        elif snapshot.authorization_digest != current_authorization_digest:
                            connection.rollback()
                            return False
                connection.execute(
                    """
                    INSERT INTO validator_snapshot_high_water(
                        network, netuid, block, block_hash, snapshot_digest,
                        authorization_digest
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(network, netuid) DO UPDATE SET
                        block = excluded.block,
                        block_hash = excluded.block_hash,
                        snapshot_digest = excluded.snapshot_digest,
                        authorization_digest = excluded.authorization_digest
                    """,
                    (
                        snapshot.network,
                        snapshot.netuid,
                        snapshot.block,
                        snapshot.block_hash,
                        snapshot.digest,
                        snapshot.authorization_digest,
                    ),
                )
                connection.commit()
                return True
            finally:
                connection.close()
        except sqlite3.Error:
            return False

    def check_and_record_request(
        self,
        validator_hotkey: str,
        nonce_hex: str,
        *,
        now: datetime,
        expires_at: datetime,
    ) -> bool:
        """Atomically refuse replay and retain the nonce through its validity."""

        now_epoch = int(now.timestamp())
        expires_epoch = int(expires_at.timestamp())
        if expires_epoch <= now_epoch:
            return False
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                clock_row = connection.execute(
                    """
                    SELECT observed_at_epoch
                    FROM validator_request_clock_high_water
                    WHERE singleton = 1
                    """
                ).fetchone()
                if clock_row is not None and now_epoch < int(clock_row[0]):
                    # Expired replay rows must never become reusable because
                    # the host wall clock stepped backward after pruning.
                    connection.rollback()
                    return False
                connection.execute(
                    """
                    INSERT INTO validator_request_clock_high_water(
                        singleton, observed_at_epoch
                    ) VALUES (1, ?)
                    ON CONFLICT(singleton) DO UPDATE SET
                        observed_at_epoch = excluded.observed_at_epoch
                    """,
                    (now_epoch,),
                )
                connection.execute(
                    "DELETE FROM validator_request_replays WHERE expires_at_epoch <= ?",
                    (now_epoch,),
                )
                count = int(
                    connection.execute("SELECT COUNT(*) FROM validator_request_replays").fetchone()[
                        0
                    ]
                )
                if count >= self.max_replay_entries:
                    connection.rollback()
                    return False
                try:
                    connection.execute(
                        """
                        INSERT INTO validator_request_replays(
                            validator_hotkey, nonce_hex, expires_at_epoch
                        ) VALUES (?, ?, ?)
                        """,
                        (validator_hotkey, nonce_hex, expires_epoch),
                    )
                except sqlite3.IntegrityError:
                    connection.rollback()
                    return False
                connection.commit()
                return True
            finally:
                connection.close()
        except sqlite3.Error:
            return False


@dataclass
class _ValidatorLimitEntry:
    in_flight: int
    window_started: float
    requests: int
    last_seen: float


class ValidatorRequestLease:
    """One verified caller slot, released exactly once by the worker."""

    def __init__(self, limiter: "ValidatorRequestLimiter", hotkey: str) -> None:
        self._limiter = limiter
        self._hotkey = hotkey
        self._released = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._limiter.release(self._hotkey)


class ValidatorRequestLimiter:
    """Bound concurrency and request rate for verified signed envelopes.

    The worker calls this after envelope signature and snapshot qualification,
    but before body admission. The bounded key table therefore cannot be filled
    with unverified claimed hotkeys, and one qualified validator cannot occupy
    every signed-work slot by stalling request bodies.
    """

    def __init__(
        self,
        *,
        max_concurrent: int = DEFAULT_VALIDATOR_MAX_CONCURRENT,
        requests_per_window: int = DEFAULT_VALIDATOR_REQUESTS_PER_WINDOW,
        window_seconds: float = DEFAULT_VALIDATOR_RATE_WINDOW_SECONDS,
        max_keys: int = MAX_VALIDATORS,
        clock=time.monotonic,
    ) -> None:
        for value, label, maximum in (
            (max_concurrent, "validator concurrency", 64),
            (requests_per_window, "validator request rate", 100_000),
            (max_keys, "validator limiter key count", MAX_VALIDATORS),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
                raise ValidatorAccessError(f"{label} is invalid")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not 0 < float(window_seconds) <= 3600
        ):
            raise ValidatorAccessError("validator rate window is invalid")
        if not callable(clock):
            raise ValidatorAccessError("validator limiter clock is invalid")
        self.max_concurrent = max_concurrent
        self.requests_per_window = requests_per_window
        self.window_seconds = float(window_seconds)
        self.max_keys = max_keys
        self._clock = clock
        self._entries: dict[str, _ValidatorLimitEntry] = {}
        self._lock = threading.Lock()

    def _now(self) -> float:
        now = float(self._clock())
        if not 0 <= now < float("inf"):
            raise ValidatorAccessError("validator limiter clock failed")
        return now

    def acquire(self, hotkey: str) -> ValidatorRequestLease | None:
        """Count one verified envelope and reserve its caller slot."""

        bittensor_account_id(hotkey)
        now = self._now()
        with self._lock:
            entry = self._entries.get(hotkey)
            if entry is None:
                if len(self._entries) >= self.max_keys:
                    idle = sorted(
                        (
                            (candidate.last_seen, candidate_hotkey)
                            for candidate_hotkey, candidate in self._entries.items()
                            if candidate.in_flight == 0
                        )
                    )
                    if not idle:
                        return None
                    del self._entries[idle[0][1]]
                entry = _ValidatorLimitEntry(
                    in_flight=0,
                    window_started=now,
                    requests=0,
                    last_seen=now,
                )
                self._entries[hotkey] = entry
            elapsed = now - entry.window_started
            if elapsed < 0 or elapsed >= self.window_seconds:
                entry.window_started = now
                entry.requests = 0
            entry.last_seen = now
            if entry.in_flight >= self.max_concurrent or entry.requests >= self.requests_per_window:
                return None
            entry.in_flight += 1
            entry.requests += 1
        return ValidatorRequestLease(self, hotkey)

    def release(self, hotkey: str) -> None:
        """Release one caller slot. Unknown or duplicate releases are harmless."""

        now = self._now()
        with self._lock:
            entry = self._entries.get(hotkey)
            if entry is None or entry.in_flight == 0:
                return
            entry.in_flight -= 1
            entry.last_seen = now

    def active_count(self, hotkey: str) -> int:
        """Return the active caller count for diagnostics and deterministic tests."""

        bittensor_account_id(hotkey)
        with self._lock:
            entry = self._entries.get(hotkey)
            return 0 if entry is None else entry.in_flight


def _canonical_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise ValidatorAccessError(f"{label} must be canonical UTC time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValidatorAccessError(f"{label} must be canonical UTC time") from exc


def canonical_utc(moment: datetime) -> str:
    """Return the wire timestamp used by signed access documents."""

    if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
        raise ValidatorAccessError("timestamp must be UTC")
    if moment.microsecond:
        raise ValidatorAccessError("timestamp must not contain fractional seconds")
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_base58(value: str) -> bytes:
    number = 0
    try:
        for character in value:
            number = number * 58 + _BASE58_INDEX[character]
    except KeyError as exc:
        raise ValidatorAccessError("hotkey is not base58") from exc
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + encoded


def bittensor_account_id(hotkey: object) -> bytes:
    """Decode one canonical Bittensor AccountId32 SS58 address."""

    if not isinstance(hotkey, str) or _SS58_RE.fullmatch(hotkey) is None:
        raise ValidatorAccessError("hotkey is not a canonical Bittensor SS58 address")
    decoded = _decode_base58(hotkey)
    if len(decoded) != 35 or decoded[0] != _BITTENSOR_SS58_FORMAT:
        raise ValidatorAccessError("hotkey must use Bittensor SS58 format 42")
    payload = decoded[:-2]
    checksum = decoded[-2:]
    expected = hashlib.blake2b(_SS58_PREFIX + payload, digest_size=64).digest()[:2]
    if not hmac.compare_digest(checksum, expected):
        raise ValidatorAccessError("hotkey has an invalid SS58 checksum")
    return payload[1:]


def load_sr25519_verifier() -> SignatureVerifier:
    """Load the small sr25519 primitive, without importing a chain client."""

    try:
        import sr25519  # type: ignore[import-not-found]  # noqa: PLC0415
    except Exception as exc:
        raise ValidatorAccessError(
            "validator access requires py-sr25519-bindings in the worker image"
        ) from exc

    def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
        try:
            return sr25519.verify(signature, message, public_key) is True
        except Exception:
            return False

    return verify


def preflight_sr25519_verifier(verifier: SignatureVerifier) -> None:
    """Prove the worker verifier accepts and rejects a fixed known-answer pair."""

    signature = base64.b64decode(_PREFLIGHT_SIGNATURE_B64, validate=True)
    corrupted = bytearray(signature)
    corrupted[0] ^= 0x01
    public_key = bittensor_account_id(_PREFLIGHT_ADDRESS)
    if (
        verifier(signature, _PREFLIGHT_MESSAGE, public_key) is not True
        or verifier(bytes(corrupted), _PREFLIGHT_MESSAGE, public_key) is not False
    ):
        raise ValidatorAccessError("sr25519 verifier failed its startup known-answer check")


@dataclass(frozen=True)
class QualifiedValidator:
    hotkey: str
    uid: int
    stake_rao: int


def _snapshot_authorization_digest(
    *,
    network: str,
    netuid: int,
    block: int,
    block_hash: str,
    minimum_stake_rao: int,
    signing_key_id: str,
    validators: Mapping[str, QualifiedValidator],
) -> str:
    """Digest the stable authorization semantics, excluding freshness fields."""

    authorization = {
        "network": network,
        "netuid": netuid,
        "block": block,
        "block_hash": block_hash,
        "minimum_stake_rao": minimum_stake_rao,
        "signing_key_id": signing_key_id,
        "validators": [
            {
                "hotkey": row.hotkey,
                "uid": row.uid,
                "stake_rao": row.stake_rao,
            }
            for row in sorted(validators.values(), key=lambda row: row.hotkey)
        ],
    }
    return "sha256:" + hashlib.sha256(canonical_json(authorization)).hexdigest()


@dataclass(frozen=True)
class ValidatorAccessSnapshot:
    network: str
    netuid: int
    block: int
    block_hash: str
    generated_at: datetime
    expires_at: datetime
    minimum_stake_rao: int
    validators: Mapping[str, QualifiedValidator]
    signing_key_id: str
    authorization_digest: str
    digest: str

    def qualifies(self, hotkey: str, *, at: datetime) -> bool:
        """Return true only while this snapshot and validator remain eligible."""

        candidate = self.validators.get(hotkey)
        return (
            self.generated_at <= at < self.expires_at
            and candidate is not None
            and candidate.stake_rao >= self.minimum_stake_rao
        )


@dataclass(frozen=True)
class StaticValidatorSnapshotProvider:
    """Fixed provider for tests and callers that own their own reload boundary."""

    snapshot: ValidatorAccessSnapshot
    max_age_seconds: int = DEFAULT_SNAPSHOT_MAX_AGE_SECONDS

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or not 0 < self.max_age_seconds <= MAX_SNAPSHOT_VALIDITY_SECONDS
        ):
            raise ValidatorAccessError("validator snapshot maximum age is invalid")

    @property
    def network(self) -> str:
        return self.snapshot.network

    @property
    def netuid(self) -> int:
        return self.snapshot.netuid

    def load(self, *, now: datetime) -> ValidatorAccessSnapshot | None:
        if (
            self.snapshot.generated_at <= now < self.snapshot.expires_at
            and now - self.snapshot.generated_at <= timedelta(seconds=self.max_age_seconds)
        ):
            return self.snapshot
        return None


class SignedValidatorSnapshotProvider:
    """Atomically reload a rotated snapshot without restarting the TLS worker.

    A stat is paid per request. Ed25519 verification is paid only when the
    file identity, mtime, or size changes. A malformed replacement does not
    evict the last verified unexpired snapshot, and its file identity is
    remembered so repeated hostile requests do not trigger repeat crypto.
    """

    def __init__(
        self,
        path: str,
        trusted_keys: Mapping[str, bytes],
        *,
        network: str,
        netuid: int,
        minimum_stake_rao: int,
        state: ValidatorAccessState,
        max_age_seconds: int = DEFAULT_SNAPSHOT_MAX_AGE_SECONDS,
        expected_uid: int | None = None,
    ) -> None:
        if not isinstance(path, str) or not path:
            raise ValidatorAccessError("validator snapshot path is required")
        if not trusted_keys:
            raise ValidatorAccessError("validator snapshot trusted keys are required")
        if not isinstance(network, str) or _NETWORK_RE.fullmatch(network) is None:
            raise ValidatorAccessError("validator snapshot network is invalid")
        if isinstance(netuid, bool) or not isinstance(netuid, int) or not 0 <= netuid <= MAX_NETUID:
            raise ValidatorAccessError("validator snapshot netuid is invalid")
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or not 0 < max_age_seconds <= MAX_SNAPSHOT_VALIDITY_SECONDS
        ):
            raise ValidatorAccessError("validator snapshot maximum age is invalid")
        if (
            isinstance(minimum_stake_rao, bool)
            or not isinstance(minimum_stake_rao, int)
            or not 0 <= minimum_stake_rao <= MAX_STAKE_RAO
        ):
            raise ValidatorAccessError("validator snapshot minimum stake is invalid")
        if not isinstance(state, ValidatorAccessState):
            raise ValidatorAccessError("validator snapshot requires durable access state")
        self.path = path
        self.trusted_keys = dict(trusted_keys)
        self.network = network
        self.netuid = netuid
        self.max_age_seconds = max_age_seconds
        self.minimum_stake_rao = minimum_stake_rao
        self.state = state
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self._lock = threading.Lock()
        self._observed_identity: tuple[int, int, int, int, int] | None = None
        self._cached: ValidatorAccessSnapshot | None = None

    @staticmethod
    def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def _current_if_fresh(self, now: datetime) -> ValidatorAccessSnapshot | None:
        snapshot = self._cached
        if snapshot is None:
            return None
        if (
            snapshot.generated_at <= now < snapshot.expires_at
            and now - snapshot.generated_at <= timedelta(seconds=self.max_age_seconds)
        ):
            return snapshot
        return None

    def load(self, *, now: datetime) -> ValidatorAccessSnapshot | None:
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            return None
        with self._lock:
            try:
                before = os.lstat(self.path)
            except OSError:
                return self._current_if_fresh(now)
            identity = self._identity(before)
            if identity == self._observed_identity:
                return self._current_if_fresh(now)
            # Remember even a bad replacement. The same inode state is not
            # reparsed or reverified on the next hostile request.
            self._observed_identity = identity
            try:
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or before.st_mode & 0o022
                    or before.st_uid != self.expected_uid
                    or before.st_size > MAX_SNAPSHOT_BYTES
                ):
                    raise ValidatorAccessError("validator snapshot file is not trustworthy")
                descriptor = os.open(
                    self.path,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                )
                try:
                    after = os.fstat(descriptor)
                    if self._identity(after) != identity or not stat.S_ISREG(after.st_mode):
                        raise ValidatorAccessError("validator snapshot changed during read")
                    encoded = os.read(descriptor, MAX_SNAPSHOT_BYTES + 1)
                finally:
                    os.close(descriptor)
                if len(encoded) > MAX_SNAPSHOT_BYTES:
                    raise ValidatorAccessError("validator snapshot exceeds its size limit")
                candidate = verify_validator_access_snapshot(
                    encoded,
                    self.trusted_keys,
                    network=self.network,
                    netuid=self.netuid,
                    required_minimum_stake_rao=self.minimum_stake_rao,
                    now=now,
                    max_age_seconds=self.max_age_seconds,
                )
            except (OSError, ValueError):
                return self._current_if_fresh(now)
            if not self.state.accept_snapshot(candidate):
                return self._current_if_fresh(now)
            self._cached = candidate
            return candidate


def verify_validator_access_snapshot(
    data: bytes | str,
    trusted_keys: Mapping[str, bytes],
    *,
    network: str,
    netuid: int,
    required_minimum_stake_rao: int,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_SNAPSHOT_MAX_AGE_SECONDS,
) -> ValidatorAccessSnapshot:
    """Verify one finalized, signed, short-lived validator qualification view."""

    if not isinstance(network, str) or _NETWORK_RE.fullmatch(network) is None:
        raise ValidatorAccessError("expected network is invalid")
    if isinstance(netuid, bool) or not isinstance(netuid, int) or not 0 <= netuid <= MAX_NETUID:
        raise ValidatorAccessError("expected netuid is invalid")
    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, int)
        or not 0 < max_age_seconds <= MAX_SNAPSHOT_VALIDITY_SECONDS
    ):
        raise ValidatorAccessError("snapshot maximum age is invalid")
    if (
        isinstance(required_minimum_stake_rao, bool)
        or not isinstance(required_minimum_stake_rao, int)
        or not 0 <= required_minimum_stake_rao <= MAX_STAKE_RAO
    ):
        raise ValidatorAccessError("required snapshot minimum stake is invalid")

    document = parse_registry_json(data)
    if frozenset(document) != _SNAPSHOT_KEYS:
        raise ValidatorAccessError("snapshot contains missing or unknown critical fields")
    if document["schema"] != VALIDATOR_ACCESS_SNAPSHOT_SCHEMA:
        raise ValidatorAccessError("snapshot schema is unsupported")
    if document["network"] != network or document["netuid"] != netuid:
        raise ValidatorAccessError("snapshot is bound to a different network or netuid")
    if document["block_is_finalized"] is not True:
        raise ValidatorAccessError("snapshot block is not finalized")

    block = document["block"]
    if isinstance(block, bool) or not isinstance(block, int) or not 0 < block <= MAX_SQLITE_INTEGER:
        raise ValidatorAccessError("snapshot block must be a bounded positive integer")
    block_hash = document["block_hash"]
    if not isinstance(block_hash, str) or _HASH_RE.fullmatch(block_hash) is None:
        raise ValidatorAccessError("snapshot block hash is invalid")

    key_id = document["signing_key_id"]
    if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
        raise ValidatorAccessError("snapshot signing key id is invalid")
    key = trusted_keys.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValidatorAccessError("snapshot signing key is not trusted")
    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise ValidatorAccessError("snapshot signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise ValidatorAccessError("snapshot signature algorithm is unsupported")
    signature_bytes = _decode_signature(signature["value_base64"], label="snapshot")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature_bytes, canonical_signed_bytes(document)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValidatorAccessError("snapshot signature verification failed") from exc

    generated_at = _canonical_time(document["generated_at"], "snapshot generated_at")
    expires_at = _canonical_time(document["expires_at"], "snapshot expires_at")
    if not generated_at < expires_at:
        raise ValidatorAccessError("snapshot validity window is invalid")
    if expires_at - generated_at > timedelta(seconds=MAX_SNAPSHOT_VALIDITY_SECONDS):
        raise ValidatorAccessError("snapshot validity window is too long")
    check_time = now or datetime.now(UTC)
    if check_time.tzinfo is None or check_time.utcoffset() != timedelta(0):
        raise ValidatorAccessError("snapshot verification time must be UTC")
    if generated_at > check_time + timedelta(seconds=MAX_REQUEST_FUTURE_SKEW_SECONDS):
        raise ValidatorAccessError("snapshot generation time is in the future")
    if not generated_at <= check_time < expires_at:
        raise ValidatorAccessError("snapshot is outside its validity window")
    if check_time - generated_at > timedelta(seconds=max_age_seconds):
        raise ValidatorAccessError("snapshot is too stale")

    minimum_stake_rao = document["minimum_stake_rao"]
    if (
        isinstance(minimum_stake_rao, bool)
        or not isinstance(minimum_stake_rao, int)
        or not 0 <= minimum_stake_rao <= MAX_STAKE_RAO
    ):
        raise ValidatorAccessError("snapshot minimum stake is invalid")
    if minimum_stake_rao != required_minimum_stake_rao:
        raise ValidatorAccessError("snapshot minimum stake does not match worker policy")
    validators_raw = document["validators"]
    if (
        not isinstance(validators_raw, list)
        or not validators_raw
        or len(validators_raw) > MAX_VALIDATORS
    ):
        raise ValidatorAccessError("snapshot validators must be a bounded nonempty list")

    validators: dict[str, QualifiedValidator] = {}
    observed_uids: set[int] = set()
    observed_order: list[str] = []
    for raw in validators_raw:
        if not isinstance(raw, dict) or frozenset(raw) != _VALIDATOR_KEYS:
            raise ValidatorAccessError("snapshot validator row is invalid")
        hotkey = raw["hotkey"]
        bittensor_account_id(hotkey)
        assert isinstance(hotkey, str)
        uid = raw["uid"]
        stake_rao = raw["stake_rao"]
        if isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= MAX_UID:
            raise ValidatorAccessError("snapshot validator uid is invalid")
        if (
            isinstance(stake_rao, bool)
            or not isinstance(stake_rao, int)
            or not 0 <= stake_rao <= MAX_STAKE_RAO
        ):
            raise ValidatorAccessError("snapshot validator stake is invalid")
        if raw["validator_permit"] is not True:
            raise ValidatorAccessError("snapshot must contain only validator-permit holders")
        if stake_rao < minimum_stake_rao:
            raise ValidatorAccessError("snapshot contains a validator below its stake floor")
        if hotkey in validators:
            raise ValidatorAccessError("snapshot contains a duplicate validator hotkey")
        if uid in observed_uids:
            raise ValidatorAccessError("snapshot contains a duplicate validator uid")
        observed_order.append(hotkey)
        observed_uids.add(uid)
        validators[hotkey] = QualifiedValidator(hotkey, uid, stake_rao)
    if observed_order != sorted(observed_order):
        raise ValidatorAccessError("snapshot validator rows must be sorted by hotkey")

    return ValidatorAccessSnapshot(
        network=network,
        netuid=netuid,
        block=block,
        block_hash=block_hash,
        generated_at=generated_at,
        expires_at=expires_at,
        minimum_stake_rao=minimum_stake_rao,
        validators=MappingProxyType(validators),
        signing_key_id=key_id,
        authorization_digest=_snapshot_authorization_digest(
            network=network,
            netuid=netuid,
            block=block,
            block_hash=block_hash,
            minimum_stake_rao=minimum_stake_rao,
            signing_key_id=key_id,
            validators=validators,
        ),
        digest="sha256:" + hashlib.sha256(canonical_json(document)).hexdigest(),
    )


def sign_validator_access_snapshot(
    unsigned_document: Mapping[str, object], private_key: bytes
) -> dict[str, object]:
    """Attach the operator artifact signature used by tests and capture tooling."""

    if "signature" in unsigned_document:
        raise ValidatorAccessError("unsigned snapshot must not contain signature")
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValidatorAccessError("Ed25519 private key seed must be 32 bytes")
    document = dict(unsigned_document)
    value = Ed25519PrivateKey.from_private_bytes(private_key).sign(canonical_json(document))
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(value).decode("ascii"),
    }
    return document


def _decode_signature(value: object, *, label: str) -> bytes:
    if not isinstance(value, str) or not value.isascii():
        raise ValidatorAccessError(f"{label} signature is not canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidatorAccessError(f"{label} signature is not canonical base64") from exc
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValidatorAccessError(f"{label} signature must be 64 bytes")
    return decoded


def build_validator_request_header(
    *,
    validator_hotkey: str,
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
    signer: RequestSigner,
) -> str:
    """Build one canonical signed header with an injected Bittensor signer."""

    bittensor_account_id(validator_hotkey)
    bittensor_account_id(worker_hotkey)
    if method != "POST" or path not in _PROTECTED_PATHS:
        raise ValidatorAccessError("validator request method or path is unsupported")
    if not isinstance(body, bytes):
        raise ValidatorAccessError("validator request body must be bytes")
    if not isinstance(channel_binding, ChannelBinding):
        raise ValidatorAccessError("validator request requires a channel binding")
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise ValidatorAccessError("validator request nonce must be 32 bytes")
    if not issued_at < expires_at:
        raise ValidatorAccessError("validator request validity window is invalid")
    if expires_at - issued_at > timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS):
        raise ValidatorAccessError("validator request validity window is too long")
    document: dict[str, object] = {
        "schema": VALIDATOR_REQUEST_SCHEMA,
        "validator_hotkey": validator_hotkey,
        "worker_hotkey": worker_hotkey,
        "network": network,
        "netuid": netuid,
        "method": method,
        "path": path,
        "body_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
        "channel_binding_type": channel_binding.binding_type.value,
        "channel_binding_digest_hex": channel_binding.digest.hex(),
        "nonce_hex": nonce.hex(),
        "issued_at": canonical_utc(issued_at),
        "expires_at": canonical_utc(expires_at),
    }
    signature = signer(canonical_json(document))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValidatorAccessError("validator signer must return a 64-byte signature")
    document["signature"] = {
        "algorithm": "sr25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    encoded = canonical_json(document)
    if len(encoded) > MAX_REQUEST_HEADER_BYTES:
        raise ValidatorAccessError("validator request header exceeds its size limit")
    return base64.b64encode(encoded).decode("ascii")


@dataclass(frozen=True)
class PreauthorizedValidatorRequest:
    """A verified signed envelope whose body and replay are not finalized."""

    validator_hotkey: str
    nonce_hex: str
    body_sha256: str
    issued_at: datetime
    expires_at: datetime


class ValidatorRequestAuthorizer:
    """Verify signed request identity, qualification, freshness, and replay."""

    def __init__(
        self,
        snapshot_provider: ValidatorSnapshotProvider | ValidatorAccessSnapshot,
        *,
        worker_hotkey: str,
        channel_binding: ChannelBinding,
        state: ValidatorAccessState,
        signature_verifier: SignatureVerifier | None = None,
    ) -> None:
        bittensor_account_id(worker_hotkey)
        if isinstance(snapshot_provider, ValidatorAccessSnapshot):
            snapshot_provider = StaticValidatorSnapshotProvider(snapshot_provider)
        if (
            not hasattr(snapshot_provider, "load")
            or not isinstance(getattr(snapshot_provider, "network", None), str)
            or isinstance(getattr(snapshot_provider, "netuid", None), bool)
            or not isinstance(getattr(snapshot_provider, "netuid", None), int)
        ):
            raise ValidatorAccessError("verified validator snapshot provider is required")
        if not isinstance(channel_binding, ChannelBinding):
            raise ValidatorAccessError("signed validator access requires a TLS channel binding")
        if not isinstance(state, ValidatorAccessState):
            raise ValidatorAccessError("signed validator access requires durable replay state")
        self.snapshot_provider = snapshot_provider
        self.worker_hotkey = worker_hotkey
        self.channel_binding = channel_binding
        self.state = state
        self.signature_verifier = signature_verifier or load_sr25519_verifier()

    def authorize(
        self,
        header: object,
        *,
        method: str,
        path: str,
        body: bytes,
        now: datetime | None = None,
    ) -> bool:
        """Return false for every refusal without exposing which check failed."""

        return (
            self.authorize_caller(
                header,
                method=method,
                path=path,
                body=body,
                now=now,
            )
            is not None
        )

    def authorize_caller(
        self,
        header: object,
        *,
        method: str,
        path: str,
        body: bytes,
        now: datetime | None = None,
    ) -> str | None:
        """Return the verified signer only after durable replay insertion."""

        preauthorized = self.preauthorize(
            header,
            method=method,
            path=path,
            now=now,
        )
        if preauthorized is None:
            return None
        return self.finalize(preauthorized, body=body, now=now)

    def preauthorize(
        self,
        header: object,
        *,
        method: str,
        path: str,
        now: datetime | None = None,
    ) -> PreauthorizedValidatorRequest | None:
        """Verify the signed envelope before a caller gets a body-read slot."""

        try:
            return self._preauthorize(header, method=method, path=path, now=now)
        except (ValidatorAccessError, TypeError, ValueError, OverflowError):
            return None

    def finalize(
        self,
        request: PreauthorizedValidatorRequest,
        *,
        body: bytes,
        now: datetime | None = None,
    ) -> str | None:
        """Bind the body and durably consume replay state before handling."""

        try:
            return self._finalize(request, body=body, now=now)
        except (ValidatorAccessError, TypeError, ValueError, OverflowError):
            return None

    def _preauthorize(
        self,
        header: object,
        *,
        method: str,
        path: str,
        now: datetime | None,
    ) -> PreauthorizedValidatorRequest:
        if (
            not isinstance(header, str)
            or not header.isascii()
            or not header
            or len(header) > MAX_REQUEST_HEADER_BYTES * 2
        ):
            raise ValidatorAccessError("validator request header is invalid")
        try:
            encoded = base64.b64decode(header, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValidatorAccessError("validator request header is invalid") from exc
        if len(encoded) > MAX_REQUEST_HEADER_BYTES:
            raise ValidatorAccessError("validator request header is too large")
        document = parse_registry_json(encoded)
        if encoded != canonical_json(document):
            raise ValidatorAccessError("validator request must be canonical JSON")
        if frozenset(document) != _REQUEST_KEYS:
            raise ValidatorAccessError("validator request fields are invalid")
        if document["schema"] != VALIDATOR_REQUEST_SCHEMA:
            raise ValidatorAccessError("validator request schema is unsupported")
        if method != "POST" or path not in _PROTECTED_PATHS:
            raise ValidatorAccessError("validator request target is unsupported")
        if document["method"] != method or document["path"] != path:
            raise ValidatorAccessError("validator request target does not match")
        if document["worker_hotkey"] != self.worker_hotkey:
            raise ValidatorAccessError("validator request worker does not match")
        if (
            document["network"] != self.snapshot_provider.network
            or document["netuid"] != self.snapshot_provider.netuid
        ):
            raise ValidatorAccessError("validator request subnet does not match")
        body_sha256 = document["body_sha256"]
        if not isinstance(body_sha256, str) or _DIGEST_RE.fullmatch(body_sha256) is None:
            raise ValidatorAccessError("validator request body digest is invalid")
        if document["channel_binding_type"] != self.channel_binding.binding_type.value:
            raise ValidatorAccessError("validator request channel type does not match")
        if document["channel_binding_digest_hex"] != self.channel_binding.digest.hex():
            raise ValidatorAccessError("validator request channel key does not match")

        validator_hotkey = document["validator_hotkey"]
        public_key = bittensor_account_id(validator_hotkey)
        assert isinstance(validator_hotkey, str)
        nonce_hex = document["nonce_hex"]
        if not isinstance(nonce_hex, str) or _HEX_32_RE.fullmatch(nonce_hex) is None:
            raise ValidatorAccessError("validator request nonce is invalid")
        issued_at = _canonical_time(document["issued_at"], "request issued_at")
        expires_at = _canonical_time(document["expires_at"], "request expires_at")
        if not issued_at < expires_at:
            raise ValidatorAccessError("validator request validity window is invalid")
        if expires_at - issued_at > timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS):
            raise ValidatorAccessError("validator request validity window is too long")
        check_time = now or datetime.now(UTC)
        if check_time.tzinfo is None or check_time.utcoffset() != timedelta(0):
            raise ValidatorAccessError("validator request verification time must be UTC")
        if issued_at > check_time + timedelta(seconds=MAX_REQUEST_FUTURE_SKEW_SECONDS):
            raise ValidatorAccessError("validator request was issued too far in the future")
        if not check_time < expires_at:
            raise ValidatorAccessError("validator request has expired")
        snapshot = self.snapshot_provider.load(now=check_time)
        if snapshot is None or not snapshot.qualifies(validator_hotkey, at=check_time):
            raise ValidatorAccessError("validator is not qualified")

        signature = document["signature"]
        if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
            raise ValidatorAccessError("validator request signature object is invalid")
        if signature["algorithm"] != "sr25519":
            raise ValidatorAccessError("validator request signature algorithm is unsupported")
        signature_bytes = _decode_signature(signature["value_base64"], label="request")
        if not self.signature_verifier(
            signature_bytes, canonical_signed_bytes(document), public_key
        ):
            raise ValidatorAccessError("validator request signature verification failed")

        return PreauthorizedValidatorRequest(
            validator_hotkey=validator_hotkey,
            nonce_hex=nonce_hex,
            body_sha256=body_sha256,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def _finalize(
        self,
        request: PreauthorizedValidatorRequest,
        *,
        body: bytes,
        now: datetime | None,
    ) -> str:
        if not isinstance(request, PreauthorizedValidatorRequest):
            raise ValidatorAccessError("preauthorized validator request is invalid")
        if not isinstance(body, bytes):
            raise ValidatorAccessError("validator request body must be bytes")
        body_sha256 = "sha256:" + hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(request.body_sha256, body_sha256):
            raise ValidatorAccessError("validator request body does not match")
        check_time = now or datetime.now(UTC)
        if check_time.tzinfo is None or check_time.utcoffset() != timedelta(0):
            raise ValidatorAccessError("validator request verification time must be UTC")
        if not check_time < request.expires_at:
            raise ValidatorAccessError("validator request has expired")
        snapshot = self.snapshot_provider.load(now=check_time)
        if snapshot is None or not snapshot.qualifies(request.validator_hotkey, at=check_time):
            raise ValidatorAccessError("validator is not qualified")

        if not self.state.check_and_record_request(
            request.validator_hotkey,
            request.nonce_hex,
            now=check_time,
            expires_at=request.expires_at,
        ):
            raise ValidatorAccessError("validator request was replayed or replay state failed")
        return request.validator_hotkey


def validate_public_worker_endpoint(value: object) -> str:
    """Accept one explicit HTTPS endpoint on a globally routable IP literal."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not value.isascii()
        or len(value) > 512
    ):
        raise ValidatorAccessError("fleet endpoint is invalid")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidatorAccessError("fleet endpoint port is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port is None
    ):
        raise ValidatorAccessError("fleet endpoint must be an explicit HTTPS origin")
    if port == 0:
        raise ValidatorAccessError("fleet endpoint port must be between 1 and 65535")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise ValidatorAccessError("fleet endpoint must use an IP literal") from exc
    if not is_globally_routable(address) or (
        isinstance(address, ipaddress.IPv6Address)
        and (
            address.ipv4_mapped is not None
            or address.sixtofour is not None
            or address.teredo is not None
            or address in _NAT64_WELL_KNOWN
            or address in _NAT64_LOCAL_USE
            or address in _IPV4_COMPATIBLE
        )
    ):
        raise ValidatorAccessError("fleet endpoint must use a globally routable IP")
    canonical_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    canonical = f"https://{canonical_host}:{port}"
    if value.rstrip("/") != canonical:
        raise ValidatorAccessError("fleet endpoint must use canonical IP and port spelling")
    return canonical


def validate_fleet_document(
    document: object,
    *,
    worker_hotkey: str,
    public_endpoint: str,
) -> tuple[str, ...]:
    """Validate local candidate endpoints and retain the axon as candidate one."""

    bittensor_account_id(worker_hotkey)
    primary = validate_public_worker_endpoint(public_endpoint)
    if not isinstance(document, dict) or frozenset(document) != _FLEET_KEYS:
        raise ValidatorAccessError("fleet manifest fields are invalid")
    if document["schema"] != WORKER_FLEET_SCHEMA or document["worker_hotkey"] != worker_hotkey:
        raise ValidatorAccessError("fleet manifest identity is invalid")
    raw = document["endpoints"]
    if not isinstance(raw, list) or len(raw) > MAX_FLEET_ENDPOINTS:
        raise ValidatorAccessError("fleet endpoints must be a bounded list")
    endpoints = [validate_public_worker_endpoint(value) for value in raw]
    if len(set(endpoints)) != len(endpoints):
        raise ValidatorAccessError("fleet manifest contains duplicate endpoints")
    if primary in endpoints:
        endpoints.remove(primary)
    combined = (primary, *endpoints)
    if len(combined) > MAX_FLEET_ENDPOINTS:
        raise ValidatorAccessError("fleet exceeds its maximum endpoint count")
    return combined


def singleton_fleet(*, public_endpoint: str) -> tuple[str, ...]:
    """The no-manifest compatibility case is exactly the chain axon candidate."""

    return (validate_public_worker_endpoint(public_endpoint),)


def load_fleet_manifest(
    path: str,
    *,
    worker_hotkey: str,
    public_endpoint: str,
    expected_uid: int | None = None,
) -> tuple[str, ...]:
    """Read a bounded, owner-controlled fleet file without following symlinks."""

    target = Path(path)
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ValidatorAccessError("fleet manifest must be a regular non-symlink file")
    if before.st_mode & 0o022:
        raise ValidatorAccessError("fleet manifest must not be group or world writable")
    owner = os.geteuid() if expected_uid is None else expected_uid
    if before.st_uid != owner:
        raise ValidatorAccessError("fleet manifest must be owned by the worker user")
    descriptor = os.open(
        target,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise ValidatorAccessError("fleet manifest changed during read")
        encoded = os.read(descriptor, MAX_FLEET_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(encoded) > MAX_FLEET_FILE_BYTES:
        raise ValidatorAccessError("fleet manifest exceeds its size limit")
    try:
        document = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidatorAccessError("fleet manifest is not valid JSON") from exc
    return validate_fleet_document(
        document,
        worker_hotkey=worker_hotkey,
        public_endpoint=public_endpoint,
    )


def fleet_response(worker_hotkey: str, endpoints: Sequence[str]) -> dict[str, object]:
    """Return the controlled discovery response without self-reported hardware ids."""

    bittensor_account_id(worker_hotkey)
    if not endpoints or len(endpoints) > MAX_FLEET_ENDPOINTS:
        raise ValidatorAccessError("fleet response must contain bounded candidates")
    validated = tuple(validate_public_worker_endpoint(endpoint) for endpoint in endpoints)
    if len(set(validated)) != len(validated):
        raise ValidatorAccessError("fleet response contains duplicate endpoints")
    return {
        "schema": WORKER_FLEET_SCHEMA,
        "worker_hotkey": worker_hotkey,
        "endpoints": list(validated),
    }
