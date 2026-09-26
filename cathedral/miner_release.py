"""Signed miner release records.

A record names one release of one miner product, for one network and netuid,
on one channel:

- the container image, by digest, in a Cathedral repository;
- the host bundle, by archive and tree digest. The bundle carries the updater's
  own code, the product launcher, a drop-in for the miner's systemd unit, and
  the trust root the next updater will use (see ``miner_bundle``);
- the runtime contract the image and launcher must both declare;
- the durable-state schema the image writes, which decides whether a failed
  activation may roll back automatically (see ``miner_updater``).

The record is Ed25519 over canonical JSON. Parsing is strict: duplicate keys
and unknown fields are refused, and the signature is checked before any other
field is read, so an unsigned document cannot learn which product, network or
channel a host follows.

Freshness matches the validator's updater: a lifetime of at most 14 days, a
not-yet-valid refusal with 300 seconds of clock skew, and expiry. The caller
also enforces a monotonic sequence floor per channel.

This module imports only the standard library and ``cryptography``, because it
ships inside the host bundle and runs under the host's system Python.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MINER_RELEASE_SCHEMA = "cathedral_miner_release_v1"
"""Schema string for this record type. Never reuse it for another payload."""

TRUST_ROOT_SCHEMA = "cathedral_miner_release_keys_v1"
"""Schema string for the file that lists the release public keys."""

MAX_RELEASE_DOCUMENT_BYTES = 16 * 1024
MAX_TRUST_ROOT_BYTES = 64 * 1024

MAX_RELEASE_LIFETIME_SECONDS = 14 * 24 * 60 * 60
"""The validator's ceiling (cathedral-validator ``updater.py:58``)."""

NOT_BEFORE_SKEW_SECONDS = 300
"""The validator's skew allowance (cathedral-validator ``updater.py:270``)."""

CHANNELS = ("canary", "stable")

IMAGE_REGISTRY_PREFIX = "ghcr.io/cathedralai/"
"""Every released image lives under this prefix.

The bundle's launcher names the exact repository, and the updater checks the
record's image against it. This prefix is a second, compiled-in barrier, so a
signed record naming a registry outside Cathedral is refused by the parser.
"""

MAX_SEQUENCE = 1 << 31
MAX_UNIX_TIME = 1 << 34
MAX_NETUID = 65535
MAX_STATE_SCHEMA = 1_000_000

_DOCUMENT_KEYS = frozenset(
    {
        "schema",
        "product",
        "network",
        "netuid",
        "channel",
        "sequence",
        "issued_unix",
        "expires_unix",
        "release",
        "signing_key_id",
        "signature",
    }
)
_RELEASE_KEYS = frozenset({"version", "image", "runtime_contract", "state_schema", "bundle"})
_BUNDLE_KEYS = frozenset({"url", "archive_sha256", "tree_sha256"})
_PROMOTED_KEYS = frozenset({"sequence", "signed_sha256", "image", "tree_sha256"})
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_KEY_ENTRY_KEYS = frozenset({"public_key_hex", "channels"})

_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[0-9a-zA-Z][0-9a-zA-Z._-]{0,63}$")
_CONTRACT_RE = re.compile(r"^[0-9a-zA-Z][0-9a-zA-Z._/-]{0,127}$")
_PRODUCT_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_NETWORK_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_REPOSITORY_RE = re.compile(r"^ghcr\.io/cathedralai/[a-z0-9][a-z0-9._-]{0,127}$")


class MinerReleaseError(ValueError):
    """One signed miner release record, or the trust root, was refused."""


@dataclass(frozen=True)
class TrustedKey:
    """One release public key and the channels it may sign."""

    public_key: bytes
    channels: frozenset[str]

    @property
    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.public_key).hexdigest()


@dataclass(frozen=True)
class BundleRef:
    url: str
    archive_sha256: str
    tree_sha256: str


@dataclass(frozen=True)
class PromotedCanary:
    sequence: int
    signed_sha256: str
    image: str
    tree_sha256: str


@dataclass(frozen=True)
class MinerRelease:
    """One verified release record.

    ``signed_sha256`` is the digest of the exact bytes the signature covers. It
    detects equivocation: two records at one sequence that differ in any
    signed field have different values here.
    """

    product: str
    network: str
    netuid: int
    channel: str
    sequence: int
    issued_unix: int
    expires_unix: int
    version: str
    image: str
    image_repository: str
    image_digest: str
    runtime_contract: str
    state_schema: int
    bundle: BundleRef
    signing_key_id: str
    signed_sha256: str
    promoted_canary: PromotedCanary | None

    def summary(self) -> dict[str, object]:
        """The fields the updater persists and ``status`` prints."""

        return {
            "sequence": self.sequence,
            "signed_sha256": self.signed_sha256,
            "version": self.version,
            "image": self.image,
            "runtime_contract": self.runtime_contract,
            "state_schema": self.state_schema,
            "tree_sha256": self.bundle.tree_sha256,
            "issued_unix": self.issued_unix,
            "expires_unix": self.expires_unix,
        }


def canonical_json(value: object) -> bytes:
    """The exact bytes a signature covers.

    Byte-identical to ``cathedral.policy_registry.canonical_json``. It is
    repeated here so this module has no dependency outside the bundle.
    """

    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise MinerReleaseError("document contains a non-canonical value") from exc


def signed_bytes(document: Mapping[str, object]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    return canonical_json(unsigned)


def strict_json(raw: bytes, *, label: str) -> Any:
    """Parse JSON, refusing duplicate keys.

    ``json.loads`` keeps the last duplicate silently. A signer and a verifier
    that disagree about which one wins is a signature-bypass primitive.
    """

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MinerReleaseError(f"{label} repeats an object key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise MinerReleaseError(f"{label} is not strict JSON") from exc


def _bounded_int(value: object, name: str, *, maximum: int, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MinerReleaseError(f"release {name} must be an integer")
    if not minimum <= value <= maximum:
        raise MinerReleaseError(f"release {name} is out of range")
    return value


def _matched_string(value: object, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise MinerReleaseError(f"release {name} is invalid")
    return value


def https_url(value: object, name: str) -> str:
    if not isinstance(value, str) or not 8 < len(value) <= 2048:
        raise MinerReleaseError(f"{name} is invalid")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise MinerReleaseError(f"{name} must be an https URL without credentials")
    return value


def split_image(image: object) -> tuple[str, str]:
    """Return (repository, digest) for a digest-pinned Cathedral image."""

    if not isinstance(image, str) or "@sha256:" not in image:
        raise MinerReleaseError("release image must be pinned by one sha256 digest")
    repository, _, digest = image.partition("@sha256:")
    if _REPOSITORY_RE.fullmatch(repository) is None:
        raise MinerReleaseError("release image is not in a Cathedral repository")
    if _SHA256_RE.fullmatch(digest) is None:
        raise MinerReleaseError("release image must use one immutable lowercase sha256 digest")
    return repository, digest


def check_validity_window(issued_unix: int, expires_unix: int, *, now_unix: int) -> None:
    """Refuse a record outside its validity window, or with too long a window.

    Shared by the parser and the offline signer, so neither can produce or
    accept what the other refuses.
    """

    if expires_unix <= issued_unix:
        raise MinerReleaseError("release expiry does not follow its issue time")
    if expires_unix - issued_unix > MAX_RELEASE_LIFETIME_SECONDS:
        raise MinerReleaseError("release lifetime exceeds 14 days")
    if now_unix < issued_unix - NOT_BEFORE_SKEW_SECONDS:
        raise MinerReleaseError("release is not valid yet")
    if now_unix >= expires_unix:
        raise MinerReleaseError("release has expired")


def load_trust_root(raw: bytes) -> dict[str, TrustedKey]:
    """Parse the release public keys and the channels each may sign.

    Canary and stable are separate roles. A key listed only for canary cannot
    sign a record a stable host accepts, so a canary key compromise reaches
    canary hosts only.
    """

    if not isinstance(raw, (bytes, bytearray)) or not raw or len(raw) > MAX_TRUST_ROOT_BYTES:
        raise MinerReleaseError("trust root size is out of range")
    document = strict_json(bytes(raw), label="trust root")
    if not isinstance(document, dict) or set(document) != {"schema", "keys"}:
        raise MinerReleaseError("trust root fields are invalid")
    if document["schema"] != TRUST_ROOT_SCHEMA:
        raise MinerReleaseError("trust root schema is unsupported")
    keys = document["keys"]
    if not isinstance(keys, dict) or not keys:
        raise MinerReleaseError("trust root contains no keys")
    resolved: dict[str, TrustedKey] = {}
    for key_id, entry in keys.items():
        _matched_string(key_id, "trust root key id", _KEY_ID_RE)
        if not isinstance(entry, dict) or set(entry) != _KEY_ENTRY_KEYS:
            raise MinerReleaseError("trust root key entry is malformed")
        public_hex = entry["public_key_hex"]
        if not isinstance(public_hex, str) or _SHA256_RE.fullmatch(public_hex) is None:
            raise MinerReleaseError("trust root public key must be 32 bytes of lowercase hex")
        channels = entry["channels"]
        if (
            not isinstance(channels, list)
            or not channels
            or len(set(channels)) != len(channels)
            or any(channel not in CHANNELS for channel in channels)
        ):
            raise MinerReleaseError("trust root key channels are invalid")
        public_key = bytes.fromhex(public_hex)
        try:
            Ed25519PublicKey.from_public_bytes(public_key)
        except ValueError as exc:
            raise MinerReleaseError("trust root public key is not Ed25519") from exc
        resolved[key_id] = TrustedKey(public_key=public_key, channels=frozenset(channels))
    return resolved


def parse_miner_release(
    raw: bytes,
    *,
    trusted_keys: Mapping[str, TrustedKey],
    expected_product: str,
    expected_network: str,
    expected_netuid: int,
    expected_channel: str,
    now_unix: int,
) -> MinerRelease:
    """Verify one signed release record and return it.

    Every ``expected_*`` value comes from the host's deploy config, never from
    the document, so a record for another product, network, netuid or channel
    fails on identity.
    """

    if not isinstance(raw, (bytes, bytearray)):
        raise MinerReleaseError("release document must be bytes")
    if not raw or len(raw) > MAX_RELEASE_DOCUMENT_BYTES:
        raise MinerReleaseError("release document size is out of range")
    document = strict_json(bytes(raw), label="release document")
    if not isinstance(document, dict) or frozenset(document) != _DOCUMENT_KEYS:
        raise MinerReleaseError("release document fields are invalid")

    # Resolve the key before verifying, because verification needs it. Nothing
    # else about the document is trusted until the signature checks out.
    key_id = _matched_string(document["signing_key_id"], "signing key id", _KEY_ID_RE)
    trusted = trusted_keys.get(key_id)
    if not isinstance(trusted, TrustedKey) or len(trusted.public_key) != 32:
        raise MinerReleaseError("release signing key is not trusted")

    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise MinerReleaseError("release signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise MinerReleaseError("release signature algorithm is unsupported")
    encoded = signature["value_base64"]
    if not isinstance(encoded, str):
        raise MinerReleaseError("release signature value is invalid")
    try:
        signature_bytes = base64.b64decode(encoded, validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise MinerReleaseError("release signature is not canonical base64") from exc
    if len(signature_bytes) != 64 or base64.b64encode(signature_bytes).decode("ascii") != encoded:
        raise MinerReleaseError("release signature must be 64 bytes")

    payload = signed_bytes(document)
    try:
        Ed25519PublicKey.from_public_bytes(trusted.public_key).verify(signature_bytes, payload)
    except (InvalidSignature, ValueError) as exc:
        raise MinerReleaseError("release signature verification failed") from exc

    # Identity and binding, only after the signature.
    if document["schema"] != MINER_RELEASE_SCHEMA:
        raise MinerReleaseError("release schema is unsupported")
    product = _matched_string(document["product"], "product", _PRODUCT_RE)
    if product != expected_product:
        raise MinerReleaseError("release names a different product")
    network = _matched_string(document["network"], "network", _NETWORK_RE)
    if network != expected_network:
        raise MinerReleaseError("release names a different network")
    netuid = _bounded_int(document["netuid"], "netuid", maximum=MAX_NETUID, minimum=0)
    if netuid != expected_netuid:
        raise MinerReleaseError("release names a different netuid")
    channel = document["channel"]
    if not isinstance(channel, str) or channel not in CHANNELS:
        raise MinerReleaseError("release channel is unsupported")
    if channel != expected_channel:
        raise MinerReleaseError("release is for a different channel")
    if channel not in trusted.channels:
        raise MinerReleaseError(f"release signing key may not sign the {channel} channel")

    sequence = _bounded_int(document["sequence"], "sequence", maximum=MAX_SEQUENCE)
    issued_unix = _bounded_int(document["issued_unix"], "issued_unix", maximum=MAX_UNIX_TIME)
    expires_unix = _bounded_int(document["expires_unix"], "expires_unix", maximum=MAX_UNIX_TIME)
    check_validity_window(issued_unix, expires_unix, now_unix=now_unix)

    release = document["release"]
    if not isinstance(release, dict):
        raise MinerReleaseError("release body is invalid")
    required = (_RELEASE_KEYS | {"promoted_canary"}) if channel == "stable" else _RELEASE_KEYS
    if frozenset(release) != required:
        raise MinerReleaseError("release body fields are invalid")

    version = _matched_string(release["version"], "version", _VERSION_RE)
    runtime_contract = _matched_string(release["runtime_contract"], "runtime contract", _CONTRACT_RE)
    state_schema = _bounded_int(release["state_schema"], "state schema", maximum=MAX_STATE_SCHEMA)
    image = release["image"]
    repository, image_digest = split_image(image)

    bundle_value = release["bundle"]
    if not isinstance(bundle_value, dict) or frozenset(bundle_value) != _BUNDLE_KEYS:
        raise MinerReleaseError("release bundle fields are invalid")
    bundle = BundleRef(
        url=https_url(bundle_value["url"], "release bundle URL"),
        archive_sha256=_matched_string(bundle_value["archive_sha256"], "archive digest", _SHA256_RE),
        tree_sha256=_matched_string(bundle_value["tree_sha256"], "tree digest", _SHA256_RE),
    )

    promoted: PromotedCanary | None = None
    if channel == "stable":
        value = release["promoted_canary"]
        if not isinstance(value, dict) or frozenset(value) != _PROMOTED_KEYS:
            raise MinerReleaseError("stable release must name the canary it came from")
        promoted = PromotedCanary(
            sequence=_bounded_int(value["sequence"], "promoted sequence", maximum=MAX_SEQUENCE),
            signed_sha256=_matched_string(value["signed_sha256"], "promoted digest", _SHA256_RE),
            image=str(value["image"]),
            tree_sha256=_matched_string(value["tree_sha256"], "promoted tree", _SHA256_RE),
        )
        # A stable record promotes exactly what the canary ran. Naming the
        # canary is only meaningful if the artifacts are the canary's own.
        if promoted.image != image or promoted.tree_sha256 != bundle.tree_sha256:
            raise MinerReleaseError("stable release is not the exact promoted canary")

    return MinerRelease(
        product=product,
        network=network,
        netuid=netuid,
        channel=channel,
        sequence=sequence,
        issued_unix=issued_unix,
        expires_unix=expires_unix,
        version=version,
        image=image,
        image_repository=repository,
        image_digest=image_digest,
        runtime_contract=runtime_contract,
        state_schema=state_schema,
        bundle=bundle,
        signing_key_id=key_id,
        signed_sha256=hashlib.sha256(payload).hexdigest(),
        promoted_canary=promoted,
    )


def enforce_monotonic_release(
    previous: Mapping[str, object] | None, candidate: MinerRelease
) -> None:
    """Refuse a record that rolls the channel back or equivocates.

    ``previous`` is the persisted floor for this channel: a mapping with
    ``sequence`` and ``signed_sha256``. A record at a lower sequence is a
    rollback. A record at the same sequence with different signed bytes means
    the signing key is being misused, so it is refused either way. A floor
    seeded at bootstrap has ``signed_sha256`` None and must be exceeded.
    """

    if previous is None:
        return
    previous_sequence = previous.get("sequence")
    if isinstance(previous_sequence, bool) or not isinstance(previous_sequence, int):
        raise MinerReleaseError("persisted release floor is malformed")
    if candidate.sequence < previous_sequence:
        raise MinerReleaseError("release metadata rolls back the local channel")
    if candidate.sequence == previous_sequence:
        previous_digest = previous.get("signed_sha256")
        if previous_digest is None:
            raise MinerReleaseError("release metadata does not pass the bootstrap floor")
        if previous_digest != candidate.signed_sha256:
            raise MinerReleaseError("release metadata equivocates at an existing sequence")


__all__ = [
    "CHANNELS",
    "IMAGE_REGISTRY_PREFIX",
    "MAX_RELEASE_DOCUMENT_BYTES",
    "MAX_RELEASE_LIFETIME_SECONDS",
    "MINER_RELEASE_SCHEMA",
    "NOT_BEFORE_SKEW_SECONDS",
    "TRUST_ROOT_SCHEMA",
    "BundleRef",
    "MinerRelease",
    "MinerReleaseError",
    "PromotedCanary",
    "TrustedKey",
    "canonical_json",
    "check_validity_window",
    "enforce_monotonic_release",
    "https_url",
    "load_trust_root",
    "parse_miner_release",
    "signed_bytes",
    "split_image",
    "strict_json",
]
