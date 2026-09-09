"""Signed SN39 miner release records.

A miner release names one immutable container image digest and the launcher
that is allowed to run it. It is the miner-side equivalent of the validator's
signed runtime release, but the payload is different in kind: the validator
ships an executable tree, while a miner ships a digest that its existing
launcher pulls.

Artifact identity is enforced by three independent barriers so that a valid
release for one product can never install as another:

1. ``schema`` is specific to this record type.
2. ``product`` names the exact artifact and is checked against the caller's
   expectation, not against a value chosen by the document.
3. The trusted key map is supplied by the caller, so a miner host that holds
   only miner release keys cannot verify a validator record at all.

Any one of those is sufficient. All three are checked because the cost is a
string comparison and the failure they prevent is installing the wrong
software on a confidential host.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cathedral.policy_registry import canonical_signed_bytes

MINER_RELEASE_SCHEMA = "cathedral_sn39_miner_release_v1"
"""Schema string for this record type. Never reuse it for another payload."""

SN39_SNP_MINER_PRODUCT = "sn39-snp-miner"
"""The only product this module currently knows how to describe."""

CANONICAL_IMAGE_REPOSITORY = "ghcr.io/cathedralai/cathedral-sn39-snp-miner"
"""Images must be digest-pinned to this repository.

The launcher enforces the same prefix. Checking it here as well means a signed
record naming an attacker-controlled registry is refused before it ever
reaches the launcher, rather than relying on a single check.
"""

MAX_RELEASE_DOCUMENT_BYTES = 16 * 1024
"""A release record is a few hundred bytes. Refuse anything unbounded."""

CHANNELS = frozenset({"canary", "stable"})

_DOCUMENT_KEYS = frozenset(
    {
        "schema",
        "product",
        "channel",
        "sequence",
        "issued_unix",
        "expires_unix",
        "release",
        "signing_key_id",
        "signature",
    }
)
_RELEASE_KEYS = frozenset({"version", "image", "runtime_contract", "launcher_sha256"})
_PROMOTED_KEYS = frozenset({"sequence", "signed_sha256"})
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})

_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[0-9a-zA-Z][0-9a-zA-Z._-]{0,63}$")
_CONTRACT_RE = re.compile(r"^[0-9a-zA-Z][0-9a-zA-Z._/-]{0,127}$")

# A sequence is a small counter, not a timestamp. Bound it so a hostile record
# cannot push the persisted floor to a value no honest release can exceed.
MAX_SEQUENCE = 1 << 31
# Unix seconds, bounded well past any plausible release and short of overflow.
MAX_UNIX_TIME = 1 << 34


class MinerReleaseError(ValueError):
    """One signed miner release record was refused."""


@dataclass(frozen=True)
class MinerRelease:
    """One verified release record.

    ``signed_sha256`` is the digest of the exact bytes the signature covers. It
    is what detects equivocation: two records at the same sequence that differ
    in any signed field produce different values here.
    """

    product: str
    channel: str
    sequence: int
    issued_unix: int
    expires_unix: int
    version: str
    image: str
    image_digest: str
    runtime_contract: str
    launcher_sha256: str
    signing_key_id: str
    signed_sha256: str
    promoted_canary: tuple[int, str] | None

    def is_expired(self, *, now_unix: int) -> bool:
        return now_unix >= self.expires_unix


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate object keys.

    ``json.loads`` keeps the last duplicate silently. A signer and a verifier
    that disagree about which one wins is a signature-bypass primitive, so the
    document is refused instead.
    """

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MinerReleaseError("release document repeats an object key")
        result[key] = value
    return result


def _bounded_int(value: object, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MinerReleaseError(f"release {name} must be an integer")
    if not 0 < value <= maximum:
        raise MinerReleaseError(f"release {name} is out of range")
    return value


def _matched_string(value: object, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise MinerReleaseError(f"release {name} is invalid")
    return value


def parse_miner_release(
    raw: bytes,
    *,
    trusted_keys: Mapping[str, bytes],
    expected_product: str = SN39_SNP_MINER_PRODUCT,
    expected_image_repository: str = CANONICAL_IMAGE_REPOSITORY,
) -> MinerRelease:
    """Verify one signed release record and return it.

    ``trusted_keys`` maps a key id to a 32-byte Ed25519 public key. The caller
    supplies it, so a host that holds only miner keys cannot verify a record
    signed for a different product even if every other field were forged.
    """

    if not isinstance(raw, (bytes, bytearray)):
        raise MinerReleaseError("release document must be bytes")
    if not raw or len(raw) > MAX_RELEASE_DOCUMENT_BYTES:
        raise MinerReleaseError("release document size is out of range")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MinerReleaseError("release document is not strict JSON") from exc
    if not isinstance(document, dict) or frozenset(document) != _DOCUMENT_KEYS:
        raise MinerReleaseError("release document fields are invalid")

    # Resolve the key before verifying, because verification needs it. Nothing
    # else about the document is trusted until the signature checks out.
    key_id = _matched_string(document["signing_key_id"], "signing key id", _KEY_ID_RE)
    key = trusted_keys.get(key_id)
    if not isinstance(key, bytes) or len(key) != 32:
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
    if (
        len(signature_bytes) != 64
        or base64.b64encode(signature_bytes).decode("ascii") != encoded
    ):
        raise MinerReleaseError("release signature must be 64 bytes")

    signed_bytes = canonical_signed_bytes(document)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, signed_bytes)
    except (InvalidSignature, ValueError) as exc:
        raise MinerReleaseError("release signature verification failed") from exc

    # Identity and binding are checked only after the signature, so an unsigned
    # document can never produce a binding-specific error that tells an
    # attacker which product or channel a host is running.
    if document["schema"] != MINER_RELEASE_SCHEMA:
        raise MinerReleaseError("release schema is unsupported")
    product = document["product"]
    if not isinstance(product, str) or product != expected_product:
        raise MinerReleaseError("release names a different product")
    channel = document["channel"]
    if not isinstance(channel, str) or channel not in CHANNELS:
        raise MinerReleaseError("release channel is unsupported")

    sequence = _bounded_int(document["sequence"], "sequence", maximum=MAX_SEQUENCE)
    issued_unix = _bounded_int(document["issued_unix"], "issued_unix", maximum=MAX_UNIX_TIME)
    expires_unix = _bounded_int(document["expires_unix"], "expires_unix", maximum=MAX_UNIX_TIME)
    if expires_unix <= issued_unix:
        raise MinerReleaseError("release expiry does not follow its issue time")

    release = document["release"]
    if not isinstance(release, dict):
        raise MinerReleaseError("release body is invalid")
    required = (
        (_RELEASE_KEYS | {"promoted_canary"}) if channel == "stable" else _RELEASE_KEYS
    )
    if frozenset(release) != required:
        raise MinerReleaseError("release body fields are invalid")

    version = _matched_string(release["version"], "version", _VERSION_RE)
    runtime_contract = _matched_string(
        release["runtime_contract"], "runtime contract", _CONTRACT_RE
    )
    launcher_sha256 = _matched_string(
        release["launcher_sha256"], "launcher digest", _SHA256_RE
    )

    image = release["image"]
    if not isinstance(image, str):
        raise MinerReleaseError("release image is invalid")
    prefix = expected_image_repository + "@sha256:"
    if not image.startswith(prefix):
        raise MinerReleaseError("release image is not pinned to the canonical repository")
    image_digest = image[len(prefix) :]
    if _SHA256_RE.fullmatch(image_digest) is None:
        raise MinerReleaseError("release image must use one immutable lowercase sha256 digest")

    promoted: tuple[int, str] | None = None
    if channel == "stable":
        promoted_value = release["promoted_canary"]
        if not isinstance(promoted_value, dict) or frozenset(promoted_value) != _PROMOTED_KEYS:
            raise MinerReleaseError("stable release must name the canary it came from")
        promoted = (
            _bounded_int(promoted_value["sequence"], "promoted sequence", maximum=MAX_SEQUENCE),
            _matched_string(promoted_value["signed_sha256"], "promoted digest", _SHA256_RE),
        )

    return MinerRelease(
        product=product,
        channel=channel,
        sequence=sequence,
        issued_unix=issued_unix,
        expires_unix=expires_unix,
        version=version,
        image=image,
        image_digest=image_digest,
        runtime_contract=runtime_contract,
        launcher_sha256=launcher_sha256,
        signing_key_id=key_id,
        signed_sha256=hashlib.sha256(signed_bytes).hexdigest(),
        promoted_canary=promoted,
    )


def enforce_monotonic_release(
    previous: Mapping[str, object] | None, candidate: MinerRelease
) -> None:
    """Refuse a record that rolls the channel back or equivocates.

    ``previous`` is the persisted floor for this channel: a mapping with
    ``sequence`` and ``signed_sha256``. A record at a lower sequence is a
    rollback. A record at the same sequence with different signed bytes is two
    different releases claiming the same position, which means the signing key
    is being misused, so it is refused rather than preferred either way.
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
        if previous_digest != candidate.signed_sha256:
            raise MinerReleaseError("release metadata equivocates at an existing sequence")


__all__ = [
    "CANONICAL_IMAGE_REPOSITORY",
    "CHANNELS",
    "MINER_RELEASE_SCHEMA",
    "MAX_RELEASE_DOCUMENT_BYTES",
    "MinerRelease",
    "MinerReleaseError",
    "SN39_SNP_MINER_PRODUCT",
    "enforce_monotonic_release",
    "parse_miner_release",
]
