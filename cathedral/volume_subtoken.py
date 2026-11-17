"""Per-mount storage sub-token for a synced volume (AB#395, phase 1).

The sealed guest never holds the storage account's keys. The registry signs one
sub-token per mount; the storage gateway in front of the bucket calls authorize()
on every request. A sub-token is limited to:

- one key prefix (the volume's own, always ending in "/"),
- one source address (the host the guest boots on),
- one expiry, never later than the lease it was issued from,
- read, write and list. Delete is not an operation here at all, so a stolen
  token or a compromised guest cannot erase history (restic prune runs from the
  control plane with its own credentials).

The token is signed with the registry key over a fixed label, so it is never a
valid lease, commit or head (volume_chain.py) and the reverse.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import time
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.volume_chain import LEASE_SCHEMA, VolumeRefused, _public_key, b64, canonical, public_b64

SUBTOKEN_SCHEMA = "cathedral_volume_subtoken_v1"
LABEL = b"cathedral.volume-subtoken.v1\n"
ALLOWED_OPS = ("get", "put", "list")
MAX_TTL_SECONDS = 3600
MAX_PREFIX_LENGTH = 512


def _check_prefix(prefix) -> str:
    if (not isinstance(prefix, str) or not prefix.endswith("/") or prefix.startswith("/")
            or len(prefix) > MAX_PREFIX_LENGTH or not prefix.isprintable()
            or any(part in ("", ".", "..") for part in prefix[:-1].split("/"))):
        raise VolumeRefused("bad_prefix")
    return prefix


def _check_ip(value) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise VolumeRefused("bad_source_ip") from None


def issue(registry_key: Ed25519PrivateKey, lease_doc: dict, *, prefix: str, source_ip: str,
          ttl_seconds: int, ops: tuple[str, ...] = ALLOWED_OPS,
          now: Callable[[], float] = time.time) -> dict:
    """Sign a sub-token for the lease's volume. The caller has already checked the lease is live."""
    lease = lease_doc["statement"]
    if lease.get("schema") != LEASE_SCHEMA:
        raise VolumeRefused("wrong_schema")
    if not ops or any(op not in ALLOWED_OPS for op in ops):
        raise VolumeRefused("bad_ops")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise VolumeRefused("bad_ttl")
    issued_at = int(now())
    if issued_at >= lease["expires_at"]:
        raise VolumeRefused("lease_expired")
    statement = {
        "schema": SUBTOKEN_SCHEMA,
        "volume_id": lease["volume_id"],
        "lease_id": lease["lease_id"],
        "prefix": _check_prefix(prefix),
        "source_ip": _check_ip(source_ip),
        "ops": sorted(set(ops)),
        "issued_at": issued_at,
        "expires_at": min(issued_at + min(ttl_seconds, MAX_TTL_SECONDS), lease["expires_at"]),
    }
    return {
        "statement": statement,
        "signer_ed25519_b64": public_b64(registry_key),
        "signature_b64": b64(registry_key.sign(LABEL + canonical(statement))),
    }


def authorize(token: dict, registry_public_b64: str, *, op: str, key: str, source_ip: str,
              now: Callable[[], float] = time.time) -> dict:
    """Return the token statement when this request is allowed; raise VolumeRefused otherwise."""
    if not isinstance(token, dict) or not isinstance(token.get("statement"), dict):
        raise VolumeRefused("malformed")
    statement = token["statement"]
    if statement.get("schema") != SUBTOKEN_SCHEMA:
        raise VolumeRefused("wrong_schema")
    if token.get("signer_ed25519_b64") != registry_public_b64:
        raise VolumeRefused("bad_signature")
    try:
        signature = base64.b64decode(token.get("signature_b64", ""), validate=True)
        _public_key(registry_public_b64).verify(signature, LABEL + canonical(statement))
    except (TypeError, ValueError, binascii.Error, InvalidSignature, VolumeRefused):
        raise VolumeRefused("bad_signature") from None
    if now() >= statement["expires_at"]:
        raise VolumeRefused("token_expired")
    if op not in ALLOWED_OPS or op not in statement["ops"]:
        raise VolumeRefused("op_not_allowed")
    if _check_ip(source_ip) != statement["source_ip"]:
        raise VolumeRefused("wrong_source_ip")
    if not isinstance(key, str) or not key.startswith(statement["prefix"]) or ".." in key.split("/"):
        raise VolumeRefused("outside_prefix")
    return statement
