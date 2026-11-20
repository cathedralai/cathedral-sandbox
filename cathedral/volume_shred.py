"""Request handler for the sealed volume shred route (AB#825). Not mounted anywhere yet.

A registry host will mount it at POST /v1/sealed-volumes/{volume_id}/shred once a
persistent registry and its host exist (AB#395). It is framework free: the host
authenticates the caller, parses the JSON body and passes both in, then sends the
returned (status, body) as is. The host also passes `enabled`, so the route answers
404 until it is switched on; this module reads no env var or config.

Request body, exact fields:

- schema: cathedral_volume_shred_request_v1
- key_id: the volume's key id (volume_log.KEY_ID_RE)
- confirm_volume_id: must equal the path volume_id, so a wrong path cannot destroy a key

200: {"status": "shredded", "receipt": <cathedral_volume_shred_receipt_v1>}, the same on
every resend. Refusal: {"status": "refused", "code": ..., "retryable": ...}. A refusal
never carries the key service's error text.

The registry owns idempotency and the owner check (VolumeRegistry.shred); this handler
adds no state. Unknown volume and wrong owner give the same 404 body, so the route is
no oracle for which volume ids exist.
"""

from __future__ import annotations

from collections.abc import Callable

from cathedral import volume_log
from cathedral.volume_chain import DESTROY_KEY_TIMEOUT_SECONDS, VolumeRefused, VolumeRegistry

REQUEST_SCHEMA = "cathedral_volume_shred_request_v1"
REQUEST_FIELDS = frozenset({"schema", "key_id", "confirm_volume_id"})

# Registry codes the owner may see as they are, with their HTTP status and retryable flag.
_REGISTRY_CODES: dict[str, tuple[int, bool]] = {
    "nothing_to_shred": (409, False),
    "key_not_bound": (409, False),
    "shred_key_mismatch": (409, False),
    "key_bound_elsewhere": (409, False),
    "shred_in_progress": (409, True),
    "volume_shredded": (410, False),
    "key_not_destroyed": (502, True),
    "key_service_timeout": (504, True),
}


def _refused(status: int, code: str, retryable: bool) -> tuple[int, dict]:
    return status, {"status": "refused", "code": code, "retryable": retryable}


def _valid_body(volume_id: object, body: object) -> str | None:
    """The request's key_id, or None when the path or body is not exactly a valid request."""
    if not isinstance(volume_id, str) or not volume_log.VOLUME_ID_RE.fullmatch(volume_id):
        return None
    if not isinstance(body, dict) or set(body) != REQUEST_FIELDS:
        return None
    if body["schema"] != REQUEST_SCHEMA:
        return None
    key_id = body["key_id"]
    if not isinstance(key_id, str) or not volume_log.KEY_ID_RE.fullmatch(key_id):
        return None
    if body["confirm_volume_id"] != volume_id:
        return None
    return key_id


def handle_shred(registry: VolumeRegistry, *, enabled: bool, caller_owner: str | None, volume_id: str,
                 body: object, destroy_key: Callable[[str, str], object],
                 timeout_seconds: float = DESTROY_KEY_TIMEOUT_SECONDS) -> tuple[int, dict]:
    """Answer one shred request. Checks run in order: enabled, caller, body, registry."""
    if enabled is not True:
        return _refused(404, "not_found", False)
    if not isinstance(caller_owner, str) or not caller_owner:
        return _refused(401, "unauthenticated", False)
    key_id = _valid_body(volume_id, body)
    if key_id is None:
        return _refused(400, "bad_request", False)
    try:
        receipt = registry.shred(volume_id, owner=caller_owner, key_id=key_id, destroy_key=destroy_key,
                                 timeout_seconds=timeout_seconds)
    except VolumeRefused as refusal:
        code = refusal.code
        if code in ("volume_unknown", "not_owner"):
            return _refused(404, "volume_not_found", False)
        if code in ("bad_key_id", "bad_volume_id"):
            return _refused(400, "bad_request", False)
        if code in _REGISTRY_CODES:
            status, retryable = _REGISTRY_CODES[code]
            return _refused(status, code, retryable)
        return _refused(500, "internal", True)
    return 200, {"status": "shredded", "receipt": receipt}
