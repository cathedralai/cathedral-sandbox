"""Private, content-addressed evidence captures with a sidecar metadata record.

The capture file itself stays content-addressed (``<sha256>.json``) so replays
can locate identical evidence and repeated writes are idempotent. Context that
is not part of the evidence (when it was captured, which admission nonce and
box it belonged to) lives in ``<sha256>.meta.json`` next to it, so adding that
context never changes the capture's name or bytes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path

CAPTURE_METADATA_SCHEMA = "cathedral_capture_metadata_v1"
MAX_ADMISSION_NONCE_BYTES = 1024
MAX_BOX_ID_CHARS = 256
_LOG = logging.getLogger(__name__)


def _metadata_document(
    capture_name: str,
    capture_sha256: str,
    *,
    admission_nonce: bytes | None,
    box_id: str | None,
    captured_at: float | None,
) -> dict[str, object]:
    # Context only: a malformed value is dropped with a warning, never raised, so
    # it can neither reject a verified quote nor skip the capture itself.
    if admission_nonce is not None and (
        not isinstance(admission_nonce, bytes)
        or not 0 < len(admission_nonce) <= MAX_ADMISSION_NONCE_BYTES
    ):
        _LOG.warning("capture metadata: dropping a malformed admission nonce")
        admission_nonce = None
    if box_id is not None and (
        not isinstance(box_id, str)
        or not 0 < len(box_id) <= MAX_BOX_ID_CHARS
        or not box_id.isprintable()
    ):
        _LOG.warning("capture metadata: dropping a malformed box ID")
        box_id = None
    moment = time.time() if captured_at is None else float(captured_at)
    return {
        "schema": CAPTURE_METADATA_SCHEMA,
        "capture": capture_name,
        "capture_sha256": capture_sha256,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(moment)),
        "admission_nonce_hex": None if admission_nonce is None else admission_nonce.hex(),
        "box_id": box_id,
    }


def _write_private(directory: Path, prefix: str, encoded: bytes) -> str:
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=directory)
    with os.fdopen(fd, "wb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    return temporary


def write_private_capture(
    document: dict[str, object],
    directory: Path,
    *,
    temporary_prefix: str,
    admission_nonce: bytes | None = None,
    box_id: str | None = None,
    captured_at: float | None = None,
) -> Path:
    """Write ``document`` as ``<sha256>.json`` plus a ``.meta.json`` sidecar.

    Both files are mode 0600 in a 0700 directory and appear atomically. The
    sidecar records the first capture of those exact bytes; a later identical
    capture leaves the original record in place. Raises ``OSError`` for write
    failures and ``ValueError`` for invalid metadata, before anything is written.
    """
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(encoded).hexdigest()
    destination = directory / (digest + ".json")
    metadata = _metadata_document(
        destination.name,
        digest,
        admission_nonce=admission_nonce,
        box_id=box_id,
        captured_at=captured_at,
    )
    metadata_encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = _write_private(directory, temporary_prefix, encoded)
    try:
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    temporary = _write_private(directory, temporary_prefix + "meta-", metadata_encoded)
    try:
        os.link(temporary, directory / (digest + ".meta.json"))
    except FileExistsError:
        pass
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination
