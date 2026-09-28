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


def _write_sidecar(path: Path, encoded: bytes) -> None:
    # Context only, like the metadata values: any failure here is logged and
    # never raised, so it can't reject evidence that is already written.
    # O_EXCL keeps the first writer's record; O_NOFOLLOW refuses a planted link.
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return
    except OSError as exc:
        _LOG.warning("capture metadata: sidecar %s not created: %s", path.name, exc)
        return
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        _LOG.warning("capture metadata: sidecar %s not written: %s", path.name, exc)
        try:
            # This call created the file, so a partial record is ours to remove
            # rather than left to block a later complete one.
            path.unlink()
        except OSError:
            pass


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

    Both files are mode 0600 in a 0700 directory. The evidence file appears
    atomically, and a failure to write it raises ``OSError``. Malformed metadata
    values are dropped with a warning, never raised. The sidecar is written
    after the evidence file and records the first capture of those exact bytes;
    a later identical capture leaves the original record in place. A sidecar
    write failure is logged and never raised, so the evidence file is kept
    without a sidecar.
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
    _write_sidecar(directory / (digest + ".meta.json"), metadata_encoded)
    return destination
