"""Customer replay from captured collateral, separate from current admission."""

from __future__ import annotations

import base64
import hmac
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from cathedral.verify import (
    _MAX_PINNED_ARTIFACT_BYTES,
    _parse_verifier_json,
    _read_bounded_subprocess,
    tdx_implementation_digest_from_bytes,
)
from cathedral.verify.capture import write_private_capture


class TdxOfflineUnavailable(ValueError):
    pass


def verify_tdx_offline(
    quote: bytes,
    expected_report_data: bytes,
    collateral_bundle: bytes,
    *,
    executable: str,
    implementation_digest: str,
) -> dict:
    """Authenticate executable bytes, then execute a private copy with no PCS.

    The implementation digest must come from local trust configuration. Neither
    the bundle nor its receipt supplies executable paths or trust anchors.
    Existing static Linux ELF requirements and sanitized execution are reused.
    """
    if (
        not isinstance(quote, bytes)
        or not 0 < len(quote) <= 1024 * 1024
        or not isinstance(expected_report_data, bytes)
        or len(expected_report_data) != 64
        or not isinstance(collateral_bundle, bytes)
        or not 0 < len(collateral_bundle) <= 24 * 1024 * 1024
    ):
        return {}
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(executable, flags)
        with os.fdopen(fd, "rb") as source:
            metadata = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o022
                or not metadata.st_mode & 0o111
                or metadata.st_uid not in {0, os.geteuid()}
                or not 0 < metadata.st_size <= _MAX_PINNED_ARTIFACT_BYTES
            ):
                raise ValueError("invalid executable")
            binary = source.read(_MAX_PINNED_ARTIFACT_BYTES + 1)
        actual = tdx_implementation_digest_from_bytes(
            (executable,), (executable,), {executable: binary}
        )
        if not hmac.compare_digest(actual, implementation_digest):
            raise ValueError("digest mismatch")
    except (OSError, AttributeError, TypeError, ValueError) as exc:
        raise TdxOfflineUnavailable("pinned offline TDX verifier is unavailable") from exc

    with tempfile.TemporaryDirectory(prefix="cathedral-tdx-offline-") as temporary:
        work = Path(temporary)
        binary_path = work / "verifier"
        binary_path.write_bytes(binary)
        binary_path.chmod(0o500)
        quote_path = work / "quote.bin"
        quote_path.write_bytes(quote)
        collateral_path = work / "collateral.json"
        collateral_path.write_bytes(collateral_bundle)
        try:
            stdout, _, code = _read_bounded_subprocess(
                [
                    str(binary_path),
                    str(quote_path),
                    expected_report_data.hex(),
                    "--collateral-bundle",
                    str(collateral_path),
                ],
                1024 * 1024,
                30,
                sanitized=True,
            )
        except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
            raise TdxOfflineUnavailable("offline TDX verifier execution failed") from exc
    if code != 0:
        return {}
    claims = _parse_verifier_json(stdout)
    if (
        any(
            claims.get(key) is not True
            for key in (
                "intel_verified",
                "report_data_match",
                "claims_bound_to_quote",
                "platform_identity_verified",
            )
        )
        or claims.get("report_data") != expected_report_data.hex()
        or claims.get("tcb_status") != "UpToDate"
        or claims.get("advisory_ids") != []
        or claims.get("debug_enabled") is not False
        or claims.get("collateral_current") is not False
        or not isinstance(claims.get("collateral_current_reason"), str)
        or not claims["collateral_current_reason"]
    ):
        return {}
    return claims


def persist_tdx_capture(
    quote: bytes,
    collateral: bytes,
    directory: Path,
    *,
    admission_nonce: bytes | None = None,
    box_id: str | None = None,
) -> Path:
    """Store quote and vendor-verified collateral together after verification.

    This records hardware verification during admission. It is not an
    admission verdict or evidence of the parent measurement-policy result.
    A ``<sha256>.meta.json`` sidecar records the capture time and, when the
    caller knows them, the admission nonce and box ID.
    """
    if not 0 < len(collateral) <= 24 * 1024 * 1024:
        raise ValueError("captured collateral size is invalid")
    document = {
        "schema": "cathedral_tdx_capture_v1",
        "quote_base64": base64.b64encode(quote).decode("ascii"),
        "collateral_base64": base64.b64encode(collateral).decode("ascii"),
    }
    return write_private_capture(
        document,
        directory,
        temporary_prefix=".tdx-capture-",
        admission_nonce=admission_nonce,
        box_id=box_id,
    )
