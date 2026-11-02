"""Shared TEE admit honesty helpers for TDX and SEV-SNP.

Peer-subnet pattern Cathedral adopts for both chips:

1. Fresh REPORT_DATA v2 bind (nonce + hotkey + TLS) — already in ``admit``
2. Measurement allowlist — already in ``admit`` / measurement list
3. Root bind — TDX MRCONFIGID or SNP HOST_DATA vs pinned ``sha256:<digest>``
4. Re-attest after release / TDX fresh boot — already in ``admit``
5. Attestation admits; pay needs measurement_allowed evidence — already in ``admit``

This module is the remote root-pin check (3). Guest startup already enforces
the same bind locally via ``cathedral.tee_box.measured_root``.
"""

from __future__ import annotations

import re

from cathedral.tee_box.measured_root import (
    MeasuredRootError,
    root_digest_from_host_data,
    root_digest_from_mrconfigid,
)
from cathedral.verify.snp import parse_snp_report
from cathedral.verify.tdx_quote import TdxQuoteParseError, parse_tdx_quote

ROOT_BINDING_MISMATCH = "root_binding_mismatch"
ROOT_BINDING_MISSING = "root_binding_missing"
ROOT_BINDING_ZERO = "root_binding_zero"

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def normalize_expected_root_digest(value: object) -> str | None:
    """Return a pinned ``sha256:<64 hex>`` or None when the pin is unused."""

    if value is None:
        return None
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError("expected_root_digest must be sha256:<64 lowercase hex> or None")
    return value


def quote_root_digest(kind: str, quote: bytes) -> str:
    """Read the launch root digest from quote bytes (TDX MRCONFIGID / SNP HOST_DATA)."""

    if kind == "tdx":
        try:
            parsed = parse_tdx_quote(quote)
        except TdxQuoteParseError as exc:
            raise ValueError(f"quote: {exc}") from exc
        try:
            return root_digest_from_mrconfigid(parsed.body.mr_config_id)
        except MeasuredRootError as exc:
            raise ValueError(str(exc)) from exc
    if kind == "sev_snp":
        try:
            report = parse_snp_report(quote)
        except ValueError as exc:
            raise ValueError(f"quote: {exc}") from exc
        try:
            return root_digest_from_host_data(report.host_data)
        except MeasuredRootError as exc:
            raise ValueError(str(exc)) from exc
    raise ValueError(f"unsupported tee kind for root binding: {kind}")


def check_root_binding(
    kind: str,
    quote: bytes,
    expected_root_digest: str | None,
) -> str | None:
    """Return a refusal reason, or None when the pin is unused or matches.

    When ``expected_root_digest`` is set, both TDX and SNP must present a
    non-zero launch binding equal to that digest. Missing/zero/mismatch are
    distinct reasons so operators can tell launch gaps from wrong roots.
    """

    pinned = normalize_expected_root_digest(expected_root_digest)
    if pinned is None:
        return None
    try:
        actual = quote_root_digest(kind, quote)
    except ValueError as exc:
        message = str(exc)
        if "zero" in message:
            return ROOT_BINDING_ZERO
        return ROOT_BINDING_MISSING
    if actual != pinned:
        return ROOT_BINDING_MISMATCH
    return None
