"""Development-only stub TDX evidence for a local subtensor chain.

NOT ATTESTATION. This exists so the full SN94 mining loop (a signed validator
request, evidence, SAT work, weights on chain, miner incentive) can run end to
end on a laptop that has no Intel TDX hardware. Nothing here proves anything
about a machine.

It stays off unless all of these hold:

* ``CATHEDRAL_LOCALNET_STUB_EVIDENCE=1`` is set explicitly;
* the worker runs the authenticated ``worker serve`` posture with the complete
  signed validator-access configuration;
* that configuration names the ``local`` network. ``finney``, ``test``, and
  every other network name refuse to start.

The stub quote is ``STUB_QUOTE_MAGIC || REPORT_DATA || platform``. REPORT_DATA is
the real v2 binding of the validator's nonce, this hotkey, and the worker's TLS
SPKI. ``platform`` is a digest of that SPKI, so each worker process looks like
one distinct machine. The only verifier that accepts it is the validator's
localnet stub (cathedral-validator ``localnet/stub_tdx_verifier.py``); the
production Go verifier and Intel DCAP both reject it as a malformed quote.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping

from cathedral.common import (
    ChannelBinding,
    Evidence,
    EvidenceKind,
    report_data_v2,
)

LOCALNET_STUB_EVIDENCE_ENV = "CATHEDRAL_LOCALNET_STUB_EVIDENCE"
LOCALNET_NETWORK = "local"
STUB_QUOTE_MAGIC = b"CATHEDRAL-LOCALNET-STUB-TDX-QUOTE-V1\x00"
_PLATFORM_DOMAIN = b"cathedral.localnet-stub-machine\x00"


class LocalnetStubRefused(ValueError):
    """The localnet stub was requested outside its development boundary."""


def localnet_stub_requested(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether the operator explicitly asked for stub evidence.

    Only the exact value ``1`` enables it. Any other non-empty value is a
    refusal rather than a silent off, so a typo cannot look like a real run.
    """

    value = (os.environ if environ is None else environ).get(LOCALNET_STUB_EVIDENCE_ENV)
    if value is None or value == "":
        return False
    if value != "1":
        raise LocalnetStubRefused(f"{LOCALNET_STUB_EVIDENCE_ENV} must be exactly 1 or unset")
    return True


def require_localnet_stub_context(*, posture: str, network: str, signed_access: bool) -> None:
    """Refuse stub evidence anywhere but the signed worker on the local chain."""

    if network != LOCALNET_NETWORK:
        raise LocalnetStubRefused(
            f"stub evidence runs only with --validator-network {LOCALNET_NETWORK}; "
            f"refusing {network!r}"
        )
    if posture != "production":
        raise LocalnetStubRefused("stub evidence runs only under `cathedral worker serve`")
    if not signed_access:
        raise LocalnetStubRefused(
            "stub evidence requires the complete signed validator-access configuration"
        )


def stub_platform(channel_binding: ChannelBinding) -> bytes:
    """Stable per-worker stand-in for a hardware platform identity."""

    return hashlib.sha256(_PLATFORM_DOMAIN + channel_binding.canonical_bytes()).digest()


def build_stub_quote(report_data: bytes, channel_binding: ChannelBinding) -> bytes:
    if not isinstance(report_data, bytes) or len(report_data) != 64:
        raise ValueError("stub quote REPORT_DATA must be exactly 64 bytes")
    return STUB_QUOTE_MAGIC + report_data + stub_platform(channel_binding)


def collect_localnet_stub_tdx(
    nonce: bytes,
    hotkey: str,
    ssh_host_key: bytes | None = None,
    *,
    channel_binding: ChannelBinding | None = None,
    report_data_version: int = 1,
) -> Evidence:
    """Same signature as ``collect_tdx``; returns a stub quote, never a real one."""

    if not localnet_stub_requested():
        raise LocalnetStubRefused(f"{LOCALNET_STUB_EVIDENCE_ENV}=1 is not set")
    if report_data_version != 2 or channel_binding is None:
        raise ValueError("localnet stub evidence answers channel-bound v2 requests only")
    report_data = report_data_v2(nonce, hotkey, channel_binding)
    return Evidence(
        kind=EvidenceKind.TDX,
        quote=build_stub_quote(report_data, channel_binding),
        cert_chain=[],
        nonce=nonce,
        miner_hotkey=hotkey,
        ssh_host_key=ssh_host_key,
        report_data_version=2,
        channel_binding=channel_binding,
    )


__all__ = [
    "LOCALNET_NETWORK",
    "LOCALNET_STUB_EVIDENCE_ENV",
    "STUB_QUOTE_MAGIC",
    "LocalnetStubRefused",
    "build_stub_quote",
    "collect_localnet_stub_tdx",
    "localnet_stub_requested",
    "require_localnet_stub_context",
    "stub_platform",
]
