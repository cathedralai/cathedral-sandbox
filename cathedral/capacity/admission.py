"""TEE box admission: may this whole-host confidential VM serve sandboxes?

A pure library: no network, no clock, no files. The control plane or the
prober calls :func:`admit` after it has itself verified the box's quote with
the pinned verifier (``cathedral.verify``: the TDX verifier in strict mode, or
``cathedral.verify.snp``), on the same TLS connection that serves the box's
sandbox API. :func:`admit` then decides, from values the caller observed:

- **REPORT_DATA binding.** The quote's REPORT_DATA must equal
  ``cathedral.common.report_data_v2(nonce, miner_hotkey, binding)``, where the
  binding is ``tls_spki_sha256`` over the SPKI of the certificate the caller saw
  in its own TLS handshake. That is the worker's existing v2 channel binding,
  byte for byte the same as cathedral-validator's
  ``cathedral_thin/independent/collect.py`` ``report_data_v2``; this module adds
  no new format. It binds the prober's 32-byte nonce, the miner hotkey and the
  TLS key, so a quote made for another prober round, another hotkey or another
  TLS endpoint is refused.
- **Hardware identity.** The raw PPID (TDX) or CHIP_ID (SEV-SNP) becomes the
  receipt's ``hardware_id`` through ``receipt.derive_hardware_id``, so an
  admission and the box's capacity receipts name one machine the same way. For
  TDX the raw PPID must also hash to the ``stable_platform_id`` the strict
  verifier emitted (``cmd/cathedral-tdx-verifier``), so the PPID is the one in
  the verified quote's PCK certificate.
- **Measurement policy.** cathedral-validator #256's policy file for TDX, and
  the same shape with a 96-hex allowlist for SEV-SNP (:func:`parse_policy`). In
  ``enforce`` an unlisted measurement is refused; in ``shadow`` it is admitted
  with ``measurement_allowed=False`` recorded.
- **One box per host, first claim wins.** Boxes are whole hosts. A hardware id
  already admitted to a different box (a different ``box_id`` or hotkey) is
  refused; the box that claimed it first keeps it until the caller removes that
  entry. The same box presenting the same host again is re-admitted.

Malformed input of any kind raises :class:`AdmissionError`. A well-formed
attestation that fails a check returns ``Admission(admitted=False, reasons=...)``.
See docs/CAPACITY.md, "Admission".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from cathedral.capacity.receipt import (
    _BOX_ID,
    _SS58,
    HARDWARE_ID_KINDS,
    ReceiptError,
    ReceiptEvidence,
    _check_evidence,
    derive_hardware_id,
)
from cathedral.channel import ChannelBindingError, _der_tlv, tls_spki_binding
from cathedral.common import ChannelBinding, ChannelBindingType, report_data_v2

TEE_KINDS = ("tdx", "sev_snp")
MODES = ("shadow", "enforce")
# The TDX schema is cathedral-validator #256's, so its policy file loads here unchanged.
POLICY_SCHEMAS = {
    "tdx": "cathedral_tdx_measurement_policy_v1",
    "sev_snp": "cathedral_snp_measurement_policy_v1",
}
_POLICY_KEYS = frozenset({"schema", "mode", "allowed_measurements"})
_POLICY_MEASUREMENT = {
    "tdx": re.compile(r"tdx-measurement-sha256:[0-9a-f]{64}"),
    "sev_snp": re.compile(r"[0-9a-f]{96}"),
}
MAX_POLICY_BYTES = 128 * 1024  # as #256
NONCE_BYTES = 32  # report_data_v2's nonce
REPORT_DATA_BYTES = 64
# cmd/cathedral-tdx-verifier/main.go: stable_platform_id =
# "tdx-platform-sha256:" + hex(SHA-256(platformDomain + lowercase hex PPID)).
TDX_PLATFORM_DOMAIN = b"cathedral-tdx-platform-v1\x00"
_STABLE_PLATFORM_ID = re.compile(r"tdx-platform-sha256:[0-9a-f]{64}")
_HEX = re.compile(r"(?:[0-9a-f]{2})+")
_HEX64 = re.compile(r"[0-9a-f]{64}")

# Refusal reasons, in the order they are checked.
REPORT_DATA_MISMATCH = "report_data_mismatch"
PLATFORM_ID_MISMATCH = "hardware_id_not_in_verified_quote"
MEASUREMENT_NOT_ALLOWED = "measurement_not_allowed"
HARDWARE_ID_CLAIMED = "hardware_id_admitted_to_another_box"


class AdmissionError(ValueError):
    """Admission input or a measurement policy is malformed."""


@dataclass(frozen=True)
class MeasurementPolicy:
    kind: str  # tdx or sev_snp, fixed by the schema
    mode: str  # shadow or enforce
    allowed_measurements: frozenset[str]
    digest: str  # sha256:<hex> of the exact policy bytes, as #256 records it

    def allows(self, measurement: str) -> bool:
        return measurement in self.allowed_measurements


@dataclass(frozen=True)
class VerifiedAttestation:
    """What the caller's own verifier run established about one quote.

    ``hardware_id`` is the raw 16-byte PPID (TDX) or 64-byte CHIP_ID (SEV-SNP),
    as bytes or lowercase hex. ``report_data`` is the 64 bytes in the verified
    quote. ``stable_platform_id`` is required for TDX (the strict verifier's
    claim, ``Attested.chip_id``) and must be None for SEV-SNP.
    """

    kind: str
    hardware_id: bytes | str
    measurement: str
    verifier_digest: str
    evidence_sha256: str
    report_data: bytes
    stable_platform_id: str | None = None


@dataclass(frozen=True)
class AdmittedBox:
    """The box an already-admitted hardware id belongs to."""

    box_id: str
    miner_hotkey: str


@dataclass(frozen=True)
class Admission:
    admitted: bool
    reasons: tuple[str, ...]  # empty exactly when admitted
    box_id: str
    miner_hotkey: str
    hardware_id: str  # derive_hardware_id(hardware_id_kind, raw): the receipt's hardware_id
    hardware_id_kind: str  # ppid or chip_id
    measurement: str
    measurement_allowed: bool
    mode: str  # the policy's mode
    policy_digest: str
    evidence: ReceiptEvidence | None  # for T4 receipts; None unless admitted


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionError("measurement policy repeats a JSON key")
        value[key] = item
    return value


def parse_policy(raw: bytes) -> MeasurementPolicy:
    """Parse one measurement policy strictly.

    ``{"schema", "mode", "allowed_measurements"}`` and nothing else, as #256:
    the schema names the kind (``POLICY_SCHEMAS``), ``mode`` is ``shadow`` or
    ``enforce``, and ``allowed_measurements`` is a sorted list of unique
    ``tdx-measurement-sha256:<64 hex>`` (TDX) or 96-hex (SEV-SNP) strings, not
    empty when enforcing. Reading the file safely is the caller's job (#256's
    loader checks owner, mode and size); this takes its bytes.
    """

    if not isinstance(raw, bytes):
        raise AdmissionError("measurement policy must be bytes")
    if not 1 <= len(raw) <= MAX_POLICY_BYTES:
        raise AdmissionError("measurement policy must be 1 byte to 128 KiB")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionError("measurement policy is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != _POLICY_KEYS:
        raise AdmissionError(
            "measurement policy must contain exactly schema, mode and allowed_measurements"
        )
    schema = document["schema"]
    # A JSON value equals a schema name only if it is that string, and a mode
    # only if it is one of MODES; NaN or Infinity can only reach
    # allowed_measurements, whose entries must be strings.
    kinds = [kind for kind, name in POLICY_SCHEMAS.items() if schema == name]
    if not kinds:
        raise AdmissionError(
            f"measurement policy schema must be one of {sorted(POLICY_SCHEMAS.values())}"
        )
    kind = kinds[0]
    mode = document["mode"]
    if mode not in MODES:
        raise AdmissionError("measurement policy mode must be shadow or enforce")
    measurements = document["allowed_measurements"]
    pattern = _POLICY_MEASUREMENT[kind]
    # Types first, so a mixed list is refused cleanly instead of failing to sort.
    if (
        not isinstance(measurements, list)
        or any(
            not isinstance(item, str) or pattern.fullmatch(item) is None for item in measurements
        )
        or measurements != sorted(measurements)
        or len(set(measurements)) != len(measurements)
    ):
        shape = "tdx-measurement-sha256:<64 hex>" if kind == "tdx" else "96 lowercase hex"
        raise AdmissionError(f"allowed_measurements must be a sorted, unique list of {shape}")
    if mode == "enforce" and not measurements:
        raise AdmissionError("an enforcing measurement policy must allow at least one measurement")
    return MeasurementPolicy(
        kind=kind,
        mode=mode,
        allowed_measurements=frozenset(measurements),
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _raw_hardware_id(value: object, size: int, name: str) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str) and _HEX.fullmatch(value) is not None:
        raw = bytes.fromhex(value)
    else:
        raise AdmissionError(f"the raw {name} must be bytes or lowercase hex")
    if len(raw) != size:
        raise AdmissionError(f"a raw {name} is {size} bytes")
    return raw


def _tls_binding(certificate_der: object, spki_der: object) -> ChannelBinding:
    """The v2 ``tls_spki_sha256`` binding for the connection the caller observed."""

    if (certificate_der is None) == (spki_der is None):
        raise AdmissionError("pass exactly one of tls_certificate_der and tls_spki_der")
    try:
        if certificate_der is not None:
            if not isinstance(certificate_der, bytes):
                raise AdmissionError("tls_certificate_der must be bytes")
            return tls_spki_binding(certificate_der)
        if not isinstance(spki_der, bytes) or not spki_der:
            raise AdmissionError("tls_spki_der must be non-empty bytes")
        # One canonical SEQUENCE { AlgorithmIdentifier SEQUENCE, BIT STRING },
        # as cathedral/channel.py's extract_spki_der returns it from a certificate.
        tag, body, end = _der_tlv(spki_der, 0)
        if tag != 0x30 or end != len(spki_der):
            raise AdmissionError("tls_spki_der is not one DER sequence")
        algorithm_tag, _, algorithm_end = _der_tlv(spki_der, body)
        key_tag, _, key_end = _der_tlv(spki_der, algorithm_end)
        if algorithm_tag != 0x30 or key_tag != 0x03 or key_end != end:
            raise AdmissionError("tls_spki_der is not a SubjectPublicKeyInfo")
        return ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, hashlib.sha256(spki_der).digest())
    except ChannelBindingError as exc:
        raise AdmissionError(f"TLS peer key: {exc}") from exc


def _check_admitted(admitted: object) -> Mapping[str, AdmittedBox]:
    if not isinstance(admitted, Mapping):
        raise AdmissionError("admitted must map hardware ids to AdmittedBox")
    for hardware_id, box in admitted.items():
        # Every key is checked, so a registry keyed some other way (upper-case
        # hex, raw ids) cannot make a duplicate silently miss.
        if not isinstance(hardware_id, str) or _HEX64.fullmatch(hardware_id) is None:
            raise AdmissionError("admitted hardware ids must be 64 lowercase hex characters")
        if (
            not isinstance(box, AdmittedBox)
            or not isinstance(box.box_id, str)
            or _BOX_ID.fullmatch(box.box_id) is None
            or not isinstance(box.miner_hotkey, str)
            or _SS58.fullmatch(box.miner_hotkey) is None
        ):
            raise AdmissionError(
                "each admitted entry must be an AdmittedBox with a valid box_id and hotkey"
            )
    return admitted


def admit(
    attestation: VerifiedAttestation,
    *,
    box_id: str,
    miner_hotkey: str,
    nonce: bytes,
    policy: MeasurementPolicy,
    admitted: Mapping[str, AdmittedBox],
    tls_certificate_der: bytes | None = None,
    tls_spki_der: bytes | None = None,
) -> Admission:
    """Decide one TEE box's admission. ``nonce`` is the 32-byte nonce the caller
    sent with its evidence request; ``tls_certificate_der`` (or its
    ``tls_spki_der``) is from the caller's own handshake on the connection that
    serves the sandbox API; ``admitted`` maps each already-admitted hardware id
    to its box. Raises :class:`AdmissionError` on malformed input."""

    if not isinstance(attestation, VerifiedAttestation):
        raise AdmissionError("attestation must be a VerifiedAttestation")
    if (
        not isinstance(policy, MeasurementPolicy)
        or not isinstance(policy.kind, str)
        or policy.kind not in TEE_KINDS
        or not isinstance(policy.mode, str)
        or policy.mode not in MODES
        or not isinstance(policy.allowed_measurements, frozenset)
        or not isinstance(policy.digest, str)
    ):
        raise AdmissionError("policy must be a MeasurementPolicy from parse_policy")
    kind = attestation.kind
    if not isinstance(kind, str) or kind not in TEE_KINDS:
        raise AdmissionError("attestation kind must be tdx or sev_snp")
    if policy.kind != kind:
        raise AdmissionError(f"a {kind} attestation needs a {kind} measurement policy")
    if not isinstance(box_id, str) or _BOX_ID.fullmatch(box_id) is None:
        raise AdmissionError("box_id must be 1-128 of A-Z a-z 0-9 . _ : -")
    if not isinstance(miner_hotkey, str) or _SS58.fullmatch(miner_hotkey) is None:
        raise AdmissionError("miner_hotkey must be an SS58 address")
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise AdmissionError(f"nonce must be exactly {NONCE_BYTES} bytes")
    if not any(nonce):
        raise AdmissionError("nonce is all zeros")
    report_data = attestation.report_data
    if not isinstance(report_data, bytes) or len(report_data) != REPORT_DATA_BYTES:
        raise AdmissionError(f"report_data must be exactly {REPORT_DATA_BYTES} bytes")
    registry = _check_admitted(admitted)
    binding = _tls_binding(tls_certificate_der, tls_spki_der)

    hardware_id_kind = HARDWARE_ID_KINDS[("tee", kind)]
    raw_id = _raw_hardware_id(
        attestation.hardware_id, 16 if hardware_id_kind == "ppid" else 64, hardware_id_kind
    )
    try:
        hardware_id = derive_hardware_id(hardware_id_kind, raw_id)
        # The receipt's own evidence checks, so what admission hands T4 is a
        # value verify_receipt accepts.
        evidence = _check_evidence(
            {
                "evidence_kind": kind,
                "evidence_sha256": attestation.evidence_sha256,
                "measurement": attestation.measurement,
                "verifier_digest": attestation.verifier_digest,
                "tls_spki_sha256": binding.digest.hex(),
            },
            kind,
        )
    except ReceiptError as exc:
        raise AdmissionError(str(exc)) from exc
    assert evidence is not None  # a TEE kind always yields evidence
    if not any(bytes.fromhex(evidence.evidence_sha256)):
        raise AdmissionError("evidence_sha256 is all zeros")

    stable_platform_id = attestation.stable_platform_id
    if kind == "tdx":
        if (
            not isinstance(stable_platform_id, str)
            or _STABLE_PLATFORM_ID.fullmatch(stable_platform_id) is None
        ):
            raise AdmissionError("a tdx attestation needs the verifier's stable_platform_id")
    elif stable_platform_id is not None:
        raise AdmissionError("a sev_snp attestation has no stable_platform_id")

    reasons: list[str] = []
    try:
        expected = report_data_v2(nonce, miner_hotkey, binding)
    except ValueError as exc:  # inputs are checked above; kept for a bare-exception-free API
        raise AdmissionError(str(exc)) from exc
    if not hmac.compare_digest(expected, report_data):
        reasons.append(REPORT_DATA_MISMATCH)
    if kind == "tdx":
        derived = (
            "tdx-platform-sha256:"
            + hashlib.sha256(TDX_PLATFORM_DOMAIN + raw_id.hex().encode()).hexdigest()
        )
        if not hmac.compare_digest(derived, stable_platform_id):
            reasons.append(PLATFORM_ID_MISMATCH)
    measurement_allowed = policy.allows(evidence.measurement)
    if not measurement_allowed and policy.mode == "enforce":
        reasons.append(MEASUREMENT_NOT_ALLOWED)
    holder = registry.get(hardware_id)
    if holder is not None and (holder.box_id, holder.miner_hotkey) != (box_id, miner_hotkey):
        reasons.append(HARDWARE_ID_CLAIMED)

    return Admission(
        admitted=not reasons,
        reasons=tuple(reasons),
        box_id=box_id,
        miner_hotkey=miner_hotkey,
        hardware_id=hardware_id,
        hardware_id_kind=hardware_id_kind,
        measurement=evidence.measurement,
        measurement_allowed=measurement_allowed,
        mode=policy.mode,
        policy_digest=policy.digest,
        evidence=None if reasons else evidence,
    )
