"""TEE box admission: may this whole-host confidential VM serve sandboxes?

A pure library: no network, no clock, no files. The control plane or the
prober first verifies the box's quote itself with the pinned verifier
(``cathedral.verify``: the TDX verifier in strict mode, or
``cathedral.verify.snp.verify_snp`` with its default ``require_chain=True``), on
the same TLS connection that serves the box's sandbox API, and passes
:func:`admit` the verifier's own ``Attested`` verdict together with the raw
quote (or SEV-SNP report) bytes it verified. :func:`admit` then decides:

- **Complete verification.** The verdict must be ``VERIFIED`` with the vendor
  chain verified; for TDX also strict policy mode, current collateral and debug
  off. A partial verdict (``STRUCTURE_OK_CHAIN_UNVERIFIED``, compatibility-mode
  TDX) is refused. The verdict must be for these quote bytes: its measurement
  (and, for SEV-SNP, its chip id) must match the quote's own.
- **REPORT_DATA binding.** The quote's REPORT_DATA, read from the quote itself,
  must equal ``cathedral.common.report_data_v2(nonce, miner_hotkey, binding)``,
  where the binding is ``tls_spki_sha256`` over the SPKI of the certificate the
  caller saw in its own TLS handshake. That is the worker's existing v2 channel
  binding, byte for byte the same as cathedral-validator's
  ``cathedral_thin/independent/collect.py`` ``report_data_v2``; this module adds
  no new format. It binds the prober's 32-byte nonce, the miner hotkey and the
  TLS key, so a quote made for another prober round, another hotkey or another
  TLS endpoint is refused.
- **Hardware identity.** For TDX, the ``stable_platform_id`` the pinned strict
  verifier emitted (``Attested.chip_id``; no verifier outputs the raw PPID)
  becomes the receipt's ``hardware_id`` through ``receipt.tdx_hardware_id``; for
  SEV-SNP, the report's CHIP_ID through ``receipt.derive_hardware_id``. An
  admission and the box's capacity receipts therefore name one machine the same
  way.
- **Measurement policy.** cathedral-validator #256's policy file for TDX, and
  the same shape with a 96-hex allowlist for SEV-SNP (:func:`parse_policy`).
  This policy decides whether the box's receipts pay. In ``enforce`` an
  unlisted measurement is refused; in ``shadow`` it is admitted and recorded
  (``measurement_allowed=False``) but gets no receipt evidence, so it cannot be
  paid. The verifier's own ``Policy.allowed_measurements`` is checked first and
  refuses anything it does not list (docs/CAPACITY.md, "Which allowlist gates").
- **One box per host, first claim wins.** Boxes are whole hosts. A hardware id
  already admitted to a different box (a different ``box_id`` or hotkey) is
  refused; the box that claimed it first keeps it until the caller removes that
  entry. The same box presenting the same host again is re-admitted. The
  caller must check and record the claim atomically (one lock or transaction),
  or two concurrent admissions of one host can both pass.
- **After the last release (optional).** A TEE box is relaunched and
  re-attested between customers. Given ``last_released_at``, when the box's
  previous customer lease ended, evidence verified at or before it is refused,
  so the previous allocation's admission cannot be reused for the next one.
  ``None`` (the default) skips the check.
- **Fresh boot (optional, TDX).** A TEE box extends RTMR3 once before its
  first lease in a boot (cathedral/tee_box/boot.py), which no guest code can
  undo. With ``require_fresh_boot=True`` a quote whose RTMR3, read from the
  quote itself, is not all zeros is refused, in shadow as in enforce: that
  boot has served a customer, and the VM must be relaunched first. This is
  the check that holds against guest root. SEV-SNP has no RTMR, so asking for
  it there is an error. ``False`` (the default) skips it.

The evidence :func:`admit` returns for the box's receipts carries the SHA-256
of the quote bytes (computed here, never taken from the caller), the nonce, the
TLS key's SPKI hash from the caller's handshake, and ``attested_at``.

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
from datetime import datetime
from typing import Any, Mapping

from cathedral.capacity.receipt import (
    _BOX_ID,
    _SS58,
    HARDWARE_ID_KINDS,
    ReceiptError,
    ReceiptEvidence,
    _check_evidence,
    _iso,
    derive_hardware_id,
    tdx_hardware_id,
)
from cathedral.channel import ChannelBindingError, _der_tlv, tls_spki_binding
from cathedral.common import (
    Attested,
    ChannelBinding,
    ChannelBindingType,
    Tier,
    report_data_v2,
)
from cathedral.verify.snp import VERIFIED, parse_snp_report
from cathedral.verify.tdx_quote import TdxQuoteParseError, parse_tdx_quote

TEE_KINDS = ("tdx", "sev_snp")
# The verifier verdict's tier names the kind.
_TIER_KINDS = {Tier.CC_CPU_TDX: "tdx", Tier.CC_CPU_SNP: "sev_snp"}
MODES = ("shadow", "enforce")
# The TDX schema is cathedral-validator #256's, so its policy file loads here unchanged.
POLICY_SCHEMAS = {
    "tdx": "cathedral_tdx_measurement_policy_v1",
    "sev_snp": "cathedral_snp_measurement_policy_v1",
}
_POLICY_KEYS = frozenset({"schema", "mode", "allowed_measurements"})
_POLICY_MEASUREMENT = {
    # v1 launch measurement or v2 image identity (docs/MRTD.md); a TDX policy
    # may list either.
    "tdx": re.compile(r"tdx-(?:measurement|image)-sha256:[0-9a-f]{64}"),
    "sev_snp": re.compile(r"[0-9a-f]{96}"),
}
MAX_POLICY_BYTES = 128 * 1024  # as #256
NONCE_BYTES = 32  # report_data_v2's nonce
MAX_QUOTE_BYTES = 64 * 1024  # a TDX quote with its PCK chain is a few KiB; an SNP report 1184 B
_HEX64 = re.compile(r"[0-9a-f]{64}")

# Refusal reasons, in the order they are checked.
VERIFICATION_INCOMPLETE = "verification_incomplete"
REPORT_DATA_MISMATCH = "report_data_mismatch"
MEASUREMENT_NOT_ALLOWED = "measurement_not_allowed"
HARDWARE_ID_CLAIMED = "hardware_id_admitted_to_another_box"
ATTESTATION_PREDATES_RELEASE = "attestation_predates_release"
BOOT_CONSUMED = "boot_consumed"
_RTMR_ZERO = bytes(48)


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
    hardware_id_kind: str  # tdx_platform or chip_id
    # The identity judged against the policy and written to the receipt
    # evidence: for TDX the v1 launch measurement, or the v2 image identity
    # when the policy lists only that (docs/MRTD.md, "Image identity").
    measurement: str
    measurement_allowed: bool
    mode: str  # the policy's mode
    policy_digest: str
    # For T4 receipts: None unless admitted with an allowed measurement, so a
    # shadow admission of an unlisted measurement is recorded but never paid.
    evidence: ReceiptEvidence | None
    # TDX audit values read from the quote itself: v1 (includes host-set
    # MROWNER) and v2. None for SEV-SNP.
    launch_measurement: str | None = None
    image_measurement: str | None = None


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
    ``tdx-measurement-sha256:<64 hex>`` or ``tdx-image-sha256:<64 hex>`` (TDX)
    or 96-hex (SEV-SNP) strings, not
    empty when enforcing. Reading the file safely is the caller's job (#256's
    loader checks owner, mode and size); this takes its bytes.
    """

    if not isinstance(raw, bytes):
        raise AdmissionError("measurement policy must be bytes")
    if not 1 <= len(raw) <= MAX_POLICY_BYTES:
        raise AdmissionError("measurement policy must be 1 byte to 128 KiB")
    # ValueError covers UnicodeDecodeError and JSONDecodeError, and also the plain
    # ValueError json.loads raises for an integer past Python's digit limit.
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except AdmissionError:
        raise  # a repeated key, with its own message (AdmissionError is a ValueError)
    except (ValueError, RecursionError) as exc:
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
        shape = (
            "tdx-measurement-sha256:<64 hex> or tdx-image-sha256:<64 hex>"
            if kind == "tdx"
            else "96 lowercase hex"
        )
        raise AdmissionError(f"allowed_measurements must be a sorted, unique list of {shape}")
    if mode == "enforce" and not measurements:
        raise AdmissionError("an enforcing measurement policy must allow at least one measurement")
    return MeasurementPolicy(
        kind=kind,
        mode=mode,
        allowed_measurements=frozenset(measurements),
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _complete(attested: Attested, kind: str) -> bool:
    """Whether the verdict is a complete, strict verification (not a partial
    one some verifier modes return): VERIFIED with the vendor chain checked,
    and for TDX strict policy mode, current collateral and debug off."""

    if attested.verification_status != VERIFIED or attested.chain_verified is not True:
        return False
    if kind == "tdx":
        return (
            attested.policy_mode == "strict"
            and attested.collateral_current is True
            and attested.debug_enabled is False
        )
    return True


def _parse_quote(
    quote: bytes, kind: str
) -> tuple[bytes, str, bool, bytes | None, bytes | None, str | None]:
    """REPORT_DATA, measurement, debug bit, (SEV-SNP) raw chip id, (TDX)
    RTMR3 and (TDX) v2 image identity, read from the quote bytes themselves."""

    try:
        if kind == "tdx":
            parsed = parse_tdx_quote(quote)
            return (
                parsed.report_data,
                parsed.measurement,
                parsed.debug_enabled,
                None,
                parsed.body.rtmr3,
                parsed.image_measurement,
            )
        report = parse_snp_report(quote)
        return (
            report.report_data,
            report.measurement,
            False,
            bytes.fromhex(report.chip_id),
            None,
            None,
        )
    except (TdxQuoteParseError, ValueError) as exc:
        raise AdmissionError(f"quote: {exc}") from exc


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
    attested: Attested,
    quote: bytes,
    *,
    verifier_digest: str,
    box_id: str,
    miner_hotkey: str,
    nonce: bytes,
    attested_at: datetime,
    policy: MeasurementPolicy,
    admitted: Mapping[str, AdmittedBox],
    tls_certificate_der: bytes | None = None,
    tls_spki_der: bytes | None = None,
    last_released_at: datetime | None = None,
    require_fresh_boot: bool = False,
) -> Admission:
    """Decide one TEE box's admission.

    ``attested`` is the pinned verifier's own verdict (``cathedral.common.Attested``)
    for ``quote``, the raw TDX quote or SEV-SNP report bytes it verified;
    ``verifier_digest`` names that verifier (``sha256:<64 hex>``). ``nonce`` is
    the 32-byte nonce the caller sent with its evidence request and
    ``attested_at`` (timezone-aware) when it verified the quote.
    ``tls_certificate_der`` (or its ``tls_spki_der``) is from the caller's own
    handshake on the connection that serves the sandbox API; ``admitted`` maps
    each already-admitted hardware id to its box. ``last_released_at``
    (timezone-aware, optional) is when the box's last customer lease ended:
    evidence whose ``attested_at`` is not strictly after it is refused with
    ``attestation_predates_release``; ``None`` skips that check.
    ``require_fresh_boot`` (TDX only) refuses a quote whose RTMR3 is not all
    zeros with ``boot_consumed``; use it for every admission before a new
    customer. Raises
    :class:`AdmissionError` on malformed input."""

    if not isinstance(attested, Attested):
        raise AdmissionError("attested must be the verifier's cathedral.common.Attested")
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
    kind = _TIER_KINDS.get(attested.tier) if isinstance(attested.tier, Tier) else None
    if kind is None:
        raise AdmissionError("attested tier must be cc_cpu_tdx or cc_cpu_snp")
    if policy.kind != kind:
        raise AdmissionError(f"a {kind} attestation needs a {kind} measurement policy")
    if not isinstance(quote, bytes) or not 1 <= len(quote) <= MAX_QUOTE_BYTES:
        raise AdmissionError("quote must be the raw quote or report, 1 byte to 64 KiB")
    if not isinstance(box_id, str) or _BOX_ID.fullmatch(box_id) is None:
        raise AdmissionError("box_id must be 1-128 of A-Z a-z 0-9 . _ : -")
    if not isinstance(miner_hotkey, str) or _SS58.fullmatch(miner_hotkey) is None:
        raise AdmissionError("miner_hotkey must be an SS58 address")
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
        raise AdmissionError(f"nonce must be exactly {NONCE_BYTES} bytes")
    if not any(nonce):
        raise AdmissionError("nonce is all zeros")
    if not isinstance(attested_at, datetime) or attested_at.utcoffset() is None:
        raise AdmissionError("attested_at must be a timezone-aware datetime")
    try:
        attested_iso = _iso(attested_at)
    except (OverflowError, ValueError) as exc:  # outside what UTC can represent
        raise AdmissionError("attested_at is out of range") from exc
    if last_released_at is not None and (
        not isinstance(last_released_at, datetime) or last_released_at.utcoffset() is None
    ):
        raise AdmissionError("last_released_at must be a timezone-aware datetime or None")
    if not isinstance(require_fresh_boot, bool):
        raise AdmissionError("require_fresh_boot must be a bool")
    if require_fresh_boot and kind != "tdx":
        # SNP has no guest-extendable report field (docs/TEE_BOX_SERVICE.md,
        # issue #274 B.d). SoftwareLeaseRegister is guest-local only.
        raise AdmissionError(
            "require_fresh_boot needs a TDX quote: SEV-SNP has no RTMR3-class "
            "register in the attestation report (issue #274 B.d BLOCKED)"
        )
    registry = _check_admitted(admitted)
    binding = _tls_binding(tls_certificate_der, tls_spki_der)

    (
        report_data,
        quote_measurement,
        quote_debug,
        quote_chip_id,
        quote_rtmr3,
        quote_image_measurement,
    ) = _parse_quote(quote, kind)
    # The verdict must be for these bytes, so the hash in the evidence names the
    # quote that was actually verified. A TDX verdict names the v1 launch
    # measurement or, when its policy listed only that, the v2 image identity.
    if attested.measurement != quote_measurement and (
        quote_image_measurement is None or attested.measurement != quote_image_measurement
    ):
        raise AdmissionError("the verdict's measurement is not the quote's")
    # A verdict matched on v2 cannot tell quotes apart by their owner fields,
    # so its v1 audit value, when the verifier reported one, must be this
    # quote's too (and likewise its v2 value).
    if (
        attested.launch_measurement is not None
        and attested.launch_measurement != quote_measurement
    ) or (
        attested.image_measurement is not None
        and attested.image_measurement != quote_image_measurement
    ):
        raise AdmissionError("the verdict's measurement is not the quote's")
    # The identity this policy is judged on: v1 unless the policy lists only
    # the v2 image identity. A policy listing v1 values behaves exactly as before.
    if (
        quote_image_measurement is not None
        and not policy.allows(quote_measurement)
        and policy.allows(quote_image_measurement)
    ):
        judged_measurement = quote_image_measurement
    else:
        judged_measurement = quote_measurement
    hardware_id_kind = HARDWARE_ID_KINDS[("tee", kind)]
    try:
        # One hardware identity per kind, derived as receipts derive it.
        if kind == "tdx":
            if not isinstance(attested.chip_id, str):
                raise AdmissionError("a tdx verdict needs the verifier's stable_platform_id")
            hardware_id = tdx_hardware_id(attested.chip_id)
        else:
            assert quote_chip_id is not None
            if attested.chip_id != quote_chip_id.hex():
                raise AdmissionError("the verdict's chip_id is not the report's")
            hardware_id = derive_hardware_id(hardware_id_kind, quote_chip_id)
        # The receipt's own evidence checks, so what admission hands T4 is a
        # value verify_receipt accepts.
        evidence = _check_evidence(
            {
                "evidence_kind": kind,
                "evidence_sha256": hashlib.sha256(quote).hexdigest(),
                "measurement": judged_measurement,
                "verifier_digest": verifier_digest,
                "tls_spki_sha256": binding.digest.hex(),
                "attestation_nonce": nonce.hex(),
                "attested_at": attested_iso,
            },
            kind,
        )
    except ReceiptError as exc:
        raise AdmissionError(str(exc)) from exc
    assert evidence is not None  # a TEE kind always yields evidence

    reasons: list[str] = []
    if not _complete(attested, kind) or quote_debug:
        reasons.append(VERIFICATION_INCOMPLETE)
    try:
        expected = report_data_v2(nonce, miner_hotkey, binding)
    except ValueError as exc:  # inputs are checked above; kept for a bare-exception-free API
        raise AdmissionError(str(exc)) from exc
    if not hmac.compare_digest(expected, report_data):
        reasons.append(REPORT_DATA_MISMATCH)
    measurement_allowed = policy.allows(evidence.measurement)
    if not measurement_allowed and policy.mode == "enforce":
        reasons.append(MEASUREMENT_NOT_ALLOWED)
    holder = registry.get(hardware_id)
    if holder is not None and (holder.box_id, holder.miner_hotkey) != (box_id, miner_hotkey):
        reasons.append(HARDWARE_ID_CLAIMED)
    # Strictly after: evidence verified in the same instant as the release may
    # have come from before it.
    if last_released_at is not None and attested_at <= last_released_at:
        reasons.append(ATTESTATION_PREDATES_RELEASE)
    if require_fresh_boot and quote_rtmr3 != _RTMR_ZERO:
        reasons.append(BOOT_CONSUMED)

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
        # Record-only in shadow: an unlisted measurement is never paid.
        evidence=evidence if not reasons and measurement_allowed else None,
        launch_measurement=quote_measurement if kind == "tdx" else None,
        image_measurement=quote_image_measurement,
    )
