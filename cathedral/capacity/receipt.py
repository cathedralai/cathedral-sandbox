"""Signed capacity receipts: what the prober saw on one box in one round.

The SN94 owner's prober creates a sandbox on a miner's box through its front
door, runs the capacity challenge, checks it, deletes the sandbox, and signs a
receipt. Validators on any netuid verify receipts with the prober keys they
pin; they never contact miner boxes themselves.

What a receipt binds, and what ``verify_receipt`` checks:

- audience: the netuid, the round and the requesting validator's nonce, so a
  validator must fetch its own receipts (copying another validator's weights
  gains nothing);
- the box: its id, the miner's hotkey, its kind and one canonical hardware
  identity for dedup, fixed by the kind (``derive_hardware_id`` over the
  digest in the TDX verifier's ``stable_platform_id``, the SEV-SNP chip id, or,
  for bare metal, ``probe_fingerprint`` of the probed address);
- the capacity paid for, which must be exactly what the challenge proved: the
  spec must equal ``spec_for(seed, vcpus=, memory_gib=)``;
- the proof: the committed result digest, the post-commitment sample nonce, the
  sample count (at least ``required_samples(lanes)``) and the outputs of exactly
  the lanes that nonce and count sample, so anyone can recompute which lanes
  were checked and re-check them;
- timing: the exec time must fit the deadline the prober set, and the deadline
  may be no looser than ``max_deadline_ms(spec)``;
- evidence (TEE boxes only, ``null`` for bare metal): which attestation the
  prober verified before it took the hardware id, as the SHA-256 of the raw
  quote or report, its launch measurement, the digest of the verifier that
  checked it, the attested TLS key's SPKI hash, the nonce the quote's
  REPORT_DATA was made over and when the prober verified it (no later than the
  receipt's ``issued_at``). With the archived quote anyone can audit it end to
  end: the hash, the measurement, the hardware id, and REPORT_DATA against
  :func:`expected_report_data` (the nonce, this box's hotkey and the TLS key);
  the receipt alone cannot re-verify the quote. ``verify_receipt`` can refuse
  evidence older than ``max_evidence_age``.

The prober signs bare-metal receipts only when told to (``sign_receipt(...,
allow_bare_metal=True)``): TEE boxes come first. ``verify_receipt`` accepts a
correctly signed bare-metal receipt; whether to pay for it is the validator's
own policy.

Wire form: canonical JSON (sorted keys, no whitespace, UTF-8) of the body, and
``signature`` = base64 Ed25519 over those bytes with the key named by
``prober_key_id``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.capacity.challenge import (
    ChallengeError,
    ChallengeSpec,
    max_deadline_ms,
    required_samples,
    sample_lanes,
    spec_for,
)
from cathedral.common import ChannelBinding, ChannelBindingType, report_data_v2

SCHEMA = "cathedral_capacity_receipt_v2"
BOX_KINDS = ("tee", "bare_metal")
# The one hardware identity each kind of box is deduplicated by: (kind, tee_kind) -> id kind.
HARDWARE_ID_KINDS = {
    ("tee", "tdx"): "tdx_platform",
    ("tee", "sev_snp"): "chip_id",
    ("bare_metal", None): "probe_fingerprint",
}
_RAW_ID_BYTES = {"tdx_platform": 32, "chip_id": 64, "probe_fingerprint": 9}
# The strict TDX verifier's stable_platform_id (cmd/cathedral-tdx-verifier/main.go
# stablePlatformID): "tdx-platform-sha256:" + hex(SHA-256(domain + PPID hex)).
_STABLE_PLATFORM_ID = re.compile(r"tdx-platform-sha256:([0-9a-f]{64})")
HARDWARE_ID_DOMAIN = b"cathedral.capacity.hardware_id.v1\x00"
MAX_VALIDITY = timedelta(hours=2)
CLOCK_SKEW = timedelta(minutes=5)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_SS58 = re.compile(r"[1-9A-HJ-NP-Za-km-z]{46,48}")
_BOX_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_LANE = re.compile(r"0|[1-9][0-9]{0,3}")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
# The verifier digest, as cathedral/verify/__init__.py's implementation digest
# and cathedral-validator's SNP verifier digest write it; a bare 64-hex digest
# (the QVL binary's SHA-256) is written with the prefix.
_VERIFIER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# The launch measurement each verifier reports: TDX as cathedral/verify/tdx_quote.py
# computes it (the v1 launch measurement, or the v2 image identity when the
# admission policy listed only that; docs/MRTD.md), SNP as the report's 48-byte
# MEASUREMENT in hex (cathedral/verify/snp.py).
_MEASUREMENT = {
    "tdx": re.compile(r"tdx-(?:measurement|image)-sha256:[0-9a-f]{64}"),
    "sev_snp": re.compile(r"[0-9a-f]{96}"),
}
_EVIDENCE_KEYS = frozenset(
    {
        "evidence_kind",
        "evidence_sha256",
        "measurement",
        "verifier_digest",
        "tls_spki_sha256",
        "attestation_nonce",
        "attested_at",
    }
)
_BODY_KEYS = frozenset(
    {
        "schema",
        "netuid",
        "round",
        "validator_nonce",
        "box",
        "capacity",
        "challenge",
        "timings_ms",
        "issued_at",
        "expires_at",
        "prober_key_id",
        "evidence",
    }
)
_BOX_KEYS = frozenset(
    {"box_id", "miner_hotkey", "kind", "tee_kind", "hardware_id", "hardware_id_kind"}
)
_CHALLENGE_KEYS = frozenset(
    {
        "seed",
        "lanes",
        "blocks",
        "steps",
        "result_digest",
        "sample_nonce",
        "sample_count",
        "sampled_outputs",
        "deadline_ms",
    }
)


class ReceiptError(ValueError):
    """A receipt is malformed, unsigned, stale, or not for this validator."""


@dataclass(frozen=True)
class ReceiptEvidence:
    """The attestation a TEE box's receipt rests on (docs/CAPACITY.md)."""

    evidence_kind: str  # the box's tee_kind: tdx or sev_snp
    evidence_sha256: str  # SHA-256 of the raw quote or report the prober verified
    # tdx-measurement-sha256:<64 hex> or tdx-image-sha256:<64 hex>, or the SNP
    # MEASUREMENT's 96 hex
    measurement: str
    verifier_digest: str  # sha256:<64 hex>
    tls_spki_sha256: str  # SHA-256 of the SPKI of the TLS key the evidence attests
    attestation_nonce: str  # 64 hex: the 32-byte nonce REPORT_DATA was made over
    attested_at: str  # YYYY-MM-DDTHH:MM:SSZ: when the prober verified the quote


@dataclass(frozen=True)
class VerifiedReceipt:
    box_id: str
    miner_hotkey: str
    kind: str
    tee_kind: str | None
    hardware_id: str
    hardware_id_kind: str
    vcpus: int
    memory_gib: int
    challenge: ChallengeSpec
    result_digest: bytes
    sample_nonce: bytes
    sample_count: int
    sampled_outputs: Mapping[int, bytes]
    deadline_ms: int
    timings_ms: Mapping[str, int]
    round: int
    issued_at: datetime
    evidence: ReceiptEvidence | None  # None for bare metal


def canonical_bytes(body: Mapping[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise ReceiptError(f"{name} must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:  # the right shape, but no such date or time
        raise ReceiptError(f"{name} is not a real date and time") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _aware(now: object) -> datetime:
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ReceiptError("now must be a timezone-aware datetime")
    return now


def _count(value: object, name: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ReceiptError(f"{name} must be an integer of at least {minimum}")
    return value


def _hex64(value: object, name: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ReceiptError(f"{name} must be 64 lowercase hex characters")
    return value


def derive_hardware_id(hardware_id_kind: str, raw: bytes) -> str:
    """The receipt's ``hardware_id``: SHA-256 over the id kind and the raw id
    the prober took from evidence it verified itself (for TDX the 32-byte digest
    in the strict verifier's ``stable_platform_id``, see :func:`tdx_hardware_id`;
    the 64-byte CHIP_ID from the SEV-SNP report), or ``probe_fingerprint``'s 9
    bytes for bare metal. One machine therefore has exactly one hardware id per
    kind of box."""

    size = _RAW_ID_BYTES.get(hardware_id_kind)
    if size is None:
        raise ReceiptError("hardware_id_kind must be tdx_platform, chip_id or probe_fingerprint")
    if not isinstance(raw, bytes) or len(raw) != size:
        raise ReceiptError(f"a raw {hardware_id_kind} is {size} bytes")
    if not any(raw):
        raise ReceiptError(f"the {hardware_id_kind} is all zeros (masked or missing)")
    return hashlib.sha256(
        HARDWARE_ID_DOMAIN + hardware_id_kind.encode() + b"\x00" + raw
    ).hexdigest()


def tdx_hardware_id(stable_platform_id: str) -> str:
    """A TDX box's ``hardware_id``, from the ``stable_platform_id`` the pinned
    strict verifier emitted for a quote the prober verified itself (with
    ``platform_identity_verified`` and ``claims_bound_to_quote`` true). The raw
    ``tdx_platform`` id is the 32-byte digest after ``tdx-platform-sha256:``;
    the verifier never outputs the PPID itself. The value is stable only under
    the pinned Go verifier: the Polaris wrapper derives a different
    ``stable_platform_id`` for the same platform (docs/CAPACITY.md)."""

    if not isinstance(stable_platform_id, str):
        raise ReceiptError("stable_platform_id must be a string")
    match = _STABLE_PLATFORM_ID.fullmatch(stable_platform_id)
    if match is None:
        raise ReceiptError("stable_platform_id must be tdx-platform-sha256:<64 lowercase hex>")
    return derive_hardware_id("tdx_platform", bytes.fromhex(match.group(1)))


def probe_fingerprint(address: str) -> str:
    """A bare-metal box's ``hardware_id``: the address the prober itself
    connected to and ran the challenge through, never anything the box reports.
    It keeps the IPv4 address, or only the /64 of an IPv6 address, and never the
    port, so one host behind one address is one id however many ports or IPv6
    interface ids it registers. An IPv4-mapped IPv6 address counts as its IPv4
    address. Honest boxes sharing one address (behind one NAT) therefore count
    as one box: the conservative choice (docs/CAPACITY.md)."""

    if not isinstance(address, str):
        raise ReceiptError("probe address must be an IP address string")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ReceiptError("probe address must be an IP address") from exc
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address):
        raw = b"\x04" + ip.packed + bytes(4)  # the whole IPv4 address
    else:
        raw = b"\x06" + ip.packed[:8]  # the IPv6 /64
    return derive_hardware_id("probe_fingerprint", raw)


def make_body(
    *,
    netuid: int,
    round: int,
    validator_nonce: str,
    box_id: str,
    miner_hotkey: str,
    kind: str,
    tee_kind: str | None,
    hardware_id: str,
    vcpus: int,
    memory_gib: int,
    challenge: ChallengeSpec,
    result_digest: bytes,
    sample_nonce: bytes,
    sample_count: int,
    sampled_outputs: Mapping[int, bytes],
    deadline_ms: int,
    timings_ms: Mapping[str, int],
    issued_at: datetime,
    valid_for: timedelta,
    prober_key_id: str,
    evidence: Mapping[str, str] | None,
) -> dict[str, Any]:
    """The body the prober signs. ``evidence`` is required for a TEE box (the
    seven ``_EVIDENCE_KEYS``, as ``dataclasses.asdict`` of a ``ReceiptEvidence``
    gives them) and must be None for bare metal; ``sign_receipt`` checks it."""

    return {
        "schema": SCHEMA,
        "netuid": netuid,
        "round": round,
        "validator_nonce": validator_nonce,
        "box": {
            "box_id": box_id,
            "miner_hotkey": miner_hotkey,
            "kind": kind,
            "tee_kind": tee_kind,
            "hardware_id": hardware_id,
            # fixed by the kind; None for a combination _check_body refuses
            "hardware_id_kind": HARDWARE_ID_KINDS.get((kind, tee_kind)),
        },
        "capacity": {"vcpus": vcpus, "memory_gib": memory_gib},
        "challenge": {
            **challenge.to_json(),
            "result_digest": result_digest.hex(),
            "sample_nonce": sample_nonce.hex(),
            "sample_count": sample_count,
            "sampled_outputs": {str(k): v.hex() for k, v in sorted(sampled_outputs.items())},
            "deadline_ms": deadline_ms,
        },
        "timings_ms": dict(timings_ms),
        "issued_at": _iso(issued_at),
        "expires_at": _iso(issued_at + valid_for),
        "prober_key_id": prober_key_id,
        # copied if it is a mapping; anything else is left for _check_body to refuse
        "evidence": dict(evidence) if isinstance(evidence, Mapping) else evidence,
    }


def sign_receipt(
    body: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    allow_bare_metal: bool = False,
) -> dict[str, Any]:
    """The prober's side: sign a body (checked first, so it never signs junk).
    A bare-metal body is refused unless ``allow_bare_metal`` is True: TEE boxes
    come first, and bare metal is deferred."""

    if not isinstance(body, Mapping):
        raise ReceiptError("body must be an object")
    if "signature" in body:
        raise ReceiptError("body already carries a signature")
    if _check_body(body).kind == "bare_metal" and allow_bare_metal is not True:
        raise ReceiptError(
            "refusing to sign a bare-metal receipt: TEE boxes come first;"
            " pass allow_bare_metal=True to sign one"
        )
    signature = private_key.sign(canonical_bytes(body))
    return {**body, "signature": base64.b64encode(signature).decode()}


def verify_receipt(
    receipt: Mapping[str, Any],
    *,
    prober_keys: Mapping[str, Ed25519PublicKey],
    netuid: int,
    validator_nonce: str,
    now: datetime,
    expected_round: int,
    max_evidence_age: timedelta | None = None,
) -> VerifiedReceipt:
    """A validator's side: signature, audience (netuid, nonce and round),
    freshness and shape, or raise. ``max_evidence_age``, when given, also
    refuses a TEE receipt whose evidence was verified longer ago than that
    before ``now``: the attestation a receipt rests on is reused across rounds,
    and this is how a validator bounds its age."""

    now = _aware(now)
    _count(expected_round, "expected_round")
    if max_evidence_age is not None and (
        not isinstance(max_evidence_age, timedelta) or max_evidence_age <= timedelta(0)
    ):
        raise ReceiptError("max_evidence_age must be a positive timedelta or None")
    if not isinstance(receipt, Mapping) or "signature" not in receipt:
        raise ReceiptError("receipt is not a signed object")
    body = {key: value for key, value in receipt.items() if key != "signature"}
    parsed = _check_body(body)
    key = prober_keys.get(body["prober_key_id"])
    if key is None:
        raise ReceiptError("receipt is signed by an unknown prober key")
    try:
        signature = base64.b64decode(receipt["signature"], validate=True)
        key.verify(signature, canonical_bytes(body))
    except (InvalidSignature, binascii.Error, TypeError, ValueError) as exc:
        raise ReceiptError("receipt signature does not verify") from exc
    if body["netuid"] != netuid:
        raise ReceiptError("receipt is for another netuid")
    if body["validator_nonce"] != validator_nonce:
        raise ReceiptError("receipt answers another validator's nonce")
    if parsed.round != expected_round:
        raise ReceiptError("receipt is from another round")
    expires_at = _parse_time(body["expires_at"], "expires_at")
    if not (parsed.issued_at <= now + CLOCK_SKEW and now < expires_at):
        raise ReceiptError("receipt is not currently valid")
    if max_evidence_age is not None and parsed.evidence is not None:
        attested_at = _parse_time(parsed.evidence.attested_at, "attested_at")
        if now - attested_at > max_evidence_age:
            raise ReceiptError("the receipt's evidence is older than max_evidence_age")
    return parsed


def expected_report_data(verified: VerifiedReceipt) -> bytes:
    """The 64-byte REPORT_DATA the quote behind a TEE receipt must carry:
    ``report_data_v2(attestation_nonce, miner_hotkey, tls_spki_sha256)``, the
    worker's v2 channel binding. An auditor holding the archived quote checks
    its SHA-256 against ``evidence_sha256``, verifies it, and compares its
    REPORT_DATA to this, which shows the quote was made for this box's hotkey,
    the TLS key the prober pinned, and the prober's nonce, not replayed from
    another box. Bare-metal receipts have no evidence and are refused."""

    if not isinstance(verified, VerifiedReceipt) or verified.evidence is None:
        raise ReceiptError("only a verified TEE receipt has evidence to audit")
    evidence = verified.evidence
    try:
        return report_data_v2(
            bytes.fromhex(evidence.attestation_nonce),
            verified.miner_hotkey,
            ChannelBinding(
                ChannelBindingType.TLS_SPKI_SHA256, bytes.fromhex(evidence.tls_spki_sha256)
            ),
        )
    except ValueError as exc:
        raise ReceiptError(f"evidence: {exc}") from exc


def _check_body(body: Mapping[str, Any]) -> VerifiedReceipt:
    if set(body) != _BODY_KEYS or body.get("schema") != SCHEMA:
        raise ReceiptError("receipt body has the wrong fields or schema")
    _count(body["netuid"], "netuid")
    round_ = _count(body["round"], "round")
    _hex64(body["validator_nonce"], "validator_nonce")
    if (
        not isinstance(body["prober_key_id"], str)
        or _KEY_ID.fullmatch(body["prober_key_id"]) is None
    ):
        raise ReceiptError("prober_key_id is malformed")

    box = body["box"]
    if not isinstance(box, Mapping) or set(box) != _BOX_KEYS:
        raise ReceiptError(f"box must have exactly {sorted(_BOX_KEYS)}")
    if not isinstance(box["box_id"], str) or _BOX_ID.fullmatch(box["box_id"]) is None:
        raise ReceiptError("box_id is malformed")
    if not isinstance(box["miner_hotkey"], str) or _SS58.fullmatch(box["miner_hotkey"]) is None:
        raise ReceiptError("miner_hotkey is not an SS58 address")
    if box["kind"] not in BOX_KINDS:
        raise ReceiptError("box kind must be tee or bare_metal")
    tee_kind = box["tee_kind"]
    if not (tee_kind is None or isinstance(tee_kind, str)) or (
        (box["kind"], tee_kind) not in HARDWARE_ID_KINDS
    ):
        raise ReceiptError("tee_kind must be tdx or sev_snp for a tee box, and null for bare metal")
    if box["hardware_id_kind"] != HARDWARE_ID_KINDS[(box["kind"], tee_kind)]:
        raise ReceiptError(
            "hardware_id_kind must be tdx_platform for tdx, chip_id for sev_snp and"
            " probe_fingerprint for bare metal"
        )
    hardware_id = _hex64(box["hardware_id"], "hardware_id")

    capacity = body["capacity"]
    if not isinstance(capacity, Mapping) or set(capacity) != {"vcpus", "memory_gib"}:
        raise ReceiptError("capacity must have vcpus and memory_gib")
    vcpus = _count(capacity["vcpus"], "vcpus", minimum=1)
    memory_gib = _count(capacity["memory_gib"], "memory_gib", minimum=1)

    challenge = body["challenge"]
    if not isinstance(challenge, Mapping) or set(challenge) != _CHALLENGE_KEYS:
        raise ReceiptError(f"challenge must have exactly {sorted(_CHALLENGE_KEYS)}")
    try:
        spec = ChallengeSpec.from_json(
            {name: challenge[name] for name in ("seed", "lanes", "blocks", "steps")}
        )
        expected = spec_for(spec.seed, vcpus=vcpus, memory_gib=memory_gib)
    except ChallengeError as exc:
        raise ReceiptError(f"challenge: {exc}") from exc
    if spec != expected:
        raise ReceiptError("the challenge does not prove the capacity the receipt pays for")
    digest = bytes.fromhex(_hex64(challenge["result_digest"], "result_digest"))
    sample_nonce = bytes.fromhex(_hex64(challenge["sample_nonce"], "sample_nonce"))
    sampled = challenge["sampled_outputs"]
    if not isinstance(sampled, Mapping):
        raise ReceiptError("sampled_outputs must be an object")
    outputs: dict[int, bytes] = {}
    for lane, value in sampled.items():
        if not isinstance(lane, str) or _LANE.fullmatch(lane) is None:
            raise ReceiptError("sampled lane keys must be plain decimal lane numbers")
        outputs[int(lane)] = bytes.fromhex(_hex64(value, "sampled output"))
    sample_count = _count(challenge["sample_count"], "sample_count", minimum=1)
    if not required_samples(spec.lanes) <= sample_count <= spec.lanes:
        raise ReceiptError(
            f"sample_count must be from {required_samples(spec.lanes)} to {spec.lanes}"
            f" for {spec.lanes} lanes"
        )
    wanted = sample_lanes(spec, digest, sample_nonce, sample_count)
    if sorted(outputs) != wanted:
        raise ReceiptError("sampled_outputs must be exactly the lanes the sample nonce picks")
    deadline_ms = _count(challenge["deadline_ms"], "deadline_ms", minimum=1)
    if deadline_ms > max_deadline_ms(spec):
        raise ReceiptError(f"deadline_ms is looser than {max_deadline_ms(spec)} for this challenge")

    timings = body["timings_ms"]
    if not isinstance(timings, Mapping) or set(timings) != {"create", "exec", "delete"}:
        raise ReceiptError("timings_ms must have create, exec and delete")
    for name, value in timings.items():
        _count(value, f"timings_ms.{name}")
    if timings["exec"] > deadline_ms:
        raise ReceiptError("the challenge finished after its deadline")

    issued_at = _parse_time(body["issued_at"], "issued_at")
    expires_at = _parse_time(body["expires_at"], "expires_at")
    if not timedelta(0) < expires_at - issued_at <= MAX_VALIDITY:
        raise ReceiptError("receipt validity must be positive and at most 2 hours")
    evidence = _check_evidence(body["evidence"], tee_kind, issued_at=issued_at)
    return VerifiedReceipt(
        box_id=box["box_id"],
        miner_hotkey=box["miner_hotkey"],
        kind=box["kind"],
        tee_kind=tee_kind,
        hardware_id=hardware_id,
        hardware_id_kind=box["hardware_id_kind"],
        vcpus=vcpus,
        memory_gib=memory_gib,
        challenge=spec,
        result_digest=digest,
        sample_nonce=sample_nonce,
        sample_count=sample_count,
        sampled_outputs=outputs,
        deadline_ms=deadline_ms,
        timings_ms=dict(timings),
        round=round_,
        issued_at=issued_at,
        evidence=evidence,
    )


def _check_evidence(
    evidence: object, tee_kind: str | None, *, issued_at: datetime | None = None
) -> ReceiptEvidence | None:
    """Required for a TEE box and null for bare metal; ``tee_kind`` is already
    checked. ``issued_at`` is the receipt's: the evidence cannot be later."""

    if tee_kind is None:
        if evidence is not None:
            raise ReceiptError("a bare-metal receipt carries no evidence (null)")
        return None
    if not isinstance(evidence, Mapping) or set(evidence) != _EVIDENCE_KEYS:
        raise ReceiptError(f"a tee receipt's evidence must have exactly {sorted(_EVIDENCE_KEYS)}")
    if not isinstance(evidence["evidence_kind"], str) or evidence["evidence_kind"] != tee_kind:
        raise ReceiptError("evidence_kind must equal the box's tee_kind")
    measurement = evidence["measurement"]
    if not isinstance(measurement, str) or _MEASUREMENT[tee_kind].fullmatch(measurement) is None:
        raise ReceiptError(
            "measurement must be tdx-measurement-sha256:<64 hex> or"
            " tdx-image-sha256:<64 hex> for tdx and 96 lowercase hex for sev_snp"
        )
    if not any(bytes.fromhex(measurement.rpartition(":")[2])):
        raise ReceiptError("measurement is all zeros")
    verifier_digest = evidence["verifier_digest"]
    if not isinstance(verifier_digest, str) or _VERIFIER_DIGEST.fullmatch(verifier_digest) is None:
        raise ReceiptError("verifier_digest must be sha256:<64 lowercase hex>")
    attestation_nonce = _hex64(evidence["attestation_nonce"], "attestation_nonce")
    if not any(bytes.fromhex(attestation_nonce)):
        raise ReceiptError("attestation_nonce is all zeros")
    attested_at = _parse_time(evidence["attested_at"], "attested_at")
    if issued_at is not None and attested_at > issued_at:
        raise ReceiptError("attested_at is after the receipt's issued_at")
    return ReceiptEvidence(
        evidence_kind=tee_kind,
        evidence_sha256=_hex64(evidence["evidence_sha256"], "evidence_sha256"),
        measurement=measurement,
        verifier_digest=verifier_digest,
        tls_spki_sha256=_hex64(evidence["tls_spki_sha256"], "tls_spki_sha256"),
        attestation_nonce=attestation_nonce,
        attested_at=evidence["attested_at"],
    )
