"""TEE box admission (cathedral/capacity/admission.py, docs/CAPACITY.md "Admission")."""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import random
import struct
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cathedral.capacity import admission as adm
from cathedral.capacity import receipt
from cathedral.channel import extract_spki_der
from cathedral.common import Attested, ChannelBinding, ChannelBindingType, Tier, report_data_v2
from cathedral.tee_box.boot import RTMR3_CONSUMED
from cathedral.verify import snp
from cathedral.verify.tdx_quote import parse_tdx_quote
from tests.tdx_quote_fixtures import synthetic_tdx_quote

HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
OTHER_HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
NONCE = bytes(range(1, 33))
PPID = bytes.fromhex("0123456789abcdef0123456789abcdef")
CHIP_ID = bytes(range(1, 65))
MR_TD = b"M" * 48
OTHER_MR_TD = b"N" * 48  # another image
SNP_MEASUREMENT = "c3" * 48
SNP_OTHER = "d4" * 48
VERIFIER = "sha256:" + "5e" * 32
ATTESTED_AT = datetime(2026, 9, 28, 11, 0, 0, tzinfo=timezone.utc)
_RNG = random.SystemRandom()


def _certificate() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "box.example")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


CERT = _certificate()
OTHER_CERT = _certificate()


def _v2_by_hand(nonce: bytes, hotkey: str, certificate: bytes) -> bytes:
    """REPORT_DATA v2 written out from its layout, not from the library, so the
    admission check is pinned to the worker's and cathedral-validator's format."""

    def field(tag: int, value: bytes) -> bytes:
        return bytes((tag,)) + struct.pack(">H", len(value)) + value

    spki = hashlib.sha256(extract_spki_der(certificate)).digest()
    return hashlib.sha512(
        b"cathedral.report-data\x00"
        + struct.pack(">H", 2)
        + field(1, nonce)
        + field(2, hotkey.encode())
        + field(3, b"tls_spki_sha256")
        + field(4, spki)
    ).digest()


def _stable_platform_id(ppid: bytes) -> str:
    # cmd/cathedral-tdx-verifier/main.go stablePlatformID, written out.
    digest = hashlib.sha256(b"cathedral-tdx-platform-v1\x00" + ppid.hex().encode()).hexdigest()
    return "tdx-platform-sha256:" + digest


STABLE_ID = _stable_platform_id(PPID)
OTHER_STABLE_ID = _stable_platform_id(bytes(reversed(PPID)))  # another platform
REPORT_DATA = _v2_by_hand(NONCE, HOTKEY, CERT)


def _tdx_quote(report_data: bytes = REPORT_DATA, mr_td: bytes = MR_TD, **changes) -> bytes:
    return synthetic_tdx_quote(report_data=report_data, mr_td=mr_td, **changes)


TDX_MEASUREMENT = parse_tdx_quote(_tdx_quote()).measurement
TDX_OTHER = parse_tdx_quote(_tdx_quote(mr_td=OTHER_MR_TD)).measurement


def _snp_report(
    report_data: bytes = REPORT_DATA, measurement: str = SNP_MEASUREMENT, chip_id: bytes = CHIP_ID
) -> bytes:
    """A raw 1184-byte SEV-SNP report at cathedral/verify/snp.py's offsets."""

    report = bytearray(snp.SNP_REPORT_SIZE)
    report[snp.REPORT_DATA_OFFSET : snp.REPORT_DATA_OFFSET + 64] = report_data
    report[snp.MEASUREMENT_OFFSET : snp.MEASUREMENT_OFFSET + 48] = bytes.fromhex(measurement)
    report[snp.CHIP_ID_OFFSET : snp.CHIP_ID_OFFSET + 64] = chip_id
    report[snp.SIGNATURE_OFFSET : snp.SIGNATURE_OFFSET + snp.SIGNATURE_SIZE] = b"\x5a" * 512
    return bytes(report)


def _tdx(quote: bytes | None = None, **changes) -> tuple[Attested, bytes]:
    """A strict TDX verdict, as cathedral/verify/__init__.py returns it, and its quote."""

    quote = _tdx_quote() if quote is None else quote
    base = Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id=STABLE_ID,
        measurement=parse_tdx_quote(quote).measurement,
        tcb=0,
        verification_status="VERIFIED",
        chain_verified=True,
        tcb_status="UpToDate",
        debug_enabled=False,
        collateral_current=True,
        platform_identity_kind="stable",
        policy_mode="strict",
    )
    return dataclasses.replace(base, **changes), quote


def _snp(report: bytes | None = None, **changes) -> tuple[Attested, bytes]:
    """A chain-verified SEV-SNP verdict, as verify_snp returns it, and its report."""

    report = _snp_report() if report is None else report
    parsed = snp.parse_snp_report(report)
    base = Attested(
        tier=Tier.CC_CPU_SNP,
        chip_id=parsed.chip_id,  # hex, as cathedral/verify/snp.py reports it
        measurement=parsed.measurement,
        tcb=1,
        verification_status="VERIFIED",
        chain_verified=True,
    )
    return dataclasses.replace(base, **changes), report


def _kind(pair) -> str:
    return "tdx" if getattr(pair[0], "tier", None) == Tier.CC_CPU_TDX else "sev_snp"


def _policy(kind: str = "tdx", mode: str = "enforce", allowed=None) -> adm.MeasurementPolicy:
    if allowed is None:
        allowed = [TDX_MEASUREMENT] if kind == "tdx" else [SNP_MEASUREMENT]
    return adm.parse_policy(_policy_bytes(kind, mode, allowed))


def _policy_bytes(kind: str, mode: str, allowed) -> bytes:
    document = {"schema": adm.POLICY_SCHEMAS[kind], "mode": mode, "allowed_measurements": allowed}
    return json.dumps(document).encode()


def _admit(pair, **changes) -> adm.Admission:
    attested, quote = pair
    arguments = {
        "verifier_digest": VERIFIER,
        "box_id": "box-1",
        "miner_hotkey": HOTKEY,
        "nonce": NONCE,
        "attested_at": ATTESTED_AT,
        "policy": _policy(_kind(pair)),
        "admitted": {},
        "tls_certificate_der": CERT,
    }
    arguments.update(changes)
    return adm.admit(attested, quote, **arguments)


# -- happy path ----------------------------------------------------------------------


def test_report_data_check_is_the_existing_v2_channel_binding():
    binding = ChannelBinding(
        ChannelBindingType.TLS_SPKI_SHA256, hashlib.sha256(extract_spki_der(CERT)).digest()
    )
    assert _v2_by_hand(NONCE, HOTKEY, CERT) == report_data_v2(NONCE, HOTKEY, binding)


def test_a_tdx_box_is_admitted_with_receipt_evidence():
    result = _admit(_tdx())
    assert result.admitted and result.reasons == ()
    assert result.hardware_id_kind == "tdx_platform"
    # the receipt's TDX hardware id: the digest in the verifier's stable_platform_id
    assert result.hardware_id == receipt.tdx_hardware_id(STABLE_ID)
    assert result.hardware_id == receipt.derive_hardware_id(
        "tdx_platform", bytes.fromhex(STABLE_ID.removeprefix("tdx-platform-sha256:"))
    )
    assert (result.measurement_allowed, result.mode) == (True, "enforce")
    assert result.policy_digest.startswith("sha256:")
    spki = hashlib.sha256(extract_spki_der(CERT)).hexdigest()
    assert result.evidence == receipt.ReceiptEvidence(
        evidence_kind="tdx",
        evidence_sha256=hashlib.sha256(_tdx_quote()).hexdigest(),  # hashed here, not passed in
        measurement=TDX_MEASUREMENT,
        verifier_digest=VERIFIER,
        tls_spki_sha256=spki,
        attestation_nonce=NONCE.hex(),
        attested_at="2026-09-28T11:00:00Z",
    )
    # what admission hands T4 is exactly what a receipt's evidence check accepts
    assert receipt._check_evidence(dataclasses.asdict(result.evidence), "tdx") == result.evidence


def test_a_snp_box_is_admitted_with_receipt_evidence():
    result = _admit(_snp())
    assert result.admitted and result.reasons == ()
    assert result.hardware_id_kind == "chip_id"
    assert result.hardware_id == receipt.derive_hardware_id("chip_id", CHIP_ID)
    assert result.evidence.evidence_kind == "sev_snp"
    assert result.evidence.measurement == SNP_MEASUREMENT
    assert result.evidence.evidence_sha256 == hashlib.sha256(_snp_report()).hexdigest()
    assert (
        receipt._check_evidence(dataclasses.asdict(result.evidence), "sev_snp") == result.evidence
    )


def test_admission_evidence_audits_against_the_quote():
    # The evidence carries the nonce, so a receipt signed over it lets an auditor
    # recompute the quote's REPORT_DATA (receipt.expected_report_data).
    result = _admit(_tdx())
    assert result.evidence.attestation_nonce == NONCE.hex()
    assert (
        bytes.fromhex(result.evidence.tls_spki_sha256)
        == hashlib.sha256(extract_spki_der(CERT)).digest()
    )
    binding = ChannelBinding(
        ChannelBindingType.TLS_SPKI_SHA256, bytes.fromhex(result.evidence.tls_spki_sha256)
    )
    expected = report_data_v2(bytes.fromhex(result.evidence.attestation_nonce), HOTKEY, binding)
    assert parse_tdx_quote(_tdx_quote()).report_data == expected


def test_there_is_no_raw_ppid_or_caller_hash_input():
    # No TDX verifier outputs the raw PPID; the hardware id is the stable_platform_id's.
    # The quote's hash and REPORT_DATA come from the quote bytes, never from the caller.
    names = set(inspect.signature(adm.admit).parameters)
    for absent in ("hardware_id", "ppid", "evidence_sha256", "report_data", "measurement"):
        assert absent not in names
    assert not hasattr(adm, "VerifiedAttestation")
    assert not hasattr(adm, "PLATFORM_ID_MISMATCH")


def test_certificate_and_its_spki_give_the_same_decision():
    by_cert = _admit(_tdx())
    by_spki = _admit(_tdx(), tls_certificate_der=None, tls_spki_der=extract_spki_der(CERT))
    assert by_cert == by_spki


# -- REPORT_DATA binding --------------------------------------------------------------


@pytest.mark.parametrize("make", [_tdx, _snp])
@pytest.mark.parametrize(
    "changes",
    [
        {"nonce": bytes(reversed(NONCE))},  # another prober round
        {"tls_certificate_der": OTHER_CERT},  # another TLS endpoint
        {"miner_hotkey": OTHER_HOTKEY},  # another miner
    ],
    ids=["wrong_nonce", "wrong_spki", "wrong_hotkey"],
)
def test_report_data_for_another_nonce_key_or_hotkey_is_refused(make, changes):
    result = _admit(make(), **changes)
    assert not result.admitted
    assert result.reasons == (adm.REPORT_DATA_MISMATCH,)
    assert result.evidence is None


def test_an_application_key_binding_of_the_same_digest_is_not_a_tls_binding():
    spki = hashlib.sha256(extract_spki_der(CERT)).digest()
    other_type = ChannelBinding(ChannelBindingType.APPLICATION_KEY_SHA256, spki)
    result = _admit(_tdx(_tdx_quote(report_data=report_data_v2(NONCE, HOTKEY, other_type))))
    assert result.reasons == (adm.REPORT_DATA_MISMATCH,)


@pytest.mark.parametrize("make", ["tdx", "sev_snp"])
def test_report_data_is_read_from_the_quote_itself(make):
    # A quote made over another nonce is refused even though its verdict is complete.
    other = _v2_by_hand(bytes(reversed(NONCE)), HOTKEY, CERT)
    pair = _tdx(_tdx_quote(report_data=other)) if make == "tdx" else _snp(_snp_report(other))
    assert _admit(pair).reasons == (adm.REPORT_DATA_MISMATCH,)


def test_a_tdx_hardware_id_follows_the_stable_platform_id():
    here = _admit(_tdx())
    other = _admit(_tdx(chip_id=OTHER_STABLE_ID))
    assert other.admitted and other.hardware_id == receipt.tdx_hardware_id(OTHER_STABLE_ID)
    assert other.hardware_id != here.hardware_id
    # A box whose stable_platform_id is not the one admitted is another machine,
    # and one presenting an admitted platform's id is that machine.
    admitted = {here.hardware_id: adm.AdmittedBox("box-1", HOTKEY)}
    assert _admit(_tdx(chip_id=OTHER_STABLE_ID), box_id="box-2", admitted=admitted).admitted
    claimed = _admit(_tdx(), box_id="box-2", admitted=admitted)
    assert claimed.reasons == (adm.HARDWARE_ID_CLAIMED,)


# -- measurement policy -----------------------------------------------------------------


def _unlisted(kind: str):
    if kind == "tdx":
        return _tdx(_tdx_quote(mr_td=OTHER_MR_TD)), TDX_OTHER
    return _snp(_snp_report(measurement=SNP_OTHER)), SNP_OTHER


@pytest.mark.parametrize("kind", ["tdx", "sev_snp"])
def test_enforce_refuses_an_unlisted_measurement_and_shadow_records_it_unpaid(kind):
    pair, other = _unlisted(kind)
    enforce = _admit(pair, policy=_policy(kind, "enforce"))
    assert not enforce.admitted
    assert enforce.reasons == (adm.MEASUREMENT_NOT_ALLOWED,)
    assert (enforce.measurement_allowed, enforce.mode) == (False, "enforce")
    assert enforce.evidence is None

    # Shadow records the box and its measurement but hands out no receipt
    # evidence: an unvetted image could attest a relay's TLS key, so its
    # capacity must not be paid at TEE rates.
    shadow = _admit(pair, policy=_policy(kind, "shadow"))
    assert shadow.admitted and shadow.reasons == ()
    assert (shadow.measurement_allowed, shadow.mode) == (False, "shadow")
    assert shadow.measurement == other
    assert shadow.evidence is None

    listed = _admit(_tdx() if kind == "tdx" else _snp(), policy=_policy(kind, "shadow"))
    assert listed.admitted and listed.measurement_allowed
    assert listed.evidence is not None  # a listed measurement pays in shadow too


def test_an_empty_shadow_policy_admits_everything_and_pays_nothing():
    result = _admit(_tdx(), policy=_policy("tdx", "shadow", []))
    assert result.admitted and not result.measurement_allowed
    assert result.evidence is None


# -- verification completeness ------------------------------------------------------------


_INCOMPLETE_TDX = {
    # a compatibility-mode TDX verdict skips the strict collateral and identity gates
    "compatibility_mode": {"policy_mode": "compatibility"},
    "no_policy_mode": {"policy_mode": None},
    "collateral_stale": {"collateral_current": False},
    "collateral_unknown": {"collateral_current": None},
    "debug_on": {"debug_enabled": True},
    "debug_unknown": {"debug_enabled": None},
    "unverified": {"verification_status": "UNVERIFIED"},
    "chain_unverified": {"chain_verified": False},
    "chain_truthy": {"chain_verified": 1},
}
_INCOMPLETE_SNP = {
    # verify_snp_report_data(require_chain=False): "must never be used for admission"
    "structure_only": {
        "verification_status": snp.STRUCTURE_OK_CHAIN_UNVERIFIED,
        "chain_verified": False,
    },
    "status_only": {"verification_status": snp.STRUCTURE_OK_CHAIN_UNVERIFIED},
    "chain_only": {"chain_verified": False},
    "default_verdict": {"verification_status": "UNVERIFIED", "chain_verified": False},
}


@pytest.mark.parametrize(
    "kind, changes",
    [("tdx", c) for c in _INCOMPLETE_TDX.values()]
    + [("sev_snp", c) for c in _INCOMPLETE_SNP.values()],
    ids=[f"tdx-{n}" for n in _INCOMPLETE_TDX] + [f"snp-{n}" for n in _INCOMPLETE_SNP],
)
def test_a_partial_verification_is_refused(kind, changes):
    pair = _tdx(**changes) if kind == "tdx" else _snp(**changes)
    result = _admit(pair)
    assert not result.admitted
    assert result.reasons == (adm.VERIFICATION_INCOMPLETE,)
    assert result.evidence is None
    # in shadow too: the policy mode never relaxes the verification
    assert _admit(pair, policy=_policy(kind, "shadow")).reasons == (adm.VERIFICATION_INCOMPLETE,)


def test_a_debug_quote_is_refused_even_under_a_debug_off_verdict():
    quote = _tdx_quote(td_attributes=(1).to_bytes(8, "little"))
    result = _admit(_tdx(quote), policy=_policy("tdx", "shadow"))
    assert result.reasons == (adm.VERIFICATION_INCOMPLETE,)


def test_the_snp_verdict_needs_no_tdx_fields():
    # verify_snp leaves policy_mode, collateral_current and debug_enabled unset;
    # the report's own debug bit is checked by the verifier.
    attested, _ = _snp()
    assert (attested.policy_mode, attested.collateral_current, attested.debug_enabled) == (
        None,
        None,
        None,
    )
    assert _admit(_snp()).admitted


@pytest.mark.parametrize("kind", ["tdx", "sev_snp"])
def test_the_verdict_must_be_for_the_quote(kind):
    # A verdict for one quote with another quote's bytes: the evidence hash
    # would name bytes nobody verified.
    if kind == "tdx":
        attested, _ = _tdx()
        pair = (attested, _tdx_quote(mr_td=OTHER_MR_TD))
    else:
        attested, _ = _snp()
        pair = (attested, _snp_report(measurement=SNP_OTHER))
    with pytest.raises(adm.AdmissionError, match="measurement is not the quote's"):
        _admit(pair)
    if kind == "sev_snp":
        other_chip = (attested, _snp_report(chip_id=bytes(reversed(CHIP_ID))))
        with pytest.raises(adm.AdmissionError, match="chip_id is not the report's"):
            _admit(other_chip)


def test_the_validator_256_policy_file_loads_unchanged():
    # the example in cathedral-validator #256's direct-tdx-measurement.env.example
    raw = (
        b'{"schema": "cathedral_tdx_measurement_policy_v1",\n "mode": "shadow",\n'
        b' "allowed_measurements": ["' + TDX_MEASUREMENT.encode() + b'"]}\n'
    )
    policy = adm.parse_policy(raw)
    assert (policy.kind, policy.mode) == ("tdx", "shadow")
    assert policy.allowed_measurements == frozenset({TDX_MEASUREMENT})
    assert policy.digest == "sha256:" + hashlib.sha256(raw).hexdigest()


def test_a_policy_for_the_other_kind_is_an_error():
    with pytest.raises(adm.AdmissionError, match="measurement policy"):
        _admit(_tdx(), policy=_policy("sev_snp"))
    with pytest.raises(adm.AdmissionError, match="measurement policy"):
        _admit(_snp(), policy=_policy("tdx"))


TDX_SCHEMA = adm.POLICY_SCHEMAS["tdx"]
SNP_SCHEMA = adm.POLICY_SCHEMAS["sev_snp"]
_BAD_POLICIES = {
    "duplicate_key": (
        '{"schema":"%s","mode":"shadow","mode":"shadow","allowed_measurements":[]}' % TDX_SCHEMA
    ),
    "extra_key": ('{"schema":"%s","mode":"shadow","allowed_measurements":[],"x":1}' % TDX_SCHEMA),
    "missing_key": '{"schema":"%s","mode":"shadow"}' % TDX_SCHEMA,
    "unknown_schema": '{"schema":"v2","mode":"shadow","allowed_measurements":[]}',
    "schema_not_string": '{"schema":["%s"],"mode":"shadow","allowed_measurements":[]}' % TDX_SCHEMA,
    "mode_case": '{"schema":"%s","mode":"Enforce","allowed_measurements":[]}' % TDX_SCHEMA,
    "mode_bool": '{"schema":"%s","mode":true,"allowed_measurements":[]}' % TDX_SCHEMA,
    "not_a_list": '{"schema":"%s","mode":"shadow","allowed_measurements":"%s"}'
    % (TDX_SCHEMA, TDX_MEASUREMENT),
    "int_entry": '{"schema":"%s","mode":"shadow","allowed_measurements":[1]}' % TDX_SCHEMA,
    "mixed_entries": '{"schema":"%s","mode":"shadow","allowed_measurements":["%s",1]}'
    % (TDX_SCHEMA, TDX_MEASUREMENT),
    "unsorted": '{"schema":"%s","mode":"shadow","allowed_measurements":["%s","%s"]}'
    % (TDX_SCHEMA, *sorted([TDX_OTHER, TDX_MEASUREMENT], reverse=True)),
    "repeated": '{"schema":"%s","mode":"shadow","allowed_measurements":["%s","%s"]}'
    % (TDX_SCHEMA, TDX_MEASUREMENT, TDX_MEASUREMENT),
    "upper_hex": '{"schema":"%s","mode":"shadow","allowed_measurements":["%s"]}'
    % (TDX_SCHEMA, "tdx-measurement-sha256:" + "A1" * 32),
    "bare_tdx_hex": '{"schema":"%s","mode":"shadow","allowed_measurements":["%s"]}'
    % (TDX_SCHEMA, "11" * 32),
    "snp_entry_in_tdx": '{"schema":"%s","mode":"shadow","allowed_measurements":["%s"]}'
    % (TDX_SCHEMA, SNP_MEASUREMENT),
    "tdx_entry_in_snp": '{"schema":"%s","mode":"shadow","allowed_measurements":["%s"]}'
    % (SNP_SCHEMA, TDX_MEASUREMENT),
    "short_snp": '{"schema":"%s","mode":"shadow","allowed_measurements":["%s"]}'
    % (SNP_SCHEMA, "33" * 32),
    "enforce_empty": '{"schema":"%s","mode":"enforce","allowed_measurements":[]}' % SNP_SCHEMA,
    "nan": '{"schema":"%s","mode":"shadow","allowed_measurements":[NaN]}' % TDX_SCHEMA,
    "top_level_list": "[1]",
    "trailing_garbage": '{"schema":"%s","mode":"shadow","allowed_measurements":[]} x' % TDX_SCHEMA,
    "empty": "",
    "deep": "[" * 60000 + "]" * 60000,
    "deep_object": '{"a":' * 20000 + "1" + "}" * 20000,
    # past Python's 4300-digit int limit: json.loads raises a plain ValueError
    "huge_int_entry": '{"schema":"%s","mode":"shadow","allowed_measurements":[%s]}'
    % (TDX_SCHEMA, "1" * 5000),
    "huge_int": "1" * 5000,
}


@pytest.mark.parametrize("name", sorted(_BAD_POLICIES))
def test_malformed_policies_are_refused(name):
    with pytest.raises(adm.AdmissionError):
        adm.parse_policy(_BAD_POLICIES[name].encode())


@pytest.mark.parametrize(
    "raw",
    [
        "not bytes",
        None,
        b"\xef\xbb\xbf" + _policy_bytes("tdx", "shadow", []),  # UTF-8 BOM
        _policy_bytes("tdx", "shadow", []).decode().encode("utf-16"),
        b"\xff\xfe\x00",
        b" " * (adm.MAX_POLICY_BYTES + 1),
    ],
    ids=["str", "none", "bom", "utf16", "not_utf8", "too_big"],
)
def test_policy_bytes_must_be_bounded_utf8_json(raw):
    with pytest.raises(adm.AdmissionError):
        adm.parse_policy(raw)


def test_the_policy_size_cap_is_128_kib_of_otherwise_valid_json():
    # Trailing whitespace keeps the JSON valid, so only the size cap can refuse it.
    raw = _policy_bytes("tdx", "enforce", [TDX_MEASUREMENT])
    at_cap = raw + b" " * (adm.MAX_POLICY_BYTES - len(raw))
    assert len(at_cap) == adm.MAX_POLICY_BYTES == 128 * 1024
    assert adm.parse_policy(at_cap).allowed_measurements == frozenset({TDX_MEASUREMENT})
    with pytest.raises(adm.AdmissionError, match="128 KiB"):
        adm.parse_policy(at_cap + b" ")


# -- one box per host -------------------------------------------------------------------


def test_a_hardware_id_already_admitted_to_another_box_is_refused():
    hardware_id = receipt.tdx_hardware_id(STABLE_ID)
    first = {hardware_id: adm.AdmittedBox("box-1", HOTKEY)}
    other_box = _admit(_tdx(), box_id="box-2", admitted=first)
    assert other_box.reasons == (adm.HARDWARE_ID_CLAIMED,)
    assert not other_box.admitted and other_box.evidence is None
    # the same box id under another hotkey is another box too
    moved = _admit(
        _tdx(_tdx_quote(report_data=_v2_by_hand(NONCE, OTHER_HOTKEY, CERT))),
        miner_hotkey=OTHER_HOTKEY,
        admitted=first,
    )
    assert moved.reasons == (adm.HARDWARE_ID_CLAIMED,)


def test_the_same_box_is_readmitted_and_other_hosts_are_independent():
    hardware_id = receipt.derive_hardware_id("chip_id", CHIP_ID)
    first = {hardware_id: adm.AdmittedBox("box-1", HOTKEY)}
    assert _admit(_snp(), admitted=first).admitted
    other_host = {
        receipt.derive_hardware_id("chip_id", bytes(64 - 1) + b"\x01"): first[hardware_id]
    }
    assert _admit(_snp(), box_id="box-2", admitted=other_host).admitted


def test_a_tdx_and_a_snp_id_never_collide():
    # the id kind is inside the hash, as for receipts
    raw = CHIP_ID[:32]
    assert receipt.derive_hardware_id("tdx_platform", raw) != receipt.derive_hardware_id(
        "chip_id", raw + bytes(32)
    )


def test_every_refusal_is_reported_together():
    hardware_id = receipt.tdx_hardware_id(STABLE_ID)
    result = _admit(
        _tdx(_tdx_quote(mr_td=OTHER_MR_TD), collateral_current=False),
        nonce=bytes(reversed(NONCE)),
        box_id="box-9",
        admitted={hardware_id: adm.AdmittedBox("box-1", HOTKEY)},
    )
    assert result.reasons == (
        adm.VERIFICATION_INCOMPLETE,
        adm.REPORT_DATA_MISMATCH,
        adm.MEASUREMENT_NOT_ALLOWED,
        adm.HARDWARE_ID_CLAIMED,
    )


# -- attestation after the last release -------------------------------------------------


def test_evidence_from_before_the_last_release_is_refused():
    released = ATTESTED_AT + timedelta(seconds=1)
    result = _admit(_tdx(), last_released_at=released)
    assert result.reasons == (adm.ATTESTATION_PREDATES_RELEASE,)
    assert not result.admitted and result.evidence is None
    assert adm.ATTESTATION_PREDATES_RELEASE == "attestation_predates_release"


def test_evidence_verified_at_the_release_instant_is_refused():
    # Strictly after: the same instant could be before the release.
    result = _admit(_snp(), last_released_at=ATTESTED_AT)
    assert result.reasons == (adm.ATTESTATION_PREDATES_RELEASE,)
    assert result.evidence is None


def test_evidence_verified_after_the_last_release_is_admitted():
    released = ATTESTED_AT - timedelta(microseconds=1)
    result = _admit(_tdx(), last_released_at=released)
    assert result.admitted and result.reasons == ()
    assert result.evidence == _admit(_tdx()).evidence


def test_the_release_is_compared_as_an_instant_across_time_zones():
    # 12:00:01 at +01:00 is 11:00:01 UTC, one second after ATTESTED_AT.
    plus_one = timezone(timedelta(hours=1))
    later = datetime(2026, 9, 28, 12, 0, 1, tzinfo=plus_one)
    earlier = datetime(2026, 9, 28, 11, 59, 59, tzinfo=plus_one)
    assert _admit(_tdx(), last_released_at=later).reasons == (adm.ATTESTATION_PREDATES_RELEASE,)
    assert _admit(_tdx(), last_released_at=earlier).admitted


def test_no_release_time_skips_the_check_and_keeps_the_old_signature():
    assert _admit(_tdx(), last_released_at=None) == _admit(_tdx())
    parameter = inspect.signature(adm.admit).parameters["last_released_at"]
    assert parameter.default is None and parameter.kind is inspect.Parameter.KEYWORD_ONLY


def test_a_release_refusal_is_reported_with_the_others():
    result = _admit(
        _tdx(collateral_current=False),
        nonce=bytes(reversed(NONCE)),
        last_released_at=ATTESTED_AT + timedelta(hours=1),
    )
    assert result.reasons == (
        adm.VERIFICATION_INCOMPLETE,
        adm.REPORT_DATA_MISMATCH,
        adm.ATTESTATION_PREDATES_RELEASE,
    )


# -- a fresh boot: RTMR3 all zeros ------------------------------------------------------

FRESH_QUOTE = _tdx_quote(rtmr3=bytes(48))
CONSUMED_QUOTE = _tdx_quote(rtmr3=RTMR3_CONSUMED)
FRESH_MEASUREMENT = parse_tdx_quote(FRESH_QUOTE).measurement
CONSUMED_MEASUREMENT = parse_tdx_quote(CONSUMED_QUOTE).measurement
BOTH = _policy("tdx", allowed=sorted([FRESH_MEASUREMENT, CONSUMED_MEASUREMENT]))


def test_a_fresh_boot_is_admitted_when_required():
    result = _admit(_tdx(FRESH_QUOTE), policy=BOTH, require_fresh_boot=True)
    assert result.admitted and result.reasons == ()
    assert result.evidence is not None and result.measurement == FRESH_MEASUREMENT


@pytest.mark.parametrize(
    "rtmr3", [RTMR3_CONSUMED, b"3" * 48, bytes(47) + b"\x01"], ids=["consumed", "other", "last"]
)
def test_a_consumed_boot_is_refused_when_required(rtmr3):
    quote = _tdx_quote(rtmr3=rtmr3)
    policy = _policy("tdx", allowed=[parse_tdx_quote(quote).measurement])
    result = _admit(_tdx(quote), policy=policy, require_fresh_boot=True)
    assert result.reasons == (adm.BOOT_CONSUMED,) and adm.BOOT_CONSUMED == "boot_consumed"
    assert not result.admitted and result.evidence is None


def test_a_consumed_boot_is_admitted_when_not_required():
    # A re-attestation during an allocation: the consumed measurement is listed.
    result = _admit(_tdx(CONSUMED_QUOTE), policy=BOTH)
    assert result.admitted and result.measurement == CONSUMED_MEASUREMENT
    assert _admit(_tdx(CONSUMED_QUOTE), policy=BOTH, require_fresh_boot=False) == result


def test_a_consumed_boot_is_refused_in_shadow_too():
    shadow = _policy("tdx", mode="shadow", allowed=[FRESH_MEASUREMENT])
    result = _admit(_tdx(CONSUMED_QUOTE), policy=shadow, require_fresh_boot=True)
    assert result.reasons == (adm.BOOT_CONSUMED,) and result.evidence is None


def test_rtmr3_is_read_from_the_quote_not_the_verdict():
    # The verdict carries only the measurement; RTMR3 comes from the bytes.
    result = _admit(_tdx(), require_fresh_boot=True)  # the fixture's RTMR3 is "3" * 48
    assert result.reasons == (adm.BOOT_CONSUMED,)


def test_the_consumed_measurement_differs_from_the_fresh_one():
    # Why a policy lists both: the Cathedral TDX measurement covers the RTMRs.
    assert FRESH_MEASUREMENT != CONSUMED_MEASUREMENT
    assert _admit(
        _tdx(CONSUMED_QUOTE), policy=_policy("tdx", allowed=[FRESH_MEASUREMENT])
    ).reasons == (adm.MEASUREMENT_NOT_ALLOWED,)


def test_fresh_boot_is_a_tdx_check():
    with pytest.raises(adm.AdmissionError, match="SEV-SNP has no RTMR3"):
        _admit(_snp(), require_fresh_boot=True)
    assert _admit(_snp(), require_fresh_boot=False).admitted
    parameter = inspect.signature(adm.admit).parameters["require_fresh_boot"]
    assert parameter.default is False and parameter.kind is inspect.Parameter.KEYWORD_ONLY


# -- malformed input -----------------------------------------------------------------------


_BAD_TDX = {
    "tier_gpu": {"tier": Tier.CC_GPU},
    "tier_str": {"tier": "cc_cpu_tdx"},
    "measurement_other": {"measurement": TDX_OTHER},
    "measurement_none": {"measurement": None},
    "stable_id_missing": {"chip_id": None},
    "stable_id_bare": {"chip_id": STABLE_ID.split(":")[1]},
    "stable_id_upper": {"chip_id": STABLE_ID.upper()},
    "stable_id_short": {"chip_id": STABLE_ID[:-2]},
    "stable_id_long": {"chip_id": STABLE_ID + "00"},
    "stable_id_newline": {"chip_id": STABLE_ID + "\n"},
    "stable_id_pck_prefix": {"chip_id": STABLE_ID.replace("platform", "pck-cert")},
    "stable_id_zero": {"chip_id": "tdx-platform-sha256:" + "0" * 64},
    "stable_id_bytes": {"chip_id": STABLE_ID.encode()},
    "stable_id_int": {"chip_id": 7},
}
_BAD_TDX_QUOTE = {
    "empty": b"",
    "truncated": _tdx_quote()[:600],
    "version_5": b"\x05\x00" + _tdx_quote()[2:],
    "str": _tdx_quote().hex(),
    "bytearray": bytearray(_tdx_quote()),
    "too_big": _tdx_quote() + bytes(adm.MAX_QUOTE_BYTES),
    "snp_report": _snp_report(),
}


@pytest.mark.parametrize("name", sorted(_BAD_TDX))
def test_a_malformed_tdx_verdict_is_an_error(name):
    with pytest.raises(adm.AdmissionError):
        _admit(_tdx(**_BAD_TDX[name]), policy=_policy("tdx"))


@pytest.mark.parametrize("name", sorted(_BAD_TDX_QUOTE))
def test_a_malformed_tdx_quote_is_an_error(name):
    attested, _ = _tdx()
    with pytest.raises(adm.AdmissionError):
        _admit((attested, _BAD_TDX_QUOTE[name]), policy=_policy("tdx"))


_BAD_SNP = {
    "chip_bytes": ({"chip_id": CHIP_ID}, None),
    "chip_upper_hex": ({"chip_id": CHIP_ID.hex().upper()}, None),
    "chip_missing": ({"chip_id": None}, None),
    "chip_other": ({"chip_id": bytes(reversed(CHIP_ID)).hex()}, None),
    "chip_zero": ({"chip_id": "00" * 64}, _snp_report(chip_id=bytes(64))),
    "measurement_tdx": ({"measurement": TDX_MEASUREMENT}, None),
    "measurement_upper": ({"measurement": SNP_MEASUREMENT.upper()}, None),
    "measurement_zero": ({"measurement": "00" * 48}, _snp_report(measurement="00" * 48)),
    "report_short": ({}, _snp_report()[:-1]),
    "report_long": ({}, _snp_report() + b"\x00"),
    "report_unsigned": ({}, _snp_report()[: snp.SIGNATURE_OFFSET] + bytes(512) + b"\x00" * 160),
    "report_is_tdx_quote": ({}, _tdx_quote()),
    "tier_tdx": ({"tier": Tier.CC_CPU_TDX}, None),
}


@pytest.mark.parametrize("name", sorted(_BAD_SNP))
def test_a_malformed_snp_verdict_or_report_is_an_error(name):
    changes, report = _BAD_SNP[name]
    attested, good = _snp(**changes)
    with pytest.raises(adm.AdmissionError):
        _admit((attested, good if report is None else report), policy=_policy("sev_snp"))


def _der_sequence(content: bytes) -> bytes:
    length = len(content)
    if length < 128:
        return b"\x30" + bytes((length,)) + content
    size = (length.bit_length() + 7) // 8
    return b"\x30" + bytes((0x80 | size,)) + length.to_bytes(size, "big") + content


def _spki_with_extra_field() -> bytes:
    spki = extract_spki_der(CERT)
    header = 2 + (spki[1] & 0x7F if spki[1] & 0x80 else 0)
    return _der_sequence(spki[header:] + b"\x02\x01\x00")


_BAD_CALL = {
    "no_tls": {"tls_certificate_der": None},
    "both_tls": {"tls_spki_der": extract_spki_der(CERT)},
    "cert_garbage": {"tls_certificate_der": b"\x30\x03\x02\x01\x01"},
    "cert_str": {"tls_certificate_der": "cert"},
    "spki_garbage": {"tls_certificate_der": None, "tls_spki_der": b"\x30\x00"},
    "spki_trailing": {"tls_certificate_der": None, "tls_spki_der": extract_spki_der(CERT) + b"\0"},
    "spki_extra_field": {"tls_certificate_der": None, "tls_spki_der": _spki_with_extra_field()},
    "spki_is_cert": {"tls_certificate_der": None, "tls_spki_der": CERT},
    "verifier_bare_hex": {"verifier_digest": "55" * 32},
    "verifier_none": {"verifier_digest": None},
    "attested_at_naive": {"attested_at": ATTESTED_AT.replace(tzinfo=None)},
    "attested_at_str": {"attested_at": "2026-09-28T11:00:00Z"},
    "attested_at_epoch": {"attested_at": ATTESTED_AT.timestamp()},
    "attested_at_overflow": {"attested_at": datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5)))},
    "attested_at_year_5": {"attested_at": datetime(5, 1, 1, tzinfo=timezone.utc)},
    "released_naive": {"last_released_at": ATTESTED_AT.replace(tzinfo=None)},
    "released_str": {"last_released_at": "2026-09-28T11:00:00Z"},
    "released_epoch": {"last_released_at": ATTESTED_AT.timestamp()},
    "fresh_boot_none": {"require_fresh_boot": None},
    "fresh_boot_int": {"require_fresh_boot": 1},
    "nonce_short": {"nonce": NONCE[:31]},
    "nonce_zero": {"nonce": bytes(32)},
    "nonce_str": {"nonce": NONCE.hex()},
    "hotkey_bad": {"miner_hotkey": "not-an-ss58-address"},
    "hotkey_bytes": {"miner_hotkey": HOTKEY.encode()},
    "box_id_bad": {"box_id": "box 1"},
    "box_id_long": {"box_id": "b" * 129},
    "admitted_list": {"admitted": []},
    "admitted_upper_key": {
        "admitted": {receipt.tdx_hardware_id(STABLE_ID).upper(): adm.AdmittedBox("b", HOTKEY)}
    },
    "admitted_tuple_value": {"admitted": {"ab" * 32: ("box-1", HOTKEY)}},
    "admitted_bad_hotkey": {"admitted": {"ab" * 32: adm.AdmittedBox("box-1", "x")}},
    "policy_dict": {"policy": {"mode": "shadow"}},
    "policy_forged_mode": {
        "policy": adm.MeasurementPolicy("tdx", "off", frozenset(), "sha256:" + "0" * 64)
    },
    "policy_forged_set": {
        "policy": adm.MeasurementPolicy("tdx", "enforce", [TDX_MEASUREMENT], "sha256:" + "0" * 64)
    },
}


@pytest.mark.parametrize("name", sorted(_BAD_CALL))
def test_malformed_call_arguments_are_an_error(name):
    with pytest.raises(adm.AdmissionError):
        _admit(_tdx(), **_BAD_CALL[name])


def test_a_verdict_of_the_wrong_type_is_an_error():
    attested, quote = _tdx()
    for junk in ({"tier": "cc_cpu_tdx"}, dataclasses.asdict(attested), None):
        with pytest.raises(adm.AdmissionError, match="cathedral.common.Attested"):
            _admit((junk, quote))


_JUNK = [
    None,
    True,
    0,
    -1,
    2**70,
    1.5,
    float("nan"),
    "",
    "x" * 600,
    "\udcff",
    b"",
    b"\x00" * 64,
    bytearray(16),
    [],
    {},
    (1,),
    object(),
]


def _mutations():
    rng = random.Random(_RNG.randrange(2**32))
    for _ in range(400):
        pair = rng.choice([_tdx, _snp])()
        attested, quote = pair
        fields = {f.name: getattr(attested, f.name) for f in dataclasses.fields(attested)}
        call = {
            "quote": quote,
            "verifier_digest": VERIFIER,
            "box_id": "box-1",
            "miner_hotkey": HOTKEY,
            "nonce": NONCE,
            "attested_at": ATTESTED_AT,
            "policy": _policy(_kind(pair)),
            "admitted": {},
            "tls_certificate_der": CERT,
            "tls_spki_der": None,
        }
        target = rng.choice([fields, call])
        name = rng.choice(sorted(target))
        value = target[name]
        if isinstance(value, (bytes, str)) and value and rng.random() < 0.5:
            data = bytearray(value if isinstance(value, bytes) else value.encode())
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            if rng.random() < 0.3:
                data = data[: rng.randrange(len(data))]
            value = bytes(data) if isinstance(value, bytes) else data.decode("latin-1")
        else:
            value = rng.choice(_JUNK)
        target[name] = value
        yield Attested(**fields), call


def test_fuzzed_input_is_an_admission_error_or_a_decision_never_another_exception():
    decisions = errors = 0
    for attested, call in _mutations():
        try:
            result = adm.admit(attested, call.pop("quote"), **call)
        except adm.AdmissionError:
            errors += 1
        else:
            decisions += 1
            assert isinstance(result, adm.Admission)
            assert result.admitted == (not result.reasons)
            assert (result.evidence is None) == (
                not result.admitted or not result.measurement_allowed
            )
    assert errors and decisions


def test_fuzzed_policies_are_an_admission_error_or_a_policy():
    rng = random.Random(_RNG.randrange(2**32))
    seed = _policy_bytes("tdx", "enforce", [TDX_MEASUREMENT])
    for _ in range(2000):
        data = bytearray(seed)
        for _ in range(rng.randrange(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            policy = adm.parse_policy(bytes(data))
        except adm.AdmissionError:
            continue
        assert policy.kind in adm.TEE_KINDS and policy.mode in adm.MODES


def test_admission_takes_no_netuid():
    # Nothing about admission is subnet specific: no netuid parameter to vary.
    assert not any("netuid" in name for name in inspect.signature(adm.admit).parameters)
    assert not any("netuid" in f.name for f in dataclasses.fields(adm.Admission))


def test_a_repeated_policy_key_keeps_its_own_message():
    raw = (
        b'{"schema":"cathedral_tdx_measurement_policy_v1","mode":"shadow",'
        b'"mode":"enforce","allowed_measurements":[]}'
    )
    with pytest.raises(adm.AdmissionError, match="repeats a JSON key"):
        adm.parse_policy(raw)


# -- v2 image identity (docs/MRTD.md, "Image identity"; #265) ----------------------

# Two VMs from one image: GCP sets MROWNER per VM, so their v1 values differ.
VM_A = _tdx_quote(mr_owner=b"a" * 48)
VM_B = _tdx_quote(mr_owner=b"b" * 48)
TDX_IMAGE = parse_tdx_quote(VM_A).image_measurement


def test_the_fixture_vms_share_an_image_identity_but_not_a_launch_measurement():
    assert parse_tdx_quote(VM_A).measurement != parse_tdx_quote(VM_B).measurement
    assert parse_tdx_quote(VM_B).image_measurement == TDX_IMAGE


def test_a_tdx_policy_accepts_image_identity_entries():
    allowed = sorted([TDX_IMAGE, TDX_MEASUREMENT])
    policy = adm.parse_policy(_policy_bytes("tdx", "enforce", allowed))
    assert policy.allowed_measurements == frozenset(allowed)
    for bad in ("tdx-image-sha256:" + "A1" * 32, "tdx-image-sha256:" + "11" * 31):
        with pytest.raises(adm.AdmissionError, match="tdx-image-sha256"):
            adm.parse_policy(_policy_bytes("tdx", "shadow", [bad]))
    with pytest.raises(adm.AdmissionError):
        adm.parse_policy(_policy_bytes("sev_snp", "shadow", [TDX_IMAGE]))


@pytest.mark.parametrize("quote", [VM_A, VM_B], ids=["vm_a", "vm_b"])
@pytest.mark.parametrize("verdict", ["image", "launch"])
def test_an_image_listing_admits_every_honest_vm_of_that_image(quote, verdict):
    # The verifier's verdict names v2 when its own policy listed only v2, and
    # v1 when it listed v1; admission accepts either for these quote bytes.
    parsed = parse_tdx_quote(quote)
    named = parsed.image_measurement if verdict == "image" else parsed.measurement
    pair = _tdx(quote, measurement=named)
    result = _admit(pair, policy=_policy("tdx", "enforce", [TDX_IMAGE]))
    assert result.admitted and result.reasons == ()
    assert result.measurement == TDX_IMAGE
    assert (result.launch_measurement, result.image_measurement) == (
        parsed.measurement,
        TDX_IMAGE,
    )
    assert result.evidence.measurement == TDX_IMAGE
    # A receipt carries the v2 value and its evidence check accepts it.
    assert receipt._check_evidence(dataclasses.asdict(result.evidence), "tdx") == result.evidence


def test_a_v1_listing_still_records_v1_and_refuses_the_other_vm():
    policy = _policy("tdx", "enforce", [parse_tdx_quote(VM_A).measurement])
    a = _admit(_tdx(VM_A), policy=policy)
    assert a.admitted and a.evidence.measurement == parse_tdx_quote(VM_A).measurement
    # The same image on another VM: the #265 failure a v2 listing fixes.
    b = _admit(_tdx(VM_B), policy=policy)
    assert b.reasons == (adm.MEASUREMENT_NOT_ALLOWED,)


def test_a_listing_of_both_identities_records_v1():
    parsed = parse_tdx_quote(VM_A)
    policy = _policy("tdx", "enforce", sorted([parsed.measurement, TDX_IMAGE]))
    assert _admit(_tdx(VM_A), policy=policy).evidence.measurement == parsed.measurement


def test_an_unlisted_image_is_refused_and_recorded_in_shadow():
    other = parse_tdx_quote(_tdx_quote(mr_td=OTHER_MR_TD)).image_measurement
    enforce = _admit(_tdx(VM_A), policy=_policy("tdx", "enforce", [other]))
    assert enforce.reasons == (adm.MEASUREMENT_NOT_ALLOWED,)
    shadow = _admit(_tdx(VM_A), policy=_policy("tdx", "shadow", [other]))
    assert shadow.admitted and not shadow.measurement_allowed and shadow.evidence is None
    assert shadow.measurement == parse_tdx_quote(VM_A).measurement


def test_a_verdict_naming_another_image_identity_is_refused():
    other = parse_tdx_quote(_tdx_quote(mr_td=OTHER_MR_TD)).image_measurement
    with pytest.raises(adm.AdmissionError, match="not the quote's"):
        _admit(_tdx(VM_A, measurement=other), policy=_policy("tdx", "enforce", [TDX_IMAGE]))


def test_snp_admission_has_no_tdx_audit_values():
    result = _admit(_snp())
    assert (result.launch_measurement, result.image_measurement) == (None, None)


def test_a_v2_verdict_for_another_vm_of_the_image_is_refused():
    # Same image, different MROWNER: the v2 values match, the v1 audit value does not.
    a, b = parse_tdx_quote(VM_A), parse_tdx_quote(VM_B)
    verdict = _tdx(
        VM_B,
        measurement=TDX_IMAGE,
        launch_measurement=a.measurement,
        image_measurement=TDX_IMAGE,
    )
    with pytest.raises(adm.AdmissionError, match="not the quote's"):
        _admit(verdict, policy=_policy("tdx", "enforce", [b.measurement]))
    honest = _tdx(
        VM_B, measurement=TDX_IMAGE, launch_measurement=b.measurement, image_measurement=TDX_IMAGE
    )
    assert _admit(honest, policy=_policy("tdx", "enforce", [TDX_IMAGE])).admitted
