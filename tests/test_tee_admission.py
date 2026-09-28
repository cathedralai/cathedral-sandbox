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
from cathedral.common import ChannelBinding, ChannelBindingType, report_data_v2

HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
OTHER_HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
NONCE = bytes(range(1, 33))
PPID = bytes.fromhex("0123456789abcdef0123456789abcdef")
CHIP_ID = bytes(range(1, 65))
TDX_MEASUREMENT = "tdx-measurement-sha256:" + "a1" * 32
TDX_OTHER = "tdx-measurement-sha256:" + "b2" * 32
SNP_MEASUREMENT = "c3" * 48
SNP_OTHER = "d4" * 48
VERIFIER = "sha256:" + "5e" * 32
EVIDENCE_SHA = "ab" * 32
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


def _tdx(**changes) -> adm.VerifiedAttestation:
    base = adm.VerifiedAttestation(
        kind="tdx",
        measurement=TDX_MEASUREMENT,
        verifier_digest=VERIFIER,
        evidence_sha256=EVIDENCE_SHA,
        report_data=_v2_by_hand(NONCE, HOTKEY, CERT),
        stable_platform_id=STABLE_ID,
    )
    return dataclasses.replace(base, **changes)


def _snp(**changes) -> adm.VerifiedAttestation:
    base = adm.VerifiedAttestation(
        kind="sev_snp",
        measurement=SNP_MEASUREMENT,
        verifier_digest=VERIFIER,
        evidence_sha256=EVIDENCE_SHA,
        report_data=_v2_by_hand(NONCE, HOTKEY, CERT),
        chip_id=CHIP_ID.hex(),  # as cathedral/verify/snp.py reports chip_id
    )
    return dataclasses.replace(base, **changes)


def _policy(kind: str = "tdx", mode: str = "enforce", allowed=None) -> adm.MeasurementPolicy:
    if allowed is None:
        allowed = [TDX_MEASUREMENT] if kind == "tdx" else [SNP_MEASUREMENT]
    return adm.parse_policy(_policy_bytes(kind, mode, allowed))


def _policy_bytes(kind: str, mode: str, allowed) -> bytes:
    document = {"schema": adm.POLICY_SCHEMAS[kind], "mode": mode, "allowed_measurements": allowed}
    return json.dumps(document).encode()


def _admit(attestation, **changes) -> adm.Admission:
    arguments = {
        "box_id": "box-1",
        "miner_hotkey": HOTKEY,
        "nonce": NONCE,
        "policy": _policy(attestation.kind if attestation.kind in adm.TEE_KINDS else "tdx"),
        "admitted": {},
        "tls_certificate_der": CERT,
    }
    arguments.update(changes)
    return adm.admit(attestation, **arguments)


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
        evidence_sha256=EVIDENCE_SHA,
        measurement=TDX_MEASUREMENT,
        verifier_digest=VERIFIER,
        tls_spki_sha256=spki,
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
    assert (
        receipt._check_evidence(dataclasses.asdict(result.evidence), "sev_snp") == result.evidence
    )


def test_raw_bytes_and_hex_chip_ids_are_one_machine():
    assert _admit(_snp(chip_id=CHIP_ID)).hardware_id == _admit(_snp()).hardware_id


def test_there_is_no_raw_ppid_input():
    # No TDX verifier outputs the raw PPID; the hardware id is the stable_platform_id's.
    names = {f.name for f in dataclasses.fields(adm.VerifiedAttestation)}
    assert "hardware_id" not in names and "ppid" not in names
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
    result = _admit(_tdx(report_data=report_data_v2(NONCE, HOTKEY, other_type)))
    assert result.reasons == (adm.REPORT_DATA_MISMATCH,)


def test_a_tdx_hardware_id_follows_the_stable_platform_id():
    here = _admit(_tdx())
    other = _admit(_tdx(stable_platform_id=OTHER_STABLE_ID))
    assert other.admitted and other.hardware_id == receipt.tdx_hardware_id(OTHER_STABLE_ID)
    assert other.hardware_id != here.hardware_id
    # A box whose stable_platform_id is not the one admitted is another machine,
    # and one presenting an admitted platform's id is that machine.
    admitted = {here.hardware_id: adm.AdmittedBox("box-1", HOTKEY)}
    assert _admit(
        _tdx(stable_platform_id=OTHER_STABLE_ID), box_id="box-2", admitted=admitted
    ).admitted
    claimed = _admit(_tdx(), box_id="box-2", admitted=admitted)
    assert claimed.reasons == (adm.HARDWARE_ID_CLAIMED,)


# -- measurement policy -----------------------------------------------------------------


@pytest.mark.parametrize(
    "make, other, kind", [(_tdx, TDX_OTHER, "tdx"), (_snp, SNP_OTHER, "sev_snp")]
)
def test_enforce_refuses_an_unlisted_measurement_and_shadow_records_it(make, other, kind):
    enforce = _admit(make(measurement=other), policy=_policy(kind, "enforce"))
    assert not enforce.admitted
    assert enforce.reasons == (adm.MEASUREMENT_NOT_ALLOWED,)
    assert (enforce.measurement_allowed, enforce.mode) == (False, "enforce")

    shadow = _admit(make(measurement=other), policy=_policy(kind, "shadow"))
    assert shadow.admitted and shadow.reasons == ()
    assert (shadow.measurement_allowed, shadow.mode) == (False, "shadow")
    assert shadow.evidence.measurement == other

    listed = _admit(make(), policy=_policy(kind, "shadow"))
    assert listed.admitted and listed.measurement_allowed


def test_an_empty_shadow_policy_admits_everything_and_allows_nothing():
    result = _admit(_tdx(), policy=_policy("tdx", "shadow", []))
    assert result.admitted and not result.measurement_allowed


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
    % (TDX_SCHEMA, TDX_OTHER, TDX_MEASUREMENT),
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


# -- one box per host -------------------------------------------------------------------


def test_a_hardware_id_already_admitted_to_another_box_is_refused():
    hardware_id = receipt.tdx_hardware_id(STABLE_ID)
    first = {hardware_id: adm.AdmittedBox("box-1", HOTKEY)}
    other_box = _admit(_tdx(), box_id="box-2", admitted=first)
    assert other_box.reasons == (adm.HARDWARE_ID_CLAIMED,)
    assert not other_box.admitted and other_box.evidence is None
    # the same box id under another hotkey is another box too
    moved = adm.admit(
        _tdx(report_data=_v2_by_hand(NONCE, OTHER_HOTKEY, CERT)),
        box_id="box-1",
        miner_hotkey=OTHER_HOTKEY,
        nonce=NONCE,
        policy=_policy(),
        admitted=first,
        tls_certificate_der=CERT,
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
        _tdx(measurement=TDX_OTHER),
        nonce=bytes(reversed(NONCE)),
        box_id="box-9",
        admitted={hardware_id: adm.AdmittedBox("box-1", HOTKEY)},
    )
    assert result.reasons == (
        adm.REPORT_DATA_MISMATCH,
        adm.MEASUREMENT_NOT_ALLOWED,
        adm.HARDWARE_ID_CLAIMED,
    )


# -- malformed input -----------------------------------------------------------------------


_BAD_ATTESTATION = {
    "kind_unknown": {"kind": "gpu_cc"},
    "kind_not_str": {"kind": ["tdx"]},
    "chip_id_set": {"chip_id": CHIP_ID},
    "measurement_bare_hex": {"measurement": "11" * 32},
    "measurement_zero": {"measurement": "tdx-measurement-sha256:" + "00" * 32},
    "measurement_snp_shape": {"measurement": SNP_MEASUREMENT},
    "measurement_none": {"measurement": None},
    "verifier_bare_hex": {"verifier_digest": "55" * 32},
    "evidence_upper": {"evidence_sha256": EVIDENCE_SHA.upper()},
    "evidence_zero": {"evidence_sha256": "00" * 32},
    "report_data_short": {"report_data": bytes(63)},
    "report_data_str": {"report_data": "00" * 64},
    "stable_id_missing": {"stable_platform_id": None},
    "stable_id_bare": {"stable_platform_id": STABLE_ID.split(":")[1]},
    "stable_id_upper": {"stable_platform_id": STABLE_ID.upper()},
    "stable_id_short": {"stable_platform_id": STABLE_ID[:-2]},
    "stable_id_long": {"stable_platform_id": STABLE_ID + "00"},
    "stable_id_newline": {"stable_platform_id": STABLE_ID + "\n"},
    "stable_id_pck_prefix": {"stable_platform_id": STABLE_ID.replace("platform", "pck-cert")},
    "stable_id_zero": {"stable_platform_id": "tdx-platform-sha256:" + "0" * 64},
    "stable_id_bytes": {"stable_platform_id": STABLE_ID.encode()},
    "stable_id_int": {"stable_platform_id": 7},
}


@pytest.mark.parametrize("name", sorted(_BAD_ATTESTATION))
def test_a_malformed_tdx_attestation_is_an_error(name):
    with pytest.raises(adm.AdmissionError):
        _admit(_tdx(**_BAD_ATTESTATION[name]), policy=_policy("tdx"))


@pytest.mark.parametrize(
    "changes",
    [
        {"chip_id": CHIP_ID[:63]},
        {"chip_id": bytes(64)},
        {"chip_id": None},
        {"chip_id": CHIP_ID.hex().upper()},
        {"chip_id": CHIP_ID.hex()[:-1]},
        {"chip_id": 7},
        {"chip_id": bytearray(CHIP_ID)},
        {"measurement": "33" * 47},
        {"measurement": TDX_MEASUREMENT},
        {"measurement": SNP_MEASUREMENT.upper()},
        {"stable_platform_id": STABLE_ID},
    ],
    ids=[
        "chip_short",
        "chip_zero",
        "chip_missing",
        "chip_upper_hex",
        "chip_odd_hex",
        "chip_int",
        "chip_bytearray",
        "measurement_short",
        "measurement_tdx",
        "measurement_upper",
        "stable_id_set",
    ],
)
def test_a_malformed_snp_attestation_is_an_error(changes):
    with pytest.raises(adm.AdmissionError):
        _admit(_snp(**changes), policy=_policy("sev_snp"))


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


def test_an_attestation_of_the_wrong_type_is_an_error():
    with pytest.raises(adm.AdmissionError):
        adm.admit(
            {"kind": "tdx"},
            box_id="box-1",
            miner_hotkey=HOTKEY,
            nonce=NONCE,
            policy=_policy(),
            admitted={},
            tls_certificate_der=CERT,
        )


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
        attestation = rng.choice([_tdx, _snp])()
        fields = {f.name: getattr(attestation, f.name) for f in dataclasses.fields(attestation)}
        call = {
            "box_id": "box-1",
            "miner_hotkey": HOTKEY,
            "nonce": NONCE,
            "policy": _policy(attestation.kind),
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
        yield adm.VerifiedAttestation(**fields), call


def test_fuzzed_input_is_an_admission_error_or_a_decision_never_another_exception():
    decisions = errors = 0
    for attestation, call in _mutations():
        try:
            result = adm.admit(attestation, **call)
        except adm.AdmissionError:
            errors += 1
        else:
            decisions += 1
            assert isinstance(result, adm.Admission)
            assert result.admitted == (not result.reasons)
            assert (result.evidence is None) == (not result.admitted)
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
