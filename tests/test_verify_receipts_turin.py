"""AB#938: verify_receipts.py reads Turin reports (the Go mirror is snpverify/turin_test.go).

The fixture is a real Turin (family 0x1A, model 0x02) version 5 report and its
AMD KDS certificates, so the layout, hwID and URL claims are checked against
AMD's own output, not against this file's reading of the spec.
"""

from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TURIN = ROOT / "cmd" / "cathedral-snp-verifier" / "snpverify" / "testdata" / "amd-turin"
TURIN_PIN = "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a"  # broker/amd_chain.go


def _vr():
    if "verify_receipts_turin_t" not in sys.modules:
        spec = importlib.util.spec_from_file_location("verify_receipts_turin_t", ROOT / "room-kit" / "verify_receipts.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
    return sys.modules["verify_receipts_turin_t"]


def _certs() -> dict:
    return {k: base64.b64encode((TURIN / f"{k}.der").read_bytes()).decode() for k in ("vcek", "ask", "ark")}


def _chain(mut=None, override=None) -> dict:
    vr = _vr()
    report = bytearray((TURIN / "attestation-report.bin").read_bytes())
    if mut:
        mut(report)
    report = bytes(report)
    rep = vr.parse_report(report)
    return vr.verify_amd(report, rep, vr.product(rep, override), "/nonexistent", TURIN_PIN, _certs())


def test_the_fixture_is_the_checked_in_turin_report() -> None:
    assert (TURIN / "attestation-report.bin").read_bytes() == (ROOT / "tests" / "fixtures" / "snp" / "attestation-report.bin").read_bytes()


def test_a_real_turin_report_verifies_with_the_turin_layout() -> None:
    out = _chain()
    # Reported TCB 01 03 02 05 00 00 00 61: FMC, bootloader, TEE, SNP, reserved x3, microcode.
    assert out == {"product": "Turin", "ark_sha256": TURIN_PIN,
                   "tcb": {"fmc": 1, "bootloader": 3, "tee": 2, "snp": 5, "microcode": 0x61}}
    assert _chain(override="Turin")["product"] == "Turin"


def test_the_kds_urls_use_the_turin_product_8_byte_hwid_and_fmc() -> None:
    vr = _vr()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pem = serialization.Encoding.PEM
    chain = b"".join(x509.load_der_x509_certificate((TURIN / f"{k}.der").read_bytes()).public_bytes(pem)
                     for k in ("ask", "ark"))
    asked = []

    def fake_fetch(url, cache, name):
        asked.append(url)
        return chain if url.endswith("/cert_chain") else (TURIN / "vcek.der").read_bytes()

    report = (TURIN / "attestation-report.bin").read_bytes()
    rep = vr.parse_report(report)
    original, vr.fetch = vr.fetch, fake_fetch
    try:
        assert vr.verify_amd(report, rep, "Turin", "/nonexistent", TURIN_PIN)["product"] == "Turin"
    finally:
        vr.fetch = original
    assert asked == [f"{vr.KDS}/Turin/cert_chain",
                     f"{vr.KDS}/Turin/d010789547cc0e11?fmcSPL=1&blSPL=3&teeSPL=2&snpSPL=5&ucodeSPL=97"]


def _set(offset: int, value: int):
    def mut(r):
        r[offset] = value
    return mut


@pytest.mark.parametrize("mut, reason", [
    (_set(0x180, 2), "VCEK fmc SPL differs from the report"),
    (_set(0x181, 4), "VCEK bootloader SPL differs from the report"),
    (_set(0x182, 3), "VCEK tee SPL differs from the report"),
    (_set(0x183, 6), "VCEK snp SPL differs from the report"),
    (_set(0x187, 0x62), "VCEK microcode SPL differs from the report"),
    (_set(0x186, 5), "report signature does not verify with the VCEK"),  # byte 6 is reserved on Turin, not SNP
    (_set(0x1A0, 0xD1), "VCEK hwID differs from the report chip id"),
    (_set(0x1A8, 1), "a Turin report chip id must be 8 bytes followed by zeros"),
    (_set(0x189, 0x12), "the report names cpuid family 26 model 18, which has no layout here"),
    (_set(0x188, 0x1B), "the report names cpuid family 27 model 2, which has no layout here"),
], ids=["fmc", "bootloader", "tee", "snp", "microcode", "reserved-6", "hwid", "chip-tail", "model-0x12", "family-0x1b"])
def test_turin_fields_are_read_at_their_offsets(mut, reason) -> None:
    vr = _vr()
    with pytest.raises(vr.Fail, match=reason):
        _chain(mut)


@pytest.mark.parametrize("override", ["Genoa", "Milan"])
def test_a_turin_report_cannot_be_read_as_milan_or_genoa(override) -> None:
    vr = _vr()
    with pytest.raises(vr.Fail, match=f"--product {override}: the report names the product Turin"):
        _chain(override=override)


def test_product_map_and_version_2() -> None:
    vr = _vr()
    for mod in (0x00, 0x02, 0x11):
        assert vr.product({"version": 3, "cpuid_fam": 0x1A, "cpuid_mod": mod}, None) == "Turin"
    # Turin firmware writes version 3 on; a version 2 report takes only Milan or Genoa.
    with pytest.raises(vr.Fail, match="only Milan and Genoa TCB layouts are handled"):
        vr.product({"version": 2, "cpuid_fam": None, "cpuid_mod": None}, "Turin")
    with pytest.raises(vr.Fail, match="--product Turin: the report names the product Genoa"):
        vr.product({"version": 5, "cpuid_fam": 0x19, "cpuid_mod": 0x11}, "Turin")


def test_the_chi_ur_2_attestation_from_engaging_loon_verifies() -> None:
    """The sealed UR hotel on the AB#938 target host (EPYC 9355P): binding, report and Turin chain."""
    import json

    vr = _vr()
    att = json.loads((TURIN / "attestation-chi-ur-2.json").read_text())
    certs = {**_certs(), "vcek": base64.b64encode((TURIN / "vcek-chi-ur-2.der").read_bytes()).decode()}
    measurement = ("1a0a6071cab3ca8b3c7cd47c868840ed10618734493e588b5c2e24a02275724e"
                   "8cfa4ebfce383b04880e73dfa5c4b1fa")
    out = vr.verify_attestation(att, measurement, None, "/nonexistent", TURIN_PIN, False, certs)
    assert out["amd"] == {"product": "Turin", "ark_sha256": TURIN_PIN,
                          "tcb": {"fmc": 1, "bootloader": 3, "tee": 3, "snp": 8, "microcode": 118}}
    # The legacy Genoa-only flag still refuses Turin instead of silently skipping it.
    with pytest.raises(vr.Fail, match="Genoa SNP floor requires a verified AMD processor generation"):
        vr.verify_attestation(att, measurement, None, "/nonexistent", TURIN_PIN, False, certs, min_genoa_snp_spl=0x1E)
