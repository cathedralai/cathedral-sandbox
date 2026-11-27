"""AB#1004: shared Turin floor primitives; archived reports are not live admission.

The strict direct entry point is exercised with current synthetic chains/CRLs in
test_direct_snp_report.py. This archived AMD chain tests legacy compatibility."""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tests import test_verify_receipts_turin as fixture

vr = fixture._vr()
FLOOR = "turin:fmc=1,bl=3,tee=3,snp=8,ucode=118"
VALUES = {"fmc": 1, "bl": 3, "tee": 3, "snp": 8, "ucode": 118}
BYTES = {"fmc": 0, "bl": 1, "tee": 2, "snp": 3, "ucode": 7}
TCBS = {"current": 0x38, "reported": 0x180, "committed": 0x1E0, "launch": 0x1F0}
REPORT = base64.b64decode(json.loads((fixture.TURIN / "attestation-chi-ur-2.json").read_text())["report_b64"])


def run_verifier(tmp_path: Path, *extra: str):
    """Real CLI and AMD signatures, with the archived report's public chain cached offline."""
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    pem = serialization.Encoding.PEM
    chain = b"".join(x509.load_der_x509_certificate((fixture.TURIN / f"{name}.der").read_bytes())
                     .public_bytes(pem) for name in ("ask", "ark"))
    (cache / "Turin-cert_chain.pem").write_bytes(chain)
    chip, tcb = REPORT[0x1A0:0x1E0].hex(), REPORT[0x180:0x188].hex()
    (cache / f"vcek-{chip[:16]}-{tcb}.der").write_bytes((fixture.TURIN / "vcek-chi-ur-2.der").read_bytes())
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps({"report_b64": base64.b64encode(REPORT).decode()}))
    proc = subprocess.run([
        sys.executable, str(fixture.ROOT / "room-kit" / "verify_receipts.py"), "--fresh-report", str(answer),
        "--report-data-hex", REPORT[0x50:0x90].hex(),
        "--ark-sha256", fixture.TURIN_PIN, "--kds-cache", str(cache), *extra,
    ], capture_output=True, text=True, timeout=10)
    return proc.returncode, json.loads(proc.stdout)


def test_archived_turin_report_passes_legacy_cli_with_complete_floor(tmp_path):
    code, out = run_verifier(tmp_path, "--min-tcb", FLOOR)
    assert (code, out["verdict"]) == (0, "PASS"), out
    assert out["attestation"]["amd"]["product"] == "Turin"
    checked = out["tcb_floor"]
    assert checked["generation"] == "turin" and checked["floor"] == VALUES
    assert checked["tcbs"] == {name: VALUES for name in TCBS}


@pytest.mark.parametrize("component", VALUES)
def test_each_turin_component_can_refuse_a_correctly_signed_report(tmp_path, component):
    floor = {**VALUES, component: VALUES[component] + 1}
    spec = "turin:" + ",".join(f"{k}={v}" for k, v in floor.items())
    code, out = run_verifier(tmp_path, "--min-tcb", spec)
    assert (code, out["verdict"]) == (1, "FAIL")
    assert out["reason"].startswith("TCB floor: current TCB ") and "is below" in out["reason"]


@pytest.mark.parametrize("tcb", TCBS)
@pytest.mark.parametrize("component", VALUES)
def test_floor_checks_each_component_on_each_tcb(tcb, component):
    # Isolate floor decoding after AMD verification, so a signature failure cannot hide a missed byte.
    report = bytearray(REPORT)
    report[TCBS[tcb] + BYTES[component]] -= 1
    with pytest.raises(vr.Fail, match=f"TCB floor: {tcb} TCB .*is below"):
        vr.check_tcb_floor(bytes(report), vr.parse_report(bytes(report)), vr.parse_min_tcb([FLOOR]))


def test_genoa_floor_does_not_satisfy_turin(tmp_path):
    code, out = run_verifier(tmp_path, "--min-tcb", "genoa:bl=0,tee=0,snp=0,ucode=0")
    assert code == 1 and "is not a generation --min-tcb names" in out["reason"]


@pytest.mark.parametrize("spec,reason", [
    ("turin:bl=3,tee=3,snp=8,ucode=118", "fmc missing"),
    ("turin:fmc=1,bl=3,tee=3,snp=8", "ucode missing"),
    ("turin:fmc=256,bl=3,tee=3,snp=8,ucode=118", "fmc must be from 0 to 255"),
    (FLOOR + ",fmc=1", "expected"),
    (FLOOR + ",reserved=0", "expected"),
    ("genoa:fmc=0,bl=3,tee=3,snp=8,ucode=118", "expected"),
])
def test_generation_specific_components_are_required(spec, reason):
    with pytest.raises(ValueError, match=reason):
        vr.parse_min_tcb([spec])


def test_explicit_zero_and_multiple_generation_floors():
    specs = ["genoa:bl=0,tee=0,snp=0,ucode=0", "turin:fmc=0,bl=0,tee=0,snp=0,ucode=0"]
    floors = vr.parse_min_tcb(specs)
    assert floors["turin"] == dict.fromkeys(VALUES, 0)
    assert "fmc" not in floors["genoa"]
    assert vr.check_tcb_floor(REPORT, vr.parse_report(REPORT), floors)["generation"] == "turin"
    with pytest.raises(ValueError, match="names turin twice"):
        vr.parse_min_tcb([FLOOR, FLOOR])


@pytest.mark.parametrize("family,model", [(0x1A, 0x12), (0x1B, 0x02), (0x19, 0x11)])
def test_turin_floor_does_not_expand_the_existing_product_map(family, model):
    rep = {**vr.parse_report(REPORT), "cpuid_fam": family, "cpuid_mod": model}
    with pytest.raises(vr.Fail, match="is not a generation --min-tcb names"):
        vr.check_tcb_floor(REPORT, rep, vr.parse_min_tcb([FLOOR]))


def test_legacy_no_floor_remains_explicitly_unchecked(tmp_path):
    code, out = run_verifier(tmp_path)
    assert code == 0 and out["tcb_floor"] == "not checked"
