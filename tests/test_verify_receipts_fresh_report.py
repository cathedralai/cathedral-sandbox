"""verify_receipts.py --fresh-report (AB#947): the broker's fresh check of a miner hotel's POST /room/attest answer.

The report is the signed synthetic Milan report of the receipt list pack (tests/fixtures/receipt_lists_v2/source/amd),
checked offline: its ASK, ARK and VCEK are served from a KDS cache folder, pinned by the pack's ARK sha256.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "room-kit" / "verify_receipts.py"
AMD = ROOT / "tests" / "fixtures" / "receipt_lists_v2" / "source" / "amd"


def _report() -> bytes:
    return base64.b64decode(json.loads((AMD / "report.json").read_text())["report_b64"])


def _pin() -> str:
    return (AMD / "ark_sha256.txt").read_text().strip()


def _cache(tmp_path: Path, report: bytes) -> Path:
    """A KDS cache holding the pack's chain, with its VCEK under the file name the report's chip id and TCB give."""
    certs = {k: x509.load_der_x509_certificate(base64.b64decode(v))
             for k, v in json.loads((AMD / "certs.json").read_text()).items()}
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    pem = serialization.Encoding.PEM
    (cache / "Milan-cert_chain.pem").write_bytes(certs["ask"].public_bytes(pem) + certs["ark"].public_bytes(pem))
    chip, tcb = report[0x1A0:0x1E0].hex(), report[0x180:0x188].hex()
    (cache / f"vcek-{chip[:16]}-{tcb}.der").write_bytes(certs["vcek"].public_bytes(serialization.Encoding.DER))
    return cache


def _run(tmp_path: Path, report: bytes, report_data_hex: str, *extra: str) -> tuple[int, dict]:
    answer = tmp_path / "answer.json"
    # binding_sha256 and measurement are the hotel's unsigned word: wrong values here must change nothing.
    answer.write_text(json.dumps({"report_b64": base64.b64encode(report).decode(), "cert_chain": None,
                                  "binding_sha256": "00" * 32, "measurement": "ff" * 48, "generated_at": 1}))
    proc = subprocess.run([sys.executable, str(CHECKER), "--fresh-report", str(answer),
                           "--report-data-hex", report_data_hex, "--ark-sha256", _pin(),
                           "--kds-cache", str(_cache(tmp_path, report)), *extra],
                          capture_output=True, text=True, check=False)
    assert proc.stdout.strip(), proc.stderr
    return proc.returncode, json.loads(proc.stdout)


def test_a_signed_report_over_the_sent_value_passes_and_names_its_signed_fields(tmp_path: Path) -> None:
    report = _report()
    code, out = _run(tmp_path, report, report[0x50:0x90].hex())
    assert (code, out["verdict"]) == (0, "PASS"), out
    fr = out["fresh_report"]
    assert fr["measurement"] == report[0x90:0xC0].hex()
    assert fr["chip_id"] == report[0x1A0:0x1E0].hex()
    assert fr["report_id"] == report[0x140:0x160].hex()
    assert fr["launch_tcb"] == report[0x1F0:0x1F8].hex()
    assert out["attestation"]["amd"]["ark_sha256"] == _pin()


def test_a_report_data_byte_flipped_in_the_sent_value_fails(tmp_path: Path) -> None:
    report = _report()
    sent = bytearray(report[0x50:0x90])
    sent[7] ^= 1
    code, out = _run(tmp_path, report, bytes(sent).hex())
    assert (code, out["verdict"], out["reason"]) == (1, "FAIL", "REPORT_DATA is not the value sent")


def test_a_report_data_byte_flipped_in_the_report_fails_its_signature(tmp_path: Path) -> None:
    report = bytearray(_report())
    report[0x50 + 7] ^= 1
    code, out = _run(tmp_path, bytes(report), report[0x50:0x90].hex())
    assert (code, out["verdict"]) == (1, "FAIL")
    assert out["reason"] == "report signature does not verify with the VCEK"


def test_a_report_naming_another_chip_fails(tmp_path: Path) -> None:
    report = bytearray(_report())
    report[0x1A0] ^= 0xFF  # the cache serves the real VCEK under the new chip's name: its hwID is the old chip
    code, out = _run(tmp_path, bytes(report), report[0x50:0x90].hex())
    assert (code, out["verdict"]) == (1, "FAIL")
    assert out["reason"] == "VCEK hwID differs from the report chip id"


def test_a_debug_policy_fails(tmp_path: Path) -> None:
    report = bytearray(_report())
    report[0x08 + 2] |= 0x08  # policy bit 19
    code, out = _run(tmp_path, bytes(report), report[0x50:0x90].hex())
    assert (code, out["reason"]) == (1, "guest policy allows debug")


def test_another_ark_pin_fails(tmp_path: Path) -> None:
    report = _report()
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps({"report_b64": base64.b64encode(report).decode()}))
    proc = subprocess.run([sys.executable, str(CHECKER), "--fresh-report", str(answer), "--report-data-hex",
                           report[0x50:0x90].hex(), "--ark-sha256", "00" * 32,
                           "--kds-cache", str(_cache(tmp_path, report))], capture_output=True, text=True, check=False)
    out = json.loads(proc.stdout)
    assert proc.returncode == 1 and "differs from the pinned value" in out["reason"]


def test_no_pin_fails(tmp_path: Path) -> None:
    report = _report()
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps({"report_b64": base64.b64encode(report).decode()}))
    proc = subprocess.run([sys.executable, str(CHECKER), "--fresh-report", str(answer), "--report-data-hex",
                           report[0x50:0x90].hex(), "--kds-cache", str(_cache(tmp_path, report))],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 1 and "needs --ark-sha256" in json.loads(proc.stdout)["reason"]


@pytest.mark.parametrize("extra", [("--require-sealed",), ("--receipts", "r.json"), ("--expected-measurement", "ab"),
                                   ("--min-genoa-snp-spl", "30")])
def test_fresh_mode_refuses_flags_it_does_not_act_on(tmp_path: Path, extra: tuple) -> None:
    proc = subprocess.run([sys.executable, str(CHECKER), "--fresh-report", "x.json", "--report-data-hex", "00" * 64,
                           *extra], capture_output=True, text=True, check=False)
    assert proc.returncode == 2 and "--fresh-report takes only" in proc.stderr


def test_report_data_hex_without_a_file_is_a_usage_error() -> None:
    proc = subprocess.run([sys.executable, str(CHECKER), "--report-data-hex", "00" * 64],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 2 and "go together" in proc.stderr
