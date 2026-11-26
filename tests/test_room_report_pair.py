"""Cross-lane pair test for the in-room report call (AB#1001): the front's real answer, the verifier's real CLI.

The front (room_receipts.RoomReports) answers over its Unix socket with a fake TSM. The boot and fresh reports
are then signed with one test VCEK (the verifier fixture's), as a chip would sign them, and the answer goes to
verify_receipts.py --room-report. Nothing in the answer is hand-built: field names, statement members, signature
encoding and REPORT_DATA all come from the front.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys

import pytest

from tests import test_room_kit_room_report as front
from tests import test_verify_receipts_room_report as verifier
from tests.test_room_kit_room_report import hotel  # noqa: F401 the front fixture

@pytest.fixture(autouse=True)
def chip_reports(monkeypatch):
    # Realistic reports (version, signature algorithm, chip id, TCB) from the verifier suite's builder, one launch.
    monkeypatch.setattr(front, "_fake_report", lambda data: verifier._with_report_id(
        verifier.snp.make_report(report_data=data), verifier.LAUNCH))


def _front_answer(hotel_fixture, nonce: bytes) -> tuple[dict, str]:
    ledger, _reports, root, _api, _tsm = hotel_fixture
    front.started(hotel_fixture)
    status, _h, answer = front.post(front.sock(root), {"report_data_hex": nonce.hex()})
    assert status == 200, answer
    return answer, ledger.hotel


def _run(tmp_path, answer: dict, nonce: str, hotel_id: str, room: str = front.ROOM) -> tuple[int, dict]:
    cache = tmp_path / "kds"
    boot = base64.b64decode(answer["attestation"]["report_b64"])
    fresh = base64.b64decode(answer["report_b64"])
    boot, fresh = verifier._sign_with_one_vcek([boot, fresh], cache)
    answer = {**answer, "report_b64": base64.b64encode(fresh).decode(),
              "attestation": {**answer["attestation"], "report_b64": base64.b64encode(boot).decode()}}
    path = tmp_path / "answer.json"
    path.write_text(json.dumps(answer))
    proc = subprocess.run([sys.executable, str(verifier.KIT / "verify_receipts.py"), "--room-report", str(path),
                           "--nonce", nonce, "--hotel", hotel_id, "--sandbox-id", room,
                           "--ark-sha256", verifier.snp.ark_pin(), "--kds-cache", str(cache),
                           "--expected-measurement", verifier.snp.MEASUREMENT],
                          capture_output=True, text=True, check=False)
    assert proc.stdout.strip(), proc.stderr
    return proc.returncode, json.loads(proc.stdout)


def test_the_verifier_accepts_the_fronts_answer(hotel, tmp_path) -> None:  # noqa: F811
    answer, hotel_id = _front_answer(hotel, front.NONCE)
    code, verdict = _run(tmp_path, answer, front.NONCE.hex(), hotel_id)
    assert code == 0, verdict


def test_the_verifier_rejects_the_fronts_answer_for_another_room(hotel, tmp_path) -> None:  # noqa: F811
    answer, hotel_id = _front_answer(hotel, front.NONCE)
    code, verdict = _run(tmp_path, answer, front.NONCE.hex(), hotel_id, room=front.OTHER)
    assert code != 0, verdict
