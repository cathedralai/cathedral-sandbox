"""verify_receipts.py --room-report (AB#1001, work package 4 of docs/IN_ROOM_REPORT_CALL.md).

The AMD chain is the synthetic Genoa chain of tests/snp_floor_support.py. One VCEK signs both the boot report and
the fresh report, as one chip does, so one KDS cache serves both. Receipts are signed with a test Ed25519 key.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

sys.path.insert(0, str(Path(__file__).resolve().parent))
import snp_floor_support as snp  # noqa: E402

KIT = Path(__file__).resolve().parents[1] / "room-kit"
NONCE = hashlib.sha512(b"room report test nonce").hexdigest()
ROOM = "room-a"
LAUNCH = hashlib.sha256(b"launch one").digest()
OTHER_LAUNCH = hashlib.sha256(b"launch two").digest()


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, KIT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


vr = _load("verify_receipts")
rr = _load("room_receipts")


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


RECEIPT_KEY = _key("ab968 test receipt")  # the key snp_floor_support puts in its binding
OTHER_KEY = _key("an outsider")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _sign_with_one_vcek(reports: list[bytes], cache: Path) -> list[bytes]:
    """Sign each report with the same fresh VCEK (one chip, one TCB), and write the KDS cache once."""
    ark, ask, ask_key = snp.roots()
    tcb, chip = reports[0][0x180:0x188], reports[0][0x1A0:0x1E0]
    vcek_key = ec.generate_private_key(ec.SECP384R1())

    def spl(n: int) -> bytes:
        return bytes([0x02, 0x01, n])

    vcek = snp._cert("SEV-VCEK", "SEV-Genoa", vcek_key.public_key(), ask_key, 3, [
        ("1.3.6.1.4.1.3704.1.4", chip), ("1.3.6.1.4.1.3704.1.3.1", spl(tcb[0])), ("1.3.6.1.4.1.3704.1.3.2", spl(tcb[1])),
        ("1.3.6.1.4.1.3704.1.3.3", spl(tcb[6])), ("1.3.6.1.4.1.3704.1.3.8", spl(tcb[7]))])
    signed = []
    for report in reports:
        r = bytearray(report)
        sig_r, sig_s = decode_dss_signature(vcek_key.sign(bytes(r[:0x2A0]), ec.ECDSA(hashes.SHA384())))
        r[0x2A0:0x2A0 + 72] = sig_r.to_bytes(72, "little")
        r[0x2E8:0x2E8 + 72] = sig_s.to_bytes(72, "little")
        signed.append(bytes(r))
    cache.mkdir(parents=True, exist_ok=True)
    pem = serialization.Encoding.PEM
    (cache / "Genoa-cert_chain.pem").write_bytes(ask.public_bytes(pem) + ark.public_bytes(pem))
    (cache / f"vcek-{chip.hex()[:16]}-{tcb.hex()}.der").write_bytes(vcek.public_bytes(serialization.Encoding.DER))
    return signed


def _with_report_id(report: bytes, report_id: bytes) -> bytes:
    r = bytearray(report)
    r[0x140:0x160] = report_id
    return bytes(r)


def _statement(binding_sha256: str, incarnation: str, **over) -> dict:
    st = {"schema": "cathedral.room.report/v1", "hotel": "ab968-hotel", "binding_sha256": binding_sha256,
          "sandbox_id": ROOM, "incarnation": incarnation, "caller_report_data_hex": NONCE, "requested_at": 1_760_000_000}
    st.update(over)
    return st


def _create_receipt(binding_sha256: str, room: str = ROOM, key: Ed25519PrivateKey = RECEIPT_KEY) -> dict:
    st = {"schema": "cathedral_sealed_hotel_receipt_v1", "binding_sha256": binding_sha256, "hotel": "ab968-hotel",
          "operation_id": "op-1", "sequence": 1, "previous_receipt_sha256": binding_sha256, "issued_at": 1_760_000_000,
          "action": "create", "target": "POST /v1/sandboxes", "sandbox_id": room, "status": 202}
    return {"statement": st, "signature_b64": _b64(key.sign(vr.canonical(st))), "receipt_sha256": vr.sha(vr.canonical(st))}


def _sign_statement(statement: dict, key: Ed25519PrivateKey = RECEIPT_KEY) -> str:
    return _b64(key.sign(rr.canonical(statement)))


class Fixture:
    """A good answer and its KDS cache. Tests change the answer, or ask for another fresh report."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.cache = tmp_path / "cache"
        boot = snp.attestation(tmp_path / "unused")  # binding and its sha; its report is re-made below
        self.binding, self.bsha = boot["binding"], boot["binding_sha256"]
        self.create = _create_receipt(self.bsha)
        self.statement = _statement(self.bsha, self.create["receipt_sha256"])
        self.boot_report = _with_report_id(snp.make_report(self.bsha), LAUNCH)

    def answer(self, fresh_data: bytes | None = None, fresh_launch: bytes = LAUNCH, **over) -> dict:
        statement = over.pop("statement", self.statement)
        data = fresh_data if fresh_data is not None else vr.room_report_data(statement)
        fresh = _with_report_id(snp.make_report(report_data=data), fresh_launch)
        boot, fresh = _sign_with_one_vcek([self.boot_report, fresh], self.cache)
        doc = {"statement": statement, "statement_sig_b64": _sign_statement(statement),
               "statement_sha256": vr.sha(vr.canonical(statement)), "report_b64": _b64(fresh), "cert_chain": None,
               "create_receipt": self.create,
               "attestation": {"binding": self.binding, "binding_sha256": self.bsha, "report_b64": _b64(boot)}}
        doc.update(over)
        return doc

    def run(self, answer: dict, nonce: str = NONCE, *extra: str) -> tuple[int, dict]:
        path = self.tmp_path / "room-report.json"
        path.write_text(json.dumps(answer))
        proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--room-report", str(path),
                               "--nonce", nonce, "--ark-sha256", snp.ark_pin(), "--kds-cache", str(self.cache), *extra],
                              capture_output=True, text=True, check=False)
        assert proc.stdout.strip(), proc.stderr
        return proc.returncode, json.loads(proc.stdout)


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    return Fixture(tmp_path)


def _fails(result: tuple[int, dict], reason: str) -> None:
    code, out = result
    assert (code, out["verdict"]) == (1, "FAIL"), out
    assert reason in out["reason"], out["reason"]


VECTOR_STATEMENT = {"schema": "cathedral.room.report/v1", "hotel": "h", "binding_sha256": "ab" * 32, "sandbox_id": "r",
                    "incarnation": "cd" * 32, "caller_report_data_hex": "00" * 64, "requested_at": 1}
# Pinned literal: the front (room_receipts.py) must make these same 64 bytes from the same statement.
VECTOR_REPORT_DATA = ("6c30d313d7917b14c94d968032e0093bdb4265b9f412898796d857eddf0020e03ad440d56d67c5f504fd35b63de12f3"
                      "84215db34ea7c0525edc86c52c0c26a16")


def test_the_formula_is_pinned_to_the_front() -> None:
    assert vr.canonical(VECTOR_STATEMENT) == rr.canonical(VECTOR_STATEMENT)
    assert vr.room_report_data(VECTOR_STATEMENT).hex() == VECTOR_REPORT_DATA
    assert hashlib.sha512(b"cathedral.room.report/v1\0" + rr.canonical(VECTOR_STATEMENT)).hexdigest() \
        == VECTOR_REPORT_DATA


def test_a_good_answer_passes(fx: Fixture) -> None:
    code, out = fx.run(fx.answer())
    assert (code, out["verdict"]) == (0, "PASS"), out
    assert out["room_report"]["sandbox_id"] == ROOM
    assert out["room_report"]["incarnation"] == fx.create["receipt_sha256"]
    assert out["fresh_report"]["report_id"] == LAUNCH.hex()


def _chain(fx: Fixture, ark=None) -> dict:
    _, ask, _ = snp.roots()
    der = serialization.Encoding.DER
    vcek = next(p for p in fx.cache.iterdir() if p.name.startswith("vcek-")).read_bytes()
    return {"vcek": _b64(vcek), "ask": _b64(ask.public_bytes(der)),
            "ark": _b64((ark or snp.roots()[0]).public_bytes(der))}


def test_the_fresh_report_chain_in_the_answer_is_used(fx: Fixture) -> None:
    answer = fx.answer()
    answer["cert_chain"] = _chain(fx)
    code, out = fx.run(answer)
    assert (code, out["verdict"]) == (0, "PASS"), out
    # a chain whose ARK is not the pinned one fails, so the field is read and not ignored
    answer["cert_chain"] = _chain(fx, ark=snp._cert("ARK-X", "ARK-X", snp.roots()[2].public_key(), snp.roots()[2], 9))
    _fails(fx.run(answer), "an AMD certificate is not signed by the one above")


def test_a_statement_signed_by_another_key_fails(fx: Fixture) -> None:
    answer = fx.answer(statement_sig_b64=_sign_statement(fx.statement, OTHER_KEY))
    _fails(fx.run(answer), "the statement: signature does not verify")


def test_a_create_receipt_signed_by_another_key_fails(fx: Fixture) -> None:
    fx.create = _create_receipt(fx.bsha, key=OTHER_KEY)
    fx.statement = _statement(fx.bsha, fx.create["receipt_sha256"])
    _fails(fx.run(fx.answer()), "the create receipt: signature does not verify")


def test_a_statement_for_another_room_fails(fx: Fixture) -> None:
    other = _statement(fx.bsha, fx.create["receipt_sha256"], sandbox_id="room-b")  # signed, but the create is room-a's
    _fails(fx.run(fx.answer(statement=other)), "the create receipt is for another room")


def test_a_statement_naming_another_incarnation_fails(fx: Fixture) -> None:
    other = _statement(fx.bsha, "11" * 32)
    _fails(fx.run(fx.answer(statement=other)), "not the incarnation the statement names")


def test_a_report_of_another_launch_fails(fx: Fixture) -> None:
    # same chip, same measurement, same VCEK; only REPORT_ID differs
    _fails(fx.run(fx.answer(fresh_launch=OTHER_LAUNCH)), "another launch")


def test_a_report_with_a_zero_report_id_fails(fx: Fixture) -> None:
    fx.boot_report = _with_report_id(fx.boot_report, bytes(32))
    _fails(fx.run(fx.answer(fresh_launch=bytes(32))), "REPORT_ID is zero")


def test_a_tampered_statement_fails(fx: Fixture) -> None:
    answer = fx.answer()
    answer["statement"] = {**fx.statement, "requested_at": fx.statement["requested_at"] + 1}
    answer.pop("statement_sha256")
    _fails(fx.run(answer), "the statement: signature does not verify")


def test_a_statement_and_signature_with_a_report_over_the_old_statement_fails(fx: Fixture) -> None:
    newer = {**fx.statement, "requested_at": fx.statement["requested_at"] + 1}
    answer = fx.answer(statement=newer, report_b64=fx.answer()["report_b64"])  # report commits to the old one
    _fails(fx.run(answer), "fresh REPORT_DATA is not the formula")


def test_a_wrong_nonce_fails(fx: Fixture) -> None:
    _fails(fx.run(fx.answer(), hashlib.sha512(b"another nonce").hexdigest()), "does not carry the nonce sent")


def test_a_malformed_nonce_fails(fx: Fixture) -> None:
    _fails(fx.run(fx.answer(), "abcd"), "--nonce must be 128 hex")


def test_an_outsider_forgery_over_the_formula_fails(fx: Fixture) -> None:
    """An outsider reads the public create receipt and binding, builds a statement, and asks the hotel attest route
    for a report over the formula. The report is chip-signed and its REPORT_DATA is right, but only the room's
    receipt key could sign the statement."""
    forged = _statement(fx.bsha, fx.create["receipt_sha256"])
    answer = fx.answer(statement=forged, statement_sig_b64=_sign_statement(forged, OTHER_KEY))
    _fails(fx.run(answer), "the statement: signature does not verify")
    answer["statement_sig_b64"] = ""
    _fails(fx.run(answer), "the statement: signature does not verify")


def test_a_fresh_report_over_other_bytes_fails(fx: Fixture) -> None:
    _fails(fx.run(fx.answer(fresh_data=bytes(range(64)))), "fresh REPORT_DATA is not the formula")


def test_a_statement_for_another_binding_fails(fx: Fixture) -> None:
    other = _statement("ee" * 32, fx.create["receipt_sha256"])
    _fails(fx.run(fx.answer(statement=other)), "another binding")


def test_a_statement_with_another_schema_or_extra_member_fails(fx: Fixture) -> None:
    _fails(fx.run(fx.answer(statement={**fx.statement, "schema": "cathedral.room.report/v2"})), "schema")
    _fails(fx.run(fx.answer(statement={**fx.statement, "extra": 1})), "exactly")


def test_a_fresh_report_of_another_chip_fails(fx: Fixture) -> None:
    other_chip = hashlib.sha512(b"another chip").hexdigest()
    fresh = snp.make_report(report_data=vr.room_report_data(fx.statement), chip_id=other_chip)
    boot_cache_fresh = _sign_with_one_vcek([_with_report_id(fresh, LAUNCH)], fx.tmp_path / "cache2")
    answer = fx.answer()
    answer["report_b64"] = _b64(boot_cache_fresh[0])
    # the fresh report's VCEK lives in a second cache; copy it beside the first
    for p in (fx.tmp_path / "cache2").iterdir():
        if p.name.startswith("vcek-"):
            (fx.cache / p.name).write_bytes(p.read_bytes())
    _fails(fx.run(answer), "chip id differs from the boot report's")


def test_the_boot_report_is_checked_too(fx: Fixture) -> None:
    answer = fx.answer()
    boot = bytearray(base64.b64decode(answer["attestation"]["report_b64"]))
    boot[0x50] ^= 1
    answer["attestation"]["report_b64"] = _b64(bytes(boot))
    _fails(fx.run(answer), "REPORT_DATA does not commit to the binding")


def test_room_report_refuses_flags_it_does_not_act_on(fx: Fixture) -> None:
    proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--room-report", "x.json", "--nonce",
                           NONCE, "--receipts", "r.json"], capture_output=True, text=True, check=False)
    assert proc.returncode == 2 and "--room-report takes only" in proc.stderr
    proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--nonce", NONCE],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 2 and "go together" in proc.stderr
