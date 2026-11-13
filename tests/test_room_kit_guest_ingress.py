"""Guest ingress key on the receipts front (room_receipts.py, AB#422).

A sealed guest with ROOM_GUEST_INGRESS=1 makes a P-256 TLS key for customer
Preview URLs inside the guest and names its SPKI sha256 in the binding, so
REPORT_DATA commits to it. verify_receipts.verify_guest_ingress checks the
field and, given the SPKI of the TLS peer that served a Preview URL, that the
session ended in the guest. Nothing serves on the key yet.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KIT = Path(__file__).resolve().parents[1] / "room-kit"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rr = _load("room_receipts_ingress_t", KIT / "room_receipts.py")
vr = _load("verify_receipts_ingress_t", KIT / "verify_receipts.py")

CONFIG_BINDING_KEYS = {"schema", "hotel", "boot_id", "created_at", "receipt_key_ed25519_b64", "measurement", "chip_id",
                       "reported_tcb", "policy", "host_data", "kernel_cmdline", "kernel_release", "software", "tenancy"}


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _fake_report(report_data: bytes) -> bytes:
    report = bytearray(0x4A0)
    report[0:4] = (3).to_bytes(4, "little")
    report[0x08:0x10] = (0x30000).to_bytes(8, "little")
    report[0x50:0x90] = report_data
    report[0x90:0xC0] = bytes.fromhex("ab" * 48)
    report[0xC0:0xE0] = bytes.fromhex("cd" * 32)
    report[0x180:0x188] = bytes.fromhex("01" * 8)
    report[0x1A0:0x1E0] = bytes.fromhex("ef" * 64)
    return bytes(report)


def _ledger(tmp_path, monkeypatch, *, ingress: bool = True, sealed: bool = True, secrets: bool = False):
    asked: list[bytes] = []

    def report(data: bytes) -> bytes:
        asked.append(data)
        return _fake_report(data)

    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest" if sealed else None)
    monkeypatch.setattr(rr, "snp_report", report)
    root = tmp_path / "room-secrets"
    root.mkdir(parents=True, exist_ok=True)
    ledger = rr.Ledger("room-a", str(tmp_path / "store"), secrets=rr.SealedSecrets(str(root)) if secrets else None,
                       ingress=rr.GuestIngress("room-a") if ingress else None)
    return ledger, asked


def _cert_spki_sha256(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _copy(att: dict) -> dict:
    out = json.loads(json.dumps(att))
    return out


# ---------------------------------------------------------------- the flag

@pytest.mark.parametrize("value,on", [(None, False), ("0", False), ("true", False), ("1", True)])
def test_only_one_turns_the_flag_on(monkeypatch, value, on) -> None:
    if value is None:
        monkeypatch.delenv("ROOM_GUEST_INGRESS", raising=False)
    else:
        monkeypatch.setenv("ROOM_GUEST_INGRESS", value)
    assert rr.guest_ingress_wanted() is on


# ---------------------------------------------------------------- the binding

def test_flag_off_leaves_the_binding_as_it_was(tmp_path, monkeypatch) -> None:
    ledger, asked = _ledger(tmp_path, monkeypatch, ingress=False)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS
    assert ledger.ingress is None
    assert asked[-1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)


def test_flag_on_names_the_guest_key_in_the_binding_that_report_data_commits_to(tmp_path, monkeypatch) -> None:
    ledger, asked = _ledger(tmp_path, monkeypatch)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS | {"guest_ingress"}
    spki = ledger.ingress.tls_spki_sha256
    assert ledger.binding["guest_ingress"] == {"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": spki}
    # The SPKI the binding names is the key in the certificate the guest will serve.
    assert _cert_spki_sha256(ledger.ingress.cert_pem) == spki
    assert ledger.binding_sha256 == hashlib.sha256(canonical(ledger.binding)).hexdigest()
    assert asked[-1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)
    assert "PRIVATE" not in repr(ledger.ingress).upper()
    # Not the miner control-plane field: a config hotel names no tls_spki_sha256 at the top.
    assert "tls_spki_sha256" not in ledger.binding


def test_level1_never_offers_the_key(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, sealed=False)
    assert ledger.ingress is None and "guest_ingress" not in ledger.binding


def test_each_boot_makes_a_new_key(tmp_path, monkeypatch) -> None:
    a, _ = _ledger(tmp_path / "a", monkeypatch)
    b, _ = _ledger(tmp_path / "b", monkeypatch)
    assert a.binding["guest_ingress"]["tls_spki_sha256"] != b.binding["guest_ingress"]["tls_spki_sha256"]


def test_sits_beside_sealed_secrets(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, secrets=True)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS | {"guest_ingress", "sealed_secrets"}


# ---------------------------------------------------------------- the verifier

def test_verifier_reads_the_key_and_checks_the_peer(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    att = ledger.attestation()
    spki = ledger.ingress.tls_spki_sha256
    vr.verify_attestation(att, "ab" * 48, None, str(tmp_path / "kds"), None, skip_amd=True)
    assert vr.verify_guest_ingress(att) == {"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": spki,
                                            "peer_checked": False}
    assert vr.verify_guest_ingress(att, spki.upper(), require=True)["peer_checked"] is True
    # The host terminates TLS with a key of its own.
    with pytest.raises(vr.Fail, match="host answered"):
        vr.verify_guest_ingress(att, "5e" * 32)


def test_a_swapped_key_breaks_report_data(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    forged = _copy(ledger.attestation())
    forged["binding"]["guest_ingress"]["tls_spki_sha256"] = "5e" * 32
    forged["binding_sha256"] = hashlib.sha256(canonical(forged["binding"])).hexdigest()
    with pytest.raises(vr.Fail, match="REPORT_DATA does not commit"):
        vr.verify_attestation(forged, None, None, str(tmp_path), None, skip_amd=True)


def test_verifier_without_a_key(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, ingress=False)
    att = ledger.attestation()
    assert vr.verify_guest_ingress(att) is None
    with pytest.raises(vr.Fail, match="names no guest ingress key"):
        vr.verify_guest_ingress(att, require=True)
    with pytest.raises(vr.Fail, match="names no guest ingress key"):
        vr.verify_guest_ingress(att, "5e" * 32)


@pytest.mark.parametrize("field", ["5e" * 32, {"tls_spki_sha256": "5e" * 32},
                                   {"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": "5E" * 32},
                                   {"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": "5e" * 31},
                                   {"schema": "cathedral_guest_ingress_v1"}])
def test_verifier_refuses_a_malformed_field(tmp_path, monkeypatch, field) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    att = _copy(ledger.attestation())
    att["binding"]["guest_ingress"] = field
    with pytest.raises(vr.Fail, match="guest_ingress"):
        vr.verify_guest_ingress(att)


def test_verifier_refuses_level1(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, sealed=False)
    att = _copy(ledger.attestation())
    att["binding"]["guest_ingress"] = {"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": "5e" * 32}
    with pytest.raises(vr.Fail, match="level 1"):
        vr.verify_guest_ingress(att)


def test_the_cli_reports_the_key(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    (tmp_path / "att.json").write_text(json.dumps(ledger.attestation()))
    (tmp_path / "chain.json").write_text(json.dumps({"receipts": list(ledger.chain), "head": ledger.head}))
    proc = subprocess.run([os.sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(tmp_path / "att.json"),
                           "--receipts", str(tmp_path / "chain.json"), "--skip-amd", "--require-sealed"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)["attestation"]["guest_ingress"]
    assert out == {"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": ledger.ingress.tls_spki_sha256,
                   "peer_checked": False}
