"""A synthetic Genoa AMD chain and sealed attestation for the verify_receipts.py floor and list tests (AB#968).

The ARK, ASK and VCEK are made here (RSA-PSS SHA-384 and P-384, as AMD's are) and sign nothing real, so a test
can set any TCB byte, VMPL, policy or CPUID model and still get a report the chain verifies.
"""
from __future__ import annotations

import base64
import datetime
import functools
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "room-kit" / "verify_receipts.py"
CHIP_ID = hashlib.sha512(b"ab968 test chip").hexdigest()
MEASUREMENT = hashlib.sha384(b"ab968 test build").hexdigest()
MANIFEST_SHA256 = hashlib.sha256(b"ab968 test manifest").hexdigest()
POLICY = 0x30000
# Genoa TCB_VERSION: bootloader, TEE, reserved x4, SNP, microcode. The phase 1 floor exactly.
FLOOR_TCB = bytes([12, 0, 0, 0, 0, 0, 30, 88])
FLOOR = "genoa:bl=12,tee=0,snp=30,ucode=88"
TCB_OFFSETS = {"current": 0x38, "reported": 0x180, "committed": 0x1E0, "launch": 0x1F0}
COMPONENT_BYTES = {"bl": 0, "tee": 1, "snp": 6, "ucode": 7}
OWNER_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"ab968 test owner").digest())
OWNER_B64 = base64.b64encode(OWNER_KEY.public_key().public_bytes_raw()).decode()
RECEIPT_KEY_B64 = base64.b64encode(
    Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"ab968 test receipt").digest()).public_key()
    .public_bytes_raw()).decode()


def shared_host_data(manifest_sha256: str = MANIFEST_SHA256) -> str:
    return manifest_sha256


def dedicated_host_data(manifest_sha256: str = MANIFEST_SHA256, owner_b64: str = OWNER_B64) -> str:
    return hashlib.sha256(b"cathedral-dedicated-v1\0" + bytes.fromhex(manifest_sha256)
                          + base64.b64decode(owner_b64)).hexdigest()


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, public, signer, serial, extensions=()):
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    builder = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
               .public_key(public).serial_number(serial)
               .not_valid_before(datetime.datetime(2024, 1, 1)).not_valid_after(datetime.datetime(2124, 1, 1)))
    for oid, value in extensions:
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), False)
    return builder.sign(signer, hashes.SHA384(), rsa_padding=pss)


@functools.lru_cache(maxsize=1)
def roots():
    ark_key = rsa.generate_private_key(65537, 2048)
    ask_key = rsa.generate_private_key(65537, 2048)
    ark = _cert("ARK-Genoa", "ARK-Genoa", ark_key.public_key(), ark_key, 1)
    ask = _cert("SEV-Genoa", "ARK-Genoa", ask_key.public_key(), ark_key, 2)
    return ark, ask, ask_key


def ark_pin() -> str:
    return hashlib.sha256(roots()[0].public_bytes(serialization.Encoding.DER)).hexdigest()


def make_report(binding_sha256: str | None = None, *, version: int = 3, model: int = 0x11, family: int = 0x19,
                vmpl: int = 0, policy: int = POLICY, host_data: str | None = None, tcbs: dict | None = None,
                report_data: bytes | None = None, chip_id: str = CHIP_ID) -> bytes:
    """An unsigned report; tcbs maps current/reported/committed/launch to 8 TCB bytes (default: the floor)."""
    r = bytearray(0x4A0)
    r[0:4] = version.to_bytes(4, "little")
    r[0x08:0x10] = policy.to_bytes(8, "little")
    r[0x30:0x34] = vmpl.to_bytes(4, "little")
    r[0x34:0x38] = (1).to_bytes(4, "little")
    if report_data is None:
        report_data = bytes.fromhex(binding_sha256) + bytes(32)
    r[0x50:0x90] = report_data
    r[0x90:0xC0] = bytes.fromhex(MEASUREMENT)
    r[0xC0:0xE0] = bytes.fromhex(host_data or shared_host_data())
    for name, offset in TCB_OFFSETS.items():
        r[offset:offset + 8] = (tcbs or {}).get(name, FLOOR_TCB)
    if version >= 3:
        r[0x188], r[0x189] = family, model
    r[0x1A0:0x1E0] = bytes.fromhex(chip_id)
    return bytes(r)


def sign(report: bytes, cache: Path) -> bytes:
    """Sign the report with a fresh VCEK for its chip and reported TCB, and put the chain in a KDS cache."""
    ark, ask, ask_key = roots()
    tcb = report[0x180:0x188]
    vcek_key = ec.generate_private_key(ec.SECP384R1())

    def spl(n: int) -> bytes:
        return bytes([0x02, 0x01, n])

    vcek = _cert("SEV-VCEK", "SEV-Genoa", vcek_key.public_key(), ask_key, 3, [
        ("1.3.6.1.4.1.3704.1.4", report[0x1A0:0x1E0]),
        ("1.3.6.1.4.1.3704.1.3.1", spl(tcb[0])), ("1.3.6.1.4.1.3704.1.3.2", spl(tcb[1])),
        ("1.3.6.1.4.1.3704.1.3.3", spl(tcb[6])), ("1.3.6.1.4.1.3704.1.3.8", spl(tcb[7]))])
    r = bytearray(report)
    sig_r, sig_s = decode_dss_signature(vcek_key.sign(bytes(r[:0x2A0]), ec.ECDSA(hashes.SHA384())))
    r[0x2A0:0x2A0 + 72] = sig_r.to_bytes(72, "little")
    r[0x2E8:0x2E8 + 72] = sig_s.to_bytes(72, "little")
    cache.mkdir(parents=True, exist_ok=True)
    pem = serialization.Encoding.PEM
    family, model = (r[0x188], r[0x189]) if r[0] >= 3 else (0x19, 0x11)
    product = "Genoa" if family == 0x19 and model >= 0x10 else "Milan"
    (cache / f"{product}-cert_chain.pem").write_bytes(ask.public_bytes(pem) + ark.public_bytes(pem))
    chip = r[0x1A0:0x1E0].hex()
    (cache / f"vcek-{chip[:16]}-{tcb.hex()}.der").write_bytes(vcek.public_bytes(serialization.Encoding.DER))
    return bytes(r)


def attestation(cache: Path, *, hotel: str = "ab968-hotel", tenancy: str = "shared", host_data: str | None = None,
                **report_knobs) -> dict:
    """A sealed attestation whose report the synthetic chain signs."""
    if host_data is None:
        host_data = dedicated_host_data() if tenancy == "dedicated" else shared_host_data()
    probe = make_report("00" * 32, host_data=host_data, **report_knobs)
    binding = {"schema": "cathedral_sealed_hotel_binding_v1", "hotel": hotel, "boot_id": "ab968-boot-1",
               "measurement": MEASUREMENT, "chip_id": CHIP_ID, "reported_tcb": probe[0x180:0x188].hex(),
               "policy": hex(report_knobs.get("policy", POLICY)), "host_data": host_data,
               "receipt_key_ed25519_b64": RECEIPT_KEY_B64, "tenancy": tenancy, "manifest_sha256": MANIFEST_SHA256}
    if tenancy == "dedicated":
        binding["owner_ed25519_b64"] = OWNER_B64
    bsha = hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report = sign(make_report(bsha, host_data=host_data, **report_knobs), cache)
    return {"binding": binding, "binding_sha256": bsha, "report_b64": base64.b64encode(report).decode()}


def run(tmp_path: Path, att: dict | None, *extra: str, pin: bool = True) -> tuple[int, dict | None, str]:
    """verify_receipts.py on att with no receipts. Returns (exit code, JSON stdout or None, stderr)."""
    args = [sys.executable, str(CHECKER)]
    if att is not None:
        path = tmp_path / "attestation.json"
        path.write_text(json.dumps(att))
        args += ["--attestation", str(path), "--kds-cache", str(tmp_path / "cache")]
    if pin:
        args += ["--ark-sha256", ark_pin()]
    proc = subprocess.run([*args, *extra], capture_output=True, text=True, check=False)
    return proc.returncode, (json.loads(proc.stdout) if proc.stdout.strip() else None), proc.stderr


def run_fresh(tmp_path: Path, *extra: str, **report_knobs) -> tuple[int, dict | None, str]:
    """--fresh-report on one signed report over a fixed REPORT_DATA."""
    cache = tmp_path / "cache"
    sent = bytes(range(64))
    report = sign(make_report(report_data=sent, **report_knobs), cache)
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps({"report_b64": base64.b64encode(report).decode()}))
    proc = subprocess.run([sys.executable, str(CHECKER), "--fresh-report", str(answer), "--report-data-hex",
                           sent.hex(), "--ark-sha256", ark_pin(), "--kds-cache", str(cache), *extra],
                          capture_output=True, text=True, check=False)
    return proc.returncode, (json.loads(proc.stdout) if proc.stdout.strip() else None), proc.stderr
