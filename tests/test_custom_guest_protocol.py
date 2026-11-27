"""Synthetic owner material only; no host or customer credentials."""
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KIT = Path(__file__).resolve().parents[1] / "room-kit"
sys.path.insert(0, str(KIT))
import custom_guest_protocol as protocol

OWNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC = OWNER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
BLOB = protocol.HOST_KEY_PREFIX + bytes(range(32, 64))
CHALLENGE = bytes(range(64, 96))


def documents(data_disk=True):
    line = " ".join(["console=ttyS0", "cathedral.owner=" + base64.urlsafe_b64encode(PUBLIC).decode().rstrip("="),
                     "cathedral.root_verity=" + "11" * 32, "cathedral.root_data_bytes=4096", "systemd.import_credentials=no"])
    m = {"version": 1, "schema": "cathedral.custom_guest.manifest/v1", "kind": "custom_guest",
             "sha256": dict.fromkeys(protocol.FILES, "22" * 32), "bytes": dict.fromkeys(protocol.FILES, 8192),
             "cmdline": line, "root_verity": "11" * 32, "root_data_bytes": 4096, "vcpus": 4, "cpu_model": "EPYC-Genoa-v1",
             "mem_gib": 4, "data_disk_gib": 0, "policy": "0x30000", "qemu_version": "10.2.1", "sev_snp_measure": "0.0.12",
             "reference_initrd": "v1-test"}
    m["sha256"]["cmdline"] = hashlib.sha256(line.encode()).hexdigest()
    m["bytes"]["cmdline"] = len(line)
    if not data_disk:
        del m["data_disk_gib"]
    b = {"version": 1, "schema": "cathedral.custom_guest.bootstrap/v1", "launch_id": "cg-0123456789ab", "hotel": "test-hotel",
             "owner_scope": "user:00000000-0000-4000-8000-000000000001", "owner_ed25519_b64": base64.b64encode(PUBLIC).decode(),
             "manifest_sha256": hashlib.sha256(protocol.canonical(m)).hexdigest(),
             "ssh_public_key": "ssh-ed25519 " + base64.b64encode(BLOB).decode(), "launch_nonce_hex": "33" * 32,
             "ports": [{"guest": 22, "proto": "tcp", "public": 20022}], "network": {"guest_ip": "10.217.0.2", "host_ip": "10.217.0.1",
                 "prefix": 30, "guest_mac": "52:54:00:c7:00:02", "public_host": "192.0.2.1"}}
    return m, b


def encoded(data_disk=True):
    m, b = documents(data_disk)
    mr, br = protocol.canonical(m), protocol.canonical(b)
    sig = OWNER.sign(protocol.BOOTSTRAP_DOMAIN + hashlib.sha256(br).digest())
    return mr, br, sig


def test_shared_vector():
    vector = json.loads((Path(__file__).parent / "fixtures/custom_guest_v1.json").read_text())
    mr, br, sig = encoded()
    assert vector["manifest_utf8"].encode() == mr
    assert vector["bootstrap_utf8"].encode() == br
    assert vector["owner_public_hex"] == PUBLIC.hex()
    assert vector["signature_hex"] == sig.hex()
    _, _, hd = protocol.validate_launch(mr, br, sig, PUBLIC)
    assert hd == vector["host_data_hex"]
    assert protocol.report_data(CHALLENGE, BLOB).hex() == vector["report_data_hex"]
    assert protocol.bootcheck_data(CHALLENGE).hex() == vector["bootcheck_data_hex"]
    assert vector["report_data_hex"] != vector["bootcheck_data_hex"]


def test_missing_data_disk_means_zero():
    mr, br, sig = encoded(False)
    m, _, _ = protocol.validate_launch(mr, br, sig, PUBLIC)
    assert m.get("data_disk_gib", 0) == 0


@pytest.mark.parametrize("document", ["manifest", "bootstrap"])
@pytest.mark.parametrize("change", ["missing_version", "version_two", "boolean_version", "unknown", "whitespace", "duplicate", "unicode", "float"])
def test_documents_reject_ambiguous_or_unversioned_bytes(document, change):
    m, b = documents()
    d = m if document == "manifest" else b
    if change == "missing_version":
        del d["version"]
    elif change == "version_two":
        d["version"] = 2
    elif change == "boolean_version":
        d["version"] = True
    elif change == "unknown":
        d["other"] = 1
    elif change == "unicode":
        d["other"] = "é"
    elif change == "float":
        d["version"] = 1.0
    raw = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if change == "whitespace":
        raw += b"\n"
    if change == "duplicate":
        raw = raw[:-1] + b',"version":1}'
    with pytest.raises(protocol.ProtocolError):
        getattr(protocol, document)(raw)


@pytest.mark.parametrize("token", ["init=/bin/sh", "rdinit=/bin/sh", "noinitrd", "root=/dev/vda", "rw", "bootconfig",
    "systemd.set_credential=a:b", "systemd.import_credentials=yes", "console=tty0", "quiet=yes", "panic=3601"])
def test_cmdline_refuses_boot_bypasses(token):
    m, _ = documents()
    with pytest.raises(protocol.ProtocolError):
        protocol.cmdline_values(m["cmdline"] + " " + token, 8192)


def test_cmdline_exact_cap_and_duplicate():
    m, _ = documents()
    prefix = m["cmdline"] + " cathedral.note="
    line = prefix + "x" * (2033 - len(prefix))
    assert protocol.cmdline_values(line, 8192)
    for bad in (line + "x", m["cmdline"] + " quiet quiet", " " + m["cmdline"], m["cmdline"].replace(" ", "  ", 1)):
        with pytest.raises(protocol.ProtocolError):
            protocol.cmdline_values(bad, 8192)


@pytest.mark.parametrize("change", ["owner", "manifest", "signature", "bootstrap", "domain"])
def test_cross_document_and_signature_binding(change):
    mr, br, sig = encoded()
    owner = PUBLIC
    if change == "owner":
        owner = b"x" * 32
    if change == "manifest":
        m = json.loads(mr); m["vcpus"] = 8; mr = protocol.canonical(m)
    if change == "bootstrap":
        b = json.loads(br); b["launch_nonce_hex"] = "55" * 32; br = protocol.canonical(b)
    if change == "signature":
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    if change == "domain":
        sig = OWNER.sign(hashlib.sha256(br).digest())
    with pytest.raises((protocol.ProtocolError, InvalidSignature)):
        protocol.validate_launch(mr, br, sig, owner)


@pytest.mark.parametrize("field,value", [("vcpus", True), ("mem_gib", 0), ("data_disk_gib", -1),
    ("policy", "0xb0000"), ("root_data_bytes", 8192), ("reference_initrd", "../other")])
def test_manifest_limits(field, value):
    m, _ = documents(); m[field] = value
    with pytest.raises(protocol.ProtocolError):
        protocol.manifest(protocol.canonical(m))


@pytest.mark.parametrize("change", ["extra_network", "same_ip", "broadcast", "ssh_options", "extra_port", "no_ssh", "same_public"])
def test_bootstrap_nested_limits(change):
    _, b = documents()
    if change == "extra_network": b["network"]["extra"] = 1
    if change == "same_ip": b["network"]["guest_ip"] = b["network"]["host_ip"]
    if change == "broadcast": b["network"]["guest_ip"] = "10.217.0.3"
    if change == "ssh_options": b["ssh_public_key"] = 'command="sh" ' + b["ssh_public_key"]
    if change == "extra_port": b["ports"][0]["extra"] = 1
    if change == "no_ssh": b["ports"][0]["guest"] = 80
    if change == "same_public": b["ports"].append({"guest": 80, "public": 20022, "proto": "tcp"})
    with pytest.raises(protocol.ProtocolError):
        protocol.bootstrap(protocol.canonical(b))


def test_report_domain_pins_key_and_challenge():
    want = protocol.report_data(CHALLENGE, BLOB)
    assert want != protocol.report_data(b"x" * 32, BLOB)
    assert want != protocol.report_data(CHALLENGE, BLOB[:-1] + b"x")
    for bad in (b"", BLOB + b"x", b"x" * len(BLOB)):
        with pytest.raises(protocol.ProtocolError):
            protocol.report_data(CHALLENGE, bad)


def test_owner_sign_cli(tmp_path):
    _mr, br, signature = encoded()
    key = tmp_path / "test-key.pem"
    key.write_bytes(OWNER.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    body = tmp_path / "bootstrap.json"; body.write_bytes(br)
    argv = [sys.executable, str(KIT / "owner_sign.py"), "--custom-guest-bootstrap", "--key", str(key), "--body", str(body)]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert base64.b64decode(result.stdout) == signature
    b = json.loads(br); b["owner_ed25519_b64"] = base64.b64encode(b"x" * 32).decode()
    body.write_bytes(protocol.canonical(b))
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert result.returncode == 1 and not result.stdout
