"""SSH connection binding with synthetic SNP certificates, plus a real loopback sshd."""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests import direct_snp_support as trust
from tests import test_custom_guest_protocol as fixture
from tests import test_direct_snp_report as direct_fixture

sys.path.insert(0, str(fixture.KIT))
import cathedral_attest as guest
import verify_custom_guest as verifier

p = fixture.protocol


def signed_answer(tmp_path, *, challenge=fixture.CHALLENGE, blob=fixture.BLOB, launch=None):
    mr, br, sig = launch or fixture.encoded()
    _, _, hd = p.validate_launch(mr, br, sig, fixture.PUBLIC)
    def mutate(raw):
        raw[0x50:0x90] = p.report_data(challenge, blob)
        raw[0xc0:0xe0] = bytes.fromhex(hd)
    answer, cache = direct_fixture.signed_report(tmp_path, mutate=mutate)
    return answer, {"challenge": fixture.CHALLENGE, "host_blob": fixture.BLOB, "manifest_raw": mr, "bootstrap_raw": br,
        "signature": sig, "owner_key": fixture.PUBLIC, "expected_measurement": direct_fixture.fixture.snp.MEASUREMENT,
        "ark_sha256": trust.cache_pin(cache), "cache": str(cache), "min_tcb": verifier.direct.vr.parse_min_tcb([trust.FLOOR]),
        "expected_chip_id": trust.CHIP, "expected_cpuid": trust.CPU, "ark_crl": (cache / "ark.crl").read_bytes()}


def test_bound_report_verifies_with_owner_documents(tmp_path):
    answer, args = signed_answer(tmp_path)
    result = verifier.verify_connection(answer, **args)
    assert result["verdict"] == "PASS" and result["ssh_channel_binding"] == "verified"
    assert result["launch_id"] == "cg-0123456789ab"
    assert "the guest consumed or enforced the bootstrap" in result["does_not_prove"]


@pytest.mark.parametrize("change", ["old_challenge", "different_key", "wrong_owner", "wrong_measurement", "wrong_host_data"])
def test_report_cannot_move_to_another_connection_or_launch(tmp_path, change):
    answer, args = signed_answer(tmp_path)
    if change == "old_challenge": args["challenge"] = b"x" * 32
    if change == "different_key": args["host_blob"] = fixture.BLOB[:-1] + b"x"
    if change == "wrong_owner": args["owner_key"] = b"x" * 32
    if change == "wrong_measurement": args["expected_measurement"] = "ff" * 48
    if change == "wrong_host_data":
        _mr, br, sig = fixture.encoded()
        b = json.loads(br); b["launch_nonce_hex"] = "ff" * 32
        br = p.canonical(b); sig = fixture.OWNER.sign(p.BOOTSTRAP_DOMAIN + fixture.hashlib.sha256(br).digest())
        args.update(bootstrap_raw=br, signature=sig)
    with pytest.raises((p.ProtocolError, verifier.direct.vr.Fail)):
        verifier.verify_connection(answer, **args)


def known(host="192.0.2.1", port=20022):
    return verifier.endpoint(host, port).encode() + b" ssh-ed25519 " + base64.b64encode(fixture.BLOB) + b"\n"


@pytest.mark.parametrize("raw", [b"", known() * 2, known("192.0.2.2"), known(port=20023), b"@cert-authority " + known(),
                                  known().replace(b"ssh-ed25519 ", b"ssh-rsa ")])
def test_known_hosts_requires_exact_connection(raw):
    with pytest.raises(p.ProtocolError):
        verifier.connection_key(raw, "192.0.2.1", 20022)


def test_ssh_config_cannot_reuse_or_proxy_a_connection(tmp_path):
    argv = verifier.ssh_command("192.0.2.1", 20022, "root", tmp_path / "identity", tmp_path / "known", fixture.CHALLENGE)
    for option in ("ControlPath=none", "ProxyCommand=none", "ProxyJump=none", "IdentityAgent=none",
                   "ForwardAgent=no", "ClearAllForwardings=yes", "StrictHostKeyChecking=accept-new",
                   "HostKeyAlgorithms=ssh-ed25519", "GlobalKnownHostsFile=/dev/null"):
        assert option in argv
    assert argv[:3] == ["/usr/bin/ssh", "-F", "/dev/null"]
    assert argv[-1] == "/usr/bin/cathedral-attest " + fixture.CHALLENGE.hex()
    for host in ("-oProxyCommand=sh", "host;sh", "a b", "a\nb"):
        with pytest.raises(p.ProtocolError):
            verifier.ssh_command(host, 22, "root", "key", "known", fixture.CHALLENGE)


def test_transport_byte_time_and_exit_bounds():
    with pytest.raises(p.ProtocolError, match="too large"):
        verifier.bounded_command([sys.executable, "-c", "print('x'*9999)"], limit=100)
    with pytest.raises(p.ProtocolError, match="deadline"):
        verifier.bounded_command([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)
    with pytest.raises(p.ProtocolError, match="failed"):
        verifier.bounded_command([sys.executable, "-c", "raise SystemExit(1)"])
    assert verifier.bounded_command([sys.executable, "-c", "print('ok')"]) == b"ok\n"


def test_guest_requires_root_before_device_access(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cathedral-attest", fixture.CHALLENGE.hex()])
    monkeypatch.setattr(guest.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(guest.snp_guest_report, "collect", lambda *_: pytest.fail("must not ask device"))
    assert guest.main() == 1
    assert json.loads(capsys.readouterr().out)["error"] == "custom_guest_report_failed"


def test_guest_report_uses_exact_connection_key_and_domain(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cathedral-attest", fixture.CHALLENGE.hex()])
    monkeypatch.setattr(guest.os, "geteuid", lambda: 0)
    monkeypatch.setattr(guest, "public_blob", lambda: fixture.BLOB)
    def collect(data):
        assert data == p.report_data(fixture.CHALLENGE, fixture.BLOB)
        return {"verification": "not_checked"}
    monkeypatch.setattr(guest.snp_guest_report, "collect", collect)
    assert guest.main() == 0
    assert json.loads(capsys.readouterr().out)["verification"] == "not_checked"


@pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("sshd") or not shutil.which("ssh"), reason="loopback sshd requires root and OpenSSH")
def test_real_ssh_connection_writes_pin_only_after_verified_report(tmp_path, monkeypatch, capsys):
    """Real SSH KEX/auth/command; SNP report/certificates are explicitly synthetic."""
    hostkey = Ed25519PrivateKey.generate()
    keypath = tmp_path / "host_key"
    keypath.write_bytes(hostkey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
    keypath.chmod(0o600)
    blob = base64.b64decode(hostkey.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[1])
    client = tmp_path / "client_key"
    client.write_bytes(fixture.OWNER.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
    client.chmod(0o600)
    port = None
    for candidate in range(25000, 25100):
        with socket.socket() as s:
            try: s.bind(("127.0.0.1", candidate))
            except OSError: continue
            port = candidate
            break
    assert port is not None
    m, b = fixture.documents(); b["network"]["public_host"] = "127.0.0.1"; b["ports"][0]["public"] = port
    mr, br = p.canonical(m), p.canonical(b)
    sig = fixture.OWNER.sign(p.BOOTSTRAP_DOMAIN + fixture.hashlib.sha256(br).digest())
    answer, args = signed_answer(tmp_path, blob=blob, launch=(mr, br, sig))
    paths = {}
    for name, data in {"manifest":mr, "bootstrap":br, "signature":sig, "owner":fixture.PUBLIC,
                        "answer":json.dumps(answer).encode()}.items():
        paths[name] = tmp_path / name; paths[name].write_bytes(data)
    forced = tmp_path / "forced.py"
    forced.write_text("import os,pathlib\nassert os.environ['SSH_ORIGINAL_COMMAND'] == " + repr("/usr/bin/cathedral-attest " + fixture.CHALLENGE.hex())
                      + "\nprint(pathlib.Path(" + repr(str(paths["answer"])) + ").read_text())\n")
    auth = tmp_path / "authorized_keys"
    auth.write_text('restrict,command="' + sys.executable + ' ' + str(forced) + '" ' + fixture.OWNER.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + "\n")
    config = tmp_path / "sshd_config"
    config.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {keypath}\nPidFile {tmp_path}/sshd.pid\nAuthorizedKeysFile {auth}\nStrictModes no\nUsePAM no\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowUsers root\n")
    daemon = subprocess.Popen([shutil.which("sshd"), "-D", "-e", "-f", str(config)], stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            assert daemon.poll() is None, "test sshd exited"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1): break
            except OSError: time.sleep(0.02)
        else: pytest.fail("test sshd did not listen")
        pin = tmp_path / "verified_known_hosts"
        argv = ["verify_custom_guest", "--host", "127.0.0.1", "--port", str(port), "--identity", str(client),
                "--manifest", str(paths["manifest"]), "--bootstrap", str(paths["bootstrap"]),
                "--bootstrap-signature", str(paths["signature"]), "--owner-public-key", str(paths["owner"]),
                "--expected-measurement", args["expected_measurement"], "--ark-sha256", args["ark_sha256"],
                "--expected-chip-id", trust.CHIP, "--expected-cpuid", trust.CPU, "--min-tcb", trust.FLOOR,
                "--kds-cache", args["cache"], "--ark-crl", str(Path(args["cache"]) / "ark.crl"), "--known-hosts-out", str(pin)]
        monkeypatch.setattr(sys, "argv", argv)
        monkeypatch.setattr(verifier.os, "urandom", lambda size: fixture.CHALLENGE if size == 32 else pytest.fail("unexpected random size"))
        # Keep the approved AMD test root fixed and tamper with REPORT_DATA after real KEX.
        raw = bytearray(base64.b64decode(answer["report_b64"])); raw[0x50] ^= 1
        paths["answer"].write_text(json.dumps({"report_b64":base64.b64encode(raw).decode()}))
        assert verifier.main() == 1
        assert not pin.exists()
        assert json.loads(capsys.readouterr().out)["verdict"] == "FAIL"
        paths["answer"].write_text(json.dumps(answer))
        assert verifier.main() == 0
        result = json.loads(capsys.readouterr().out)
        assert result["verdict"] == "PASS"
        assert verifier.connection_key(pin.read_bytes(), "127.0.0.1", port) == blob
        prior = pin.read_bytes()
        assert verifier.main() == 1  # refuses to overwrite existing trust file
        assert pin.read_bytes() == prior
    finally:
        daemon.terminate()
        daemon.wait(timeout=5)
