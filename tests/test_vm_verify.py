"""AB#999 PR VM2: verify_vm.py, the customer's check of one SSH connection to a sealed VM (spec r3 6.4).

Synthetic AMD chains for Genoa and Turin (keys made here; they sign only test reports), the
shared vm_measure vectors for the bundle and identity, a fake sev-snp-measure that answers
with the vector measurements, and a fake guest in place of SSH. No SNP hardware, no network.
One test runs the real sev-snp-measure (CI passes it as CATHEDRAL_SEV_SNP_MEASURE).
"""
from __future__ import annotations

import base64
import datetime
import functools
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
import vm_measure_support as support
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_vm_under_test", REPO / "room-kit" / "vm" / "verify_vm.py")
vv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vv)
vr = vv.vr

VEC = support.load()
IDS = VEC["identities"]
NOW = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
PRODUCT = {"genoa": "Genoa", "turin": "Turin"}
SPL_OIDS = {"bl": "1.3.6.1.4.1.3704.1.3.1", "tee": "1.3.6.1.4.1.3704.1.3.2", "snp": "1.3.6.1.4.1.3704.1.3.3",
            "ucode": "1.3.6.1.4.1.3704.1.3.8", "fmc": "1.3.6.1.4.1.3704.1.3.9"}
TCB_OFFSETS = (0x38, 0x180, 0x1E0, 0x1F0)  # current, reported, committed, launch
CHIPS = {"genoa": hashlib.sha512(b"vm2 genoa chip").digest(),
         "turin": hashlib.sha256(b"vm2 turin chip").digest()[:8] + bytes(56)}
HOST_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"vm2 host key 1").digest())
OTHER_HOST_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"vm2 host key 2").digest())
TESTDATA = REPO / "cmd" / "cathedral-snp-verifier" / "snpverify" / "testdata"


def measurement(identity: str, vcpus: int) -> str:
    return next(m["expected_measurement"] for m in VEC["measurements"]
                if m["identity"] == identity and m["vcpus"] == vcpus)


def blob(key: Ed25519PrivateKey) -> bytes:
    return vv.protocol.HOST_KEY_PREFIX + key.public_key().public_bytes_raw()


# ---- synthetic AMD chain --------------------------------------------------------------

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, public, signer, serial, extensions=()):
    builder = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
               .public_key(public).serial_number(serial)
               .not_valid_before(NOW - datetime.timedelta(days=1)).not_valid_after(NOW + datetime.timedelta(days=365)))
    for oid, raw in extensions:
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), raw), False)
    return builder.sign(signer, hashes.SHA384(), rsa_padding=PSS)


@functools.lru_cache(None)
def roots(family: str):
    """ARK key, ASK key, ARK, ASK of one family. Named as AMD names them, made here."""
    p = PRODUCT[family]
    ark_key, ask_key = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
    ark = _cert(f"ARK-{p}", f"ARK-{p}", ark_key.public_key(), ark_key, 1)
    ask = _cert(f"SEV-{p}", f"ARK-{p}", ask_key.public_key(), ark_key, 2)
    return ark_key, ask_key, ark, ask


def ark_pin(family: str) -> str:
    return hashlib.sha256(roots(family)[2].public_bytes(serialization.Encoding.DER)).hexdigest()


def crl(family: str, *, revoked: bool = False, stale: bool = False) -> bytes:
    ark_key, _, ark, _ = roots(family)
    before, after = NOW - datetime.timedelta(hours=1), NOW + datetime.timedelta(days=2)
    if stale:
        before, after = NOW - datetime.timedelta(days=2), NOW - datetime.timedelta(days=1)
    builder = x509.CertificateRevocationListBuilder().issuer_name(ark.subject).last_update(before).next_update(after)
    if revoked:  # the ASK's serial
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(2)
                                                  .revocation_date(NOW - datetime.timedelta(hours=2)).build())
    return builder.sign(ark_key, hashes.SHA384(), rsa_padding=PSS).public_bytes(serialization.Encoding.DER)


def tcb(family: str, **lower: int) -> bytes:
    """The approved floor in this family's TCB_VERSION layout, with components given lowered."""
    raw = bytearray(8)
    for name, index in vr.TCB_COMPONENTS[family].items():
        raw[index] = vv.APPROVED_CPUS[family]["floor"][name] - lower.get(name, 0)
    return bytes(raw)


def make_report(family: str, *, report_data: bytes, measurement_hex: str, host_data_hex: str, version: int = 5,
                cpuid: tuple | None = None, policy: int = 0x30000, vmpl: int = 0, signer: int = 0,
                tcbs: dict | None = None) -> bytes:
    r = bytearray(vv.REPORT_BYTES)
    r[0:4] = version.to_bytes(4, "little")
    r[0x08:0x10] = policy.to_bytes(8, "little")
    r[0x30:0x34] = vmpl.to_bytes(4, "little")
    r[0x34:0x38] = (1).to_bytes(4, "little")  # ECDSA P-384 with SHA-384
    r[0x48:0x4C] = signer.to_bytes(4, "little")
    r[0x50:0x90] = report_data
    r[0x90:0xC0] = bytes.fromhex(measurement_hex)
    r[0xC0:0xE0] = bytes.fromhex(host_data_hex)
    r[0x140:0x160] = hashlib.sha256(b"vm2 report id").digest()
    for offset in TCB_OFFSETS:
        r[offset:offset + 8] = (tcbs or {}).get(offset, tcb(family))
    if version >= 3:
        r[0x188:0x18B] = bytes(cpuid or vv.APPROVED_CPUS[family]["cpuid"])
    r[0x1A0:0x1E0] = CHIPS[family]
    return bytes(r)


def sign(report: bytes, family: str, cache: Path, *, foreign_ask: bool = False) -> bytes:
    """Sign with a fresh VCEK for the report's chip and reported TCB; put ASK, ARK and VCEK in a KDS cache."""
    _, ask_key, ark, ask = roots(family)
    turin = family == "turin"
    reported = report[0x180:0x188]
    chip = report[0x1A0:0x1E0]
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    exts = [("1.3.6.1.4.1.3704.1.4", chip[:8] if turin else chip)]
    for name, index in vr.TCB_COMPONENTS[family].items():
        n = reported[index]
        exts.append((SPL_OIDS[name], bytes([2, 2, 0, n]) if n >= 128 else bytes([2, 1, n])))
    issuer_key = rsa.generate_private_key(65537, 2048) if foreign_ask else ask_key
    vcek = _cert("SEV-VCEK", f"SEV-{PRODUCT[family]}", vcek_key.public_key(), issuer_key, 3, exts)
    r = bytearray(report)
    sig_r, sig_s = decode_dss_signature(vcek_key.sign(bytes(r[:0x2A0]), ec.ECDSA(hashes.SHA384())))
    r[0x2A0:0x2A0 + 72], r[0x2E8:0x2E8 + 72] = sig_r.to_bytes(72, "little"), sig_s.to_bytes(72, "little")
    cache.mkdir(parents=True, exist_ok=True)
    pem = serialization.Encoding.PEM
    (cache / f"{PRODUCT[family]}-cert_chain.pem").write_bytes(ask.public_bytes(pem) + ark.public_bytes(pem))
    (cache / f"vcek-{chip.hex()[:16]}-{reported.hex()}.der").write_bytes(vcek.public_bytes(serialization.Encoding.DER))
    return bytes(r)


# ---- the customer's files and a fake guest --------------------------------------------

FAKE_TOOL = '''#!{python}
import hashlib, re, sys
TABLE = {table!r}
if sys.argv[1:] == ["--version"]:
    print("sev-snp-measure 0.0.12")
    sys.exit(0)
args = sys.argv[1:]
vcpus = int(args[args.index("--vcpus") + 1])
line = args[args.index("--append") + 1]
identity = re.search(r"cathedral\\.vm=([0-9a-f]{{64}})$", line).group(1)
print(TABLE.get("%d/%s" % (vcpus, identity)) or hashlib.sha384(("%d|" % vcpus + line).encode()).hexdigest())
'''


@pytest.fixture
def files(tmp_path: Path) -> dict:
    """Per family: the vector bundle directory. Also identity a, a fake sev-snp-measure and a KDS cache."""
    table = {f"{m['vcpus']}/{IDS[m['identity']]['identity_sha256']}": m["expected_measurement"]
             for m in VEC["measurements"]}
    tool = tmp_path / "fake-sev-snp-measure"
    tool.write_text(FAKE_TOOL.format(python=sys.executable, table=table))
    tool.chmod(0o755)
    key = tmp_path / "id_ed25519"
    key.write_text("not a key: the fake guest never reads it\n")
    return {"genoa": support.materialize(VEC, tmp_path / "bundle-genoa", "genoa"),
            "turin": support.materialize(VEC, tmp_path / "bundle-turin", "turin"),
            "identity": IDS["a"]["identity_utf8"].encode("ascii"), "tool": str(tool), "key": str(key),
            "cache": tmp_path / "kds"}


class Guest:
    """Stands in for exchange(): answers the challenge as a VM would, with a report the
    synthetic chain signs. bound is the key REPORT_DATA names, shown the key the connection recorded."""

    def __init__(self, family: str, cache: Path, *, identity: str = "a", vcpus: int = 4, bound=HOST_KEY,
                 shown=HOST_KEY, foreign_ask: bool = False, fixed_challenge: bytes | None = None, **knobs):
        self.family, self.cache, self.bound, self.shown = family, cache, bound, shown
        self.foreign_ask, self.fixed_challenge = foreign_ask, fixed_challenge
        self.measurement = knobs.pop("measurement_hex", measurement(identity, vcpus))
        self.host_data = knobs.pop("host_data_hex", IDS[identity]["host_data_hex"])
        self.knobs, self.answers, self.seen = knobs, [], []

    def __call__(self, host, port, user, ssh_key, challenge):
        self.seen.append((host, port, user, ssh_key, challenge))
        data = vv.report_data(self.fixed_challenge or challenge, blob(self.bound))
        report = sign(make_report(self.family, report_data=data, measurement_hex=self.measurement,
                                  host_data_hex=self.host_data, **self.knobs),
                      self.family, self.cache, foreign_ask=self.foreign_ask)
        answer = json.dumps({"report_b64": base64.b64encode(report).decode()}).encode()
        self.answers.append(answer)
        return answer, blob(self.shown)


def run(files: dict, family: str, guest, **override) -> dict:
    kwargs = {"bundle": files[family], "identity_raw": files["identity"], "vcpus": 4, "cpu_family": family,
              "ark_sha256": ark_pin(family), "host": "203.0.113.10", "port": 22001, "user": "cathedral",
              "ssh_key": files["key"], "floor": vv.floor_for(family, None), "cache": str(files["cache"]),
              "ark_crl": crl(family), "tool": files["tool"], "exchange": guest}
    return vv.verify(**{**kwargs, **override})


def refused(files: dict, family: str, guest, **override) -> vv.Refused:
    with pytest.raises(vv.Refused) as caught:
        run(files, family, guest, **override)
    return caught.value


# ---- PASS ---------------------------------------------------------------------------

@pytest.mark.parametrize("family", ["genoa", "turin"])
@pytest.mark.parametrize("version", [3, 4, 5])
def test_pass_on_both_families_and_report_versions_3_to_5(files, family, version):
    guest = Guest(family, files["cache"], version=version)
    result = run(files, family, guest)
    assert result["verdict"] == "PASS" and result["schema"] == "cathedral.vm.verify/v1"
    assert result["vm_id"] == IDS["a"]["vm_id"] and result["identity_sha256"] == IDS["a"]["identity_sha256"]
    assert result["bundle"] == VEC["bundles"][family]["bundle_id"]
    assert result["report"]["version"] == version
    assert result["report"]["measurement"] == measurement("a", 4)
    assert result["report"]["host_data"] == IDS["a"]["host_data_hex"]
    assert result["report"]["chip_id"] == CHIPS[family].hex()
    assert result["amd"]["product"] == PRODUCT[family] and result["amd"]["ark_sha256"] == ark_pin(family)
    assert result["amd"]["certificate_status"]["ask_revocation"] == "not revoked"
    assert result["ssh"] == {"host": "203.0.113.10", "port": 22001, "user": "cathedral", "channel_binding": "verified",
                             "host_key": "ssh-ed25519 " + base64.b64encode(blob(HOST_KEY)).decode()}
    challenge = guest.seen[0][4]
    assert len(challenge) == 32 and result["challenge_hex"] == challenge.hex()
    assert result["chip_id_pin"] == "not_checked"


def test_each_run_draws_a_new_challenge(files):
    guest = Guest("genoa", files["cache"])
    run(files, "genoa", guest)
    run(files, "genoa", guest)
    assert guest.seen[0][4] != guest.seen[1][4]


# ---- failure sequences --------------------------------------------------------------

def test_wrong_measurement_is_refused(files):
    # The VM runs 4 vCPUs; the customer expects 2.
    assert refused(files, "genoa", Guest("genoa", files["cache"]), vcpus=2).code == "measurement_mismatch"
    # Another VM's launch (identity b) checked against identity a.
    assert refused(files, "genoa", Guest("genoa", files["cache"], identity="b")).code == "measurement_mismatch"


def test_wrong_host_data_is_refused(files):
    guest = Guest("turin", files["cache"], host_data_hex=IDS["b"]["host_data_hex"])
    exc = refused(files, "turin", guest)
    assert exc.code == "host_data_mismatch" and exc.exit_code == 1


def test_replayed_answer_is_refused(files):
    guest = Guest("genoa", files["cache"])
    assert run(files, "genoa", guest)["verdict"] == "PASS"
    recorded = guest.answers[0]

    def replay(host, port, user, ssh_key, challenge):
        return recorded, blob(HOST_KEY)

    assert refused(files, "genoa", replay).code == "report_data_mismatch"


def test_answer_for_a_stale_challenge_is_refused(files):
    guest = Guest("turin", files["cache"], fixed_challenge=bytes(32))
    assert refused(files, "turin", guest).code == "report_data_mismatch"


def test_report_bound_to_another_host_key_is_refused(files):
    # The report names key 1; the SSH connection the verifier opened recorded key 2.
    guest = Guest("genoa", files["cache"], bound=HOST_KEY, shown=OTHER_HOST_KEY)
    assert refused(files, "genoa", guest).code == "report_data_mismatch"


@pytest.mark.parametrize("family", ["genoa", "turin"])
def test_ark_of_the_other_family_is_refused(files, family):
    other = "turin" if family == "genoa" else "genoa"
    exc = refused(files, family, Guest(family, files["cache"]), ark_sha256=ark_pin(other))
    assert exc.code == "amd_chain" and "pinned" in str(exc)


def test_vcek_from_a_foreign_ask_is_refused(files):
    assert refused(files, "turin", Guest("turin", files["cache"], foreign_ask=True)).code == "amd_chain"


@pytest.mark.parametrize("bad", [{"revoked": True}, {"stale": True}])
def test_revoked_ask_or_stale_crl_is_refused(files, bad):
    exc = refused(files, "genoa", Guest("genoa", files["cache"]), ark_crl=crl("genoa", **bad))
    assert exc.code == "amd_chain"


def test_crl_signed_by_the_other_family_is_refused(files):
    exc = refused(files, "turin", Guest("turin", files["cache"]), ark_crl=crl("genoa"))
    assert exc.code == "amd_chain"


def test_report_from_the_other_family_is_refused(files):
    # A Genoa chip's report, checked as a Turin VM (the Turin bundle and Turin ARK).
    guest = Guest("genoa", files["cache"])
    assert refused(files, "turin", guest).code == "cpu_family_mismatch"


@pytest.mark.parametrize("family,cpuid,code", [
    ("genoa", (0x19, 0x11, 0x02), "cpuid_unapproved"),
    ("genoa", (0x19, 0x10, 0x01), "cpuid_unapproved"),
    ("turin", (0x1A, 0x02, 0x00), "cpuid_unapproved"),
    ("genoa", (0x19, 0x01, 0x01), "cpu_family_mismatch"),  # Milan
    ("turin", (0x1B, 0x00, 0x00), "cpu_family_mismatch"),  # no layout
])
def test_unapproved_cpu_is_refused(files, family, cpuid, code):
    assert refused(files, family, Guest(family, files["cache"], cpuid=cpuid)).code == code


@pytest.mark.parametrize("family", ["genoa", "turin"])
@pytest.mark.parametrize("version", [0, 1, 2, 6, 7])
def test_report_versions_outside_3_to_5_are_refused(files, family, version):
    exc = refused(files, family, Guest(family, files["cache"], version=version))
    assert exc.code == "report_version" and exc.exit_code == 1
    if version == 2:
        assert "no CPUID" in str(exc)


@pytest.mark.parametrize("knobs,code,words", [
    ({"policy": 0x30000 | 1 << 19}, "policy", "POLICY"),  # debug
    ({"policy": 0x30000 | 1 << 18}, "policy", "POLICY"),  # migration agent
    ({"policy": 0x20000}, "policy", "POLICY"),  # SMT not allowed: not the bundle's policy
    ({"vmpl": 1}, "vmpl", "VMPL 1"),
    ({"signer": 1 << 2}, "signer", "not signed by the VCEK"),  # VLEK
    ({"signer": 2}, "signer", "masks the chip key"),
    ({"signer": 1 << 8}, "signer", "reserved"),
])
def test_policy_vmpl_and_signer_are_refused(files, knobs, code, words):
    exc = refused(files, "turin", Guest("turin", files["cache"], **knobs))
    assert exc.code == code and words in str(exc)


@pytest.mark.parametrize("family", ["genoa", "turin"])
def test_each_tcb_component_below_the_floor_is_refused(files, family):
    for name in vr.TCB_COMPONENTS[family]:
        if vv.APPROVED_CPUS[family]["floor"][name] == 0:
            continue  # Genoa TEE floor is 0: nothing below it
        for offset in TCB_OFFSETS:
            guest = Guest(family, files["cache"], tcbs={offset: tcb(family, **{name: 1})})
            assert refused(files, family, guest).code == "tcb_floor", (name, hex(offset))


def test_min_tcb_may_only_raise_the_floor(files):
    with pytest.raises(vv.CannotCheck) as caught:
        vv.floor_for("turin", ["turin:fmc=1,bl=3,tee=3,snp=7,ucode=118"])
    assert caught.value.code == "min_tcb" and caught.value.exit_code == 2
    with pytest.raises(vv.CannotCheck):
        vv.floor_for("turin", ["genoa:bl=12,tee=0,snp=30,ucode=88"])
    raised = vv.floor_for("turin", ["turin:fmc=1,bl=3,tee=3,snp=9,ucode=118"])
    assert raised["snp"] == 9
    assert refused(files, "turin", Guest("turin", files["cache"]), floor=raised).code == "tcb_floor"


def test_identity_naming_another_base_root_is_refused(files):
    doc = {**json.loads(files["identity"]), "base_root_verity": "2" * 64}
    other = vv.vm_measure.identity_document(doc["vm_id"], doc["ssh_public_key"], doc["base_root_verity"],
                                            doc["base_root_data_bytes"], salt_hex=doc["salt_hex"])
    exc = refused(files, "genoa", Guest("genoa", files["cache"]), identity_raw=other)
    assert exc.code == "identity_bundle_mismatch" and exc.exit_code == 1


@pytest.mark.parametrize("override,code", [
    ({"cpu_family": "turin"}, "bundle_cpu_family"),  # the genoa bundle as a turin VM
    ({"identity_raw": b"{}"}, "identity_invalid"),
    ({"ark_sha256": "00" * 31}, "ark_sha256"),
    ({"tool": "/nonexistent/sev-snp-measure"}, "expected_values"),
])
def test_local_inputs_that_cannot_be_checked_exit_2(files, override, code):
    exc = refused(files, "genoa", Guest("genoa", files["cache"]), **override)
    assert isinstance(exc, vv.CannotCheck) and exc.code == code and exc.exit_code == 2


def test_tampered_bundle_file_cannot_be_checked(files):
    initrd = files["genoa"] / "initrd.cpio.zst"
    initrd.write_bytes(initrd.read_bytes() + b"x")
    assert refused(files, "genoa", Guest("genoa", files["cache"])).code == "expected_values"


@pytest.mark.parametrize("raw,code", [
    (b"not json", "answer_invalid"),
    (b'{"report_b64": "AA==", "report_b64": "AA=="}', "answer_invalid"),
    (b'{"report_b64": NaN}', "answer_invalid"),
    (b'["report_b64"]', "answer_invalid"),
    (b'{"report_b64": "@@@@"}', "report_invalid"),
    (json.dumps({"report_b64": base64.b64encode(bytes(1183)).decode()}).encode(), "report_invalid"),
    (b"{" + b" " * 65536 + b"}", "answer_invalid"),
])
def test_malformed_answers_are_refused(raw, code):
    with pytest.raises(vv.Refused) as caught:
        vv.parse_answer(raw)
    assert caught.value.code == code


def test_ssh_argv_is_776s_with_the_vm_attest_command(tmp_path):
    """The connection options are verify_custom_guest.ssh_command's; only the program (a test
    hook, /usr/bin/ssh by default) and the remote command are the VM's."""
    challenge, known = bytes(range(32)), tmp_path / "known_hosts"
    ours = vv.ssh_argv("203.0.113.10", 22001, "cathedral", "id_ed25519", known, challenge)
    theirs = vv.vcg.ssh_command("203.0.113.10", 22001, "cathedral", "id_ed25519", known, challenge)
    assert ours[0] == vv.SSH_BIN == "/usr/bin/ssh" and ours[1:-1] == theirs[1:-1]
    assert ours[-1] == "sudo -n /run/cathedral/bin/cathedral-attest " + challenge.hex()


@pytest.mark.parametrize("host,port,user", [("-oProxyCommand=x", 22001, "cathedral"), ("203.0.113.10", 0, "cathedral"),
                                            ("203.0.113.10", 22001, "Root;id")])
def test_ssh_target_is_validated_before_any_connection(tmp_path, host, port, user):
    with pytest.raises(vv.CannotCheck) as caught:
        vv.ssh_argv(host, port, user, "id_ed25519", tmp_path / "known_hosts", bytes(32))
    assert caught.value.code == "ssh_target"


# ---- the command line, through a fake ssh ---------------------------------------------

FAKE_SSH = '''#!{python}
import json, os, sys
argv = sys.argv[1:]
with open(os.environ["FAKE_SSH_ARGV"], "w") as f:
    json.dump(argv, f)
known = next(a.split("=", 1)[1] for a in argv if a.startswith("UserKnownHostsFile="))
with open(known, "w") as f:
    f.write(os.environ["FAKE_SSH_KNOWN"])
sys.stdout.write(open(os.environ["FAKE_SSH_ANSWER"]).read())
sys.stderr.write(os.environ.get("FAKE_SSH_STDERR", ""))
sys.exit(int(os.environ.get("FAKE_SSH_EXIT", "0")))
'''


@pytest.fixture
def cli(files, tmp_path, monkeypatch, capsys):
    """main() with SSH_BIN replaced by a fake ssh that records its argv and plays a prepared answer."""
    ssh = tmp_path / "fake-ssh"
    ssh.write_text(FAKE_SSH.format(python=sys.executable))
    ssh.chmod(0o755)
    challenge = hashlib.sha256(b"vm2 cli challenge").digest()
    monkeypatch.setattr(vv, "SSH_BIN", str(ssh))
    monkeypatch.setattr(vv, "new_challenge", lambda: challenge)
    identity = tmp_path / "vm-identity.json"
    identity.write_bytes(files["identity"])
    crl_path = tmp_path / "ark.crl"
    crl_path.write_bytes(crl("turin"))
    report = sign(make_report("turin", report_data=vv.report_data(challenge, blob(HOST_KEY)),
                              measurement_hex=measurement("a", 4), host_data_hex=IDS["a"]["host_data_hex"]),
                  "turin", files["cache"])
    answer = tmp_path / "answer.json"
    answer.write_text(json.dumps({"schema": "cathedral.snp.guest-report/v1", "report_b64": base64.b64encode(report).decode()}))
    monkeypatch.setenv("FAKE_SSH_ARGV", str(tmp_path / "argv.json"))
    monkeypatch.setenv("FAKE_SSH_ANSWER", str(answer))
    monkeypatch.setenv("FAKE_SSH_KNOWN", "[203.0.113.10]:22001 ssh-ed25519 " + base64.b64encode(blob(HOST_KEY)).decode() + "\n")
    argv = ["verify", "--bundle", str(files["turin"]), "--identity", str(identity), "--vcpus", "4",
            "--cpu-family", "turin", "--ark-sha256", ark_pin("turin"), "--host", "203.0.113.10", "--port", "22001",
            "--ssh-key", files["key"], "--ark-crl", str(crl_path), "--kds-cache", str(files["cache"]),
            "--tool", files["tool"]]

    def call(*extra: str) -> tuple[int, dict]:
        code = vv.main(argv + list(extra))
        out = capsys.readouterr().out.strip().splitlines()
        assert len(out) == 1
        return code, json.loads(out[0])

    call.challenge, call.argv_file = challenge, tmp_path / "argv.json"
    return call


def test_cli_pass_runs_one_hardened_ssh_connection(cli):
    code, result = cli()
    assert code == 0 and result["verdict"] == "PASS" and result["challenge_hex"] == cli.challenge.hex()
    argv = json.loads(cli.argv_file.read_text())
    assert argv[:3] == ["-F", "/dev/null", "-T"]
    options = dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv) if a == "-o")
    for key, value in {"StrictHostKeyChecking": "accept-new", "HostKeyAlgorithms": "ssh-ed25519",
                       "GlobalKnownHostsFile": "/dev/null", "IdentityAgent": "none", "IdentitiesOnly": "yes",
                       "ForwardAgent": "no", "ControlMaster": "no", "ControlPath": "none",
                       "ProxyCommand": "none", "ProxyJump": "none", "BatchMode": "yes"}.items():
        assert options[key] == value, key
    assert argv[-4:] == ["-l", "cathedral", "203.0.113.10",
                         f"sudo -n /run/cathedral/bin/cathedral-attest {cli.challenge.hex()}"]
    assert argv[argv.index("-p") + 1] == "22001"


def test_cli_matches_the_lowercased_name_openssh_records(cli, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_KNOWN", "[vm1.example.test]:22001 ssh-ed25519 "
                       + base64.b64encode(blob(HOST_KEY)).decode() + "\n")
    code, result = cli("--host", "VM1.Example.Test")
    assert code == 0 and result["ssh"]["host"] == "vm1.example.test"


def test_cli_refusal_exits_1(cli, monkeypatch):
    monkeypatch.setenv("FAKE_SSH_KNOWN", "[203.0.113.10]:22001 ssh-ed25519 "
                       + base64.b64encode(blob(OTHER_HOST_KEY)).decode() + "\n")
    code, result = cli()
    assert code == 1 and result["verdict"] == "FAIL" and result["code"] == "report_data_mismatch"


@pytest.mark.parametrize("exit_code", ["1", "255"])
def test_cli_ssh_or_remote_command_failure_exits_2(cli, monkeypatch, exit_code):
    # 255: ssh itself failed; 1: the attest command in the VM failed. Neither is a verdict.
    monkeypatch.setenv("FAKE_SSH_EXIT", exit_code)
    monkeypatch.setenv("FAKE_SSH_STDERR", "ssh: connect to host 203.0.113.10 port 22001: Connection refused")
    code, result = cli()
    assert code == 2 and result["verdict"] == "ERROR" and result["code"] == "ssh_failed"
    assert "run the same ssh by hand" in result["reason"]


@pytest.mark.parametrize("known", [
    "",
    "[203.0.113.11]:22001 ssh-ed25519 {key}\n",
    "[203.0.113.10]:22001 ecdsa-sha2-nistp256 {key}\n",
    "[203.0.113.10]:22001 ssh-ed25519 {key}\n[203.0.113.10]:22001 ssh-ed25519 {key}\n",
    "[203.0.113.10]:22001 ssh-ed25519 {short}\n",
    "[203.0.113.10]:22001 ssh-ed25519 @@@@\n",
])
def test_cli_refuses_a_recorded_host_key_that_is_not_one_ed25519_key_for_this_endpoint(cli, monkeypatch, known):
    monkeypatch.setenv("FAKE_SSH_KNOWN", known.format(key=base64.b64encode(blob(HOST_KEY)).decode(),
                                                      short=base64.b64encode(blob(HOST_KEY)[:-1]).decode()))
    code, result = cli()
    assert code == 1 and result["verdict"] == "FAIL" and result["code"] == "host_key_invalid"


def test_cli_pin_is_reserved(capsys):
    assert vv.main(["pin", "--anything"]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "not_available"


# ---- pinned values and real reports ---------------------------------------------------

def test_approved_floors_name_every_component_of_their_layout():
    for family, approved in vv.APPROVED_CPUS.items():
        assert set(approved["floor"]) == set(vr.TCB_COMPONENTS[family])
    assert vv.APPROVED_CPUS["turin"]["floor"] == {"fmc": 1, "bl": 3, "tee": 3, "snp": 8, "ucode": 118}  # D 10.4
    assert vv.APPROVED_CPUS["genoa"]["floor"] == {"bl": 12, "tee": 0, "snp": 30, "ucode": 88}  # sealed README


def _testdata_report(path: Path) -> bytes:
    def find(node):
        if isinstance(node, dict):
            for key, value in node.items():
                yield from ([value] if key == "report_b64" else find(value))
        elif isinstance(node, list):
            for value in node:
                yield from find(value)
    return base64.b64decode(next(find(json.loads(path.read_text()))))


def test_real_turin_v5_report_meets_the_turin_rules():
    """chi-ur-2's archived report: version 5, CPUID 1a:02:01, every TCB at the D 10.4 floor."""
    report = _testdata_report(TESTDATA / "amd-turin" / "attestation-chi-ur-2.json")
    rep = vr.parse_report(report)
    assert rep["version"] == 5 and rep["version"] in vv.REPORT_VERSIONS
    assert vr.product(rep, None) == "Turin"
    assert (rep["cpuid_fam"], rep["cpuid_mod"], rep["cpuid_step"]) == vv.APPROVED_CPUS["turin"]["cpuid"]
    assert vr.check_tcb_floor(report, rep, {"turin": vv.floor_for("turin", None)})["generation"] == "turin"


def test_real_genoa_report_has_the_approved_cpuid_and_an_older_snp_level():
    """An archived Genoa hotel report: CPUID 19:11:01, SNP 27, below the sealed floor's 30."""
    report = _testdata_report(TESTDATA / "attestation-library.json")
    rep = vr.parse_report(report)
    assert vr.product(rep, None) == "Genoa"
    assert (rep["cpuid_fam"], rep["cpuid_mod"], rep["cpuid_step"]) == vv.APPROVED_CPUS["genoa"]["cpuid"]
    with pytest.raises(vr.Fail, match="SNP firmware 27 is below 30"):
        vr.check_tcb_floor(report, rep, {"genoa": vv.floor_for("genoa", None)})


@pytest.fixture
def real_tool() -> str:
    path = os.environ.get("CATHEDRAL_SEV_SNP_MEASURE")
    if os.environ.get("CI") and not path:
        pytest.fail("CI must pass the hash-installed sev-snp-measure as CATHEDRAL_SEV_SNP_MEASURE")
    path = path or vv.vm_measure.default_tool()
    try:
        vv.vm_measure.check_tool(path)
    except vv.vm_measure.Refusal:
        if os.environ.get("CI"):
            pytest.fail(f"sev-snp-measure 0.0.12 is not at {path}")
        pytest.skip("sev-snp-measure 0.0.12 is not installed (requirements/vm-measure.txt)")
    return path


@pytest.mark.parametrize("family", ["genoa", "turin"])
def test_expected_values_equal_the_shared_vectors_with_the_real_tool(tmp_path, real_tool, family):
    bundle = support.materialize(VEC, tmp_path / family, family)
    values = vv.expected_values(bundle, IDS["a"]["identity_utf8"].encode("ascii"), 4, family, real_tool)
    assert values["expected_measurement"] == measurement("a", 4)
    assert values["host_data"] == IDS["a"]["host_data_hex"]
    assert values["identity_sha256"] == IDS["a"]["identity_sha256"] and values["vm_id"] == IDS["a"]["vm_id"]
