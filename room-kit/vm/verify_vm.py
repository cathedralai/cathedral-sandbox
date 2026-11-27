#!/usr/bin/env python3
"""Verify a sealed customer VM from your own trusted machine (AB#999, VM2; VM runtime spec r3 6.4).

One command opens one SSH connection to the VM, sends it a fresh 32-byte challenge, and
checks the SNP report the VM returns on that same connection:

- the AMD chain: your pinned ARK, then the ASK and the VCEK from AMD KDS, their validity
  periods, the ARK-signed CRL, and the report signature;
- REPORT_DATA binds your challenge and the SSH host key OpenSSH verified on this connection;
- MEASUREMENT and HOST_DATA equal what vm_measure.py computes from your bundle and your
  vm-identity.json, never values from the VM, the host or the API;
- POLICY 0x30000, VMPL 0, a VCEK signer, an approved CPU and its firmware floor.

  verify_vm.py verify --bundle DIR --identity vm-identity.json --vcpus N --cpu-family genoa|turin
                      --ark-sha256 HEX --host HOST --port PORT --ssh-key FILE [--user cathedral]
                      [--min-tcb SPEC] [--ark-crl FILE] [--kds-cache DIR] [--tool PATH]

One JSON line on stdout. Exit 0 PASS; 1 FAIL (the VM's evidence was refused); 2 ERROR (the
check could not run: local inputs, sev-snp-measure, SSH or AMD KDS unreachable).
`pin` (spec 7.5: the recovery key and the chip, kept locally) is reserved for the next PR.

Needs Python 3.11+, cryptography>=42 and sev-snp-measure 0.0.12 (requirements/vm-measure.txt),
with vm_measure.py beside this file and verify_receipts.py one folder up, from one reviewed
checkout.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature

VM_KIT = Path(__file__).resolve().parent
sys.path[:0] = [str(VM_KIT), str(VM_KIT.parent)]
import custom_guest_protocol as protocol
import verify_custom_guest as vcg
import verify_receipts as vr
import vm_measure

SCHEMA = "cathedral.vm.verify/v1"

# ---- guest contract ---------------------------------------------------------------
# What the VM's measured initrd provides, in one place.
# - Spec r3 6.4 fixes the attest path (cathedral-attest from the measured initrd, bind-mounted
#   at /run/cathedral/bin) and the REPORT_DATA tag: the VM's own, so a VM report never reads
#   as a custom guest one (custom_guest_protocol.REPORT_DOMAIN).
# - The answer member is report_b64, as snp_guest_report.collect prints it (#774, #776).
# - Chaser confirms in PR VM1b: the login user and running the attest command with sudo -n.
GUEST_USER = "cathedral"  # the login user (README: ssh -p <port> cathedral@<host>)
GUEST_ATTEST = "/run/cathedral/bin/cathedral-attest"
GUEST_ATTEST_COMMAND = "sudo -n " + GUEST_ATTEST + " {challenge_hex}"
# REPORT_DATA = sha512(REPORT_DATA_DOMAIN || challenge[32] || sha256(host_key_blob)): the
# custom guest formula (D 10.1, 10.2, custom_guest_protocol.report_data) under the VM's tag.
REPORT_DATA_DOMAIN = b"cathedral-vm-report/v1\0"
ANSWER_REPORT_KEY = "report_b64"

# ---- report rules -----------------------------------------------------------------
# 3 and 4 carry the CPUID fields; Turin firmware writes 5 (AMD SEV-SNP ABI 1.58, table 23).
# 2 has no CPUID, so no floor can apply: refused, so a host on old firmware shows up as a
# clear refusal. 6 and later have no reviewed layout: refused.
REPORT_VERSIONS = (3, 4, 5)
REPORT_BYTES = 1184
POLICY = 0x30000  # SMT allowed, no migration agent, no debug (spec r3 6.1)
# The one CPU, by its exact family:model:stepping, that each family's floor is approved for
# (D 10.4: keyed by stepping too). A floor is never applied to another stepping.
APPROVED_CPUS = {
    # D 10.4: chi-ur-2, whose report (cmd/cathedral-snp-verifier/snpverify/testdata/amd-turin/
    # attestation-chi-ur-2.json) is CPUID 1a:02:01 with all four TCBs 0103030800000076.
    "turin": {"cpuid": (0x1A, 0x02, 0x01), "floor": {"fmc": 1, "bl": 3, "tee": 3, "snp": 8, "ucode": 118}},
    # Current sealed floor (room-kit/sealed/README.md, AB#968), confirm at the first Genoa live
    # proof. CPUID of our Genoa hotel reports (snpverify/testdata/attestation-library.json).
    "genoa": {"cpuid": (0x19, 0x11, 0x01), "floor": {"bl": 12, "tee": 0, "snp": 30, "ucode": 88}},
}
CHECKS = ("bundle and identity", "SSH connection host key", "report version", "CPU family and stepping",
          "AMD chain and report signature", "REPORT_DATA: challenge and SSH host key", "POLICY 0x30000",
          "VMPL 0", "VCEK signer, chip key not masked", "TCB floor", "MEASUREMENT", "HOST_DATA")
DOES_NOT_PROVE = [
    "what runs after switch_root: your own OS and software",
    "disk freshness: the host can corrupt or roll back root disk blocks (spec r3 Q6)",
    "availability",
    "that a later connection reaches this VM, unless it checks this host key and attests again",
    "that the VM stays on one chip across reports: the chip pin (verify_vm.py pin, spec 7.5) is not in this version",
]

SSH_BIN = "/usr/bin/ssh"  # what verify_custom_guest.ssh_command runs; tests point it at a fake
SSH_TIMEOUT = 45
ANSWER_MAX = 65536
REPORT_B64_MAX = 2048
CRL_MAX = 1024 * 1024
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class Refused(Exception):
    """The VM's evidence failed a check: verdict FAIL, exit 1."""

    verdict, exit_code = "FAIL", 1

    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code


class CannotCheck(Refused):
    """The check could not run to a verdict: verdict ERROR, exit 2."""

    verdict, exit_code = "ERROR", 2


def need(condition: object, code: str, reason: str, kind: type[Refused] = Refused) -> None:
    if not condition:
        raise kind(code, reason)


# ---- expected values (from the customer's own files) ---------------------------------

def expected_values(bundle: Path, identity_raw: bytes, vcpus: int, cpu_family: str, tool: str | None) -> dict:
    """vm_measure.launch_values over the customer's bundle and identity, plus the identity's vm_id."""
    try:
        manifest, _ = vm_measure.read_manifest(bundle)
    except (vm_measure.Refusal, OSError) as exc:
        raise CannotCheck("bundle_invalid", str(exc) or type(exc).__name__) from None
    try:
        identity = vm_measure.parse_identity(identity_raw)
    except vm_measure.Refusal as exc:
        raise CannotCheck("identity_invalid", str(exc)) from None
    need(manifest["cpu_family"] == cpu_family, "bundle_cpu_family",
         f"the bundle is built for {manifest['cpu_family']}, not --cpu-family {cpu_family}", CannotCheck)
    # The measurement covers the cmdline, which names the identity, which names the base root by
    # its verity hash. So the identity must name this bundle's base root, or the VM's root could
    # be any image with that other hash.
    need(identity["base_root_verity"] == manifest["base_root_verity"]
         and identity["base_root_data_bytes"] == manifest["base_root_data_bytes"],
         "identity_bundle_mismatch", "the identity names another base root than this bundle's manifest")
    try:
        values = vm_measure.launch_values(bundle, identity_raw, vcpus, cpu_family, tool)
    except (vm_measure.Refusal, OSError) as exc:
        raise CannotCheck("expected_values", str(exc) or type(exc).__name__) from None
    values["vm_id"] = identity["vm_id"]
    return values


def floor_for(cpu_family: str, specs: list[str] | None) -> dict[str, int]:
    """The approved floor, or a --min-tcb for this family that raises it (never lowers it)."""
    floor = dict(APPROVED_CPUS[cpu_family]["floor"])
    if not specs:
        return floor
    try:
        given = vr.parse_min_tcb(specs)
    except ValueError as exc:
        raise CannotCheck("min_tcb", str(exc)) from None
    need(set(given) == {cpu_family}, "min_tcb", f"--min-tcb must name {cpu_family} only", CannotCheck)
    for name, value in given[cpu_family].items():
        need(value >= floor[name], "min_tcb",
             f"--min-tcb may only raise the floor: {name}={value} is below {floor[name]}", CannotCheck)
    return given[cpu_family]


# ---- SSH channel binding ------------------------------------------------------------
# The connection, its bounded run and the known_hosts read are verify_custom_guest.py's (#776),
# used unchanged. The VM differs in two places, kept here: the remote command (spec r3 6.4)
# and the REPORT_DATA tag.

def ssh_argv(host: str, port: int, user: str, ssh_key: str, known_hosts: Path, challenge: bytes) -> list[str]:
    """#776's argv (one connection; no user or system config, agent, mux or proxy; ed25519 host
    keys only; accept-new on an empty known_hosts, so OpenSSH records the key only after it
    checked the KEX signature), with the VM's attest command as the remote command."""
    try:
        argv = vcg.ssh_command(host, port, user, ssh_key, known_hosts, challenge)
    except protocol.ProtocolError as exc:
        raise CannotCheck("ssh_target", str(exc)) from None
    # #776 ends its argv with the host and the custom guest's command. Refuse a layout this
    # wrapper was not written for rather than send the wrong command.
    need(argv[0] == "/usr/bin/ssh" and argv[-2] == host and argv[-1] == "/usr/bin/cathedral-attest " + challenge.hex(),
         "ssh_target", "verify_custom_guest.ssh_command changed its argv layout", CannotCheck)
    return [SSH_BIN, *argv[1:-1], GUEST_ATTEST_COMMAND.format(challenge_hex=challenge.hex())]


def exchange(host: str, port: int, user: str, ssh_key: str, challenge: bytes) -> tuple[bytes, bytes]:
    """One SSH connection: run the guest's attest command with the challenge. Returns its stdout
    and the host key blob that OpenSSH verified on that same connection."""
    need(Path(ssh_key).is_file(), "ssh_key", f"--ssh-key {ssh_key}: not a file", CannotCheck)
    with tempfile.TemporaryDirectory(prefix="cathedral-vm-verify-") as temp:
        known = Path(temp) / "known_hosts"
        known.touch(mode=0o600)
        argv = ssh_argv(host, port, user, ssh_key, known, challenge)
        try:
            out = vcg.bounded_command(argv, timeout=SSH_TIMEOUT, limit=ANSWER_MAX)
        except protocol.ProtocolError as exc:
            raise CannotCheck("ssh_failed", f"{exc}; run the same ssh by hand to see why") from None
        except OSError as exc:
            raise CannotCheck("ssh_failed", f"cannot run {argv[0]}: {exc.strerror or type(exc).__name__}") from None
        with open(known, "rb") as f:
            raw = f.read(4097)
    try:
        return out, vcg.connection_key(raw, host, port)
    except ValueError as exc:  # protocol.ProtocolError, or binascii.Error from the base64 field
        raise Refused("host_key_invalid", str(exc) or "the recorded host key is not base64") from None


def report_data(challenge: bytes, host_blob: bytes) -> bytes:
    """The 64 bytes the VM must put in REPORT_DATA for this challenge on this connection."""
    need(type(challenge) is bytes and len(challenge) == 32, "challenge", "the challenge must be 32 bytes", CannotCheck)
    try:
        protocol.host_key_blob(host_blob)
    except protocol.ProtocolError as exc:
        raise Refused("host_key_invalid", str(exc)) from None
    return hashlib.sha512(REPORT_DATA_DOMAIN + challenge + hashlib.sha256(host_blob).digest()).digest()


def new_challenge() -> bytes:
    """32 fresh bytes per run, so an answer recorded earlier never matches."""
    return os.urandom(32)


# ---- the report ---------------------------------------------------------------------

def _unique(pairs: list) -> dict:
    doc = {}
    for key, value in pairs:
        if key in doc:
            raise ValueError("duplicate member")
        doc[key] = value
    return doc


def _no_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def parse_answer(raw: bytes) -> bytes:
    """The 1184 report bytes from the guest's answer. Only report_b64 is read: every other
    member is unsigned and ignored."""
    need(len(raw) <= ANSWER_MAX, "answer_invalid", f"the answer exceeds {ANSWER_MAX} bytes")
    try:
        doc = json.loads(raw.decode("ascii"), object_pairs_hook=_unique, parse_constant=_no_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("answer_invalid", "the answer is not one strict ASCII JSON object") from None
    need(type(doc) is dict, "answer_invalid", "the answer is not a JSON object")
    b64 = doc.get(ANSWER_REPORT_KEY)
    need(type(b64) is str and 0 < len(b64) <= REPORT_B64_MAX, "answer_invalid", f"the answer has no {ANSWER_REPORT_KEY}")
    try:
        report = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise Refused("report_invalid", f"{ANSWER_REPORT_KEY} is not base64") from None
    need(len(report) == REPORT_BYTES, "report_invalid", f"the report is {len(report)} bytes, not {REPORT_BYTES}")
    return report


def check_report(report: bytes, *, expected: dict, report_data_bytes: bytes, cpu_family: str, floor: dict,
                 ark_sha256: str, cache: str, ark_crl: bytes | None) -> dict:
    """Every check of spec r3 6.4 on one report, in order. The AMD chain comes before the field
    checks, so a refusal named after a field is about a report AMD signed."""
    rep = vr.parse_report(report)
    version = rep["version"]
    need(version in REPORT_VERSIONS, "report_version",
         f"report version {version} is refused: only {', '.join(map(str, REPORT_VERSIONS))} are accepted"
         + (" (version 2 has no CPUID fields, so no firmware floor can apply)" if version == 2 else ""))
    try:
        product = vr.product(rep, None)
    except vr.Fail as exc:
        raise Refused("cpu_family_mismatch", str(exc)) from None
    need(product.lower() == cpu_family, "cpu_family_mismatch", f"the report is from a {product} chip, not {cpu_family}")
    cpuid = (rep["cpuid_fam"], rep["cpuid_mod"], rep["cpuid_step"])
    shown = ":".join(f"{b:02x}" for b in cpuid)
    approved = ":".join(f"{b:02x}" for b in APPROVED_CPUS[cpu_family]["cpuid"])
    need(cpuid == APPROVED_CPUS[cpu_family]["cpuid"], "cpuid_unapproved",
         f"CPUID {shown} has no approved firmware floor (approved for {cpu_family}: {approved})")
    try:
        amd = vr.verify_amd(report, rep, product, cache, ark_sha256, current_certificates=True, ark_crl=ark_crl)
    except OSError as exc:
        raise CannotCheck("kds_unavailable", f"AMD KDS: {exc}") from None
    except (vr.Fail, InvalidSignature, ValueError, x509.ExtensionNotFound) as exc:
        raise Refused("amd_chain", str(exc) or type(exc).__name__) from None
    need(rep["report_data"] == report_data_bytes, "report_data_mismatch",
         "REPORT_DATA does not bind this run's challenge and this connection's SSH host key")
    need(rep["policy"] == POLICY, "policy", f"POLICY is {rep['policy']:#x}, not {POLICY:#x}")
    vmpl = int.from_bytes(report[0x30:0x34], "little")
    need(vmpl == 0, "vmpl", f"the report is from VMPL {vmpl}, not VMPL 0")
    signer = int.from_bytes(report[0x48:0x4C], "little")
    need((signer >> 2) & 7 == 0, "signer", "the report is not signed by the VCEK")
    need(not signer & 2, "signer", "the report masks the chip key")
    need(signer & ~1 == 0, "signer", "the report sets reserved signer bits")
    try:
        tcb = vr.check_tcb_floor(report, rep, {cpu_family: floor})
    except vr.Fail as exc:
        raise Refused("tcb_floor", str(exc)) from None
    need(rep["measurement"] == expected["expected_measurement"], "measurement_mismatch",
         "MEASUREMENT differs from the one computed from your bundle, identity and vCPU count")
    need(rep["host_data"] == expected["host_data"], "host_data_mismatch",
         "HOST_DATA differs from the one computed from your identity")
    return {"report": {"version": version, "measurement": rep["measurement"], "host_data": rep["host_data"],
                       "report_data_hex": rep["report_data"].hex(), "chip_id": rep["chip_id"].hex(),
                       "report_id": report[0x140:0x160].hex(), "policy": f"{rep['policy']:#x}", "vmpl": vmpl,
                       "cpuid": shown, "tcb_floor": tcb},
            "amd": amd}


def verify(*, bundle: Path, identity_raw: bytes, vcpus: int, cpu_family: str, ark_sha256: str, host: str,
           port: int, user: str, ssh_key: str, floor: dict, cache: str, ark_crl: bytes | None,
           tool: str | None, exchange=exchange) -> dict:
    """The PASS verdict, or Refused / CannotCheck naming the first check that did not pass."""
    need(type(ark_sha256) is str and HEX64_RE.fullmatch(ark_sha256.lower()) is not None, "ark_sha256",
         "--ark-sha256 must be 64 hex characters", CannotCheck)
    host = host.lower() if type(host) is str else host  # OpenSSH records the host name lowercased
    expected = expected_values(bundle, identity_raw, vcpus, cpu_family, tool)
    challenge = new_challenge()
    answer, host_blob = exchange(host, port, user, ssh_key, challenge)
    checked = check_report(parse_answer(answer), expected=expected,
                           report_data_bytes=report_data(challenge, host_blob), cpu_family=cpu_family,
                           floor=floor, ark_sha256=ark_sha256.lower(), cache=cache, ark_crl=ark_crl)
    return {"schema": SCHEMA, "verdict": "PASS", "vm_id": expected["vm_id"],
            "identity_sha256": expected["identity_sha256"], "bundle": expected["bundle"],
            "cpu_family": cpu_family, "vcpus": vcpus, "challenge_hex": challenge.hex(),
            "ssh": {"host": host, "port": port, "user": user, "channel_binding": "verified",
                    "host_key": "ssh-ed25519 " + base64.b64encode(host_blob).decode()},
            **checked, "checks": list(CHECKS), "chip_id_pin": "not_checked", "does_not_prove": DOES_NOT_PROVE}


# ---- command line -------------------------------------------------------------------

def _read_limited(path: str, limit: int, code: str) -> bytes:
    try:
        with open(path, "rb") as f:
            raw = f.read(limit + 1)
    except OSError as exc:
        raise CannotCheck(code, f"{path}: {exc.strerror or type(exc).__name__}") from None
    need(len(raw) <= limit, code, f"{path}: more than {limit} bytes", CannotCheck)
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("verify", help="attest one SSH connection to your VM")
    p.add_argument("--bundle", required=True, help="the bundle directory your VM runs (manifest.json and files)")
    p.add_argument("--identity", required=True, help="your VM's vm-identity.json, kept from create")
    p.add_argument("--vcpus", required=True, type=int)
    p.add_argument("--cpu-family", required=True, choices=sorted(APPROVED_CPUS))
    p.add_argument("--ark-sha256", required=True, help="the AMD root fingerprint you trust for that family")
    p.add_argument("--host", required=True)
    p.add_argument("--port", required=True, type=int, help="the VM's SSH port")
    p.add_argument("--ssh-key", required=True, help="your SSH private key file for the VM")
    p.add_argument("--user", default=GUEST_USER)
    p.add_argument("--min-tcb", action="append", help="raise the built-in floor: " + vr.MIN_TCB_HELP)
    p.add_argument("--ark-crl", help="a current AMD KDS DER CRL for offline use; otherwise fetched live")
    p.add_argument("--kds-cache", default=os.path.expanduser("~/.cache/amd-kds"))
    p.add_argument("--tool", help="sev-snp-measure 0.0.12 path (default: beside this Python, then PATH)")
    sub.add_parser("pin", help="reserved: spec 7.5, the next PR")
    # pin takes any arguments for now and answers not_available; verify takes none it does not know.
    args, unknown = parser.parse_known_args(argv)
    if unknown and args.command == "verify":
        parser.error("unrecognized arguments: " + " ".join(unknown))
    try:
        need(args.command == "verify", "not_available", "verify_vm.py pin (spec 7.5) is not in this version",
             CannotCheck)
        identity_raw = _read_limited(args.identity, vm_measure.DOC_MAX, "identity_invalid")
        crl = _read_limited(args.ark_crl, CRL_MAX, "ark_crl") if args.ark_crl else None
        result = verify(bundle=Path(args.bundle), identity_raw=identity_raw, vcpus=args.vcpus,
                        cpu_family=args.cpu_family, ark_sha256=args.ark_sha256, host=args.host, port=args.port,
                        user=args.user, ssh_key=args.ssh_key, floor=floor_for(args.cpu_family, args.min_tcb),
                        cache=args.kds_cache, ark_crl=crl, tool=args.tool)
    except Refused as exc:
        print(json.dumps({"schema": SCHEMA, "verdict": exc.verdict, "code": exc.code, "reason": str(exc)},
                         sort_keys=True))
        return exc.exit_code
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
