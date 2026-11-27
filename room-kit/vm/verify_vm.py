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

Before any connection, the identity must name the SSH key you gave at create: the host writes
vm-identity.json, and whoever holds the key it names is root at first boot.

  verify_vm.py verify|pin --bundle DIR --identity vm-identity.json --vcpus N --cpu-family genoa|turin
                          --ark-sha256 HEX --host HOST --port PORT --ssh-key FILE [--create-key FILE.pub]
                          [--user cathedral] [--min-tcb SPEC] [--ark-crl FILE] [--kds-cache DIR]
                          [--tool PATH] [--pin-dir DIR]

`pin` (spec r3 7.5, once, after first login) is `verify` plus, on the same connection and only
after the attest command succeeded, `cathedral-vm recovery show`. It keeps the recovery key,
the chip and the SSH host key locally, keyed by identity sha256, only when every check passed.
`verify` with a pin also refuses another SSH host key (host_key_changed) or another chip
(chip_id_changed). The pin store is ${XDG_DATA_HOME:-~/.local/share}/cathedral/vm-pins/.

One JSON line on stdout. Exit 0 PASS; 1 FAIL (the VM's evidence was refused); 2 ERROR (the
check could not run: local inputs, the pin store, sev-snp-measure, SSH or AMD KDS unreachable).

Needs Python 3.11+, cryptography>=42 and sev-snp-measure 0.0.12 (requirements/vm-measure.txt),
with vm_measure.py beside this file and verify_receipts.py one folder up, from one reviewed
checkout.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import secrets
import selectors
import stat
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature

VM_KIT = Path(__file__).resolve().parent
sys.path[:0] = [str(VM_KIT), str(VM_KIT.parent)]
import verify_receipts as vr
import vm_measure

SCHEMA = "cathedral.vm.verify/v1"

# ---- guest contract ---------------------------------------------------------------
# What the VM's measured initrd provides (spec r3 6.4: cathedral-attest from the initrd,
# bind-mounted at /run/cathedral/bin). The guest side is PR VM1b: Chaser confirms every
# value in this block there. Until then they are the values agreed with team-lead, 27 Nov.
GUEST_USER = "cathedral"  # the login user (README: ssh -p <port> cathedral@<host>)
GUEST_ATTEST = "/run/cathedral/bin/cathedral-attest"
GUEST_ATTEST_COMMAND = "sudo -n " + GUEST_ATTEST + " {challenge_hex}"
# REPORT_DATA = sha512(REPORT_DATA_DOMAIN || challenge[32] || sha256(host_key_blob)), the
# custom guest pattern (D 10.1, 10.2) under the VM's own tag.
REPORT_DATA_DOMAIN = b"cathedral-vm-report/v1\0"
ANSWER_REPORT_KEY = "report_b64"  # the guest prints one JSON object with this member
# spec r3 7.5: `sudo cathedral-vm recovery show` prints R, vm_id, identity_sha256 and CHIP_ID.
# Its output here (VM1b confirms): one JSON object on one line with exactly these members, R as
# canonical base64 of 32 bytes, chip_id as 128 hex.
GUEST_VM_TOOL = "/run/cathedral/bin/cathedral-vm"
GUEST_RECOVERY_COMMAND = "sudo -n " + GUEST_VM_TOOL + " recovery show"
RECOVERY_FIELDS = frozenset({"recovery_key_b64", "vm_id", "identity_sha256", "chip_id"})
RECOVERY_KEY_BYTES = 32

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
CHECKS = ("identity names your create key", "bundle and identity", "SSH connection host key", "report version", "CPU family and stepping",
          "AMD chain and report signature", "REPORT_DATA: challenge and SSH host key", "POLICY 0x30000",
          "VMPL 0", "VCEK signer, chip key not masked", "TCB floor", "MEASUREMENT", "HOST_DATA",
          "pinned SSH host key and CHIP_ID, when this identity has a pin")
DOES_NOT_PROVE = [
    "what runs after switch_root: your own OS and software",
    "disk freshness: the host can corrupt or roll back root disk blocks (spec r3 Q6)",
    "availability",
    "that a later connection reaches this VM, unless it checks this host key and attests again",
]
NOT_PINNED = "that the VM stays on one chip across reports: this identity has no pin yet (verify_vm.py pin)"

# ---- the pin store (spec r3 7.5) ----------------------------------------------------
PIN_SCHEMA = "cathedral.vm.pin/v1"
PIN_FIELDS = frozenset({"schema", "vm_id", "identity_sha256", "chip_id", "ssh_host_key", "recovery_key_b64",
                        "pinned_at"})
# What a second pin of the same VM must repeat. pinned_at is the first pin's and is kept.
PIN_COMPARED = ("vm_id", "identity_sha256", "chip_id", "ssh_host_key", "recovery_key_b64")
PIN_MAX = 4096

SSH_BIN = "/usr/bin/ssh"
SSH_TIMEOUT = 45
SSH_EXIT_ERROR = 255  # ssh's own failure (connection, host key, auth), not the remote command's
ANSWER_MAX = 65536
REPORT_B64_MAX = 2048
CRL_MAX = 1024 * 1024
ED25519_BLOB_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
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


def identity_key(identity_raw: bytes, create_key: str) -> dict:
    """The identity's first-boot SSH key must be the public key the customer gave at create.

    The host writes vm-identity.json at create. An identity naming the operator's key would
    boot a VM, measured and attested like any other, whose root at first boot is the operator,
    who could plant anything and then add the customer's key. MEASUREMENT and HOST_DATA only
    prove which identity booted, so this comparison is what ties that identity to the customer."""
    try:
        identity = vm_measure.parse_identity(identity_raw)
    except vm_measure.Refusal as exc:
        raise CannotCheck("identity_invalid", str(exc)) from None
    try:
        given = vm_measure.ssh_public_key(create_key)
    except vm_measure.Refusal as exc:
        raise CannotCheck("create_key", f"--create-key: {exc}") from None
    need(identity["ssh_public_key"] == given, "identity_key_mismatch",
         "the identity names another first-boot SSH key than the one you gave at create")
    digest = hashlib.sha256(base64.b64decode(given.split()[1])).digest()
    # The fingerprint ssh-keygen -l prints: SHA256 of the key blob, base64 without padding.
    return {"key": given, "sha256": "SHA256:" + base64.b64encode(digest).decode().rstrip("=")}


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
# The four helpers below copy the pattern of verify_custom_guest.py. Consolidate with
# verify_custom_guest.py (#776, merged): a follow-up imports its helpers instead.

def endpoint(host: str, port: int) -> str:
    """The known_hosts name of host:port."""
    need(type(port) is int and 1 <= port <= 65535, "ssh_target", "--port must be 1 to 65535", CannotCheck)
    need(type(host) is str and 0 < len(host) <= 253, "ssh_target", "--host is invalid", CannotCheck)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        need(all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in host.split(".")),
             "ssh_target", "--host must be an IP address or a DNS name", CannotCheck)
    return host if port == 22 else f"[{host}]:{port}"


def ssh_argv(host: str, port: int, user: str, ssh_key: str, known_hosts: Path, challenge: bytes,
             remote: str | None = None) -> list[str]:
    """One connection, no user or system config, no agent, mux or proxy, ed25519 host keys only.

    accept-new on an empty known_hosts: OpenSSH writes the server's key there before it has
    verified the KEX signature. That is safe here because a failed verification makes ssh exit
    255, and exchange() refuses any nonzero exit before it reads the file. The pin PR must keep
    a host key only from a run that exited 0, for the same reason (it does: pin stores the key
    exchange() returns, which exists only after exit 0)."""
    endpoint(host, port)
    need(type(user) is str and USER_RE.fullmatch(user) is not None, "ssh_target", "--user is invalid", CannotCheck)
    need(type(challenge) is bytes and len(challenge) == 32, "challenge", "the challenge must be 32 bytes", CannotCheck)
    options = {
        "UserKnownHostsFile": str(known_hosts), "GlobalKnownHostsFile": "/dev/null",
        "StrictHostKeyChecking": "accept-new", "HostKeyAlgorithms": "ssh-ed25519",
        "HashKnownHosts": "no", "CheckHostIP": "no", "VerifyHostKeyDNS": "no", "UpdateHostKeys": "no",
        "BatchMode": "yes", "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
        "IdentitiesOnly": "yes", "IdentityAgent": "none", "ForwardAgent": "no", "ForwardX11": "no",
        "ClearAllForwardings": "yes", "PermitLocalCommand": "no", "ControlMaster": "no",
        "ControlPath": "none", "ProxyCommand": "none", "ProxyJump": "none",
        "ConnectTimeout": "15", "ConnectionAttempts": "1", "LogLevel": "ERROR",
    }
    argv = [SSH_BIN, "-F", "/dev/null", "-T"]
    for key, value in options.items():
        argv += ["-o", f"{key}={value}"]
    return argv + ["-i", str(Path(ssh_key).resolve()), "-p", str(port), "-l", user, host,
                   remote or GUEST_ATTEST_COMMAND.format(challenge_hex=challenge.hex())]


def run_bounded(argv: list[str], timeout: float = SSH_TIMEOUT, limit: int = ANSWER_MAX) -> tuple[int, bytes, bytes]:
    """Run our own child, drain both pipes within byte and time bounds, and always reap it."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, "out")
            selector.register(proc.stderr, selectors.EVENT_READ, "err")
            deadline = time.monotonic() + timeout
            while selector.get_map():
                left = deadline - time.monotonic()
                need(left > 0, "ssh_failed", f"no answer within {timeout:g} s", CannotCheck)
                for key, _ in selector.select(min(left, 0.1)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.data].extend(chunk)
                    need(len(output["out"]) <= limit, "answer_invalid", f"the answer exceeds {limit} bytes")
                    need(len(output["err"]) <= limit, "ssh_failed", f"ssh wrote more than {limit} bytes of errors",
                         CannotCheck)
            try:
                code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise CannotCheck("ssh_failed", f"no answer within {timeout:g} s") from None
        return code, bytes(output["out"]), bytes(output["err"])
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def connection_key(raw: bytes, host: str, port: int) -> bytes:
    """The SSH wire blob of the one ed25519 host key this connection recorded."""
    need(type(raw) is bytes and len(raw) <= 4096, "host_key_invalid", "known_hosts is too large")
    lines = raw.splitlines()
    need(len(lines) == 1, "host_key_invalid", "expected exactly one host key for this connection")
    parts = lines[0].split()
    need(len(parts) == 3 and parts[0] == endpoint(host, port).encode() and parts[1] == b"ssh-ed25519",
         "host_key_invalid", "the recorded host key is not one ssh-ed25519 key for this host and port")
    try:
        blob = base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError):
        raise Refused("host_key_invalid", "the recorded host key is not base64") from None
    need(len(blob) == len(ED25519_BLOB_PREFIX) + 32 and blob.startswith(ED25519_BLOB_PREFIX)
         and base64.b64encode(blob) == parts[2], "host_key_invalid", "the recorded host key is not an ed25519 key")
    return blob


def _printable(raw: bytes, limit: int = 200) -> str:
    return "".join(c for c in raw[:limit].decode("ascii", "replace") if 0x20 <= ord(c) <= 0x7E)


def exchange(host: str, port: int, user: str, ssh_key: str, challenge: bytes,
             remote: str | None = None) -> tuple[bytes, bytes]:
    """One SSH connection: run the guest's attest command with the challenge (or remote, which
    starts with it). Returns its stdout and the host key blob OpenSSH recorded on that same
    connection. The key is read only after ssh exited 0."""
    need(Path(ssh_key).is_file(), "ssh_key", f"--ssh-key {ssh_key}: not a file", CannotCheck)
    with tempfile.TemporaryDirectory(prefix="cathedral-vm-verify-") as temp:
        known = Path(temp) / "known_hosts"
        known.touch(mode=0o600)
        try:
            code, out, err = run_bounded(ssh_argv(host, port, user, ssh_key, known, challenge, remote))
        except OSError as exc:
            raise CannotCheck("ssh_failed", f"cannot run {SSH_BIN}: {exc.strerror or type(exc).__name__}") from None
        need(code != SSH_EXIT_ERROR, "ssh_failed", f"ssh failed: {_printable(err)}", CannotCheck)
        # stderr only: under pin, stdout may hold the recovery key.
        need(code == 0, "attest_failed", f"the VM's command exited {code}: {_printable(err)}")
        with open(known, "rb") as f:
            host_blob = connection_key(f.read(4097), host, port)
    return out, host_blob


def report_data(challenge: bytes, host_blob: bytes) -> bytes:
    """The 64 bytes the VM must put in REPORT_DATA for this challenge on this connection."""
    need(type(challenge) is bytes and len(challenge) == 32, "challenge", "the challenge must be 32 bytes", CannotCheck)
    need(type(host_blob) is bytes and len(host_blob) == len(ED25519_BLOB_PREFIX) + 32
         and host_blob.startswith(ED25519_BLOB_PREFIX), "host_key_invalid", "the host key is not an ed25519 blob")
    return hashlib.sha512(REPORT_DATA_DOMAIN + challenge + hashlib.sha256(host_blob).digest()).digest()


def new_challenge() -> bytes:
    """32 fresh bytes per run, so an answer recorded earlier never matches."""
    return os.urandom(32)


# ---- the pin store ------------------------------------------------------------------

def default_pin_dir() -> Path:
    """${XDG_DATA_HOME:-~/.local/share}/cathedral/vm-pins (a relative XDG_DATA_HOME is ignored)."""
    base = os.environ.get("XDG_DATA_HOME", "")
    root = Path(base) if base.startswith("/") else Path.home() / ".local" / "share"
    return root / "cathedral" / "vm-pins"


def _pin_name(identity_sha256: str) -> str:
    need(type(identity_sha256) is str and HEX64_RE.fullmatch(identity_sha256) is not None, "pin_store_invalid",
         "an identity sha256 is 64 lowercase hex", CannotCheck)
    return identity_sha256 + ".json"


def _open_pin_dir(pin_dir: Path, create: bool) -> int | None:
    """The pin directory, opened without following a link, owned by us and closed to others.
    None when it does not exist and create is false."""
    if create:
        try:
            os.makedirs(pin_dir, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise CannotCheck("pin_store_invalid", f"{pin_dir}: {exc.strerror or type(exc).__name__}") from None
    try:
        fd = os.open(pin_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CannotCheck("pin_store_invalid", f"{pin_dir}: {exc.strerror or type(exc).__name__} "
                          "(it must be a directory, not a link)") from None
    st = os.fstat(fd)
    if not (stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0):
        os.close(fd)
        raise CannotCheck("pin_store_invalid", f"{pin_dir} must be a directory you own with mode 0700")
    return fd


def _check_pin(doc: dict, identity_sha256: str) -> dict:
    ok = (set(doc) == PIN_FIELDS and doc["schema"] == PIN_SCHEMA and doc["identity_sha256"] == identity_sha256
          and type(doc["vm_id"]) is str and vm_measure.VM_ID_RE.fullmatch(doc["vm_id"]) is not None
          and type(doc["chip_id"]) is str and re.fullmatch(r"[0-9a-f]{128}", doc["chip_id"]) is not None
          and type(doc["pinned_at"]) is str and len(doc["pinned_at"]) <= 32)
    need(ok, "pin_store_invalid", f"{identity_sha256}.json: not a {PIN_SCHEMA} record for this identity", CannotCheck)
    try:
        host_key = doc["ssh_host_key"].split(" ")
        blob = base64.b64decode(host_key[1], validate=True)
        r = base64.b64decode(doc["recovery_key_b64"], validate=True)
    except (AttributeError, IndexError, TypeError, binascii.Error, ValueError):
        raise CannotCheck("pin_store_invalid", f"{identity_sha256}.json: a key is not base64") from None
    need(len(host_key) == 2 and host_key[0] == "ssh-ed25519" and base64.b64encode(blob).decode() == host_key[1]
         and blob.startswith(ED25519_BLOB_PREFIX) and len(blob) == len(ED25519_BLOB_PREFIX) + 32
         and len(r) == RECOVERY_KEY_BYTES and base64.b64encode(r).decode() == doc["recovery_key_b64"],
         "pin_store_invalid", f"{identity_sha256}.json: a key has the wrong form", CannotCheck)
    return doc


def load_pin(identity_sha256: str, pin_dir: Path | None = None) -> dict | None:
    """The pin of one identity, checked, or None when there is none. verify reads it, and VM6
    re-wrap reads R from it.
    A pin that is a link, not ours, open to others or malformed refuses (pin_store_invalid)."""
    name = _pin_name(identity_sha256)
    dfd = _open_pin_dir(pin_dir or default_pin_dir(), create=False)
    if dfd is None:
        return None
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CannotCheck("pin_store_invalid", f"{name}: {exc.strerror or type(exc).__name__} "
                              "(it must be a regular file, not a link)") from None
        try:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0,
                 "pin_store_invalid", f"{name} must be a regular file you own with mode 0600", CannotCheck)
            raw = b""
            while len(raw) <= PIN_MAX:
                chunk = os.read(fd, PIN_MAX + 1 - len(raw))
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    need(len(raw) <= PIN_MAX, "pin_store_invalid", f"{name}: more than {PIN_MAX} bytes", CannotCheck)
    try:
        doc = vm_measure.parse_document(raw, "pin")
    except vm_measure.Refusal as exc:
        raise CannotCheck("pin_store_invalid", f"{name}: {exc}") from None
    return _check_pin(doc, identity_sha256)


def _same_pin(existing: dict, record: dict) -> str:
    differs = [k for k in PIN_COMPARED if existing[k] != record[k]]
    # Names only: the values include the recovery key.
    need(not differs, "pin_exists", f"this identity is already pinned with another {', '.join(differs)}; "
         "the pin is left unchanged")
    return "unchanged"


def store_pin(record: dict, pin_dir: Path | None = None) -> tuple[str, Path]:
    """Keep a pin. Never replaces one: the same values again is "unchanged", other values refuse
    pin_exists. The record is written to a new private file, then linked into place, so a pin is
    either whole or absent and a concurrent pin of the same identity cannot be overwritten."""
    pin_dir = pin_dir or default_pin_dir()
    name = _pin_name(record["identity_sha256"])
    _check_pin(record, record["identity_sha256"])
    existing = load_pin(record["identity_sha256"], pin_dir)
    if existing is not None:
        return _same_pin(existing, record), pin_dir / name
    raw = vm_measure.canonical(record)
    dfd = _open_pin_dir(pin_dir, create=True)
    temp = f".{name}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        except FileExistsError:
            existing = load_pin(record["identity_sha256"], pin_dir)
            return _same_pin(existing, record) if existing else "unchanged", pin_dir / name
        finally:
            os.unlink(temp, dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return "stored", pin_dir / name


def parse_recovery(raw: bytes, expected: dict, chip_id: str) -> str:
    """R from the guest's `cathedral-vm recovery show` line, after the attestation passed. The
    line is untrusted: it must name this identity and the chip the verified report names."""
    try:
        doc = json.loads(raw.decode("ascii"), object_pairs_hook=_unique, parse_constant=_no_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused("recovery_invalid", "the recovery record is not one strict ASCII JSON object") from None
    need(type(doc) is dict and set(doc) == RECOVERY_FIELDS and all(type(v) is str for v in doc.values()),
         "recovery_invalid", f"the recovery record must have exactly {', '.join(sorted(RECOVERY_FIELDS))}")
    try:
        r = base64.b64decode(doc["recovery_key_b64"], validate=True)
    except (binascii.Error, ValueError):
        raise Refused("recovery_invalid", "recovery_key_b64 is not base64") from None
    need(len(r) == RECOVERY_KEY_BYTES and base64.b64encode(r).decode() == doc["recovery_key_b64"],
         "recovery_invalid", f"the recovery key must be {RECOVERY_KEY_BYTES} bytes in canonical base64")
    need(doc["vm_id"] == expected["vm_id"] and doc["identity_sha256"] == expected["identity_sha256"],
         "recovery_identity_mismatch", "the recovery record names another VM than your identity")
    need(doc["chip_id"].lower() == chip_id, "recovery_chip_mismatch",
         "the recovery record names another chip than the verified report")
    return doc["recovery_key_b64"]


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
    checks, so a refusal named after a field is about a report AMD signed.

    The version, product and CPUID are read from the unsigned bytes first only to choose the
    chain (the product's KDS path and TCB layout) and the floor. They can only refuse: a forged
    value either names a chain that does not sign the report or fails the checks after it."""
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


def _attest(*, bundle: Path, identity_raw: bytes, create_key: str, vcpus: int, cpu_family: str,
            ark_sha256: str, host: str, port: int, user: str, ssh_key: str, floor: dict, cache: str,
            ark_crl: bytes | None, tool: str | None, pin_dir: Path | None, with_recovery: bool,
            exchange) -> tuple[dict, bytes | None, dict]:
    """Every verify check. Returns the PASS verdict, the recovery line (pin only) and the
    expected values, or raises Refused / CannotCheck naming the first check that did not pass."""
    need(type(ark_sha256) is str and HEX64_RE.fullmatch(ark_sha256.lower()) is not None, "ark_sha256",
         "--ark-sha256 must be 64 hex characters", CannotCheck)
    host = host.lower() if type(host) is str else host  # OpenSSH records the host name lowercased
    key = identity_key(identity_raw, create_key)  # before any connection
    expected = expected_values(bundle, identity_raw, vcpus, cpu_family, tool)
    pin_dir = pin_dir or default_pin_dir()
    pinned = load_pin(expected["identity_sha256"], pin_dir)
    challenge = new_challenge()
    remote = GUEST_ATTEST_COMMAND.format(challenge_hex=challenge.hex())
    if with_recovery:
        # Same exec, so the same connection; && so R is printed only after the attest command succeeded.
        remote += " && " + GUEST_RECOVERY_COMMAND
    out, host_blob = exchange(host, port, user, ssh_key, challenge, remote)
    host_key = "ssh-ed25519 " + base64.b64encode(host_blob).decode()
    need(pinned is None or pinned["ssh_host_key"] == host_key, "host_key_changed",
         "this connection's SSH host key differs from the one pinned for this identity")
    recovery = None
    if with_recovery:
        lines = [line for line in out.split(b"\n") if line.strip()]
        need(len(lines) == 2, "answer_invalid", "pin expects two lines: the report answer, then the recovery record")
        out, recovery = lines
    checked = check_report(parse_answer(out), expected=expected,
                           report_data_bytes=report_data(challenge, host_blob), cpu_family=cpu_family,
                           floor=floor, ark_sha256=ark_sha256.lower(), cache=cache, ark_crl=ark_crl)
    need(pinned is None or pinned["chip_id"] == checked["report"]["chip_id"], "chip_id_changed",
         "the report's CHIP_ID differs from the one pinned for this identity: the VM runs on another chip")
    result = {"schema": SCHEMA, "verdict": "PASS", "vm_id": expected["vm_id"],
              "identity_sha256": expected["identity_sha256"], "bundle": expected["bundle"],
              "cpu_family": cpu_family, "vcpus": vcpus, "challenge_hex": challenge.hex(), "identity_key": key,
              "ssh": {"host": host, "port": port, "user": user, "channel_binding": "verified", "host_key": host_key},
              **checked, "checks": list(CHECKS),
              "pin": {"state": "matched" if pinned else "none", "path": str(pin_dir / _pin_name(expected["identity_sha256"]))},
              "does_not_prove": DOES_NOT_PROVE + ([] if pinned else [NOT_PINNED])}
    return result, recovery, expected


def verify(*, exchange=exchange, pin_dir: Path | None = None, **inputs) -> dict:
    """The PASS verdict, or Refused / CannotCheck naming the first check that did not pass.
    Reads the pin of this identity, if any, and never writes one."""
    return _attest(**inputs, pin_dir=pin_dir, with_recovery=False, exchange=exchange)[0]


def pin(*, exchange=exchange, pin_dir: Path | None = None, **inputs) -> dict:
    """verify, then keep R, the chip and the host key of this identity (spec r3 7.5). Nothing is
    written unless every check passed and the guest's record names this identity and this chip."""
    result, recovery, expected = _attest(**inputs, pin_dir=pin_dir, with_recovery=True, exchange=exchange)
    record = {"schema": PIN_SCHEMA, "vm_id": expected["vm_id"], "identity_sha256": expected["identity_sha256"],
              "chip_id": result["report"]["chip_id"], "ssh_host_key": result["ssh"]["host_key"],
              "recovery_key_b64": parse_recovery(recovery, expected, result["report"]["chip_id"]),
              "pinned_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
    state, path = store_pin(record, pin_dir)
    result["pin"] = {"state": state, "path": str(path)}
    result["does_not_prove"] = DOES_NOT_PROVE
    return result


# ---- command line -------------------------------------------------------------------

def _read_limited(path: str, limit: int, code: str) -> bytes:
    try:
        with open(path, "rb") as f:
            raw = f.read(limit + 1)
    except OSError as exc:
        raise CannotCheck(code, f"{path}: {exc.strerror or type(exc).__name__}") from None
    need(len(raw) <= limit, code, f"{path}: more than {limit} bytes", CannotCheck)
    return raw


def _add_inputs(p: argparse.ArgumentParser) -> None:
    p.add_argument("--bundle", required=True, help="the bundle directory your VM runs (manifest.json and files)")
    p.add_argument("--identity", required=True, help="your VM's vm-identity.json, kept from create")
    p.add_argument("--vcpus", required=True, type=int)
    p.add_argument("--cpu-family", required=True, choices=sorted(APPROVED_CPUS))
    p.add_argument("--ark-sha256", required=True, help="the AMD root fingerprint you trust for that family")
    p.add_argument("--host", required=True)
    p.add_argument("--port", required=True, type=int, help="the VM's SSH port")
    p.add_argument("--ssh-key", required=True, help="your SSH private key file for the VM")
    p.add_argument("--create-key", help="the public key you gave at create (default: <--ssh-key>.pub)")
    p.add_argument("--user", default=GUEST_USER)
    p.add_argument("--min-tcb", action="append", help="raise the built-in floor: " + vr.MIN_TCB_HELP)
    p.add_argument("--ark-crl", help="a current AMD KDS DER CRL for offline use; otherwise fetched live")
    p.add_argument("--kds-cache", default=os.path.expanduser("~/.cache/amd-kds"))
    p.add_argument("--tool", help="sev-snp-measure 0.0.12 path (default: beside this Python, then PATH)")
    p.add_argument("--pin-dir", help="the pin store (default: ${XDG_DATA_HOME:-~/.local/share}/cathedral/vm-pins)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, text in (("verify", "attest one SSH connection to your VM"),
                       ("pin", "verify, then keep the recovery key, chip and host key locally (spec r3 7.5)")):
        _add_inputs(sub.add_parser(name, help=text))
    args = parser.parse_args(argv)
    try:
        identity_raw = _read_limited(args.identity, vm_measure.DOC_MAX, "identity_invalid")
        create_raw = _read_limited(args.create_key or args.ssh_key + ".pub", vm_measure.DOC_MAX, "create_key")
        try:
            create_key = create_raw.decode("ascii")
        except UnicodeDecodeError:
            raise CannotCheck("create_key", "--create-key: not an ASCII public key file") from None
        crl = _read_limited(args.ark_crl, CRL_MAX, "ark_crl") if args.ark_crl else None
        run = verify if args.command == "verify" else pin
        result = run(bundle=Path(args.bundle), identity_raw=identity_raw, create_key=create_key, vcpus=args.vcpus,
                     cpu_family=args.cpu_family, ark_sha256=args.ark_sha256, host=args.host, port=args.port,
                     user=args.user, ssh_key=args.ssh_key, floor=floor_for(args.cpu_family, args.min_tcb),
                     cache=args.kds_cache, ark_crl=crl, tool=args.tool,
                     pin_dir=Path(args.pin_dir) if args.pin_dir else None)
    except Refused as exc:
        print(json.dumps({"schema": SCHEMA, "verdict": exc.verdict, "code": exc.code, "reason": str(exc)},
                         sort_keys=True))
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001 - anything unforeseen is "could not check", never a PASS
        print(json.dumps({"schema": SCHEMA, "verdict": "ERROR", "code": "unexpected_error",
                          "reason": f"{type(exc).__name__}: {str(exc)[:200]}"}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
