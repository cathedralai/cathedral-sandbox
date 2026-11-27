#!/usr/bin/env python3
"""Verify one SSH connection to a custom SNP guest before trusting its host key.

All launch expectations come from owner-provided files and flags. No API lookup,
agent forwarding, password, private payload or automatic secret release. A new
connection must use the verified key and re-attest after any relaunch.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import selectors
import subprocess
import tempfile
import time
from pathlib import Path

import custom_guest_protocol as protocol
import verify_guest_report as direct
from cryptography.exceptions import InvalidSignature


def bounded_command(argv, timeout=45, limit=65536):
    """Drain both pipes with byte/time bounds; terminate and reap our own child."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, "out")
            selector.register(proc.stderr, selectors.EVENT_READ, "err")
            deadline = time.monotonic() + timeout
            while selector.get_map():
                left = deadline - time.monotonic()
                protocol.need(left > 0, "SSH report deadline exceeded")
                for key, _ in selector.select(min(left, 0.1)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        protocol.need(len(output[key.data]) <= limit, "SSH response too large")
            try:
                code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise protocol.ProtocolError("SSH report deadline exceeded") from exc
        protocol.need(code == 0, "SSH report command failed")
        return bytes(output["out"])
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def endpoint(host, port):
    protocol.need(type(port) is int and 1 <= port <= 65535, "SSH port invalid")
    protocol.need(type(host) is str and len(host) <= 253, "SSH host invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        protocol.need(all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                          for part in host.split(".")), "SSH host invalid")
    return host if port == 22 else f"[{host}]:{port}"


def ssh_command(host, port, user, identity, known_hosts, challenge):
    endpoint(host, port)
    protocol.need(type(user) is str and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user), "SSH user invalid")
    protocol.need(type(challenge) is bytes and len(challenge) == 32, "challenge must be 32 bytes")
    # No user/system SSH config, multiplexed connection, proxy or forwarded agent.
    options = {
        "UserKnownHostsFile": str(known_hosts), "GlobalKnownHostsFile": "/dev/null",
        "StrictHostKeyChecking": "accept-new", "HostKeyAlgorithms": "ssh-ed25519",
        "HashKnownHosts": "no", "CheckHostIP": "no", "VerifyHostKeyDNS": "no",
        "UpdateHostKeys": "no", "BatchMode": "yes", "PasswordAuthentication": "no",
        "KbdInteractiveAuthentication": "no", "IdentitiesOnly": "yes", "IdentityAgent": "none",
        "ForwardAgent": "no", "ClearAllForwardings": "yes", "PermitLocalCommand": "no",
        "ControlMaster": "no", "ControlPath": "none", "ProxyCommand": "none", "ProxyJump": "none",
        "ConnectTimeout": "15", "ConnectionAttempts": "1", "LogLevel": "ERROR",
    }
    argv = ["/usr/bin/ssh", "-F", "/dev/null", "-T"]
    for key, value in options.items():
        argv += ["-o", f"{key}={value}"]
    return argv + ["-i", str(Path(identity).resolve()), "-p", str(port), "-l", user, host,
                   "/usr/bin/cathedral-attest " + challenge.hex()]


def connection_key(raw, host, port):
    protocol.need(type(raw) is bytes and len(raw) <= 4096, "known_hosts too large")
    lines = raw.splitlines()
    protocol.need(len(lines) == 1, "expected exactly one SSH connection host key")
    parts = lines[0].split()
    protocol.need(len(parts) == 3 and parts[0] == endpoint(host, port).encode()
                  and parts[1] == b"ssh-ed25519", "known_hosts does not match this connection")
    blob = protocol.host_key_blob(base64.b64decode(parts[2], validate=True))
    protocol.need(base64.b64encode(blob) == parts[2], "noncanonical SSH key encoding")
    return blob


def verify_connection(answer, *, challenge, host_blob, manifest_raw, bootstrap_raw, signature,
                      owner_key, expected_measurement, ark_sha256, cache, min_tcb,
                      expected_chip_id, expected_cpuid, ark_crl=None):
    _, bootstrap, host_data = protocol.validate_launch(manifest_raw, bootstrap_raw, signature, owner_key)
    result = direct.verify(answer, report_data_hex=protocol.report_data(challenge, host_blob).hex(),
                           expected_measurement=expected_measurement, expected_host_data=host_data,
                           ark_sha256=ark_sha256, cache=cache, product="Turin", min_tcb=min_tcb,
                           expected_chip_id=expected_chip_id, expected_cpuid=expected_cpuid, ark_crl=ark_crl)
    result.update(verdict="PASS", ssh_channel_binding="verified", launch_id=bootstrap["launch_id"],
                  ssh_host_key="ssh-ed25519 " + base64.b64encode(host_blob).decode())
    result["does_not_prove"] = [item for item in result["does_not_prove"]
                                if item != "the SSH connection terminates in this guest"]
    result["does_not_prove"].append("any future connection without a matching key and fresh attestation")
    return result


def read_limit(path, limit):
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    protocol.need(len(raw) <= limit, "input file too large")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "identity", "manifest", "bootstrap", "bootstrap-signature", "owner-public-key",
                 "expected-measurement", "ark-sha256", "expected-chip-id", "expected-cpuid", "known-hosts-out"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--port", type=int, default=20022)
    parser.add_argument("--user", default="root")
    parser.add_argument("--min-tcb", action="append", required=True)
    parser.add_argument("--kds-cache", default=os.path.expanduser("~/.cache/amd-kds"))
    parser.add_argument("--ark-crl")
    args = parser.parse_args()
    try:
        m, b = read_limit(args.manifest, 16384), read_limit(args.bootstrap, 16384)
        sig, owner = read_limit(args.bootstrap_signature, 64), read_limit(args.owner_public_key, 32)
        _, launch, _ = protocol.validate_launch(m, b, sig, owner)
        protocol.need(args.host == launch["network"]["public_host"] and args.port == launch["ports"][0]["public"],
                      "SSH endpoint differs from owner-signed bootstrap")
        challenge = os.urandom(32)
        with tempfile.TemporaryDirectory(prefix="cathedral-ssh-attest-") as temp:
            known = Path(temp) / "known_hosts"
            known.touch(mode=0o600)
            raw = bounded_command(ssh_command(args.host, args.port, args.user, args.identity, known, challenge))
            host_blob = connection_key(read_limit(known, 4096), args.host, args.port)
            def unique(pairs):
                doc = {}
                for key, value in pairs:
                    protocol.need(key not in doc, "duplicate answer field")
                    doc[key] = value
                return doc
            answer = json.loads(raw, object_pairs_hook=unique)
            result = verify_connection(answer, challenge=challenge, host_blob=host_blob, manifest_raw=m,
                bootstrap_raw=b, signature=sig, owner_key=owner, expected_measurement=args.expected_measurement,
                ark_sha256=args.ark_sha256, cache=args.kds_cache, min_tcb=direct.vr.parse_min_tcb(args.min_tcb),
                expected_chip_id=args.expected_chip_id, expected_cpuid=args.expected_cpuid,
                ark_crl=read_limit(args.ark_crl, 1024 * 1024) if args.ark_crl else None)
            # Never overwrite an existing pin or write a key before every check succeeds.
            fd = os.open(args.known_hosts_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(endpoint(args.host, args.port).encode() + b" ssh-ed25519 " + base64.b64encode(host_blob) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, direct.vr.Fail, InvalidSignature, RecursionError) as exc:
        print(json.dumps({"verdict": "FAIL", "reason": str(exc) or type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
