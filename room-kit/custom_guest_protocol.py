"""Custom guest v1 document and report domains (AB#1004, spec-r9 §§8,10).

Pure checks shared by the owner tools. This module does not launch a guest,
prove its bootstrap ran, or grant access based on API-supplied expectations.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import struct
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BOOTSTRAP_DOMAIN = b"cathedral-custom-guest-bootstrap/v1\0"
HOST_DATA_DOMAIN = b"cathedral-dedicated-v2\0"
REPORT_DOMAIN = b"cathedral-custom-guest-report/v1\0"
BOOTCHECK_DOMAIN = b"cathedral-custom-guest-bootcheck/v1\0"
FILES = {"OVMF.amdsev.fd", "vmlinuz", "initrd", "cmdline", "root.raw"}
MANIFEST_FIELDS = {"version", "schema", "kind", "sha256", "bytes", "cmdline", "root_verity",
                   "root_data_bytes", "vcpus", "cpu_model", "mem_gib", "data_disk_gib",
                   "policy", "qemu_version", "sev_snp_measure", "reference_initrd"}
BOOTSTRAP_FIELDS = {"version", "schema", "launch_id", "hotel", "owner_scope", "owner_ed25519_b64",
                    "manifest_sha256", "ssh_public_key", "launch_nonce_hex", "ports", "network"}
SSH_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"}
HOST_KEY_PREFIX = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)


class ProtocolError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise ProtocolError(message)


def fields(doc, expected, label, optional=()):
    need(type(doc) is dict and set(doc) <= expected and expected - set(optional) <= set(doc),
         f"{label}: missing or unknown field")


def integer(value, lo, hi, label):
    need(type(value) is int and lo <= value <= hi, f"{label}: integer out of range")


def hex64(value, label):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
         f"{label}: expected 64 lowercase hex characters")


def canonical(doc):
    def check(value):
        if type(value) is str:
            need(all(0x20 <= ord(c) <= 0x7e for c in value), "non-printable or non-ASCII string")
        elif type(value) is int:
            pass
        elif type(value) is list:
            for item in value:
                check(item)
        elif type(value) is dict:
            for key, item in value.items():
                need(type(key) is str, "object key must be a string")
                check(key)
                check(item)
        else:
            raise ProtocolError("only integers, strings, objects and arrays are allowed")
    check(doc)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("ascii")


def parse_document(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 16384, "document must be 1 to 16384 bytes")
    try:
        doc = json.loads(raw)
        need(type(doc) is dict and canonical(doc) == raw, "document is not canonical JSON")
        return doc
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProtocolError("invalid document JSON") from exc


def decode64(value, size, label):
    try:
        need(type(value) is str, f"{label}: base64 string required")
        raw = base64.b64decode(value, validate=True)
        need(len(raw) == size and base64.b64encode(raw).decode() == value, f"{label}: noncanonical base64 or length")
        return raw
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"{label}: invalid base64") from exc


def cmdline_values(line, root_bytes):
    need(type(line) is str and 1 <= len(line) <= 2033 and all(0x20 <= ord(c) <= 0x7e for c in line),
         "cmdline: invalid bytes or length")
    need(line.strip() == line and "  " not in line, "cmdline: single spaces required")
    values = {}
    for token in line.split(" "):
        key, sep, value = token.partition("=")
        need(key not in values, "cmdline: repeated token")
        values[key] = value
        valid = False
        if key == "cathedral.owner":
            valid = re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is not None
            if valid:
                raw = base64.urlsafe_b64decode(value + "=")
                valid = base64.urlsafe_b64encode(raw).decode().rstrip("=") == value
        elif key == "cathedral.root_verity":
            valid = re.fullmatch(r"[0-9a-f]{64}", value) is not None
        elif key == "cathedral.root_data_bytes":
            valid = re.fullmatch(r"[1-9][0-9]{0,11}", value) is not None
            if valid:
                n = int(value)
                valid = n % 4096 == 0 and n < root_bytes
        elif key == "systemd.import_credentials":
            valid = value == "no"
        elif key == "console":
            valid = value in ("ttyS0", "ttyS0,115200")
        elif key == "quiet":
            valid = not sep
        elif key == "loglevel":
            valid = re.fullmatch(r"[0-7]", value) is not None
        elif key == "panic":
            valid = value == "-1" or (re.fullmatch(r"0|[1-9][0-9]{0,3}", value) is not None and int(value) <= 3600)
        elif key == "cathedral.note":
            valid = bool(sep) and bool(value)
        need(valid, "cmdline: token refused")
    need({"cathedral.owner", "cathedral.root_verity", "cathedral.root_data_bytes", "systemd.import_credentials"} <= set(values),
         "cmdline: required token missing")
    return values


def manifest(raw):
    doc = parse_document(raw)
    fields(doc, MANIFEST_FIELDS, "manifest", optional={"data_disk_gib"})
    need(type(doc["version"]) is int and doc["version"] == 1 and doc["schema"] == "cathedral.custom_guest.manifest/v1"
         and doc["kind"] == "custom_guest", "manifest: unsupported version/schema/kind")
    fields(doc["sha256"], FILES, "manifest sha256")
    fields(doc["bytes"], FILES, "manifest bytes")
    for name in FILES:
        hex64(doc["sha256"][name], "manifest digest")
        integer(doc["bytes"][name], 1, 200 * 1024**3, "manifest bytes")
    integer(doc["vcpus"], 1, 56, "vcpus")
    integer(doc["mem_gib"], 4, 640, "mem_gib")
    integer(doc.get("data_disk_gib", 0), 0, 400, "data_disk_gib")
    need(doc["cpu_model"] in ("EPYC-Genoa-v1", "EPYC-v4") and doc["policy"] == "0x30000", "CPU or policy refused")
    need(doc["qemu_version"] == "10.2.1" and doc["sev_snp_measure"] == "0.0.12", "tool version refused")
    need(isinstance(doc["reference_initrd"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", doc["reference_initrd"]), "reference initrd invalid")
    tokens = cmdline_values(doc["cmdline"], doc["bytes"]["root.raw"])
    need(doc["root_verity"] == tokens["cathedral.root_verity"] and type(doc["root_data_bytes"]) is int
         and doc["root_data_bytes"] == int(tokens["cathedral.root_data_bytes"]), "verity fields differ from cmdline")
    line = doc["cmdline"].encode("ascii")
    need(doc["sha256"]["cmdline"] == hashlib.sha256(line).hexdigest() and doc["bytes"]["cmdline"] == len(line), "cmdline digest/size mismatch")
    return doc


def bootstrap(raw):
    doc = parse_document(raw)
    fields(doc, BOOTSTRAP_FIELDS, "bootstrap")
    need(type(doc["version"]) is int and doc["version"] == 1 and doc["schema"] == "cathedral.custom_guest.bootstrap/v1", "bootstrap: unsupported version/schema")
    need(type(doc["launch_id"]) is str and re.fullmatch(r"cg-[0-9a-f]{12}", doc["launch_id"]), "launch id invalid")
    need(type(doc["hotel"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", doc["hotel"]), "hotel invalid")
    scope = doc["owner_scope"]
    need(type(scope) is str and re.fullmatch(r"(?:user|org):[0-9a-f-]{36}", scope), "owner scope invalid")
    try:
        need(str(uuid.UUID(scope.split(":")[1])) == scope.split(":")[1], "owner scope UUID invalid")
    except ValueError as exc:
        raise ProtocolError("owner scope UUID invalid") from exc
    decode64(doc["owner_ed25519_b64"], 32, "owner")
    hex64(doc["manifest_sha256"], "manifest hash")
    hex64(doc["launch_nonce_hex"], "launch nonce")
    ssh = doc["ssh_public_key"]
    need(type(ssh) is str and len(ssh) <= 16384, "SSH key invalid")
    parts = ssh.split(" ")
    need(len(parts) == 2 and parts[0] in SSH_TYPES, "SSH key must have supported type, base64 and no comment")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        kind = parts[0].encode()
        need(blob.startswith(struct.pack(">I", len(kind)) + kind) and len(blob) > len(kind) + 4
             and base64.b64encode(blob).decode() == parts[1], "SSH key wire type invalid")
    except ValueError as exc:
        raise ProtocolError("SSH key invalid") from exc
    ports = doc["ports"]
    need(type(ports) is list and 1 <= len(ports) <= 8, "ports invalid")
    seen = set()
    for i, port in enumerate(ports):
        fields(port, {"guest", "public", "proto"}, "port")
        integer(port["public"], 20000, 29999, "public port")
        integer(port["guest"], 1, 65535, "guest port")
        need(port["proto"] == "tcp" and port["public"] not in seen and (port["guest"] == 22) == (i == 0), "port mapping invalid")
        seen.add(port["public"])
    net = doc["network"]
    fields(net, {"guest_ip", "host_ip", "prefix", "guest_mac", "public_host"}, "network")
    integer(net["prefix"], 30, 30, "network prefix")
    need(all(type(net[key]) is str for key in ("guest_ip", "host_ip", "public_host")), "network addresses must be strings")
    try:
        guest, host = ipaddress.IPv4Address(net["guest_ip"]), ipaddress.IPv4Address(net["host_ip"])
        subnet = ipaddress.IPv4Network(f"{host}/30", strict=False)
        need(guest != host and guest in subnet.hosts() and host in subnet.hosts(), "network addresses invalid")
        ipaddress.IPv4Address(net["public_host"])
    except (ValueError, TypeError) as exc:
        raise ProtocolError("network addresses invalid") from exc
    need(type(net["guest_mac"]) is str and re.fullmatch(r"52:54:00(?::[0-9a-f]{2}){3}", net["guest_mac"]), "guest MAC invalid")
    return doc


def validate_launch(manifest_raw, bootstrap_raw, signature, owner_key):
    m, b = manifest(manifest_raw), bootstrap(bootstrap_raw)
    need(type(owner_key) is bytes and len(owner_key) == 32, "independent owner key required")
    need(type(signature) is bytes and len(signature) == 64, "bootstrap signature must be 64 bytes")
    owner = decode64(b["owner_ed25519_b64"], 32, "owner")
    tokens = cmdline_values(m["cmdline"], m["bytes"]["root.raw"])
    need(owner == owner_key and base64.urlsafe_b64encode(owner).decode().rstrip("=") == tokens["cathedral.owner"], "owner key differs")
    need(b["manifest_sha256"] == hashlib.sha256(manifest_raw).hexdigest(), "bootstrap names another manifest")
    Ed25519PublicKey.from_public_bytes(owner_key).verify(signature, BOOTSTRAP_DOMAIN + hashlib.sha256(bootstrap_raw).digest())
    return m, b, hashlib.sha256(HOST_DATA_DOMAIN + hashlib.sha256(manifest_raw).digest() + owner_key + hashlib.sha256(bootstrap_raw).digest()).hexdigest()


def host_key_blob(blob):
    need(type(blob) is bytes and len(blob) == len(HOST_KEY_PREFIX) + 32 and blob.startswith(HOST_KEY_PREFIX), "host key must be SSH wire-format ed25519")
    return blob


def report_data(challenge, blob):
    need(type(challenge) is bytes and len(challenge) == 32, "challenge must be 32 bytes")
    return hashlib.sha512(REPORT_DOMAIN + challenge + hashlib.sha256(host_key_blob(blob)).digest()).digest()


def bootcheck_data(random_bytes):
    need(type(random_bytes) is bytes and len(random_bytes) == 32, "boot challenge must be 32 bytes")
    return hashlib.sha512(BOOTCHECK_DOMAIN + random_bytes).digest()
