#!/usr/bin/env python3
"""Write manifest.json and bootstrap.json for one rehearsal launch (spec-r9 8.1 to 8.3), for the offline test.

The documents are built field for field as #780's measure phase builds them
(ops/custom-guest/custom_guest_host.py ph_measure at f456fe1), from the files in
--images: OVMF.amdsev.fd, vmlinuz, initrd, cmdline, root.raw. Stdlib only; no key
is read or written. It prints the HOST_DATA the launcher will pass and the
command the owner runs to sign bootstrap.json.

REHEARSAL-ONLY test image; never offered to customers. A real launch gets its documents
from the operator's measure phase, never from this script.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys

NAMES = ("OVMF.amdsev.fd", "vmlinuz", "initrd", "cmdline", "root.raw")


def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--images", required=True, help="directory with the five launch files")
    ap.add_argument("--out", required=True, help="directory for manifest.json and bootstrap.json")
    ap.add_argument("--owner-pub", required=True, help="the owner's 32 raw public key bytes")
    ap.add_argument("--owner-scope", required=True, help="user:<uuid> or org:<uuid>")
    ap.add_argument("--ssh-public-key", required=True, help="'ssh-ed25519 AAAA...' (a comment is dropped)")
    ap.add_argument("--launch-id", default="cg-" + secrets.token_hex(6))
    ap.add_argument("--hotel", default="chi-ur-2")
    ap.add_argument("--link", type=int, default=0, help="n of 10.217.<n>.0/30 (tap cgst<n>)")
    ap.add_argument("--public-host", required=True)
    ap.add_argument("--public-port", type=int, default=20022)
    ap.add_argument("--vcpus", type=int, default=4)
    ap.add_argument("--mem-gib", type=int, default=8)
    ap.add_argument("--cpu-model", default="EPYC-v4")
    ap.add_argument("--launch-nonce-hex", default=secrets.token_hex(32))
    ap.add_argument("--reference-initrd", default="rehearsal-test-v1")
    ap.add_argument("--qemu-version", default="10.2.1")
    a = ap.parse_args()

    if not re.fullmatch(r"cg-[0-9a-f]{12}", a.launch_id):
        sys.exit("--launch-id must be cg-<12 lowercase hex>")
    if not 0 <= a.link <= 255 or not 20000 <= a.public_port <= 29999:
        sys.exit("--link 0..255, --public-port 20000..29999")
    owner = open(a.owner_pub, "rb").read()
    if len(owner) != 32:
        sys.exit("--owner-pub must hold 32 raw bytes")
    cmdline = open(os.path.join(a.images, "cmdline"), "rb").read().decode("ascii")
    tokens = dict(t.split("=", 1) for t in cmdline.split(" ") if "=" in t)
    if tokens.get("cathedral.owner") != base64.urlsafe_b64encode(owner).rstrip(b"=").decode():
        sys.exit("cmdline cathedral.owner is not --owner-pub: the measured cmdline names another owner")

    manifest = {"version": 1, "schema": "cathedral.custom_guest.manifest/v1", "kind": "custom_guest",
                "sha256": {n: sha256_file(os.path.join(a.images, n)) for n in NAMES},
                "bytes": {n: os.path.getsize(os.path.join(a.images, n)) for n in NAMES},
                "cmdline": cmdline, "root_verity": tokens["cathedral.root_verity"],
                "root_data_bytes": int(tokens["cathedral.root_data_bytes"]), "vcpus": a.vcpus,
                "cpu_model": a.cpu_model, "mem_gib": a.mem_gib, "data_disk_gib": 0, "policy": "0x30000",
                "qemu_version": a.qemu_version, "sev_snp_measure": "0.0.12",
                "reference_initrd": a.reference_initrd}
    m_raw = canonical(manifest)
    hexid = a.launch_id[3:]
    bootstrap = {"version": 1, "schema": "cathedral.custom_guest.bootstrap/v1", "launch_id": a.launch_id,
                 "hotel": a.hotel, "owner_scope": a.owner_scope,
                 "owner_ed25519_b64": base64.b64encode(owner).decode(),
                 "manifest_sha256": hashlib.sha256(m_raw).hexdigest(),
                 "ssh_public_key": " ".join(a.ssh_public_key.split()[:2]),
                 "launch_nonce_hex": a.launch_nonce_hex,
                 "ports": [{"guest": 22, "proto": "tcp", "public": a.public_port}],
                 "network": {"guest_ip": f"10.217.{a.link}.2", "host_ip": f"10.217.{a.link}.1", "prefix": 30,
                             "guest_mac": f"52:54:00:c7:{hexid[0:2]}:{hexid[2:4]}",
                             "public_host": a.public_host}}
    b_raw = canonical(bootstrap)
    os.makedirs(a.out, exist_ok=True)
    for name, raw in (("manifest.json", m_raw), ("bootstrap.json", b_raw)):
        with open(os.path.join(a.out, name), "wb") as f:
            f.write(raw)
    host_data = hashlib.sha256(b"cathedral-dedicated-v2\0" + hashlib.sha256(m_raw).digest() + owner
                               + hashlib.sha256(b_raw).digest()).digest()
    print(json.dumps({"launch_id": a.launch_id, "manifest_sha256": hashlib.sha256(m_raw).hexdigest(),
                      "bootstrap_sha256": hashlib.sha256(b_raw).hexdigest(),
                      "host_data_hex": host_data.hex(), "host_data_b64": base64.b64encode(host_data).decode(),
                      "tap": f"cgst{a.link}", "guest_mac": bootstrap["network"]["guest_mac"]}, indent=1))
    print("sign (owner key holder): python3 room-kit/owner_sign.py --custom-guest-bootstrap "
          f"--key OWNER_KEY.pem --body {os.path.join(a.out, 'bootstrap.json')} | base64 -d > "
          f"{os.path.join(a.out, 'bootstrap.sig')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
