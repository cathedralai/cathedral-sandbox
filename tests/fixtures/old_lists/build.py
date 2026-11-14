#!/usr/bin/env python3
"""Build the receipt lists that the golden test feeds to the checker.

The lists use fixed test keys derived from labels, so every run writes the same
bytes. Case arguments use the placeholder {dir} for the case folder.

    build.py            write the input files and cases.json
    build.py --record   also run the checker and write each case's golden output
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
SANDBOX_ID = "0f1e2d3c-4b5a-4968-8776-655443322110"


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"old-list-test-key:" + label.encode()).digest())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class Hotel:
    """One binding and the chain signed under it."""

    def __init__(self, sealed: bool, label: str, tag: str):
        self.key = test_key(label)
        self.sealed = sealed
        pub = b64(self.key.public_key().public_bytes_raw())
        if sealed:
            self.binding = {
                "schema": "cathedral_sealed_hotel_binding_v1", "hotel": "h1", "boot_id": tag,
                "measurement": "ab" * 48, "chip_id": "cd" * 64, "reported_tcb": "01" * 8,
                "policy": "0x30000", "host_data": "ef" * 32, "receipt_key_ed25519_b64": pub}
        else:
            self.binding = {"schema": "cathedral_hotel_binding_v1", "level": "hotel", "hotel": "h1",
                            "boot_id": tag, "receipt_key_ed25519_b64": pub}
        self.bsha = sha(canonical(self.binding))
        self.head = self.bsha
        self.chain: list[dict] = []

    def attestation(self) -> dict:
        report = ""
        if self.sealed:
            r = bytearray(0x4A0)
            r[0:4] = (3).to_bytes(4, "little")
            r[0x50:0x90] = bytes.fromhex(self.bsha) + bytes(32)
            r[0x90:0xC0] = bytes.fromhex(self.binding["measurement"])
            r[0xC0:0xE0] = bytes.fromhex(self.binding["host_data"])
            r[0x180:0x188] = bytes.fromhex(self.binding["reported_tcb"])
            r[0x1A0:0x1E0] = bytes.fromhex(self.binding["chip_id"])
            r[0x08:0x10] = int(self.binding["policy"], 16).to_bytes(8, "little")
            report = b64(bytes(r))
        return {"binding": self.binding, "binding_sha256": self.bsha, "report_b64": report}

    def sign(self, action: str, room: str | None, status: int = 200, **extra) -> dict:
        seq = len(self.chain) + 1
        statement = {
            "schema": "cathedral_sealed_hotel_receipt_v1" if self.sealed else "cathedral_hotel_receipt_v1",
            "binding_sha256": self.bsha, "hotel": "h1",
            "operation_id": str(__import__("uuid").UUID(bytes=hashlib.sha256(f"{self.bsha}{seq}".encode()).digest()[:16])),
            "sequence": seq, "previous_receipt_sha256": self.head, "issued_at": 1_700_000_000 + seq,
            "action": action, "target": f"POST /v1/sandboxes/{room}" if room else "POST /v1/sandboxes",
            "sandbox_id": room, "customer_request_sha256": sha(b"req%d" % seq), "command_sha256": None,
            "image": None, "image_digest": None, "status": status, "result_sha256": sha(b"res%d" % seq),
            **extra}
        receipt = {"statement": statement, "signature_b64": b64(self.key.sign(canonical(statement))),
                   "receipt_sha256": sha(canonical(statement))}
        self.head = receipt["receipt_sha256"]
        self.chain.append(receipt)
        return receipt


def write(case: Path, name: str, doc) -> None:
    case.mkdir(parents=True, exist_ok=True)
    (case / name).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")


def policy(mode: str, allow: list[str]) -> dict:
    p = {"mode": mode, "allow": allow}
    return {"network_policy": p, "network_policy_sha256": sha(canonical(p))}


def three_rooms(h: Hotel, link: bool = False) -> None:
    extra = {"cathedral_sandbox_id": SANDBOX_ID} if link else {}
    h.sign("create", "r1", 202, image="alpine:3.20", **policy("deny_all", []), **extra)
    h.sign("create", "r2", 202, image="alpine:3.20", **policy("allowlist", ["example.org"]))
    h.sign("exec", "r1", 200, command_sha256=sha(b"cmd"))
    h.sign("network_set", "r2", 200, **policy("deny_all", []))
    h.sign("delete", "r1", 200)


def main() -> int:
    cases: dict[str, dict] = {}
    ATT = ["--attestation", "{dir}/attestation_doc.json", "--receipts", "{dir}/receipts.json"]

    def add(name, hotel, doc, args, att=None):
        case = HERE / "cases" / name
        write(case, "attestation_doc.json", att if att is not None else hotel.attestation())
        write(case, "receipts.json", doc)
        cases[name] = {"args": args}

    h = Hotel(False, "level1", "boot-1")
    three_rooms(h)
    add("hotel_level1_list", h, h.chain, ATT)
    add("hotel_level1_whole_chain_head", h, {"receipts": h.chain, "head": h.head}, ATT)
    add("hotel_level1_wrong_head", h, {"receipts": h.chain, "head": "00" * 32}, ATT)
    add("hotel_level1_chain_with_gap", h, {"receipts": h.chain[:1] + h.chain[2:], "head": h.head}, ATT)
    add("hotel_level1_filtered_chain", h, {"receipts": h.chain[:1] + h.chain[2:], "filtered": True}, ATT)

    s = Hotel(True, "sealed", "boot-s")
    three_rooms(s, link=True)
    sealed_args = [*ATT, "--skip-amd", "--expected-measurement", "ab" * 48]
    add("sealed_skip_amd", s, s.chain, sealed_args)
    add("sealed_whole_chain_head", s, {"receipts": s.chain, "head": s.head}, sealed_args)
    add("sealed_wrong_measurement", s, s.chain, [*ATT, "--skip-amd", "--expected-measurement", "00" * 48])
    add("sandbox_link_found", s, s.chain, [*sealed_args, "--cathedral-sandbox", SANDBOX_ID])
    add("sandbox_link_not_found", s, s.chain,
        [*sealed_args, "--cathedral-sandbox", "11111111-2222-4333-8444-555555555555"])

    t = Hotel(True, "timeline", "boot-t")
    tun = {"tunables": {"runtime": "runsc"}, "tunables_sha256": sha(canonical({"runtime": "runsc"})),
           "tunables_runtime": "runsc", "tunables_runtime_args": []}
    start = ["sleep", "infinity"]
    t.sign("create", "r1", 202, image="alpine:3.20", **policy("allowlist", ["example.org", "example.net"]),
           **tun, start_command=start, start_command_sha256=sha(canonical(start)))
    t.sign("network_set", "r1", 200, **policy("deny_all", []))
    t.sign("exec", "r1", 200)
    t.sign("network_set", "r1", 500)
    t.sign("delete", "r1", 200)
    t.sign("create", "r1", 202, **policy("deny_all", []))
    add("policy_timeline", t, {"receipts": t.chain, "head": t.head}, sealed_args)

    # An archived binding from an earlier boot: served by a local broker in the test.
    old, new = Hotel(True, "archive-old", "boot-old"), Hotel(True, "archive-new", "boot-new")
    old.sign("create", "room-a", 202)
    new.sign("create", "room-a", 202)
    case = HERE / "cases" / "archived_binding"
    write(case, "attestation_doc.json", new.attestation())
    write(case, "receipts.json", {"receipts": [old.chain[0], new.chain[0]], "head": new.head,
                                  "binding_sha256": new.bsha, "scanned": 2})
    write(case, "archive.json", {old.bsha: old.binding})
    cases["archived_binding"] = {"broker": True, "args": [
        "--broker", "{broker}", "--key-file", "{dir}/guest_key.txt", "--operator-key-file", "{dir}/operator_key.txt",
        "--hotel", "h1", "--skip-amd"]}
    (case / "guest_key.txt").write_text("guest\n")
    (case / "operator_key.txt").write_text("operator\n")
    cases["archived_binding_no_operator_key"] = {"args": [*ATT, "--skip-amd"]}
    cdir = HERE / "cases" / "archived_binding_no_operator_key"
    write(cdir, "attestation_doc.json", new.attestation())
    write(cdir, "receipts.json", {"receipts": [old.chain[0], new.chain[0]]})

    (HERE / "cases.json").write_text(json.dumps(cases, indent=1, sort_keys=True) + "\n")
    if "--record" in sys.argv:
        sys.path.insert(0, str(HERE))
        from run_case import run_case
        for name in sorted(cases):
            out, code = run_case(name)
            (HERE / "cases" / name / "golden.stdout").write_bytes(out)
            (HERE / "cases" / name / "golden.exit").write_text(f"{code}\n")
            print(name, code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
