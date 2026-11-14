#!/usr/bin/env python3
"""Build the receipt-list pack that every checker (Python, Go, the API's own) runs.

Layout:
  source/        trust.json (ARK pin, measurements), keys.json (public test keys), amd/ (synthetic chain)
  good/<name>/   lists a checker must accept
  bad/<name>/    lists a checker must refuse, each for one stated reason
  MANIFEST.json  sha256 of every file, and a root hash

Every case folder holds the list files, a case.json, and nothing else. case.json:
  description  what the list shows
  args         command line flags, with {dir} standing for the case folder
  expect       exit_code, verdict, for a FAIL the exact reason, and "pointers": JSON pointers into
               the JSON the checker prints, each with the value it must have

The root hash is the sha256 of the lines "<path> <sha256>\\n" over all files except MANIFEST.json,
sorted by path. A checker that copies this folder records that hash and refreshes the copy when it changes.

Usage:
  generate.py            write every file (and the exchange case, tests/fixtures/oneshot_exchange/good_basic)
  generate.py --check    rebuild in memory, fail on any file that differs, is missing or is extra, and
                         re-verify the synthetic AMD chain with the checker (verify_amd, from the bundle's
                         certificates)
  generate.py --amd      make the synthetic AMD chain and the one signed report (their signatures are
                         random, so they are made once, committed, and only re-verified)

Receipts are signed with Ed25519, which is deterministic. With fixed keys, times and ids the same
code writes the same bytes. Keys are derived from public labels: they are test data and sign nothing real.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKER = HERE.parents[2] / "room-kit" / "verify_receipts.py"
SKIP = {"generate.py", "MANIFEST.json", "__pycache__"}

BASE_TIME = 1_700_000_000
MEASUREMENT = hashlib.sha384(b"receipt-lists-v2 test measurement").hexdigest()
OTHER_MEASUREMENT = hashlib.sha384(b"receipt-lists-v2 other test measurement").hexdigest()
CHIP_ID = hashlib.sha512(b"receipt-lists-v2 test chip").hexdigest()
REPORTED_TCB = bytes([3, 0, 0, 0, 0, 0, 8, 115])
HOST_DATA = hashlib.sha256(b"receipt-lists-v2 test host data").hexdigest()
POLICY = "0x30000"


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def pretty(doc) -> bytes:
    return (json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()


def load_checker():
    spec = importlib.util.spec_from_file_location("verify_receipts_for_pack", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def signing_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"receipt-lists-v2 test receipt key").digest())


# ---------------------------------------------------------------- synthetic AMD chain

def make_amd(report_version: int = 3, cpuid_family: int = 0x19, cpuid_model: int = 0x01) -> dict[str, bytes]:
    """ARK, ASK and VCEK (RSA-PSS SHA-384, as AMD's are) and one report signed by the VCEK.

    report_version 2 writes a report with no CPUID fields (a checker then needs --product to know the product)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.x509.oid import NameOID

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    start = datetime.datetime(2024, 1, 1)
    end = datetime.datetime(2124, 1, 1)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def cert(subject, issuer, public, signer, serial, extensions=()):
        builder = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
                   .public_key(public).serial_number(serial).not_valid_before(start).not_valid_after(end))
        for oid, value in extensions:
            builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), False)
        return builder.sign(signer, hashes.SHA384(), rsa_padding=pss)

    ark_key = rsa.generate_private_key(65537, 2048)
    ask_key = rsa.generate_private_key(65537, 2048)
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark = cert("ARK-TEST", "ARK-TEST", ark_key.public_key(), ark_key, 1)
    ask = cert("ASK-TEST", "ARK-TEST", ask_key.public_key(), ark_key, 2)
    tcb = REPORTED_TCB

    def spl(n: int) -> bytes:
        return bytes([0x02, 0x01, n])

    vcek = cert("VCEK-TEST", "ASK-TEST", vcek_key.public_key(), ask_key, 3, [
        ("1.3.6.1.4.1.3704.1.4", bytes.fromhex(CHIP_ID)),
        ("1.3.6.1.4.1.3704.1.3.1", spl(tcb[0])), ("1.3.6.1.4.1.3704.1.3.2", spl(tcb[1])),
        ("1.3.6.1.4.1.3704.1.3.3", spl(tcb[6])), ("1.3.6.1.4.1.3704.1.3.8", spl(tcb[7]))])
    der = serialization.Encoding.DER
    report = bytearray(shared_attestation(b"")["report_unsigned"])
    report[0:4] = report_version.to_bytes(4, "little")
    if report_version < 3:
        report[0x188] = report[0x189] = 0  # the CPUID family and model exist from version 3 on
    else:
        report[0x188], report[0x189] = cpuid_family, cpuid_model
    r_s = decode_dss_signature(vcek_key.sign(bytes(report[:0x2A0]), ec.ECDSA(hashes.SHA384())))
    report[0x2A0:0x2A0 + 72] = r_s[0].to_bytes(72, "little")
    report[0x2E8:0x2E8 + 72] = r_s[1].to_bytes(72, "little")
    certs = {"vcek": b64(vcek.public_bytes(der)), "ask": b64(ask.public_bytes(der)), "ark": b64(ark.public_bytes(der))}
    return {
        "source/amd/certs.json": pretty(certs),
        "source/amd/report.json": pretty({"binding_sha256": shared_attestation(b"")["binding_sha256"],
                                          "report_b64": b64(bytes(report))}),
        "source/amd/ark_sha256.txt": (sha(ark.public_bytes(der)) + "\n").encode(),
    }


def shared_attestation(amd_report_json: bytes) -> dict:
    """The one binding every list uses. report_unsigned is what the VCEK signs."""
    pub = b64(signing_key().public_key().public_bytes_raw())
    binding = {
        "schema": "cathedral_sealed_hotel_binding_v1", "hotel": "pack-hotel", "boot_id": "pack-boot-1",
        "measurement": MEASUREMENT, "chip_id": CHIP_ID, "reported_tcb": REPORTED_TCB.hex(),
        "policy": POLICY, "host_data": HOST_DATA, "receipt_key_ed25519_b64": pub}
    bsha = sha(canonical(binding))
    r = bytearray(0x4A0)
    r[0:4] = (3).to_bytes(4, "little")
    r[0x08:0x10] = int(POLICY, 16).to_bytes(8, "little")
    r[0x34:0x38] = (1).to_bytes(4, "little")
    r[0x50:0x90] = bytes.fromhex(bsha) + bytes(32)
    r[0x90:0xC0] = bytes.fromhex(MEASUREMENT)
    r[0xC0:0xE0] = bytes.fromhex(HOST_DATA)
    r[0x180:0x188] = REPORTED_TCB
    r[0x188], r[0x189] = 0x19, 0x01
    r[0x1A0:0x1E0] = bytes.fromhex(CHIP_ID)
    out = {"binding": binding, "binding_sha256": bsha, "report_unsigned": bytes(r)}
    if amd_report_json:
        signed = json.loads(amd_report_json)
        if signed["binding_sha256"] != bsha:
            raise SystemExit("source/amd/report.json signs another binding: run generate.py --amd")
        out["report_b64"] = signed["report_b64"]
    return out


class Pack:
    def __init__(self, amd: dict[str, bytes]):
        self.amd = amd
        att = shared_attestation(amd["source/amd/report.json"])
        self.binding, self.bsha = att["binding"], att["binding_sha256"]
        self.attestation = {"binding": self.binding, "binding_sha256": self.bsha, "report_b64": att["report_b64"]}
        self.certs = json.loads(amd["source/amd/certs.json"])
        self.ark = amd["source/amd/ark_sha256.txt"].decode().strip()
        self.key = signing_key()
        self.files: dict[str, bytes] = {}

    def new_hotel(self) -> Hotel:
        return Hotel(self)

    def add(self, kind: str, name: str, files: dict[str, bytes], case: dict) -> None:
        for fname, data in files.items():
            self.files[f"{kind}/{name}/{fname}"] = data
        self.files[f"{kind}/{name}/case.json"] = pretty(case)

    def source_files(self) -> dict[str, bytes]:
        trust = {"ark_sha256": self.ark, "measurements": [MEASUREMENT], "other_measurement": OTHER_MEASUREMENT,
                 "binding_sha256": self.bsha}
        keys = {"receipt_key_ed25519_b64": self.binding["receipt_key_ed25519_b64"],
                "note": "test data: the private key is derived from a public label and signs nothing real"}
        return {"source/trust.json": pretty(trust), "source/keys.json": pretty(keys),
                "source/attestation_doc.json": pretty(self.attestation), **self.amd}


class Hotel:
    """A chain signed under the shared binding, with each room's own numbering."""

    def __init__(self, pack: Pack):
        self.pack = pack
        self.chain: list[dict] = []
        self.head = pack.bsha
        self.room_seq: dict[str, int] = {}
        self.room_head: dict[str, str | None] = {}

    def sign(self, action: str, room: str | None, status: int = 200, numbered: bool = True, **fields) -> dict:
        seq = len(self.chain) + 1
        statement = {
            "schema": "cathedral_sealed_hotel_receipt_v1", "binding_sha256": self.pack.bsha, "hotel": "pack-hotel",
            "operation_id": str(uuid.UUID(bytes=hashlib.sha256(f"{self.pack.bsha}:{seq}".encode()).digest()[:16])),
            "sequence": seq, "previous_receipt_sha256": self.head, "issued_at": BASE_TIME + seq,
            "action": action, "target": f"POST /v1/sandboxes/{room}/{action}" if room else "POST /v1/sandboxes",
            "sandbox_id": room, "customer_request_sha256": sha(b"request %d" % seq), "command_sha256": None,
            "image": None, "image_digest": None, "status": status, "result_sha256": sha(b"result %d" % seq)}
        if room and numbered:
            n = self.room_seq.get(room, 0) + 1
            statement["room_sequence"] = n
            statement["room_previous_receipt_sha256"] = self.room_head.get(room)
        statement.update(fields)
        for key in [k for k, v in statement.items() if v is DEL]:
            del statement[key]  # DEL leaves the field out of the signed statement
        receipt = {"statement": statement, "signature_b64": b64(self.pack.key.sign(canonical(statement))),
                   "receipt_sha256": sha(canonical(statement))}
        self.head = receipt["receipt_sha256"]
        self.chain.append(receipt)
        if room:
            self.room_seq[room] = self.room_seq.get(room, 0) + 1
            self.room_head[room] = receipt["receipt_sha256"]
        return receipt

    def room(self, room: str) -> list[dict]:
        return [r for r in self.chain if r["statement"]["sandbox_id"] == room]


HOTEL_ARGS = ["--attestation", "{dir}/attestation_doc.json", "--receipts", "{dir}/receipts.json", "--skip-amd",
              "--expected-measurement", MEASUREMENT]


def hotel_case(pack: Pack, kind: str, name: str, description: str, doc, expect: dict, extra_args=()) -> None:
    exp = {"exit_code": 0, "verdict": "PASS"} if kind == "good" else {"exit_code": 1, "verdict": "FAIL"}
    exp.update(expect)
    pack.add(kind, name, {"attestation_doc.json": pretty(pack.attestation), "receipts.json": pretty(doc)},
             {"description": description, "args": [*HOTEL_ARGS, *extra_args], "expect": exp})


def whole(hotel: Hotel, receipts=None) -> dict:
    return {"receipts": hotel.chain if receipts is None else receipts, "head": hotel.head}


NUMBERING_SHOWS = "No receipt of this room is missing from this list, between its first receipt and its last."
NUMBERING_DOES_NOT_SHOW = ("That nothing was still running in the room when the list was read, or that no receipt "
                            "was signed after it. There is no closed verdict for an ordinary room.")


def numbering_cases(pack: Pack) -> None:
    room = "/chain/room_numbering/rooms"

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("create", "room-b", 202)
    h.sign("exec", "room-a")
    h.sign("exec", "room-b")
    h.sign("exec", "room-a")
    h.sign("delete", "room-b")
    hotel_case(pack, "good", "numbered_rooms_interleaved",
               "Two rooms signed in turn: each room's own receipts are numbered 1 to n and link to each other.",
               whole(h), {"pointers": {
                   f"{room}/room-a/receipts": 3, f"{room}/room-b/receipts": 3, f"{room}/room-a/first": 1,
                   f"{room}/room-a/last": 5, f"{room}/room-a/head": h.room("room-a")[-1]["receipt_sha256"],
                   "/chain/room_numbering/shows/0": NUMBERING_SHOWS,
                   "/chain/room_numbering/does_not_show/0": NUMBERING_DOES_NOT_SHOW}})
    hotel_case(pack, "good", "numbered_list_reordered",
               "The same room's receipts in a shuffled order: they are sorted by room_sequence before they are checked.",
               {"receipts": [h.room("room-a")[2], h.room("room-a")[0], h.room("room-a")[1]]},
               {"pointers": {f"{room}/room-a/receipts": 3}})
    hotel_case(pack, "good", "numbered_one_room_list",
               "A per-room list that names its head and count, as the room's own receipt route answers.",
               {"receipts": h.room("room-a"), "room_head": h.room("room-a")[-1]["receipt_sha256"], "count": 3},
               {"pointers": {f"{room}/room-a/receipts": 3}})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("delete", "room-a")
    h.sign("create", "room-a", 202)
    h.sign("exec", "room-a")
    hotel_case(pack, "good", "numbered_room_id_used_again",
               "A room id created, deleted and created again under one key: its numbers go on.",
               whole(h), {"pointers": {f"{room}/room-a/receipts": 4, f"{room}/room-a/last": 4}})

    h = pack.new_hotel()
    h.sign("create", "room-old", 202, numbered=False)
    h.sign("exec", "room-old", numbered=False)
    h.sign("exec", "room-old")  # signed after the fields existed
    h.sign("create", "room-new", 202)
    h.sign("exec", "room-new")
    hotel_case(pack, "good", "mixed_old_and_new_receipts",
               "One room whose first receipts have no numbering fields and a later one does: a warning, no numbering "
               "claim for that room. Another room is numbered in full.",
               whole(h), {"pointers": {
                   f"{room}/room-new/receipts": 2,
                   "/checked": "whole chain to the head the server named; each numbered room: its receipts run "
                               "1 to n with no gap and every link right; room room-old has receipts with and "
                               "without numbering: no numbering claim for it"}})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202, numbered=False)
    h.sign("exec", "room-a", numbered=False)
    hotel_case(pack, "good", "unnumbered_room_unchanged",
               "A room with no numbering fields at all: today's output, no room_numbering key.",
               whole(h), {"pointers": {"/checked": "whole chain to the head the server named"}})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("exec", "room-a")
    h.sign("room_end", "room-a", reason="reaped after its lifetime")
    hotel_case(pack, "good", "room_end_with_reason",
               "A room_end receipt names why the room ended; it is reported and nothing is said about later receipts.",
               whole(h), {"pointers": {f"{room}/room-a/ended/reason": "reaped after its lifetime",
                                       f"{room}/room-a/receipts": 3}})

    # --- bad numbering
    def bad_hotel():
        hh = pack.new_hotel()
        hh.sign("create", "room-a", 202)
        hh.sign("exec", "room-a")
        hh.sign("exec", "room-a")
        hh.sign("delete", "room-a")
        return hh

    h = bad_hotel()
    a = h.room("room-a")
    hotel_case(pack, "bad", "numbering_middle_receipt_dropped",
               "The room's second receipt is missing from the list: its numbers jump from 1 to 3.",
               {"receipts": [a[0], a[2], a[3]]},
               {"reason": "room room-a: room_sequence jumps from 1 to 3: a receipt is missing"})
    hotel_case(pack, "bad", "numbering_last_receipt_dropped_with_head",
               "A per-room list that names count 4 but holds 3 receipts.",
               {"receipts": a[:3], "room_head": a[3]["receipt_sha256"], "count": 4},
               {"reason": "room room-a: the last receipt is not the room_head the list names"})
    hotel_case(pack, "bad", "numbering_count_differs",
               "A per-room list whose count is not the number of receipts it holds.",
               {"receipts": a, "room_head": a[3]["receipt_sha256"], "count": 5},
               {"reason": "room room-a: the list names 5 receipts but holds 4"})
    hotel_case(pack, "bad", "numbering_first_receipt_dropped",
               "The room's first receipt is missing: its numbers start at 2.",
               {"receipts": a[1:]}, {"reason": "room room-a: room_sequence does not start at 1 (first is 2)"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("exec", "room-a")
    h.sign("exec", "room-a", room_sequence=2)
    hotel_case(pack, "bad", "numbering_duplicate", "Two receipts of one room carry room_sequence 2.",
               whole(h), {"reason": "room room-a: room_sequence 2 appears more than once"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("exec", "room-a", room_previous_receipt_sha256="00" * 32)
    hotel_case(pack, "bad", "numbering_bad_link", "A room receipt links to a hash that is not the room's previous receipt.",
               whole(h), {"reason": "room room-a: room receipt 2 does not link to room receipt 1"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202, room_previous_receipt_sha256="00" * 32)
    hotel_case(pack, "bad", "numbering_first_link_not_null", "A room's first receipt links to something.",
               whole(h), {"reason": "room room-a: room receipt 1 must have a null room_previous_receipt_sha256"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("exec", "room-a", room_sequence="2")
    hotel_case(pack, "bad", "numbering_sequence_is_text", "room_sequence is the text 2, not the number 2.",
               whole(h), {"reason": "room room-a: receipt 2: room_sequence is not an integer"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202, room_sequence=True)
    hotel_case(pack, "bad", "numbering_sequence_is_boolean", "room_sequence is true, which is not the number 1.",
               whole(h), {"reason": "room room-a: receipt 1: room_sequence is not an integer"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("create", "room-b", 202)
    h.sign("exec", "room-a")
    hotel_case(pack, "bad", "numbering_head_for_several_rooms",
               "A list that names a room_head but holds receipts of two rooms.",
               {"receipts": h.chain, "room_head": h.head, "count": 3},
               {"reason": "the list names a room_head but holds receipts of 2 rooms"})


def serial_cases(pack: Pack) -> None:
    room = "/chain/room_numbering/rooms"
    h = pack.new_hotel()
    h.sign("create", "room-s", 202, serial=True)
    h.sign("file_put", "room-s", 200)
    h.sign("exec", "room-s")
    h.sign("file_get", "room-s")
    h.sign("file_put", "room-s")
    sentence = ("Every request on a signed route that named the room and reached it through the front before the last "
                "receipt was signed is in this list, in the order it ran, and none was still running.")
    hotel_case(pack, "good", "serial_room_closed_by_file_put",
               "A serial room whose last action is a successful file put: closed to that action, alive when it ran.",
               whole(h), {"pointers": {
                   f"{room}/room-s/serial": True, f"{room}/room-s/closed_to": "file_put",
                   f"{room}/room-s/alive_at_last_action": True, "/chain/room_numbering/shows/0": sentence}})

    h = pack.new_hotel()
    h.sign("create", "room-s", 202, serial=True)
    h.sign("exec", "room-s")
    h.sign("delete", "room-s")
    hotel_case(pack, "good", "serial_room_last_action_delete",
               "A serial room whose last action is a delete: closed to the delete, no claim that it was alive.",
               whole(h), {"pointers": {f"{room}/room-s/closed_to": "delete",
                                       f"{room}/room-s/alive_at_last_action": None}})

    h = pack.new_hotel()
    h.sign("create", "room-s", 202, serial=True)
    h.sign("exec", "room-s", 500)
    hotel_case(pack, "good", "serial_room_failed_exec_not_alive",
               "A serial room whose last action is an exec that failed: no claim that it was alive.",
               whole(h), {"pointers": {f"{room}/room-s/closed_to": "exec",
                                       f"{room}/room-s/alive_at_last_action": None}})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202, serial=True)
    h.sign("create", "room-a", 202)
    hotel_case(pack, "bad", "serial_second_create", "A serial room has a second create.", whole(h),
               {"reason": "room room-a: receipt 2: a second create in a serial room"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202, serial=True)
    h.sign("exec", "room-a", 502)
    hotel_case(pack, "bad", "serial_lost_answer", "A serial room has a receipt for a lost answer (status 502).",
               whole(h), {"reason": "room room-a: receipt 2: a lost answer (status 502) in a serial room"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("exec", "room-a", serial=True)
    hotel_case(pack, "bad", "serial_flag_on_exec", "The serial flag is on an exec, not on the create.", whole(h),
               {"reason": "room room-a: receipt 2: serial is set on a receipt that is not a successful create"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 500, serial=True)
    hotel_case(pack, "bad", "serial_flag_on_failed_create", "The serial flag is on a create that failed.", whole(h),
               {"reason": "room room-a: receipt 1: serial is set on a receipt that is not a successful create"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202, numbered=False, serial=True)
    h.sign("exec", "room-a", numbered=False)
    hotel_case(pack, "bad", "serial_create_without_numbering", "A serial create in a room whose receipts are not numbered.",
               whole(h), {"reason": "room room-a: receipt 1: a serial create needs numbered receipts"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 500)
    h.sign("create", "room-a", 202, serial=True)
    hotel_case(pack, "bad", "serial_create_not_receipt_one", "The serial create is the room's second receipt.",
               whole(h), {"reason": "room room-a: receipt 2: a serial create must be receipt 1 of its room"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202, serial="yes")
    hotel_case(pack, "bad", "serial_flag_is_text", "The serial flag is the text yes.", whole(h),
               {"reason": "room room-a: receipt 1: serial is not a boolean"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("room_end", "room-a")
    hotel_case(pack, "bad", "room_end_without_reason", "A room_end receipt that names no reason.", whole(h),
               {"reason": "room room-a: receipt 2: room_end has no reason"})

    h = pack.new_hotel()
    h.sign("create", "room-a", 202)
    h.sign("room_end", "room-a", reason="")
    hotel_case(pack, "bad", "room_end_empty_reason", "A room_end receipt whose reason is empty.", whole(h),
               {"reason": "room room-a: receipt 2: room_end has no reason"})


CLAIM_ID = "5b7c1a2e-9d3f-4e6a-8b10-2c4d6e8f0a1b"
POOL_WORDS = ("Nothing ran in this room before the claim except the machine's own main process, and no request "
              "reached it through the front. This rests on the rules of the measured front, so it holds only for "
              "the measurements you allowed.")


def claim_fields(create: dict, **over) -> dict:
    fields = {"cathedral_sandbox_id": CLAIM_ID, "lifetime_seconds": 3600, "pooled_from": create["receipt_sha256"]}
    fields.update(over)
    return fields


def pool_cases(pack: Pack) -> None:
    pools = "/pool_rooms"

    h = pack.new_hotel()
    c = h.sign("create", "pool-1", 202, pool=True)
    h.sign("claim", "pool-1", 200, **claim_fields(c))
    h.sign("exec", "pool-1")
    hotel_case(pack, "good", "pool_room_claimed",
               "A pre-made room: receipt 1 is a pool create, receipt 2 is the claim made from it. The claim's id is the link.",
               whole(h), {"pointers": {
                   f"{pools}/pool-1/state": "claimed", f"{pools}/pool-1/pooled_from": c["receipt_sha256"],
                   f"{pools}/pool-1/shows/0": POOL_WORDS, "/room_links/pool-1": CLAIM_ID,
                   "/sandbox_link/rooms/0": "pool-1"}},
               extra_args=["--cathedral-sandbox", CLAIM_ID])

    h = pack.new_hotel()
    h.sign("create", "pool-1", 202, pool=True)
    hotel_case(pack, "good", "pool_room_unclaimed",
               "A pre-made room that has not been claimed: reported as unclaimed, and it names no link.",
               whole(h), {"pointers": {f"{pools}/pool-1/state": "unclaimed", "/room_links": {}}})

    h = pack.new_hotel()
    c = h.sign("create", "pool-1", 202, pool=True)
    h.sign("claim", "pool-1", 409, **claim_fields(c))
    hotel_case(pack, "good", "pool_room_claim_failed",
               "A claim that failed: the room is closed and gives no link.",
               whole(h), {"pointers": {f"{pools}/pool-1/state": "closed", "/room_links": {}}})

    h = pack.new_hotel()
    h.sign("create", "pool-1", 202, pool=True)
    h.sign("delete", "pool-1")
    hotel_case(pack, "good", "pool_room_retired_unclaimed",
               "A pre-made room deleted before any claim: retired, no link.",
               whole(h), {"pointers": {f"{pools}/pool-1/state": "retired", "/room_links": {}}})

    h = pack.new_hotel()
    h.sign("create", "pool-1", 202, pool=True)
    hotel_case(pack, "bad", "pool_unclaimed_has_no_link",
               "An unclaimed pre-made room never matches a sandbox id.", whole(h),
               {"reason": f"no successful create receipt names Cathedral sandbox {CLAIM_ID}"},
               extra_args=["--cathedral-sandbox", CLAIM_ID])

    h = pack.new_hotel()
    c = h.sign("create", "pool-1", 202, numbered=False, pool=True)
    h.sign("claim", "pool-1", 200, numbered=False, **claim_fields(c))
    hotel_case(pack, "bad", "pool_claim_without_numbering",
               "A claim in a room whose receipts are not numbered: nothing shows that no receipt sits between "
               "create and claim.", whole(h),
               {"reason": "room pool-1: receipt 2: a claim needs numbered receipts: cannot show nothing sits "
                          "between create and claim"})

    h = pack.new_hotel()
    c = h.sign("create", "pool-1", 202, pool=True)
    h.sign("claim", "pool-1", 200, **claim_fields(c, pooled_from="00" * 32))
    hotel_case(pack, "bad", "pool_claim_pooled_from_wrong",
               "The claim names a different create than the room's receipt 1.", whole(h),
               {"reason": "room pool-1: receipt 2: pooled_from is not the pool create's receipt hash"})

    h = pack.new_hotel()
    h.sign("create", "room-n", 202)
    c = h.chain[0]
    h.sign("claim", "room-n", 200, **claim_fields(c))
    hotel_case(pack, "bad", "pool_claim_without_pool_create",
               "A claim in a room whose receipt 1 is an ordinary create.", whole(h),
               {"reason": "room room-n: receipt 2: a claim in a room that was not made as a pool room"})

    h = pack.new_hotel()
    c = h.sign("create", "pool-1", 202, pool=True)
    h.sign("exec", "pool-1")
    h.sign("claim", "pool-1", 200, **claim_fields(c))
    hotel_case(pack, "bad", "pool_claim_not_receipt_two",
               "A request reached the room between create and claim.", whole(h),
               {"reason": "room pool-1: receipt 3: a claim must be receipt 2 of a pool room"})

    h = pack.new_hotel()
    h.sign("create", "pool-1", 202, pool=True)
    h.sign("exec", "pool-1")
    hotel_case(pack, "bad", "pool_receipt_two_is_not_a_claim",
               "Receipt 2 of a pre-made room is an exec.", whole(h),
               {"reason": "room pool-1: receipt 2: receipt 2 of a pool room is not a claim"})

    h = pack.new_hotel()
    h.sign("create", "pool-1", 202, pool=True, cathedral_sandbox_id=CLAIM_ID)
    hotel_case(pack, "bad", "pool_create_names_a_link", "A pool create that already names a sandbox id.", whole(h),
               {"reason": "room pool-1: receipt 1: a pool create names a sandbox link"})

    h = pack.new_hotel()
    h.sign("create", "pool-1", 202, pool=True, serial=True)
    hotel_case(pack, "bad", "pool_create_is_serial", "A create that is both pool and serial.", whole(h),
               {"reason": "room pool-1: receipt 1: a pool create cannot also be serial"})

    h = pack.new_hotel()
    h.sign("create", "pool-1", 202)
    h.sign("exec", "pool-1", pool=True)
    hotel_case(pack, "bad", "pool_flag_on_exec", "The pool flag is on an exec.", whole(h),
               {"reason": "room pool-1: receipt 2: pool is set on a receipt that is not a successful create"})

    h = pack.new_hotel()
    c = h.sign("create", "pool-1", 202, pool=True)
    h.sign("claim", "pool-1", 200, target="POST /v1/sandboxes/other-room/claim", **claim_fields(c))
    hotel_case(pack, "bad", "pool_claim_target_names_another_room", "The claim's signed target names another room.",
               whole(h), {"reason": "room pool-1: receipt 2: the claim's target is not POST /v1/sandboxes/pool-1/claim"})

    h = pack.new_hotel()
    c = h.sign("create", "pool-1", 202, pool=True)
    h.sign("claim", "pool-1", 200, **claim_fields(c, cathedral_sandbox_id=CLAIM_ID.upper()))
    hotel_case(pack, "bad", "pool_claim_id_not_lower_case_uuid", "The claim's sandbox id is not a lower-case UUID.",
               whole(h), {"reason": "room pool-1: receipt 2: cathedral_sandbox_id is not a lower-case UUID"})

    h = pack.new_hotel()
    c = h.sign("create", "pool-1", 202, pool=True)
    h.sign("claim", "pool-1", 200, **claim_fields(c, lifetime_seconds=0))
    hotel_case(pack, "bad", "pool_claim_lifetime_not_positive", "The claim's lifetime is zero.", whole(h),
               {"reason": "room pool-1: receipt 2: lifetime_seconds is not a positive integer"})


# ---------------------------------------------------------------- run mode (a one-shot's file)

RUN_ID = "7d9c3a5e-1b2f-4c6d-8e0a-9f1b2c3d4e5f"
RUN_ROOM = "run-room-1"
BATCH_ID = "0b1c2d3e-4f50-4162-8384-95a6b7c8d9e0"
IMAGE_REF = "images.example.test/app@sha256:" + sha(b"receipt-lists-v2 image reference")
IMAGE_ID = "sha256:" + sha(b"receipt-lists-v2 image id")
CONTEXT_PATH = "/work/in/.context.json"
END_PATH = "/work/.cathedral-end"
RESULT_PATH = "/work/out/result.json"
LOG_PATH = "/work/out/log.txt"
RUN_PATH = "/work/in/run.py"
DATA_PATH = "/work/in/data.csv"
UNICODE_PATH = "/work/in/a b+c&d=e%f~ü.txt"  # not a valid path form: used by a bad list
NESTED_PATH = "/work/in/dir/a-b_c.d.txt"
CONTEXT = {"submission": "sub-0001", "note": "café"}
FILE_BYTES = {RUN_PATH: b"print('ok')\n", DATA_PATH: b"a,b\n1,2\n", UNICODE_PATH: b"unicode path input\n", NESTED_PATH: b"nested input\n",
              RESULT_PATH: b'{"ok":true}\n', LOG_PATH: b"done\n"}
DEL = object()  # an override value that removes the field


SIZES = json.loads((HERE.parents[2] / "broker" / "oneshot_create_keys.json").read_text())["sizes"]


def base_recipe() -> dict:
    return {
        "schema": "cathedral_oneshot_recipe_v1",
        "request": {
            "image": IMAGE_REF, "command": ["python", RUN_PATH], "env": {"MODE": "check"}, "cwd": "/work",
            "size": "sealed-1x2", "timeout_seconds": 60, "network": {"mode": "deny_all", "allow": []},
            "image_id": IMAGE_ID, "max_spend_usd": "0.50",
            "outputs": [{"path": RESULT_PATH, "max_bytes": 65536, "optional": False},
                        {"path": LOG_PATH, "max_bytes": 65536, "optional": True}],
            "inputs": [{"path": RUN_PATH, "mode": "755"}, {"path": DATA_PATH, "mode": "644"}]},
        "create": {"ttl_seconds": None, "broker_guest": "guest-1"},  # None: the timeout plus the room margin
        "file_modes": {"context": "644", "end_marker": "644"}}


def enc(pairs: dict[str, str]) -> str:
    """The query as the machine's front signs it: sorted keys, quote_plus values (Go's url.Values.Encode)."""
    from urllib.parse import quote_plus
    return "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in sorted(pairs.items()))


def put_target(room: str, mode: str, path: str) -> str:
    return f"PUT /v1/sandboxes/{room}/files?{enc({'mode': mode, 'path': path})}"


def get_target(room: str, max_bytes: int, path: str) -> str:
    return f"GET /v1/sandboxes/{room}/files?{enc({'max_bytes': str(max_bytes), 'path': path})}"


def broker_form(net):
    """The network the broker writes into the create, and the policy the machine signs for it."""
    if net is None or net == "":
        return {"mode": "deny_all", "allow": []}, {"mode": "deny_all", "allow": []}
    if isinstance(net, str):
        return net, {"mode": net, "allow": []}
    if not net.get("mode"):
        body = {**net, "mode": "deny_all", "allow": net.get("allow") or []}
        return body, {"mode": "deny_all", "allow": []}
    # The machine signs the canonical policy: names lower case, unique, sorted; only an allowlist keeps any.
    names = sorted({n.lower() for n in net.get("allow") or []}) if net["mode"] == "allowlist" else []
    return net, {"mode": net["mode"], "allow": names}


def step(role: str, action: str, target: str, status: int = 200, **fields) -> dict:
    return {"role": role, "action": action, "target": target, "status": status, "fields": fields}


def _plain_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def make_run(pack: Pack, *, truth_edit=None, recipe_edit=None, context=None, overrides=None, steps_edit=None,
             drop=(), create_body=None, exec_body=None, bundle_edit=None, args_edit=None, absent=(),
             held=(RESULT_PATH,), inline=(LOG_PATH,), held_bytes=None, caller_hashes=None, exec_response="confirmed",
             numbered=True, room=RUN_ROOM, no_context_arg=False, input_files=(), truth_context=None,
             extra_files=None, bundle_raw=None, recipe_raw=None, context_raw=None, file_bytes=None, exec_answer=None):
    fb = {**FILE_BYTES, **(file_bytes or {})}
    recipe = base_recipe()
    if truth_edit:
        truth_edit(recipe)
    margin = json.loads((HERE.parents[2] / "broker" / "oneshot_create_keys.json").read_text())["room_margin_seconds"]
    if recipe["create"]["ttl_seconds"] is None:
        recipe["create"]["ttl_seconds"] = recipe["request"]["timeout_seconds"] + margin
    checker_recipe = json.loads(json.dumps(recipe))
    if recipe_edit:
        recipe_edit(checker_recipe)
        if (checker_recipe["create"]["ttl_seconds"] == recipe["create"]["ttl_seconds"]
                and checker_recipe["request"].get("timeout_seconds") != recipe["request"]["timeout_seconds"]
                and _plain_int(checker_recipe["request"].get("timeout_seconds"))):
            checker_recipe["create"]["ttl_seconds"] = checker_recipe["request"]["timeout_seconds"] + margin
    req, cr, modes = recipe["request"], recipe["create"], recipe["file_modes"]
    ctx = CONTEXT if truth_context is None else truth_context
    outputs_bytes = {o["path"]: (None if o["path"] in absent else fb.get(o["path"], b"output\n"))
                     for o in req["outputs"]}
    labels = {"cathedral_sandbox_id": RUN_ID, "cathedral_serial": "1",
              "broker_guest": cr.get("broker_guest", "guest-2"), "broker_batch": BATCH_ID}
    network_body, policy = broker_form(req.get("network"))
    body = {"image": req["image"], "resources": SIZES.get(req["size"], SIZES["sealed-1x2"]), "network": network_body,
            "ttl_seconds": cr["ttl_seconds"], "labels": labels}
    if create_body:
        body = create_body(body)
    create_bytes = body if isinstance(body, bytes) else canonical(body)
    ebody = {"cmd": req["command"], "timeout_seconds": req["timeout_seconds"], "env": req["env"]}
    for key in ("cwd", "user"):
        if key in req:
            ebody[key] = req[key]
    if exec_body:
        ebody = exec_body(ebody)
    exec_bytes = ebody if isinstance(ebody, bytes) else canonical(ebody)
    exec_resp = exec_answer if exec_answer is not None else canonical({"exit_code": 0, "stdout": "", "stderr": ""})
    steps = [step("create", "create", "POST /v1/sandboxes", 202, image=req["image"], image_digest=IMAGE_ID,
                  network_policy=policy, network_policy_sha256=sha(canonical(policy)),
                  cathedral_sandbox_id=RUN_ID, serial=True, customer_request_sha256=sha(create_bytes)),
             step("context", "file_put", put_target(room, modes.get("context", "644"), CONTEXT_PATH), 200,
                  customer_request_sha256=sha(canonical(ctx)))]
    for i, inp in enumerate(req["inputs"]):
        steps.append(step(f"in{i}", "file_put", put_target(room, inp.get("mode", "644"), inp["path"]), 200,
                          customer_request_sha256=sha(fb.get(inp["path"], b"input\n"))))
    steps.append(step("exec", "exec", f"POST /v1/sandboxes/{room}/exec", 200, customer_request_sha256=sha(exec_bytes),
                      result_sha256=sha(exec_resp if exec_response != "mismatch" else b"other answer")))
    for j, out in enumerate(req["outputs"]):
        data = outputs_bytes[out["path"]]
        steps.append(step(f"get{j}", "file_get", get_target(room, out["max_bytes"], out["path"]),
                          404 if data is None else 200,
                          result_sha256=sha(b'{"error":"not found"}' if data is None else data)))
    steps.append(step("end", "file_put", put_target(room, modes.get("end_marker", "644"), END_PATH), 200,
                      customer_request_sha256=sha(b"")))
    for role, over in (overrides or {}).items():
        target = next(s for s in steps if s["role"] == role)
        for key, value in over.items():
            if key in ("action", "target", "status"):
                target[key] = value
            elif value is DEL:
                target["fields"][key] = DEL
            else:
                target["fields"][key] = value
    if steps_edit:
        steps_edit(steps)
    hotel = pack.new_hotel()
    receipts = {}
    for s in steps:
        receipts[s["role"]] = hotel.sign(s["action"], room, s["status"], numbered=numbered, target=s["target"],
                                         **s["fields"])
    chain = [r for role, r in receipts.items() if role not in drop]

    in_hash = {i["path"]: sha(fb.get(i["path"], b"input\n")) for i in req["inputs"]}
    request = {k: v for k, v in req.items() if k not in ("inputs", "outputs")}
    request.update(outputs=req["outputs"], context=ctx,
                   inputs=[{"path": i["path"], "mode": i.get("mode", "644"), "sha256": in_hash[i["path"]]}
                           for i in req["inputs"]])
    bundle = {"schema": "cathedral_oneshot_bundle_v1", "oneshot_id": RUN_ID, "request": request,
              "attestation": json.loads(json.dumps(pack.attestation)), "amd_certs": dict(pack.certs),
              "receipts": chain, "not_proven": [],
              "create_request_b64": b64(create_bytes), "exec_request_b64": b64(exec_bytes),
              "inline_outputs": {p: b64(outputs_bytes[p]) for p in inline if outputs_bytes.get(p) is not None}}
    if exec_response != "unconfirmed":
        bundle["exec_response_b64"] = b64(exec_resp)
    if bundle_edit:
        bundle_edit(bundle)

    files = {"bundle.json": pretty(bundle), "recipe.json": pretty(checker_recipe)}
    args = ["--oneshot", "{dir}/bundle.json", "--recipe", "{dir}/recipe.json"]
    if no_context_arg:
        args.append("--no-context")
    else:
        files["context.json"] = pretty(context if context is not None else ctx)
        args += ["--context", "{dir}/context.json"]
    args += ["--ark-sha256", pack.ark, "--expected-measurement", MEASUREMENT]
    hashes = {}
    for path, digest in in_hash.items():
        if path in input_files:
            files[f"inputs/{len(hashes)}.bin"] = fb.get(path, b"input\n")
            args += ["--input-file", f"{path}={{dir}}/inputs/{len(hashes)}.bin"]
            hashes[path] = digest
            continue
        given = (caller_hashes or {}).get(path, digest)
        if given is not None:
            args += ["--input-sha256", f"{path}={given}"]
            hashes[path] = given
    files["inputs.json"] = pretty(hashes)
    files.update(extra_files or {})
    for name, edit in (("bundle.json", bundle_raw), ("recipe.json", recipe_raw), ("context.json", context_raw)):
        if edit and name in files:
            files[name] = edit(files[name])
    for path in held:
        name = path.rsplit("/", 1)[-1]
        data = (held_bytes or {}).get(path, outputs_bytes.get(path) if path in outputs_bytes else b"held\n")
        files[f"outputs/{name}"] = data if data is not None else b"held for an absent output\n"
        args += ["--output-file", f"{path}={{dir}}/outputs/{name}"]
    if args_edit:
        args_edit(args)
    return files, args


def run_case(pack: Pack, kind: str, name: str, description: str, expect: dict, **kw) -> None:
    files, args = make_run(pack, **kw)
    exp = {"exit_code": 0, "verdict": "PASS"} if kind == "good" else {"exit_code": 1, "verdict": "FAIL"}
    exp.update(expect)
    pack.add(kind, name, files, {"description": description, "args": args, "expect": exp})


def fail(n: int, text: str) -> dict:
    return {"reason": f"check {n}: {text}"}


def run_good_cases(pack: Pack) -> None:
    run = "/run"
    stub = pack_snapshot_stub(pack)
    run_case(pack, "good", "run_fork_create_reports_its_fork_and_the_missing_source",
             "The held-output run whose create is a fork of a snapshot: chain.forks names it and says its snapshot "
             "receipt is not in the file.", {"pointers": {
                 "/chain/forks/0/room": RUN_ROOM, "/chain/forks/0/snapshot_id": SNAP_ID,
                 "/chain/forks/0/source_room": "room-a", "/chain/forks/0/in_list": False,
                 "/chain/forks/0/fork_source": "not_in_list"}},
             overrides={"create": fork_fields(stub)})
    run_case(pack, "good", "run_held_output_confirmed_exit_code",
             "A run whose result file is held by the checker, whose log is in the file, and whose exec answer confirms "
             "the exit code.", {"pointers": {
                 f"{run}/oneshot_id": RUN_ID, f"{run}/room": RUN_ROOM, f"{run}/outputs/0/state": "present",
                 f"{run}/outputs/0/sha256": sha(FILE_BYTES[RESULT_PATH]), f"{run}/outputs/0/bytes": "held",
                 f"{run}/outputs/1/bytes": "held", f"{run}/exit_code/status": "confirmed", f"{run}/exit_code/value": 0,
                 f"{run}/image/compared_with_recipe": True, "/room_links/run-room-1": RUN_ID,
                 f"{run}/does_not_show/6": "That the machine's disk was left unaltered by its host: the receipts do "
                                            "not show it either way.",
                 f"{run}/does_not_show/7": "That the approved build is the same as the published source: the "
                                            "allowed measurements are your own list.",
                 "/chain/room_numbering/rooms/run-room-1/serial": True,
                 "/chain/room_numbering/rooms/run-room-1/receipts": 8}})
    run_case(pack, "good", "run_output_receipt_only",
             "No output bytes are held: each output line says receipt only.",
             {"pointers": {f"{run}/outputs/0/bytes": "receipt_only", f"{run}/outputs/1/bytes": "receipt_only"}},
             held=(), inline=())
    run_case(pack, "good", "run_optional_output_absent", "An optional output the run did not write: reported absent.",
             {"pointers": {f"{run}/outputs/1/state": "absent", f"{run}/outputs/0/state": "present"}},
             absent=(LOG_PATH,), inline=())
    run_case(pack, "good", "run_exit_code_not_confirmed",
             "The file holds no exec answer: the exit code is not confirmed and the verdict is still PASS.",
             {"pointers": {f"{run}/exit_code/status": "not confirmed"}}, exec_response="unconfirmed")
    run_case(pack, "good", "run_exit_code_answer_not_the_signed_one",
             "An exec answer that does not hash to the receipt's result: not confirmed, still PASS.",
             {"pointers": {f"{run}/exit_code/status": "not confirmed"}}, exec_response="mismatch")

    def nested_input(r):
        r["request"]["inputs"].append({"path": NESTED_PATH, "mode": "600"})
    run_case(pack, "good", "run_path_with_a_folder_dots_dashes_and_underscores",
             "An input in a folder, with dots, dashes and underscores in its path: the signed target is the "
             "sorted, escaped form.", {}, truth_edit=nested_input)
    run_case(pack, "good", "run_input_given_as_file", "The caller gives an input as a file, not a hash.", {},
             input_files=(RUN_PATH,))
    run_case(pack, "good", "run_no_context", "A run with no context: the checker is told --no-context.", {},
             truth_context={}, no_context_arg=True)

    def no_network_no_guest(r):
        r["create"].pop("broker_guest")
        r["request"].pop("image_id")
    run_case(pack, "good", "run_no_broker_guest_no_image_id",
             "A recipe with no broker_guest and no image_id: any id-safe guest label is accepted, the signed "
             "image_digest is reported and not compared.",
             {"pointers": {f"{run}/image/compared_with_recipe": False}}, truth_edit=no_network_no_guest)
    def net(value):
        return lambda r: r["request"].update(network=value)
    run_case(pack, "good", "run_network_internet_by_name",
             "The recipe names the network by its mode name: the create carries the name, the signed policy is internet.",
             {}, truth_edit=net("internet"))
    run_case(pack, "good", "run_network_allowlist_with_names",
             "An allowlist with names: the create carries the object as written, the policy lists the names.",
             {}, truth_edit=net({"mode": "allowlist", "allow": ["example.org", "example.net"]}))
    run_case(pack, "good", "run_network_empty_object_is_deny_all",
             "An empty network object is the broker's deny_all.", {}, truth_edit=net({}))
    run_case(pack, "good", "run_run_id_flag_agrees", "The caller's run id, the file's and the create's agree.", {},
             args_edit=lambda a: a.extend(["--run-id", RUN_ID]))

    def two_measurements(a):
        a[a.index("--expected-measurement") + 1] = OTHER_MEASUREMENT
        a.append("--expected-measurement")
        a.append(MEASUREMENT)
    run_case(pack, "good", "run_two_allowed_measurements", "Two measurements are allowed; the machine has the second.",
             {}, args_edit=two_measurements)

    def measurements_file(a):
        i = a.index("--expected-measurement")
        del a[i:i + 2]
        a.extend(["--allowed-measurements", "{dir}/allowed.json"])
    run_case(pack, "good", "run_allowed_measurements_file", "The allowed measurements come as a file holding a list.",
             {}, args_edit=measurements_file, extra_files={"allowed.json": pretty([OTHER_MEASUREMENT, MEASUREMENT])})


def edit_report(pack: Pack, flip: int):
    def edit(bundle):
        raw = bytearray(base64.b64decode(bundle["attestation"]["report_b64"]))
        raw[flip] ^= 0x01
        bundle["attestation"] = {**bundle["attestation"], "report_b64": b64(bytes(raw))}
    return edit


def run_bad_cases(pack: Pack) -> None:
    def bad(name, description, expect, **kw):
        run_case(pack, "bad", name, description, expect, **kw)

    def drop_arg(flag, count=2):
        def edit(args):
            i = args.index(flag)
            del args[i:i + count]
        return edit

    # ---- inputs the checker is given
    bad("run_input_no_pin", "No --ark-sha256: run mode has no AMD root to trust.",
        {"reason": "inputs: run mode needs --ark-sha256"}, args_edit=drop_arg("--ark-sha256"))
    bad("run_input_no_recipe", "No recipe.", {"reason": "inputs: run mode needs --recipe"},
        args_edit=drop_arg("--recipe"))
    bad("run_input_no_context_choice", "Neither --context nor --no-context.",
        {"reason": "inputs: run mode needs --context FILE or --no-context"}, args_edit=drop_arg("--context"))
    bad("run_input_no_measurement", "No allowed measurement.",
        {"reason": "inputs: run mode needs --expected-measurement or --allowed-measurements"},
        args_edit=drop_arg("--expected-measurement"))
    bad("run_input_for_a_path_the_recipe_lacks", "An input hash for a path that is not an input of the recipe.",
        {"reason": "inputs: --input-sha256 names /work/in/other.bin, which is not an input of the recipe"},
        args_edit=lambda a: a.extend(["--input-sha256", "/work/in/other.bin=" + "ab" * 32]))
    bad("run_output_file_for_a_path_the_recipe_lacks", "An output file for a path that is not an output of the recipe.",
        {"reason": "inputs: --output-file names /work/out/other.bin, which is not an output of the recipe"},
        args_edit=lambda a: a.extend(["--output-file", "/work/out/other.bin={dir}/outputs/result.json"]))

    # ---- check 1: attestation, AMD chain, measurement, receipt signatures
    bad("run_c1_measurement_not_allowed", "The machine's measurement is not the one allowed.",
        fail(1, "measurement differs from the expected build"),
        args_edit=lambda a: a.__setitem__(a.index("--expected-measurement") + 1, OTHER_MEASUREMENT))

    def two_other(a):
        i = a.index("--expected-measurement")
        a[i + 1] = OTHER_MEASUREMENT
        a.extend(["--expected-measurement", hashlib.sha384(b"a third measurement").hexdigest()])
    bad("run_c1_measurement_not_in_allowed_list", "The machine's measurement is in neither of two allowed ones.",
        fail(1, "measurement is not one of the allowed measurements"), args_edit=two_other)
    bad("run_c1_pin_differs", "The ARK is not the pinned one.",
        fail(1, f"ARK sha256 {pack.ark} differs from the pinned value"),
        args_edit=lambda a: a.__setitem__(a.index("--ark-sha256") + 1, "00" * 32))
    bad("run_c1_report_signature", "One byte of the chip signature is changed.",
        fail(1, "report signature does not verify with the VCEK"), bundle_edit=edit_report(pack, 0x2A0 + 10))
    bad("run_c1_report_does_not_commit_to_binding", "One byte of the report data is changed.",
        fail(1, "REPORT_DATA does not commit to the binding"), bundle_edit=edit_report(pack, 0x50 + 3))

    def other_binding(steps):
        next(s for s in steps if s["role"] == "in0")["fields"]["binding_sha256"] = "11" * 32
    bad("run_c1_receipt_names_another_binding", "A receipt names another binding than the attestation's.",
        fail(1, "receipt 3 names another binding"), steps_edit=other_binding)
    bad("run_c1_no_certificates", "The file holds no AMD certificates.",
        fail(1, "the file holds no AMD certificates (amd_certs)"), bundle_edit=lambda b: b.pop("amd_certs"))
    bad("run_c1_certificate_not_signed_by_issuer", "The VCEK slot holds the ASK: the chain does not verify.",
        fail(1, "an AMD certificate is not signed by the one above it in the chain"),
        bundle_edit=lambda b: b["amd_certs"].update(vcek=b["amd_certs"]["ask"]))
    bad("run_c1_certificates_not_der", "The certificates are not base64 DER.",
        fail(1, "the AMD certificates are not base64 DER certificates (vcek, ask, ark)"),
        bundle_edit=lambda b: b["amd_certs"].update(vcek="not base64!"))
    bad("run_c1_hotel_level_attestation", "A level 1 (unsealed) binding in a one-shot's file.",
        fail(1, "an SEV-SNP attestation is required"),
        bundle_edit=lambda b: b["attestation"].update(binding={**b["attestation"]["binding"], "level": "hotel"}))
    bad("run_c1_skip_amd_refused", "--skip-amd is refused in run mode.",
        fail(1, "--skip-amd is not allowed in run mode"), args_edit=lambda a: a.append("--skip-amd"))

    def changed(bundle):
        bundle["receipts"][1]["statement"]["status"] = 201
    bad("run_c1_receipt_changed_after_signing", "A receipt's statement is changed after it was signed.",
        fail(1, "receipt 2: receipt_sha256 mismatch"), bundle_edit=changed)

    # ---- check 2: the room's numbers, the create, no lost answer
    gap = {"drop": ("in0",)}
    bad("run_c2_gap", "A receipt is missing from the middle of the list.",
        fail(2, f"room {RUN_ROOM}: room_sequence jumps from 2 to 4: a receipt is missing"), **gap)
    bad("run_c2_duplicate", "Two receipts carry room_sequence 2.",
        fail(2, f"room {RUN_ROOM}: room_sequence 2 appears more than once"),
        overrides={"in0": {"room_sequence": 2}})
    bad("run_c2_bad_link", "A room receipt links to the wrong receipt.",
        fail(2, f"room {RUN_ROOM}: room receipt 3 does not link to room receipt 2"),
        overrides={"in0": {"room_previous_receipt_sha256": "00" * 32}})
    bad("run_c2_no_numbering", "The receipts carry no room numbering.",
        fail(2, f"room {RUN_ROOM}: the receipts are not numbered (room_sequence)"), numbered=False)
    bad("run_c2_receipt_one_is_not_a_create", "Receipt 1 is not a create.", fail(2, "receipt 1 is not a create"),
        overrides={"create": {"action": "exec"}})
    bad("run_c2_no_serial_flag", "The create does not say serial: true.", fail(2, "receipt 1 does not say serial: true"),
        overrides={"create": {"serial": DEL}})
    bad("run_c2_serial_flag_false", "The create says serial: false.", fail(2, "receipt 1 does not say serial: true"),
        overrides={"create": {"serial": False}})
    bad("run_c2_lost_answer", "A receipt records a lost answer (status 502).",
        fail(2, "receipt 6 is a lost answer (status 502)"), overrides={"get0": {"status": 502}})
    bad("run_c2_other_room", "A receipt names another room.", fail(2, f"receipt 4 names room other-room, not {RUN_ROOM}"),
        overrides={"in1": {"sandbox_id": "other-room"}})
    bad("run_c2_room_id_not_safe", "The room id has a space and a bang.", fail(2, "the room id is not a safe id"),
        room="bad room!")

    # ---- check 3: the exact list of actions
    bad("run_c3_extra_receipt", "A request after the end marker.", fail(3, "the list has 9 receipts, the recipe needs 8"),
        steps_edit=lambda s: s.append(step("extra", "exec", f"POST /v1/sandboxes/{RUN_ROOM}/exec", 200)))
    bad("run_c3_missing_receipt", "The end marker is missing.", fail(3, "the list has 7 receipts, the recipe needs 8"),
        drop=("end",))
    in0 = put_target(RUN_ROOM, "755", RUN_PATH)
    bad("run_c3_wrong_action", "An input put is an exec.",
        fail(3, f"receipt 3 is exec {in0}, the recipe needs file_put {in0}"), overrides={"in0": {"action": "exec"}})
    bad("run_c3_wrong_mode", "An input is put with mode 600, the recipe says 755.",
        fail(3, f"receipt 3 is file_put {put_target(RUN_ROOM, '600', RUN_PATH)}, the recipe needs file_put {in0}"),
        overrides={"in0": {"target": put_target(RUN_ROOM, "600", RUN_PATH)}})
    extra = in0 + "&x=1"
    bad("run_c3_extra_query_key", "A put target with one more query key.",
        fail(3, f"receipt 3 is file_put {extra}, the recipe needs file_put {in0}"), overrides={"in0": {"target": extra}})
    other_path = put_target(RUN_ROOM, "755", "/work/in/other.py")
    bad("run_c3_wrong_path", "An input put to another path.",
        fail(3, f"receipt 3 is file_put {other_path}, the recipe needs file_put {in0}"),
        overrides={"in0": {"target": other_path}})
    get0 = get_target(RUN_ROOM, 65536, RESULT_PATH)
    big = get_target(RUN_ROOM, 131072, RESULT_PATH)
    bad("run_c3_wrong_max_bytes", "A get with a larger max_bytes than the recipe's.",
        fail(3, f"receipt 6 is file_get {big}, the recipe needs file_get {get0}"), overrides={"get0": {"target": big}})
    other_exec = "POST /v1/sandboxes/other-room/exec"
    bad("run_c3_other_room_in_target", "The exec's target names another room.",
        fail(3, f"receipt 5 is exec {other_exec}, the recipe needs exec POST /v1/sandboxes/{RUN_ROOM}/exec"),
        overrides={"exec": {"target": other_exec}})

    def delete_before_end(steps):
        steps.insert(len(steps) - 1, step("del", "delete", f"DELETE /v1/sandboxes/{RUN_ROOM}", 200))
    end_t = put_target(RUN_ROOM, "644", END_PATH)
    bad("run_c3_delete_before_the_end", "A delete before the end marker.",
        fail(3, f"receipt 8 is delete DELETE /v1/sandboxes/{RUN_ROOM}, the recipe needs file_put {end_t}"),
        steps_edit=delete_before_end)

    # ---- check 4: the create
    bad("run_c4_status", "The create did not succeed.", fail(4, "the create did not succeed (status 500)"),
        overrides={"create": {"status": 500}})
    bad("run_c4_no_image_digest", "The create has no image_digest.", fail(4, "the create receipt has no image_digest"),
        overrides={"create": {"image_digest": None}})
    bad("run_c4_image_digest_malformed", "The image_digest is not sha256: and 64 hex.",
        fail(4, "image_digest is not sha256: and 64 lower-case hex"), overrides={"create": {"image_digest": "sha256:abc"}})
    bad("run_c4_image_id_differs", "The recipe's image_id is not the signed image_digest.",
        fail(4, "the create's image_digest is not the recipe's image_id"),
        recipe_edit=lambda r: r["request"].update(image_id="sha256:" + "22" * 32))
    bad("run_c4_pool_create", "The create is a pool create.", fail(4, "the create is a pool create"),
        overrides={"create": {"pool": True}})
    off = {"mode": "internet", "allow": []}
    bad("run_c4_network", "The signed network rule is not the recipe's.",
        fail(4, "the signed network rule is not the recipe's"),
        overrides={"create": {"network_policy": off, "network_policy_sha256": sha(canonical(off))}})
    bad("run_c4_run_id", "The file's oneshot_id is not the id the create names.",
        fail(4, f"the create names sandbox {RUN_ID}, not the file's oneshot_id {RUN_ID[:-1]}0"),
        bundle_edit=lambda b: b.update(oneshot_id=RUN_ID[:-1] + "0"))
    bad("run_c4_run_id_flag_differs", "The run id the caller was sent is not the file's.",
        fail(4, "the run id you gave is not the file's oneshot_id"),
        args_edit=lambda a: a.extend(["--run-id", RUN_ID[:-1] + "0"]))
    bad("run_c4_no_create_bytes", "The file holds no create bytes.",
        fail(4, "the file holds no create bytes (create_request_b64): the broker that made this run does not hand "
                "them back"), bundle_edit=lambda b: b.pop("create_request_b64"))
    bad("run_c4_create_bytes_hash", "The create bytes are not the bytes the receipt hashed.",
        fail(4, "the create bytes do not hash to the receipt's customer_request_sha256"),
        bundle_edit=lambda b: b.update(create_request_b64=b64(b'{"image":"x"}')))
    bad("run_c4_unknown_key", "The create holds a key that is not a create key.",
        fail(4, "the create has a key it should not have: env"), create_body=lambda body: {**body, "env": {}})
    bad("run_c4_key_missing", "The create lacks a key.", fail(4, "the create lacks the key ttl_seconds"),
        create_body=lambda body: {k: v for k, v in body.items() if k != "ttl_seconds"})
    bad("run_c4_image", "The create's image is not the recipe's.", fail(4, "the create's image is not the recipe's"),
        create_body=lambda body: {**body, "image": "images.example.test/other@sha256:" + "33" * 32})
    bad("run_c4_size", "The create's resources are not those of the recipe's size.",
        fail(4, "the create's resources are not those of the recipe's size"),
        create_body=lambda body: {**body, "resources": SIZES["sealed-4x8"]})
    bad("run_c4_ttl", "The create's ttl_seconds is not the recipe's.", fail(4, "the create's ttl_seconds is not the recipe's"),
        create_body=lambda body: {**body, "ttl_seconds": 600})
    bad("run_c4_network_in_bytes", "The create's network is not the broker's form of the recipe's.",
        fail(4, "the create's network is not the broker's form of the recipe's"),
        create_body=lambda body: {**body, "network": {"mode": "internet", "allow": []}})

    def labels(**over):
        return lambda body: {**body, "labels": {**body["labels"], **over}}
    bad("run_c4_label_serial", "The serial label is not 1.", fail(4, "the label cathedral_serial is not 1"),
        create_body=labels(cathedral_serial="2"))
    bad("run_c4_label_broker_guest_not_the_recipes", "The broker_guest label is not the recipe's.",
        fail(4, "the label broker_guest is not the recipe's"), create_body=labels(broker_guest="guest-9"))
    bad("run_c4_label_broker_guest_not_id_safe", "With no broker_guest in the recipe, the label is not an id-safe string.",
        fail(4, "the label broker_guest is not an id-safe string"),
        truth_edit=lambda r: r["create"].pop("broker_guest"), create_body=labels(broker_guest="has space"))
    bad("run_c4_label_broker_batch", "The broker_batch label is not a lower-case UUID.",
        fail(4, "the label broker_batch is not a lower-case UUID"), create_body=labels(broker_batch="BATCH"))
    bad("run_c4_label_extra", "The create carries a fifth label.",
        fail(4, "the labels are not exactly the four expected (extra: customer)"), create_body=labels(customer="x"))
    bad("run_c4_label_missing", "The create lacks the broker_batch label.",
        fail(4, "the labels are not exactly the four expected (missing: broker_batch)"),
        create_body=lambda body: {**body, "labels": {k: v for k, v in body["labels"].items() if k != "broker_batch"}})
    bad("run_c4_label_run_id", "The sandbox id label is not the run id.", fail(4, "the label cathedral_sandbox_id is not the run id"),
        create_body=labels(cathedral_sandbox_id="11111111-2222-4333-8444-555555555555"))
    dup = (b'{"image":"' + IMAGE_REF.encode() + b'","image":"' + IMAGE_REF.encode() + b'"}')
    bad("run_c4_duplicate_key", "The create bytes repeat a key.", fail(4, "the create bytes repeat the key 'image'"),
        create_body=lambda body: dup)
    bad("run_c4_float", "The create bytes hold a number with a decimal point.",
        fail(4, "the create bytes hold the number 660.0, which is not an integer"),
        create_body=lambda body: canonical(body).replace(b'"ttl_seconds":660', b'"ttl_seconds":660.0'))

    # ---- check 5: the context and the inputs
    bad("run_c5_context_put_status", "The put of the context failed.",
        fail(5, "the put of the context did not succeed (status 500)"), overrides={"context": {"status": 500}})
    bad("run_c5_context_hash", "The context the caller expects is not the one written.",
        fail(5, "the context put does not carry the expected context (its hash differs)"),
        context={"submission": "another"})
    bad("run_c5_input_put_status", "The put of an input failed.",
        fail(5, f"the put of input {RUN_PATH} did not succeed (status 500)"), overrides={"in0": {"status": 500}})
    bad("run_c5_input_hash", "The caller's hash for an input is not what was written.",
        fail(5, f"the put of input {RUN_PATH} does not carry the bytes whose hash you gave"),
        caller_hashes={RUN_PATH: "44" * 32})
    bad("run_c5_input_not_given", "The caller gives no hash and no file for an input.",
        fail(5, f"no hash or file was given for input {DATA_PATH}"), caller_hashes={DATA_PATH: None})

    # ---- check 6: the exec
    bad("run_c6_status", "The exec did not answer 200.", fail(6, "the exec did not return 200 (status 500)"),
        overrides={"exec": {"status": 500}})
    bad("run_c6_no_exec_bytes", "The file holds no exec bytes.", fail(6, "the file holds no exec bytes (exec_request_b64)"),
        bundle_edit=lambda b: b.pop("exec_request_b64"))
    bad("run_c6_bytes_hash", "The exec bytes are not the bytes the receipt hashed.",
        fail(6, "the exec bytes do not hash to the receipt's customer_request_sha256"),
        bundle_edit=lambda b: b.update(exec_request_b64=b64(b'{"cmd":["true"]}')))
    bad("run_c6_extra_key", "The exec holds a key the recipe does not have.",
        fail(6, "the exec has a key it should not have: user"), exec_body=lambda body: {**body, "user": "root"})
    bad("run_c6_key_missing", "The exec lacks the cwd the recipe has.", fail(6, "the exec lacks the key cwd"),
        exec_body=lambda body: {k: v for k, v in body.items() if k != "cwd"})
    bad("run_c6_cmd", "The exec's command is not the recipe's.", fail(6, "the exec's cmd is not the recipe's"),
        recipe_edit=lambda r: r["request"].update(command=["python", "/work/in/other.py"]))
    bad("run_c6_env", "The exec's environment is not the recipe's.", fail(6, "the exec's env is not the recipe's"),
        recipe_edit=lambda r: r["request"].update(env={"MODE": "other"}))
    bad("run_c6_timeout", "The exec's timeout is not the recipe's.", fail(6, "the exec's timeout_seconds is not the recipe's"),
        recipe_edit=lambda r: r["request"].update(timeout_seconds=61),
        create_body=lambda body: {**body, "ttl_seconds": 661})  # the create follows the recipe's lifetime
    bad("run_c6_cwd", "The exec's cwd is not the recipe's.", fail(6, "the exec's cwd is not the recipe's"),
        recipe_edit=lambda r: r["request"].update(cwd="/other"))

    # ---- check 7: the gets and the end marker
    bad("run_c7_partial_answer", "A get answered 206.", fail(7, f"the get of {RESULT_PATH} answered 206, not 200"),
        overrides={"get0": {"status": 206}})
    bad("run_c7_too_large", "A get answered 413.", fail(7, f"the get of {RESULT_PATH} answered 413, not 200"),
        overrides={"get0": {"status": 413}})
    bad("run_c7_server_error", "A get answered 500.", fail(7, f"the get of {RESULT_PATH} answered 500, not 200"),
        overrides={"get0": {"status": 500}})
    bad("run_c7_held_bytes_hash", "The bytes the caller holds are not the bytes the get returned.",
        fail(7, f"the bytes held for {RESULT_PATH} do not hash to the receipt's result_sha256"),
        held_bytes={RESULT_PATH: b"other bytes\n"})
    bad("run_c7_inline_bytes_hash", "The inline bytes in the file are not the bytes the get returned.",
        fail(7, f"the inline bytes of {LOG_PATH} do not hash to the receipt's result_sha256"),
        bundle_edit=lambda b: b["inline_outputs"].update({LOG_PATH: b64(b"other\n")}))

    def small_output(r):
        r["request"]["outputs"][0]["max_bytes"] = 4
    bad("run_c7_length_over_max_bytes", "The held output is longer than its max_bytes.",
        fail(7, f"{RESULT_PATH} is {len(FILE_BYTES[RESULT_PATH])} bytes, over its max_bytes 4"), truth_edit=small_output)
    bad("run_c7_required_output_missing", "A required output answered 404.",
        fail(7, f"the required output {RESULT_PATH} was not found (404)"), absent=(RESULT_PATH,), held=(), inline=())
    bad("run_c7_held_file_for_absent_output", "The caller holds a file for an optional output the receipt says is absent.",
        fail(7, f"bytes are held for {LOG_PATH}, but the receipt says it was absent"), absent=(LOG_PATH,),
        held=(RESULT_PATH, LOG_PATH), inline=())
    bad("run_c7_end_marker_hash", "The end marker put does not carry empty bytes.",
        fail(7, "the end marker put does not carry empty bytes"),
        overrides={"end": {"customer_request_sha256": sha(b"x")}})
    bad("run_c7_end_marker_status", "The end marker put failed.", fail(7, "the end marker put did not succeed (status 500)"),
        overrides={"end": {"status": 500}})

    # ---- check 8: the request in the file equals the recipe
    bad("run_c8_field", "The request in the file has another size than the recipe.",
        fail(8, "the request in the file differs from the recipe in size"),
        bundle_edit=lambda b: b["request"].update(size="large"))
    bad("run_c8_input_hash", "The request in the file names another hash for an input.",
        fail(8, "the request in the file differs from the recipe in inputs"),
        bundle_edit=lambda b: b["request"]["inputs"][0].update(sha256="55" * 32))
    bad("run_c8_unknown_key", "The request holds a key that is not a request field.",
        fail(8, "the request holds a key that is not a request field: extra"),
        bundle_edit=lambda b: b["request"].update(extra=1))
    bad("run_c8_no_request", "The file holds no request.", fail(8, "the file holds no request"),
        bundle_edit=lambda b: b.pop("request"))


def run_hardening_cases(pack: Pack) -> None:
    """Lists a caller's pin, the inline copies, the network form, the exact request and the file's shape."""
    def bad(name, description, expect, **kw):
        run_case(pack, "bad", name, description, expect, **kw)

    def pin_in_request(r, digest=IMAGE_ID):
        r["create"].pop("image_id", None)
        r["request"]["image_id"] = digest

    def drop_file_image_id(b):
        b["request"].pop("image_id", None)

    # ---- the image pin lives in the recipe's request, once
    bad("run_c4_image_id_in_request_differs", "The image_id in the recipe's request is not the signed image_digest.",
        fail(4, "the create's image_digest is not the recipe's image_id"),
        recipe_edit=lambda r: pin_in_request(r, "sha256:" + "22" * 32), bundle_edit=drop_file_image_id)
    bad("run_c8_image_id_missing_from_file", "The recipe pins the image, the file's request omits the pin.",
        fail(8, "the request in the file differs from the recipe in image_id"),
        recipe_edit=pin_in_request, bundle_edit=drop_file_image_id)
    bad("run_recipe_image_id_in_create", "image_id is in the recipe's create, where it is not a member.",
        {"reason": "recipe: unknown member image_id"},
        recipe_edit=lambda r: r["create"].update(image_id=IMAGE_ID))
    bad("run_recipe_unknown_member_top", "The recipe has a member at its top level that the checker does not know.",
        {"reason": "recipe: unknown member extra"}, recipe_edit=lambda r: r.update(extra=1))
    bad("run_recipe_unknown_member_request", "The recipe's request has a member the checker does not know.",
        {"reason": "recipe: unknown member pin"}, recipe_edit=lambda r: r["request"].update(pin=1))
    bad("run_recipe_unknown_member_create", "The recipe's create has a member the checker does not know.",
        {"reason": "recipe: unknown member pool"}, recipe_edit=lambda r: r["create"].update(pool=True))
    bad("run_recipe_unknown_member_file_modes", "The recipe's file_modes has a member the checker does not know.",
        {"reason": "recipe: unknown member mode"}, recipe_edit=lambda r: r["file_modes"].update(mode="644"))
    bad("run_recipe_unknown_member_output", "An output entry in the recipe has a member the checker does not know.",
        {"reason": "recipe: unknown member required"},
        recipe_edit=lambda r: r["request"]["outputs"][0].update(required=True))
    bad("run_recipe_unknown_member_input", "An input entry in the recipe has a member the checker does not know.",
        {"reason": "recipe: unknown member sha256"},
        recipe_edit=lambda r: r["request"]["inputs"][0].update(sha256="x"))

    # ---- every copy of an output in the file is checked
    inline = "/work/out/"
    bad("run_c7_inline_disagrees_with_held_file", "The caller holds the right file; the file's inline copy is other bytes.",
        fail(7, f"the inline bytes of {RESULT_PATH} do not hash to the receipt's result_sha256"),
        bundle_edit=lambda b: b["inline_outputs"].update({RESULT_PATH: b64(b"other\n")}))
    bad("run_c7_inline_for_absent_output", "An inline copy for an optional output whose get answered 404.",
        fail(7, f"the inline bytes of {LOG_PATH} are given, but the receipt says it was absent"), absent=(LOG_PATH,),
        held=(RESULT_PATH,), inline=(), bundle_edit=lambda b: b["inline_outputs"].update({LOG_PATH: b64(b"done\n")}))
    bad("run_c7_inline_for_undeclared_path", "An inline copy for a path the recipe does not declare.",
        fail(7, f"inline_outputs names {inline}other.txt, which is not an output of the recipe"),
        bundle_edit=lambda b: b["inline_outputs"].update({f"{inline}other.txt": b64(b"x")}))
    bad("run_c7_inline_not_a_string", "An inline value that is a number.",
        fail(7, f"the inline bytes of {LOG_PATH} are not a base64 string"),
        bundle_edit=lambda b: b["inline_outputs"].update({LOG_PATH: 123}))
    bad("run_c7_inline_not_an_object", "inline_outputs is a list.", fail(7, "inline_outputs is not an object"),
        bundle_edit=lambda b: b.update(inline_outputs=[]))

    # ---- the network: each form the request allows has one policy
    def network_both(value):
        def recipe(r):
            r["request"]["network"] = value
        return recipe, (lambda b: b["request"].update(network=value))
    r_edit, b_edit = network_both("internet")
    bad("run_c4_network_internet_in_recipe", "The recipe and the file say internet; the signed create is deny_all.",
        fail(4, "the signed network rule is not the recipe's"), recipe_edit=r_edit, bundle_edit=b_edit)
    r_edit, b_edit = network_both({"mode": "allowlist", "allow": ["example.org"]})
    bad("run_c4_network_allowlist_in_recipe", "The recipe and the file name an allowlist; the signed create is deny_all.",
        fail(4, "the signed network rule is not the recipe's"), recipe_edit=r_edit, bundle_edit=b_edit)
    r_edit, b_edit = network_both(5)
    bad("run_recipe_network_not_a_mode", "The recipe's network is a number.",
        {"reason": "recipe: network is not an object or a mode name"}, recipe_edit=r_edit, bundle_edit=b_edit)
    r_edit, b_edit = network_both("bogus")
    bad("run_recipe_network_unknown_mode", "The recipe's network names a mode that is not deny_all, internet or allowlist.",
        {"reason": "recipe: network mode bogus is not deny_all, internet or allowlist"}, recipe_edit=r_edit,
        bundle_edit=b_edit)

    # ---- check 8 compares the request as it is
    bad("run_c8_input_list_holds_a_number", "The file's input list holds a number besides the inputs.",
        fail(8, "the file's request: an input must hold exactly path, sha256 and mode"),
        bundle_edit=lambda b: b["request"]["inputs"].append(7))
    bad("run_c8_input_has_unknown_member", "An input entry in the file has a member besides path, mode and sha256.",
        fail(8, "the file's request: an input must hold exactly path, sha256 and mode"),
        bundle_edit=lambda b: b["request"]["inputs"][0].update(note="x"))
    bad("run_c8_input_carries_content", "An input entry in the file carries content_b64.",
        fail(8, "the request holds content_b64, which a file must not carry"),
        bundle_edit=lambda b: b["request"]["inputs"][0].update(content_b64="eA=="))
    bad("run_c8_output_list_holds_a_string", "The file's output list holds a string besides the outputs.",
        fail(8, "the request in the file differs from the recipe in outputs"),
        bundle_edit=lambda b: b["request"]["outputs"].append("x"))
    bad("run_c8_optional_is_a_string", "An output's optional is the text false.",
        fail(8, "the request in the file differs from the recipe in outputs"),
        bundle_edit=lambda b: b["request"]["outputs"][1].update(optional="false"))
    bad("run_c8_outputs_not_a_list", "The file's outputs is a number.",
        fail(8, "the request in the file differs from the recipe in outputs"),
        bundle_edit=lambda b: b["request"].update(outputs=123))
    bad("run_c8_max_spend_differs", "The recipe's max_spend_usd is 1; the file says the string 0.50.",
        fail(8, "the request in the file differs from the recipe in max_spend_usd"),
        recipe_edit=lambda r: r["request"].update(max_spend_usd=1))

    # ---- shape: repeated keys at any level, wrong types
    def twice(key, value):
        old = f' "{key}": "{value}",\n'.encode()
        return lambda raw: raw.replace(old, old + old, 1)
    bad("run_shape_file_repeats_a_key", "The one-shot file repeats a key at its top level.",
        {"reason": "inputs: the one-shot file repeats the key 'oneshot_id'"}, bundle_raw=twice("oneshot_id", RUN_ID))
    bad("run_shape_file_repeats_a_nested_key", "The one-shot file repeats a key inside its request.",
        {"reason": "inputs: the one-shot file repeats the key 'size'"},
        bundle_raw=lambda raw: raw.replace(b'  "size": "sealed-1x2",\n', b'  "size": "sealed-1x2",\n  "size": "sealed-1x2",\n', 1))
    bad("run_shape_recipe_repeats_a_key", "The recipe repeats a key.", {"reason": "inputs: the recipe repeats the key 'schema'"},
        recipe_raw=lambda raw: raw.replace(b' "schema": "cathedral_oneshot_recipe_v1"',
                                           b' "schema": "cathedral_oneshot_recipe_v1",\n "schema": '
                                           b'"cathedral_oneshot_recipe_v1"', 1))
    bad("run_shape_context_repeats_a_key", "The context file repeats a key.",
        {"reason": "inputs: the context file repeats the key 'a'"}, context_raw=lambda raw: b'{"a":1,"a":2}\n')
    bad("run_shape_recipe_outputs_not_a_list", "The recipe's outputs is a number.",
        {"reason": "recipe: outputs is not a list"}, recipe_edit=lambda r: r["request"].update(outputs=123))
    bad("run_shape_file_receipts_not_a_list", "The file's receipts is a text.", fail(1, "the file holds no receipts"),
        bundle_edit=lambda b: b.update(receipts="none"))
    bad("run_shape_file_not_an_object", "The one-shot file is a JSON list.",
        fail(1, "the file is not a cathedral_oneshot_bundle_v1"), bundle_raw=lambda raw: b"[]\n")


def run_second_review_cases(pack: Pack) -> None:
    """The size fixes the resources, each required request field is required, names are compared canonically."""
    def bad(name, description, expect, **kw):
        run_case(pack, "bad", name, description, expect, **kw)

    def good(name, description, expect, **kw):
        run_case(pack, "good", name, description, expect, **kw)

    # ---- size: the checker owns the table of sealed sizes
    def both_sizes(value):
        return (lambda r: r["request"].update(size=value)), (lambda b: b["request"].update(size=value))
    r_edit, b_edit = both_sizes("this-is-not-a-size")
    bad("run_c4_size_unknown", "A size that is not a sealed size, in the recipe and in the file.",
        fail(4, "the size this-is-not-a-size is not a sealed size"), recipe_edit=r_edit, bundle_edit=b_edit)
    r_edit, b_edit = both_sizes("sealed-2x4")
    bad("run_c4_size_resources_of_another_size", "A known size whose signed resources are another size's.",
        fail(4, "the create's resources are not those of the recipe's size"), recipe_edit=r_edit, bundle_edit=b_edit)
    bad("run_recipe_create_resources_present", "The recipe carries resources: the size fixes them.",
        {"reason": "recipe: unknown member resources"},
        recipe_edit=lambda r: r["create"].update(resources={"vcpu": 1, "memory_gib": 2, "disk_gib": 10}))

    # ---- every required request field is required, in the recipe and in the file
    for field in ("image", "command", "env", "size", "timeout_seconds", "network", "outputs", "inputs",
                  "max_spend_usd"):
        bad(f"run_recipe_missing_{field}", f"The recipe's request and the file's request both lack {field}.",
            {"reason": f"recipe: the request has no {field}"},
            recipe_edit=lambda r, f=field: r["request"].pop(f), bundle_edit=lambda b, f=field: b["request"].pop(f))

    # ---- the shapes of the file are exact (spec G4 5.5)
    def drop(*path):
        def edit(b):
            node = b
            for part in path[:-1]:
                node = node[part]
            del node[path[-1]]
        return edit

    def put(value, *path):
        def edit(b):
            node = b
            for part in path[:-1]:
                node = node[part]
            node[path[-1]] = value
        return edit

    def shape(reason):
        return {"reason": "check 1: " + reason}

    bad("run_shape_unknown_top_member", "The file has a member the shapes do not name.",
        shape("the file has an unknown member extra"), bundle_edit=put(1, "extra"))
    bad("run_shape_no_not_proven", "The file has no not_proven.", shape("the file has no not_proven"),
        bundle_edit=drop("not_proven"))
    for case, value in (("null", None), ("string", "none"), ("list_of_numbers", [1]), ("object", {})):
        bad(f"run_shape_not_proven_{case}", f"not_proven is {case.replace('_', ' ')}.",
            shape("not_proven is not a list of strings"), bundle_edit=put(value, "not_proven"))
    good("run_shape_not_proven_with_reasons", "not_proven holds reasons; every check holds, so the file passes.",
         {}, bundle_edit=put(["the API saw a slow answer"], "not_proven"))
    bad("run_shape_no_inline_outputs", "The file has no inline_outputs.", shape("the file has no inline_outputs"),
        bundle_edit=drop("inline_outputs"))
    bad("run_shape_attestation_extra_member", "The attestation holds a member besides the three.",
        shape("attestation has an unknown member extra"), bundle_edit=put(1, "attestation", "extra"))
    bad("run_shape_attestation_missing_member", "The attestation lacks report_b64.",
        shape("attestation has no report_b64"), bundle_edit=drop("attestation", "report_b64"))
    bad("run_shape_amd_certs_extra_member", "amd_certs holds a fourth member.",
        shape("amd_certs has an unknown member extra"), bundle_edit=put("x", "amd_certs", "extra"))
    bad("run_shape_receipt_extra_member", "A receipt object holds a member besides the three.",
        shape("a receipt has an unknown member extra"), bundle_edit=put(1, "receipts", 0, "extra"))
    bad("run_shape_receipt_missing_member", "A receipt object lacks its signature.",
        shape("a receipt has no signature_b64"), bundle_edit=drop("receipts", 0, "signature_b64"))
    bad("run_shape_input_without_mode", "An input in the file's request has no mode.",
        fail(8, "the file's request: an input must hold exactly path, sha256 and mode"),
        bundle_edit=drop("request", "inputs", 0, "mode"))
    bad("run_shape_receipts_swapped", "Two receipts are swapped in the file; each is signed.",
        fail(2, f"room {RUN_ROOM}: the receipts are not in the order of their room numbers"),
        bundle_edit=lambda b: b["receipts"].insert(1, b["receipts"].pop(2)))
    bad("run_shape_receipts_reversed", "The receipts are in reverse order.",
        fail(2, f"room {RUN_ROOM}: the receipts are not in the order of their room numbers"),
        bundle_edit=lambda b: b["receipts"].reverse())

    # ---- the exec answer is read only when its hash is the signed one
    deep = b"[" * 1100 + b"]" * 1100
    good("run_exec_answer_unmatched_and_deep", "An exec answer that does not hash to the signed result, nested 1,100 "
         "levels: not confirmed, never read, still PASS.", {"pointers": {"/run/exit_code/status": "not confirmed"}},
         bundle_edit=put(b64(deep), "exec_response_b64"))
    bad("run_exec_answer_matched_and_deep", "An exec answer that is the signed one, nested past the limit.",
        fail(6, "the exec answer nests too deeply to read"), exec_answer=b"[" * 100 + b"]" * 100)
    for case, token in (("point", b"9" * 50 + b"." + b"9" * 51), ("exponent", b"1e" + b"0" * 99),
                        ("signed_exponent", b"-" + b"1" * 49 + b"e+" + b"0" * 50)):
        bad(f"run_exec_answer_matched_long_token_{case}", "A signed exec answer holding a number literal of 101 "
            "characters.", fail(6, "the exec answer holds a number literal of more than 100 characters"),
            exec_answer=b'{"exit_code":0,"meta":' + token + b"}")
    good("run_exec_answer_matched_token_100_characters", "A signed exec answer holding a number literal of exactly 100 "
         "characters.", {"pointers": {"/run/exit_code/status": "confirmed", "/run/exit_code/value": 0}},
         exec_answer=b'{"exit_code":0,"meta":' + b"9" * 49 + b"." + b"9" * 50 + b"}")
    for case, value in (("null", None), ("number", 3), ("object", {}), ("list", []), ("boolean", False),
                        ("not_base64", "***"), ("padding_broken", "abc")):
        bad(f"run_shape_exec_response_{case}", f"exec_response_b64 is {case.replace('_', ' ')}.",
            {"reason": "check 1: exec_response_b64 is not a string of valid base64"},
            bundle_edit=put(value, "exec_response_b64"))
    good("run_shape_exec_response_absent", "exec_response_b64 is left out: the exit code is not confirmed.",
         {"pointers": {"/run/exit_code/status": "not confirmed"}}, exec_response="unconfirmed")
    good("run_exec_answer_matched_and_shallow", "An exec answer that is the signed one and is read.",
         {"pointers": {"/run/exit_code/status": "confirmed", "/run/exit_code/value": 3}},
         exec_answer=canonical({"exit_code": 3}))

    # ---- the context in the file's request, when it is there, is the expected one
    bad("run_c8_context_differs", "The file's request.context is not the context the caller expects; the signed "
        "context file is right.", fail(8, "the file's request.context is not the expected context"),
        bundle_edit=lambda b: b["request"].update(context={"submission": "another"}))
    bad("run_c8_context_is_a_number", "The file's request.context is a number.",
        fail(8, "the file's request.context is not the expected context"),
        bundle_edit=lambda b: b["request"].update(context=7))
    bad("run_c8_context_present_when_none_expected", "The caller expects no context; the file's request holds one.",
        fail(8, "the file's request.context is not the expected context"), truth_context={}, no_context_arg=True,
        bundle_edit=lambda b: b["request"].update(context={"submission": "sub-0001"}))
    good("run_c8_context_equal_in_request", "request.context is present and equal to the expected context.",
         {"pointers": {"/run/context_check": "the signed context file and the request in the file"}})
    good("run_c8_context_not_in_request", "The request in the file has no context member: the signed file put binds it.",
         {"pointers": {"/run/context_check": "the signed context file only"}},
         bundle_edit=lambda b: b["request"].pop("context"))

    # ---- the network is compared as the machine canonicalises it
    names = {"mode": "allowlist", "allow": ["example.org", "Example.NET"]}
    good("run_network_names_in_other_order_and_case", "An allowlist written with other order and case than the signed "
         "policy: the same names.", {}, truth_edit=lambda r: r["request"].update(network=names))
    good("run_network_create_bytes_in_another_order", "The create bytes list the same names in another order and case "
         "than the recipe does.", {}, truth_edit=lambda r: r["request"].update(
             network={"mode": "allowlist", "allow": ["example.org", "example.net"]}),
         create_body=lambda body: {**body, "network": {"mode": "allowlist", "allow": ["EXAMPLE.net", "example.org"]}})
    bad("run_c4_network_create_bytes_other_name", "The create bytes name another host than the recipe does.",
        fail(4, "the create's network is not the broker's form of the recipe's"),
        truth_edit=lambda r: r["request"].update(network={"mode": "allowlist", "allow": ["example.org"]}),
        create_body=lambda body: {**body, "network": {"mode": "allowlist", "allow": ["other.net"]}})


IMAGE_RULE = "image must end in @sha256: and 64 lower-case hex"


def run_validity_cases(pack: Pack) -> None:
    """A recipe must be a valid one-shot request (spec G4 5.1) and an inline output at most 64 KiB (5.5)."""
    def bad(name, description, expect, **kw):
        run_case(pack, "bad", name, description, expect, **kw)

    def good(name, description, **kw):
        run_case(pack, "good", name, description, {}, **kw)

    def req(**members):
        return lambda r: r["request"].update(members)

    bad("run_rule_image_unpinned", "The image is a tag, not a digest.", {"reason": f"recipe: {IMAGE_RULE}"},
        truth_edit=req(image="images.example.test/app:latest", image_id=IMAGE_ID))
    bad("run_rule_image_unpinned_in_file_only", "The recipe is valid; the file's request names an unpinned image.",
        {"reason": f"check 8: the file's request: {IMAGE_RULE}"},
        bundle_edit=lambda b: b["request"].update(image="images.example.test/app:latest"))
    bad("run_rule_command_too_long", "A command of 129 strings.", {"reason": "recipe: command must hold 1 to 128 strings"},
        truth_edit=req(command=["true"] * 129))
    good("run_rule_command_128", "A command of 128 strings.", truth_edit=req(command=["true"] * 128))
    bad("run_rule_env_too_many", "An environment of 65 entries.", {"reason": "recipe: env must hold at most 64 entries"},
        truth_edit=req(env={f"K{i}": "v" for i in range(65)}))
    ins = lambda n: [{"path": f"/work/in/f{i}.bin", "mode": "644"} for i in range(n)]
    bad("run_rule_inputs_too_many", "Nine inputs.", {"reason": "recipe: inputs must hold at most 8 entries"},
        truth_edit=req(inputs=ins(9)))
    good("run_rule_inputs_8", "Eight inputs.", truth_edit=req(inputs=ins(8)))
    bad("run_rule_input_path_outside", "An input path outside /work/in/.",
        {"reason": "recipe: an input path must be under /work/in/"},
        truth_edit=req(inputs=[{"path": "/tmp/data.csv", "mode": "644"}]))
    bad("run_rule_input_path_is_the_folder", "An input path that is the folder itself.",
        {"reason": "recipe: an input path must be under /work/in/"},
        truth_edit=req(inputs=[{"path": "/work/in/", "mode": "644"}]))
    bad("run_rule_output_path_outside", "An output path outside /work/out/.",
        {"reason": "recipe: an output path must be under /work/out/"},
        truth_edit=req(outputs=[{"path": "/tmp/log.txt", "max_bytes": 65536, "optional": False}]), held=(), inline=())
    bad("run_rule_output_max_bytes_too_large", "An output max_bytes of 64 KiB plus one.",
        {"reason": "recipe: an output max_bytes must be at most 65536"},
        truth_edit=req(outputs=[{"path": RESULT_PATH, "max_bytes": 65537, "optional": False}]), held=(), inline=())
    good("run_rule_output_max_bytes_64_kib", "An output max_bytes of exactly 64 KiB.",
         truth_edit=req(outputs=[{"path": RESULT_PATH, "max_bytes": 65536, "optional": False}]), held=(), inline=())
    bad("run_rule_timeout_zero", "A timeout of 0 seconds.", {"reason": "recipe: timeout_seconds must be at least 1"},
        truth_edit=req(timeout_seconds=0))
    bad("run_rule_context_too_large", "A context of 4097 canonical bytes.",
        {"reason": "inputs: the context is larger than 4 KiB (4096 canonical bytes)"},
        truth_context={"k": "a" * 4089})
    good("run_rule_context_4_kib", "A context of exactly 4096 canonical bytes.", truth_context={"k": "a" * 4088})

    bad("run_rule_inline_output_too_large", "An inline output of 64 KiB plus one byte.",
        fail(7, f"the inline bytes of {LOG_PATH} are 65537 bytes, over the 64 KiB an inline output may have"),
        file_bytes={LOG_PATH: b"x" * 65537})
    good("run_rule_inline_output_64_kib", "An inline output of exactly 64 KiB.",
         file_bytes={LOG_PATH: b"x" * 65536})


def _nest(arrays: int):
    """The integer 1 inside the given number of lists."""
    value = 1
    for _ in range(arrays):
        value = [value]
    return value


def _knobs(**members):
    return {"truth_edit": lambda r: r["request"].update(members)}


def _ins(*items):
    return _knobs(inputs=[{"path": p, "mode": "644"} if isinstance(p, str) else p for p in items])


def _outs(*items):
    out = [{"path": p, "max_bytes": 9, "optional": False} if isinstance(p, str) else p for p in items]
    return {**_knobs(outputs=out), "held": (), "inline": ()}


def _file_side(**edits):
    return {"bundle_edit": lambda b: b["request"].update(edits)}


_IMG = "images.example.test/"
_DIGEST = "@sha256:" + "a" * 64
USER_FORM = ("recipe: user must be digits only, or a name of letters, digits, _ and - that starts with a letter or _ "
             "and may end in $")
MAX_SPEND_RULE = ("max_spend_usd must be an integer from 1 to 999999999999, or a decimal string of 1 to 12 digits "
                  "and up to 6 decimals, greater than zero")
IN_PATH = "an input path"
OUT_PATH = "an output path"


def _path_rules(kind, prefix, make):
    """The path forms (spec G4 5.1, Forms) for inputs or outputs: one entry per rule, with the cases past it."""
    noun = f"an {kind} path"
    p = f"recipe: {noun} "
    long_ok, long_bad = prefix + "a" * (1024 - len(prefix)), prefix + "a" * (1025 - len(prefix))
    return [
        (f"{kind}_path_length", make(long_ok), [("1025", make(long_bad), p + "must be at most 1024 characters")]),
        (f"{kind}_path_dots", make(prefix + "a..b"), [
            ("dotdot", make(prefix + "../x"), p + "must not hold a . or .. segment"),
            ("dot", make(prefix + "./x"), p + "must not hold a . or .. segment"),
            ("dotdot_last", make(prefix + "d/.."), p + "must not hold a . or .. segment")]),
        (f"{kind}_path_segments", make(prefix + "a/b"), [
            ("empty", make(prefix + "a//b"), p + "must not hold an empty segment"),
            ("trailing_slash", make(prefix + "a/"), p + "must not hold an empty segment")]),
        (f"{kind}_path_characters", make(prefix + "A-z_0.9"), [
            ("space", make(prefix + "a b"), p + "may hold only letters, digits, . _ and - in a segment"),
            ("non_ascii", make(prefix + "caf\u00e9"), p + "may hold only letters, digits, . _ and - in a segment"),
            ("percent", make(prefix + "a%2Fb"), p + "may hold only letters, digits, . _ and - in a segment"),
            ("old_vector", make(UNICODE_PATH if kind == "input" else "/work/out/a b+c&d=e%f~\u00fc.txt"),
             p + "may hold only letters, digits, . _ and - in a segment")]),
        (f"{kind}_path_twice", make(prefix + "a", prefix + "b"),
         [("duplicate", make(prefix + "a", prefix + "a"), f"recipe: {noun} is given twice")]),
    ]


def build_form_rules():
    """Every form rule of spec G4 5.1: (id, knobs at the bound that pass, [(case, knobs past it, reason)])."""
    rules = _path_rules("input", "/work/in/", lambda *ps: _ins(*ps))
    rules += _path_rules("output", "/work/out/", lambda *ps: _outs(*ps))
    rules += [
        ("input_not_the_context_path", _ins("/work/in/.context.jsonx"),
         [("context_path", _ins("/work/in/.context.json"), "recipe: an input path must not be /work/in/.context.json")]),
        ("input_mode", _ins({"path": "/work/in/x", "mode": "0644"}), [
            ("eight", _ins({"path": "/work/in/x", "mode": "8"}), "recipe: an input mode must be 3 or 4 octal digits"),
            ("two_digits", _ins({"path": "/work/in/x", "mode": "64"}),
             "recipe: an input mode must be 3 or 4 octal digits"),
            ("five_digits", _ins({"path": "/work/in/x", "mode": "00644"}),
             "recipe: an input mode must be 3 or 4 octal digits"),
            ("not_octal", _ins({"path": "/work/in/x", "mode": "0689"}),
             "recipe: an input mode must be 3 or 4 octal digits")]),
        ("image_length", _knobs(image=_IMG + "a" * (512 - len(_IMG) - len(_DIGEST)) + _DIGEST),
         [("513", _knobs(image=_IMG + "a" * (513 - len(_IMG) - len(_DIGEST)) + _DIGEST),
           "recipe: image must be at most 512 characters")]),
        ("env_name", _knobs(env={"A" * 128: "v", "_x1": "v"}), [
            ("129", _knobs(env={"A" * 129: "v"}), "recipe: an env name must be a letter or _, then up to 127 letters, digits or _"),
            ("digit_first", _knobs(env={"1A": "v"}),
             "recipe: an env name must be a letter or _, then up to 127 letters, digits or _"),
            ("dash", _knobs(env={"A-B": "v"}),
             "recipe: an env name must be a letter or _, then up to 127 letters, digits or _"),
            ("empty", _knobs(env={"": "v"}),
             "recipe: an env name must be a letter or _, then up to 127 letters, digits or _")]),
        ("env_value_length", _knobs(env={"K": "v" * 8192}),
         [("8193", _knobs(env={"K": "v" * 8193}), "recipe: an env value must be at most 8192 characters")]),
        ("cwd_length", _knobs(cwd="/" + "a" * 1023), [
            ("1025", _knobs(cwd="/" + "a" * 1024), "recipe: cwd must be 1 to 1024 characters"),
            ("empty", _knobs(cwd=""), "recipe: cwd must be 1 to 1024 characters")]),
        ("user_length", _knobs(user="a" * 64),
         [("65", _knobs(user="a" * 65), "recipe: user must be at most 64 characters")]),
        ("user_form", _knobs(user="_svc-1$"), [
            ("dollar_inside", _knobs(user="svc$x"), USER_FORM),
            ("digit_first", _knobs(user="1abc"), USER_FORM),
            ("space", _knobs(user="a b"), USER_FORM),
            ("empty", _knobs(user=""), USER_FORM)]),
        ("user_digits", _knobs(user="1000"), []),
        ("output_max_bytes_at_least_one", _outs({"path": "/work/out/x", "max_bytes": 1, "optional": False}),
         [("zero", _outs({"path": "/work/out/x", "max_bytes": 0, "optional": False}),
           "recipe: an output max_bytes must be at least 1"),
          ("negative", _outs({"path": "/work/out/x", "max_bytes": -1, "optional": False}),
           "recipe: an output max_bytes must be at least 1")]),
        ("ttl_is_timeout_plus_margin", {"truth_edit": lambda r: r["create"].update(ttl_seconds=660)}, [
            ("one_second_short", {"truth_edit": lambda r: r["create"].update(ttl_seconds=659)},
             "recipe: create.ttl_seconds must be timeout_seconds + 600"),
            ("one_second_over", {"truth_edit": lambda r: r["create"].update(ttl_seconds=661)},
             "recipe: create.ttl_seconds must be timeout_seconds + 600"),
            ("the_old_value", {"truth_edit": lambda r: r["create"].update(ttl_seconds=300)},
             "recipe: create.ttl_seconds must be timeout_seconds + 600")]),
        ("max_spend_largest_integer", _knobs(max_spend_usd=999999999999), [
            ("one_more", _knobs(max_spend_usd=1000000000000), "recipe: " + MAX_SPEND_RULE),
            ("long_integer_literal", {"recipe_raw": lambda raw: raw.replace(
                b'"max_spend_usd": "0.50"', b'"max_spend_usd": 1' + b"0" * 5000)},
             "inputs: the recipe holds a number literal of more than 100 characters"),
            ("long_decimal_literal", {"recipe_raw": lambda raw: raw.replace(
                b'"max_spend_usd": "0.50"', b'"max_spend_usd": ' + b"9" * 50 + b"." + b"9" * 51)},
             "inputs: the recipe holds a number literal of more than 100 characters")]),
        ("max_spend_twelve_digit_string", _knobs(max_spend_usd="999999999999.999999"), [
            ("thirteen_digits", _knobs(max_spend_usd="1000000000000"), "recipe: " + MAX_SPEND_RULE),
            ("double_zero_whole", _knobs(max_spend_usd="00.50"), "recipe: " + MAX_SPEND_RULE),
            ("long_string", _knobs(max_spend_usd="1" * 5000), "recipe: " + MAX_SPEND_RULE)]),
        ("max_spend_integer", _knobs(max_spend_usd=1), []),
        ("max_spend_small_decimal", _knobs(max_spend_usd="0.000001"), []),
        ("max_spend_long_decimal", _knobs(max_spend_usd="100.123456"), []),
        ("max_spend_whole_string", _knobs(max_spend_usd="12"), []),
        ("max_spend_form", _knobs(max_spend_usd="0.50"), [
            ("zero", _knobs(max_spend_usd=0), "recipe: " + MAX_SPEND_RULE),
            ("negative", _knobs(max_spend_usd=-1), "recipe: " + MAX_SPEND_RULE),
            ("boolean", _knobs(max_spend_usd=True), "recipe: " + MAX_SPEND_RULE),
            ("zero_string", _knobs(max_spend_usd="0"), "recipe: " + MAX_SPEND_RULE),
            ("zero_point_zero", _knobs(max_spend_usd="0.0"), "recipe: " + MAX_SPEND_RULE),
            ("zero_point_six_zeros", _knobs(max_spend_usd="0.000000"), "recipe: " + MAX_SPEND_RULE),
            ("leading_point", _knobs(max_spend_usd=".5"), "recipe: " + MAX_SPEND_RULE),
            ("trailing_point", _knobs(max_spend_usd="1."), "recipe: " + MAX_SPEND_RULE),
            ("exponent", _knobs(max_spend_usd="1e3"), "recipe: " + MAX_SPEND_RULE),
            ("plus_sign", _knobs(max_spend_usd="+1"), "recipe: " + MAX_SPEND_RULE),
            ("leading_space", _knobs(max_spend_usd=" 1"), "recipe: " + MAX_SPEND_RULE),
            ("trailing_newline", _knobs(max_spend_usd="1\n"), "recipe: " + MAX_SPEND_RULE),
            ("leading_zero", _knobs(max_spend_usd="01"), "recipe: " + MAX_SPEND_RULE),
            ("seven_decimals", _knobs(max_spend_usd="1.1234567"), "recipe: " + MAX_SPEND_RULE),
            ("empty", _knobs(max_spend_usd=""), "recipe: " + MAX_SPEND_RULE),
            ("a_float", _knobs(max_spend_usd=1.5), "inputs: the recipe holds the number 1.5, which is not an integer"),
            ("string_in_the_recipe_integer_in_the_file", {**_knobs(max_spend_usd="1"), **_file_side(max_spend_usd=1)},
             "check 8: the request in the file differs from the recipe in max_spend_usd")]),
        ("context_depth", {"truth_context": {"a": _nest(31)}}, [
            ("33_levels", {"truth_context": {"a": _nest(32)}}, "inputs: context nests deeper than 32 levels"),
            ("40_levels", {"truth_context": {"a": _nest(39)}}, "inputs: context nests deeper than 32 levels"),
            ("62_levels", {"truth_context": {"a": _nest(61)}}, "inputs: context nests deeper than 32 levels"),
            ("big_600_levels", {"truth_context": {"a": _nest(600)}},
             "inputs: the one-shot file nests too deeply to read"),  # the bundle's request holds it too, and loads first
            ("40_levels_in_the_files_request", {"truth_context": {"a": 1}, **_file_side(context={"a": _nest(39)})},
             "check 8: the file's request: context nests deeper than 32 levels"),
            ("big_in_the_files_request", {"truth_context": {"a": 1}, **_file_side(context={"a": _nest(600)})},
             "inputs: the one-shot file nests too deeply to read")]),
        ("image_control_character", _knobs(image=_IMG + "app" + _DIGEST), [
            ("tab", _knobs(image=_IMG + "a\tpp" + _DIGEST), "recipe: image must hold no control character"),
            ("newline_inside", _knobs(image=_IMG + "a\npp" + _DIGEST), "recipe: image must hold no control character"),
            ("nul", _knobs(image=_IMG + "a\x00pp" + _DIGEST), "recipe: image must hold no control character"),
            ("del", _knobs(image=_IMG + "a\x7fpp" + _DIGEST), "recipe: image must hold no control character")]),
        ("file_request_forms", {}, [
            ("image_has_a_tab", _file_side(image=_IMG + "a\tpp" + _DIGEST),
             "check 8: the file's request: image must hold no control character"),
            ("image_has_a_nul", _file_side(image=_IMG + "a\x00pp" + _DIGEST),
             "check 8: the file's request: image must hold no control character"),
            ("image_id_malformed", _file_side(image_id="sha256:ABC"),
             "check 8: the file's request: image_id must be sha256: and 64 lower-case hex"),
            ("timeout_is_a_boolean", _file_side(timeout_seconds=True),
             "check 8: the file's request: timeout_seconds must be an integer"),
            ("max_spend_is_a_boolean", _file_side(max_spend_usd=True), "check 8: the file's request: " + MAX_SPEND_RULE)]),
        ("network_name_label_newline", _knobs(network={"mode": "allowlist", "allow": ["a.org"]}), [
            ("inner_newline", _knobs(network={"mode": "allowlist", "allow": ["a\n.org"]}),
             "recipe: network allow entry 'a\\n.org' is not a valid allowlist entry")]),
        ("context_no_floats", {"truth_context": {"a": {"b": 1, "c": [1, 2]}}}, [
            ("deep_float", {"truth_context": {"a": {"b": 1.5}}},
             "inputs: the context file holds the number 1.5, which is not an integer"),
            ("one_point_zero", {"truth_context": {"a": {"b": 1.0}}},
             "inputs: the context file holds the number 1.0, which is not an integer"),
            ("exponent", {"truth_context": {"a": {"b": 1}}, "context_raw": lambda raw: b'{"a":{"b":1e3}}'},
             "inputs: the context file holds the number 1e3, which is not an integer"),
            ("in_a_list", {"truth_context": {"a": [1]}, "context_raw": lambda raw: b'{"a":[1,[2.5]]}'},
             "inputs: the context file holds the number 2.5, which is not an integer"),
            ("float_in_the_files_request", {"truth_context": {"a": {"b": 1}},
                                            **_file_side(context={"a": {"b": 1.5}})},
             "check 8: the file's request: context must hold no floating point number")]),
    ]
    return rules


def run_form_cases(pack: Pack) -> None:
    """One good list at each bound and the bad lists past it (spec G4 5.1, Forms)."""
    for rule, at, past in build_form_rules():
        if rule == "file_request_forms":
            continue
        run_case(pack, "good", f"run_form_{rule}", f"The bound of the form rule {rule}: it is accepted.", {}, **at)
        for case, knobs, reason in past:
            if case.startswith("big_"):
                continue  # too large to keep as a saved list; the table test builds it in memory
            run_case(pack, "bad", f"run_form_{rule}_{case}", f"One step past the form rule {rule}: {case}.",
                     {"reason": reason}, **knobs)
    # Nesting is counted on the raw text before any parse, so the answer is the same on every interpreter.
    def nested(n):
        return b"[" * n + b"]" * n
    inputs = [("one_shot_file", "bundle_raw", "inputs: the one-shot file nests too deeply to read",
               "check 1: the file is not a cathedral_oneshot_bundle_v1"),
              ("recipe", "recipe_raw", "inputs: the recipe nests too deeply to read",
               "recipe: the document is not a cathedral_oneshot_recipe_v1"),
              ("context_file", "context_raw", "inputs: the context file nests too deeply to read",
               "inputs: context nests deeper than 32 levels")]
    for name, knob, too_deep, real in inputs:
        for depth, reason in ((64, real), (65, too_deep), (5000, too_deep)):
            run_case(pack, "bad", f"run_form_depth_{depth}_{name}",
                     f"The {name.replace('_', ' ')} is a list nested {depth} levels deep.", {"reason": reason},
                     **{knob: (lambda raw, d=depth: nested(d))})
    # An unpaired surrogate is refused on the raw text, in a key or a value, in every form (after depth and number
    # length, before the parse).
    surrogate = {
        "high_alone": b"\\ud800", "low_alone": b"\\udc00", "low_before_high": b"\\udc00\\ud800",
        "high_then_other_escape": b"\\ud800\\u0041", "high_then_plain_char": b"\\ud800x",
        "high_then_high": b"\\ud800\\ud800", "raw_utf8_bytes": b"\xed\xa0\x80"}
    for form, payload in surrogate.items():
        for where, raw in (("value", b'{"k": "' + payload + b'"}'), ("key", b'{"' + payload + b'": 1}')):
            run_case(pack, "bad", f"run_form_surrogate_{form}_in_a_{where}_of_the_context_file",
                     f"The context file holds an unpaired surrogate ({form.replace('_', ' ')}) in a {where}.",
                     {"reason": "inputs: the context file holds an unpaired surrogate"},
                     context_raw=lambda _raw, r=raw: r)
    utf16 = b"\xff\xfe" + '{"k": "\ud800"}'.encode("utf-16-le", "surrogatepass")
    run_case(pack, "bad", "run_form_surrogate_unpaired_utf16_unit_in_the_context_file",
             "The context file is UTF-16 text with a lone surrogate unit.",
             {"reason": "inputs: the context file holds an unpaired surrogate"}, context_raw=lambda _raw: utf16)
    run_case(pack, "bad", "run_form_surrogate_in_the_one_shot_file", "The one-shot file holds a lone surrogate escape.",
             {"reason": "inputs: the one-shot file holds an unpaired surrogate"},
             bundle_raw=lambda _raw: b'{"k": "\\ud800"}')
    run_case(pack, "bad", "run_form_surrogate_in_the_recipe", "The recipe holds a lone surrogate escape.",
             {"reason": "inputs: the recipe holds an unpaired surrogate"}, recipe_raw=lambda _raw: b'{"k": "\\ud800"}')
    run_case(pack, "bad", "run_form_surrogate_and_repeated_key", "A context with a repeated key and a lone surrogate: "
             "the surrogate is reported.", {"reason": "inputs: the context file holds an unpaired surrogate"},
             context_raw=lambda _raw: b'{"a": 1, "a": "\\ud800"}')
    run_case(pack, "bad", "run_form_surrogate_and_long_number", "A context with a number literal of 101 characters "
             "and a lone surrogate: the number is reported.",
             {"reason": "inputs: the context file holds a number literal of more than 100 characters"},
             context_raw=lambda _raw: b'{"a": ' + b"1" * 101 + b', "b": "\\ud800"}')
    run_case(pack, "good", "run_form_surrogate_pair_escaped", "A context string written as an escaped surrogate "
             "pair is the one character it stands for.", {}, truth_context={"k": "\U0001F600"},
             context_raw=lambda _raw: b'{"k": "\\ud83d\\ude00"}')
    run_case(pack, "good", "run_form_surrogate_literal_backslash", "A backslash followed by ud800 is text, not an "
             "escape.", {}, truth_context={"k": "\\ud800"})
    run_case(pack, "good", "run_form_brackets_in_a_string", "A context string of 4,000 opening brackets is a string, "
             "not nesting.", {}, truth_context={"k": "[" * 4000})
    run_case(pack, "good", "run_form_brackets_and_quotes_in_a_string", "A context string with quotes, backslashes and "
             "brackets is read as a string.", {}, truth_context={"k": '"' + "[" * 200 + "\\" + "]" * 200 + '\\"{'})
    run_case(pack, "bad", "run_form_input_sha256_upper_case", "The file's request holds an upper-case input sha256.",
             {"reason": "check 8: the file's request: an input sha256 must be 64 lower-case hex"},
             bundle_edit=lambda b: b["request"]["inputs"][0].update(sha256=b["request"]["inputs"][0]["sha256"].upper()))


SNAP_ID = "snap_0123456789ab"
SNAP_IMAGE = "sha256:" + hashlib.sha256(b"snapshot image 1").hexdigest()
SNAP_ARCHIVE = hashlib.sha256(b"snapshot archive 1").hexdigest()


def snap_content(image: str = SNAP_IMAGE, archive: str = SNAP_ARCHIVE) -> str:
    """The snapshot's content hash: sha256 of the canonical document of its two parts (AB#604)."""
    return sha(canonical({"schema": "cathedral_snapshot_content_v1", "image_id": image,
                          "work_archive_sha256": archive}))


def snap_fields(snap: str = SNAP_ID, image: str = SNAP_IMAGE, archive: str = SNAP_ARCHIVE, size=4096) -> dict:
    return {"snapshot_id": snap, "snapshot_image_id": image, "snapshot_work_archive_sha256": archive,
            "snapshot_size_bytes": size, "snapshot_content_sha256": snap_content(image, archive)}


def fork_fields(snapshot_receipt: dict) -> dict:
    st = snapshot_receipt["statement"]
    return {"snapshot_id": st.get("snapshot_id", SNAP_ID),
            "snapshot_content_sha256": st.get("snapshot_content_sha256", snap_content()),
            "snapshot_receipt_sha256": snapshot_receipt["receipt_sha256"],
            "snapshot_source_sandbox_id": st.get("sandbox_id", "room-a")}


def delete_fields(snap: str = SNAP_ID, source: str | None = "room-a") -> dict:
    fields = {"target": f"DELETE /v1/snapshots/{snap}", "snapshot_id": snap}
    if source is not None:
        fields["snapshot_source_sandbox_id"] = source
    return fields


def snap_hotel(pack: Pack, s=None, f=None, d=None, s_status: int = 202, with_delete: bool = True):
    """Room A is created and snapshotted, room B is a fork of the snapshot, then the snapshot is deleted.
    s, f and d replace or DEL members of the snapshot, the fork's create and the delete."""
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    snap = h.sign("snapshot", "room-a", s_status, **({**snap_fields(), **(s or {})} if s_status < 300 else (s or {})))
    fork = h.sign("create", "room-b", 200, **{**fork_fields(snap), **(f or {})})
    dele = h.sign("snapshot_delete", None, 200, **{**delete_fields(), **(d or {})}) if with_delete else None
    return h, snap, fork, dele


FORK_ENTRY = {"room": "room-b", "snapshot_id": SNAP_ID, "snapshot_content_sha256": snap_content(),
              "source_room": "room-a", "in_list": True}
SNAP_SHAPE = "receipt {i} of the list: {text}"


def snapshot_cases(pack: Pack) -> None:
    """Check 11: snapshot and fork edges (AB#604 CS-4). Case names start with the rule they cover."""
    def doc(h, receipts, headed):
        # A list with a head must be a whole chain from receipt 1; a part of a chain has none.
        return whole(h, receipts) if headed else {"receipts": h.chain if receipts is None else receipts}

    def good(name, description, h, pointers, receipts=None, headed=True):
        hotel_case(pack, "good", name, description, doc(h, receipts, headed), {"pointers": pointers})

    def bad(name, description, h, reason, receipts=None, headed=True):
        hotel_case(pack, "bad", name, description, doc(h, receipts, headed), {"reason": reason})

    forks = "/chain/forks"
    h, snap, *_ = snap_hotel(pack)
    good("snapshot_r1_basic_fork",
         "Room A is snapshotted, room B is a fork of it, the snapshot is deleted: one fork edge, found in the list.",
         h, {forks: [FORK_ENTRY]})

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("create", "room-b", 200)
    good("snapshot_r1_create_without_fork_members",
         "Ordinary creates carry none of the snapshot members: the check leaves them alone.", h,
         {"/chain/receipts": 2})

    good("snapshot_r1_failed_snapshot_carries_no_members",
         "A snapshot that did not succeed carries no snapshot member: nothing to check, no edge.",
         pack_alone(pack), {forks: []})

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("snapshot_delete", None, 200, **delete_fields(source=None))
    good("snapshot_r1_delete_without_source_member",
         "A snapshot delete that does not name the source room (the front no longer knew it) is allowed.", h,
         {forks: []})

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot", "room-a", 202, **snap_fields("snap_0123456789ac", archive=hashlib.sha256(b"archive 2").hexdigest()))
    good("snapshot_r2_content_hash_recomputes_for_each_snapshot",
         "Two snapshots with different parts have different content hashes; each recomputes from its own parts.",
         h, {forks: []})

    # Rule 3 (scope by binding) needs two bindings in one list, which the command line offers only with an
    # archive fetch from a broker; tests/test_verify_receipt_lists.py makes those lists in memory.

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot", "room-a", 202, **snap_fields())
    good("snapshot_r4_repeat_snapshot_agrees",
         "The same snapshot signed twice by its room, with the same content hash: no disagreement.", h, {forks: []})

    h, *_ = snap_hotel(pack, with_delete=False)
    out_of_place = [h.chain[2], h.chain[0], h.chain[1]]
    good("snapshot_r5_order_is_by_signed_sequence_not_by_place_in_the_list",
         "The fork's receipt stands first in the list file; the snapshot it names has the lower sequence, so it "
         "comes earlier.", h, {forks: [FORK_ENTRY]}, receipts=out_of_place)

    h, snap, *_ = snap_hotel(pack, with_delete=False)
    h.sign("create", "room-c", 200, **fork_fields(snap))
    good("snapshot_r5_two_forks_of_one_snapshot",
         "Two rooms forked from one snapshot give two edges.", h,
         {forks: [FORK_ENTRY, {**FORK_ENTRY, "room": "room-c"}]})

    h = pack_fork_only(pack)
    good("snapshot_r6_fork_source_not_in_list",
         "A list of room B alone: the snapshot receipt it names is in room A's list, not here. Not a failure; the "
         "output says so.", h, {forks: [{**FORK_ENTRY, "in_list": False, "fork_source": "not_in_list"}]},
         receipts=h.chain[2:], headed=False)

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    snap = h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot_delete", None, 500, **delete_fields())
    h.sign("create", "room-b", 200, **fork_fields(snap))
    good("snapshot_r7_a_failed_delete_is_not_a_delete",
         "A snapshot delete that did not succeed leaves the snapshot in place: a fork after it is fine.", h,
         {forks: [FORK_ENTRY]})

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    snap = h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot_delete", None, 200, **delete_fields("snap_0123456789ac"))
    h.sign("create", "room-b", 200, **fork_fields(snap))
    good("snapshot_r7_delete_of_another_snapshot_is_no_bar",
         "A delete of another snapshot id does not stop a fork of this one.", h, {forks: [FORK_ENTRY]})

    # ---- rule 1: shapes, before anything else
    def sn(**kw):
        return {"s": kw}

    def fk(**kw):
        return {"f": kw}

    def dl(**kw):
        return {"d": kw}

    shapes = [
        ("snapshot_id_not_string", "A snapshot receipt whose snapshot_id is a number.", sn(snapshot_id=7), 2,
         "snapshot_id is not a string"),
        ("snapshot_id_null", "A snapshot receipt whose snapshot_id is null.", sn(snapshot_id=None), 2,
         "snapshot_id is not a string"),
        ("image_id_without_prefix", "snapshot_image_id without sha256:.", sn(snapshot_image_id="a" * 64), 2,
         "snapshot_image_id is not sha256: and 64 lower-case hex"),
        ("image_id_upper_case", "snapshot_image_id in upper case.", sn(snapshot_image_id="sha256:" + "A" * 64), 2,
         "snapshot_image_id is not sha256: and 64 lower-case hex"),
        ("image_id_short", "snapshot_image_id one digit short.", sn(snapshot_image_id="sha256:" + "a" * 63), 2,
         "snapshot_image_id is not sha256: and 64 lower-case hex"),
        ("image_id_number", "snapshot_image_id is a number.", sn(snapshot_image_id=5), 2,
         "snapshot_image_id is not sha256: and 64 lower-case hex"),
        ("archive_upper_case", "snapshot_work_archive_sha256 in upper case.",
         sn(snapshot_work_archive_sha256="A" * 64), 2, "snapshot_work_archive_sha256 is not 64 lower-case hex"),
        ("archive_with_prefix", "snapshot_work_archive_sha256 with a sha256: prefix.",
         sn(snapshot_work_archive_sha256="sha256:" + "a" * 64), 2,
         "snapshot_work_archive_sha256 is not 64 lower-case hex"),
        ("archive_long", "snapshot_work_archive_sha256 one digit long.", sn(snapshot_work_archive_sha256="a" * 65),
         2, "snapshot_work_archive_sha256 is not 64 lower-case hex"),
        ("size_negative", "snapshot_size_bytes below 0.", sn(snapshot_size_bytes=-1), 2,
         "snapshot_size_bytes is not an integer of 0 or more"),
        ("size_string", "snapshot_size_bytes written as a string.", sn(snapshot_size_bytes="4096"), 2,
         "snapshot_size_bytes is not an integer of 0 or more"),
        ("size_boolean", "snapshot_size_bytes is true.", sn(snapshot_size_bytes=True), 2,
         "snapshot_size_bytes is not an integer of 0 or more"),
        ("size_float", "snapshot_size_bytes is 4096.5.", sn(snapshot_size_bytes=4096.5), 2,
         "snapshot_size_bytes is not an integer of 0 or more"),
        ("content_upper_case", "snapshot_content_sha256 in upper case.",
         sn(snapshot_content_sha256=snap_content().upper()), 2, "snapshot_content_sha256 is not 64 lower-case hex"),
        ("content_short", "snapshot_content_sha256 one digit short.", sn(snapshot_content_sha256=snap_content()[:63]),
         2, "snapshot_content_sha256 is not 64 lower-case hex"),
        ("snapshot_lacks_image_id", "A successful snapshot with four of the five members.",
         sn(snapshot_image_id=DEL), 2, "a snapshot receipt has some of its five snapshot members and not all"),
        ("snapshot_lacks_content", "A successful snapshot with four of the five members.",
         sn(snapshot_content_sha256=DEL), 2, "a snapshot receipt has some of its five snapshot members and not all"),
        ("snapshot_lacks_id", "A successful snapshot with four of the five members.",
         sn(snapshot_id=DEL), 2, "a snapshot receipt has some of its five snapshot members and not all"),
        ("fork_lacks_source", "A create with three of the four fork members.",
         fk(snapshot_source_sandbox_id=DEL), 3, "a create has some of its four snapshot fork members and not all"),
        ("fork_lacks_receipt_hash", "A create with three of the four fork members.",
         fk(snapshot_receipt_sha256=DEL), 3, "a create has some of its four snapshot fork members and not all"),
        ("fork_lacks_content", "A create with three of the four fork members.",
         fk(snapshot_content_sha256=DEL), 3, "a create has some of its four snapshot fork members and not all"),
        ("fork_receipt_hash_upper_case", "A fork's snapshot_receipt_sha256 in upper case.",
         fk(snapshot_receipt_sha256="A" * 64), 3, "snapshot_receipt_sha256 is not 64 lower-case hex"),
        ("fork_receipt_hash_short", "A fork's snapshot_receipt_sha256 one digit short.",
         fk(snapshot_receipt_sha256="a" * 63), 3, "snapshot_receipt_sha256 is not 64 lower-case hex"),
        ("fork_source_number", "A fork's snapshot_source_sandbox_id is a number.",
         fk(snapshot_source_sandbox_id=4), 3, "snapshot_source_sandbox_id is not a string"),
        ("fork_source_null", "A fork's snapshot_source_sandbox_id is null.",
         fk(snapshot_source_sandbox_id=None), 3, "snapshot_source_sandbox_id is not a string"),
        ("fork_snapshot_id_number", "A fork's snapshot_id is a number.", fk(snapshot_id=9), 3,
         "snapshot_id is not a string"),
        ("fork_content_upper_case", "A fork's snapshot_content_sha256 in upper case.",
         fk(snapshot_content_sha256=snap_content().upper()), 3, "snapshot_content_sha256 is not 64 lower-case hex"),
        ("delete_names_a_room", "A snapshot_delete with a sandbox_id.", {"d": {"sandbox_id": "room-a"}}, 4,
         "a snapshot_delete has a sandbox_id: it must be null"),
        ("delete_lacks_snapshot_id", "A snapshot_delete with no snapshot_id.", dl(snapshot_id=DEL), 4,
         "snapshot_id is not a string"),
        ("delete_snapshot_id_number", "A snapshot_delete whose snapshot_id is a number.", dl(snapshot_id=3), 4,
         "snapshot_id is not a string"),
        ("delete_source_null", "A snapshot_delete with a null source: absent is allowed, null is not.",
         dl(snapshot_source_sandbox_id=None), 4, "snapshot_source_sandbox_id is not a string"),
        ("delete_source_number", "A snapshot_delete whose source is a number.",
         dl(snapshot_source_sandbox_id=2), 4, "snapshot_source_sandbox_id is not a string"),
    ]
    shapes += [
        ("snapshot_lacks_sandbox_id", "A successful snapshot receipt with no sandbox_id.", sn(sandbox_id=DEL), 2,
         "a snapshot receipt has no sandbox_id string"),
        ("fork_lacks_sandbox_id", "A fork's create with no sandbox_id.", fk(sandbox_id=DEL), 3,
         "a fork's create has no sandbox_id string"),
        ("fork_sandbox_id_null", "A fork's create whose sandbox_id is null.", fk(sandbox_id=None), 3,
         "a fork's create has no sandbox_id string"),
        ("delete_lacks_sandbox_id", "A snapshot_delete with no sandbox_id member: it must be an explicit null.",
         dl(sandbox_id=DEL), 4, "a snapshot_delete has no sandbox_id member: it must be null, not left out"),
        ("snapshot_id_empty", "A snapshot receipt whose snapshot_id is the empty string.", sn(snapshot_id=""), 2,
         "snapshot_id is empty"),
        ("fork_snapshot_id_empty", "A fork whose snapshot_id is the empty string.", fk(snapshot_id=""), 3,
         "snapshot_id is empty"),
        ("fork_source_empty", "A fork whose source room is the empty string.", fk(snapshot_source_sandbox_id=""), 3,
         "snapshot_source_sandbox_id is empty"),
        ("delete_snapshot_id_empty", "A snapshot_delete whose snapshot_id is the empty string.", dl(snapshot_id=""),
         4, "snapshot_id is empty"),
        ("delete_source_empty", "A snapshot_delete whose source room is the empty string.",
         dl(snapshot_source_sandbox_id=""), 4, "snapshot_source_sandbox_id is empty"),
    ]
    for name, description, kw, i, text in shapes:
        over = kw.get("s")
        if over and "snapshot_content_sha256" not in over and DEL not in over.values() and (
                "snapshot_image_id" in over or "snapshot_work_archive_sha256" in over):
            # One fault per case: the content hash agrees with the malformed part, so rule 2 has nothing to say.
            over["snapshot_content_sha256"] = snap_content(over.get("snapshot_image_id", SNAP_IMAGE),
                                                           over.get("snapshot_work_archive_sha256", SNAP_ARCHIVE))
        h, *_ = snap_hotel(pack, **kw)
        bad(f"snapshot_r1_{name}", description, h, SNAP_SHAPE.format(i=i, text=text))

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("snapshot", "room-a", 409, **snap_fields())
    bad("snapshot_r1_failed_snapshot_carries_members",
        "A snapshot that did not succeed carries the five members.", h,
        SNAP_SHAPE.format(i=2, text="a snapshot receipt that did not succeed carries snapshot members"))

    # ---- rule 2: the content hash recomputes
    h, *_ = snap_hotel(pack, s={"snapshot_content_sha256": "0" * 64}, f={"snapshot_content_sha256": "0" * 64})
    bad("snapshot_r2_content_hash_does_not_recompute",
        "The snapshot's content hash is not the hash of its image id and work archive hash.", h,
        "receipt 2: snapshot_content_sha256 does not recompute from snapshot_image_id and "
        "snapshot_work_archive_sha256")
    h, *_ = snap_hotel(pack, s={"snapshot_image_id": "sha256:" + "b" * 64})
    bad("snapshot_r2_image_id_changed_after_hashing",
        "The image id was changed and the old content hash kept.", h,
        "receipt 2: snapshot_content_sha256 does not recompute from snapshot_image_id and "
        "snapshot_work_archive_sha256")

    # ---- rule 4: repeats agree
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot", "room-a", 202, **snap_fields(archive=hashlib.sha256(b"archive 2").hexdigest()))
    bad("snapshot_r4_repeat_snapshot_disagrees_on_content",
        "One snapshot id signed twice in one binding with two different content hashes.", h,
        f"snapshot {SNAP_ID}: receipt 2 and receipt 3 disagree on snapshot_content_sha256")
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("create", "room-b", 200)
    h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot", "room-b", 202, **snap_fields())
    bad("snapshot_r4_repeat_snapshot_disagrees_on_source_room",
        "One snapshot id signed by two rooms in one binding.", h,
        f"snapshot {SNAP_ID}: receipt 3 and receipt 4 disagree on the source room")

    # ---- rule 5: the fork matches the snapshot it names
    other_hash = hashlib.sha256(b"archive 2").hexdigest()
    h, *_ = snap_hotel(pack, f={"snapshot_id": "snap_0123456789ac"}, with_delete=False)
    bad("snapshot_r5_fork_names_another_snapshot_id", "The fork's snapshot_id is not the named snapshot's.", h,
        "receipt 3: the fork names a snapshot receipt with another snapshot_id")
    h, *_ = snap_hotel(pack, f={"snapshot_content_sha256": snap_content(archive=other_hash)}, with_delete=False)
    bad("snapshot_r5_fork_names_another_content_hash", "The fork's content hash is not the named snapshot's.", h,
        "receipt 3: the fork names a snapshot receipt with another snapshot_content_sha256")
    h, *_ = snap_hotel(pack, f={"snapshot_source_sandbox_id": "room-z"}, with_delete=False)
    bad("snapshot_r5_fork_names_another_source_room",
        "The fork's source room is not the room that signed the named snapshot.", h,
        "receipt 3: the fork names a snapshot receipt of another room than snapshot_source_sandbox_id")
    h2 = pack.new_hotel()
    h2.sign("create", "room-a", 200)
    snap = h2.sign("snapshot", "room-a", 202, **snap_fields())
    h2.sign("create", "room-b", 200, **{**fork_fields(snap), "snapshot_receipt_sha256": h2.chain[0]["receipt_sha256"]})
    bad("snapshot_r5_fork_names_a_receipt_that_is_not_a_snapshot",
        "The fork's snapshot_receipt_sha256 is the hash of room A's create.", h2,
        "receipt 3: the fork names a receipt that is not a successful snapshot receipt")
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    failed = h.sign("snapshot", "room-a", 409)
    h.sign("create", "room-b", 200, **{**fork_fields(failed), "snapshot_id": SNAP_ID,
                                      "snapshot_content_sha256": snap_content()})
    bad("snapshot_r5_fork_names_a_failed_snapshot",
        "The fork names a snapshot receipt that did not succeed.", h,
        "receipt 3: the fork names a receipt that is not a successful snapshot receipt")
    # the named snapshot receipt has a higher sequence than the fork: signed apart, listed first
    late = pack.new_hotel()
    for _ in range(4):
        late.sign("create", "pad", 200)
    late_snap = late.sign("snapshot", "room-a", 202, **snap_fields())
    early = pack.new_hotel()
    early.sign("create", "pad", 200)
    early_fork = early.sign("create", "room-b", 200, **fork_fields(late_snap))
    bad("snapshot_r5_snapshot_has_a_later_sequence_than_the_fork",
        "The named snapshot receipt is listed before the fork but its signed sequence (5) is after the fork's (2).",
        early, "receipt 2: the fork names a snapshot receipt that does not come before it",
        receipts=[late_snap, early_fork], headed=False)

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    bare = h.sign("snapshot", "room-a", 202)
    h.sign("create", "room-b", 200, **fork_fields(bare))
    bad("snapshot_r5_fork_names_a_snapshot_receipt_that_states_no_snapshot",
        "A snapshot receipt with no snapshot members (a front without this change signs one) can never be a fork's "
        "source.", h, "receipt 3: the fork names a snapshot receipt that states no snapshot")
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("snapshot", "room-a", 202)
    good("snapshot_r1_successful_snapshot_without_members_passes_shapes",
         "A successful snapshot receipt with none of the five members is an honest receipt of a front that signs "
         "snapshot as a plain action.", h, {forks: []})
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    snap = h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("create", "room-b", 409, **fork_fields(snap))
    bad("snapshot_r1_create_that_did_not_succeed_carries_fork_members",
        "A create that failed carries the four fork members: a front adds them only to a successful create.", h,
        SNAP_SHAPE.format(i=3, text="a create that did not succeed carries snapshot fork members"))

    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    first = h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("create", "room-b", 200, **fork_fields(first))
    good("snapshot_r5_agreeing_retry_fork_names_the_first",
         "The snapshot was signed twice with the same hash; the fork names the first receipt, as the front does.", h,
         {forks: [FORK_ENTRY]})
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("snapshot", "room-a", 202, **snap_fields())
    second = h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("create", "room-b", 200, **fork_fields(second))
    bad("snapshot_r5_fork_names_a_later_signing_of_the_snapshot",
        "The snapshot was signed twice; the fork names the second receipt, but the front names the first.", h,
        "receipt 4: the fork names a snapshot receipt that is not the first to sign that snapshot "
        "(receipt 2 signed it first)")

    # ---- rule 7: a fork after a delete of the same snapshot
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    snap = h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot_delete", None, 200, **delete_fields())
    h.sign("create", "room-b", 200, **fork_fields(snap))
    bad("snapshot_r7_fork_after_delete",
        "A fork whose create comes after the snapshot's delete in the same binding.", h,
        f"receipt 4: the fork is of snapshot {SNAP_ID}, which receipt 3 deleted before it")
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    snap = h.sign("snapshot", "room-a", 202, **snap_fields())
    h.sign("snapshot_delete", None, 200, **delete_fields(source=None))
    h.sign("create", "room-b", 200, **fork_fields(snap))
    bad("snapshot_r7_fork_after_delete_without_source_member",
        "The delete does not name the source room: it still ends the snapshot's life in this binding.", h,
        f"receipt 4: the fork is of snapshot {SNAP_ID}, which receipt 3 deleted before it")
    h = pack.new_hotel()
    h.sign("snapshot_delete", None, 200, **delete_fields())
    h.sign("create", "room-b", 200, **fork_fields(pack_snapshot_stub(pack)))
    bad("snapshot_r7_fork_after_delete_when_the_snapshot_receipt_is_not_in_the_list",
        "The snapshot's receipt is in another list; the delete and the fork are here.", h,
        f"receipt 2: the fork is of snapshot {SNAP_ID}, which receipt 1 deleted before it")


def pack_snapshot_stub(pack: Pack) -> dict:
    """The snapshot receipt of room A as another list holds it: signed under the pack's binding at sequence 2."""
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    return h.sign("snapshot", "room-a", 202, **snap_fields())


def pack_fork_only(pack: Pack) -> Hotel:
    """Room B's own list: a fork create whose snapshot receipt is held by room A's list."""
    snap = pack_snapshot_stub(pack)
    h = pack.new_hotel()
    h.sign("create", "pad", 200)
    h.sign("create", "pad", 200)
    h.sign("create", "room-b", 200, **fork_fields(snap))
    return h


def pack_alone(pack: Pack) -> Hotel:
    h = pack.new_hotel()
    h.sign("create", "room-a", 200)
    h.sign("snapshot", "room-a", 409)
    return h


CASE_SETS = [numbering_cases, serial_cases, pool_cases, run_good_cases, run_bad_cases, run_hardening_cases, run_second_review_cases, run_validity_cases, run_form_cases, snapshot_cases]


def build(amd: dict[str, bytes]) -> dict[str, bytes]:
    pack = Pack(amd)
    for case_set in CASE_SETS:
        case_set(pack)
    files = {**pack.source_files(), **pack.files}
    lines = "".join(f"{path} {sha(data)}\n" for path, data in sorted(files.items()))
    files["MANIFEST.json"] = pretty({"files": {p: sha(d) for p, d in sorted(files.items())},
                                     "root_sha256": sha(lines.encode()),
                                     "root_rule": "sha256 of '<path> <sha256>' lines, sorted by path, "
                                                  "MANIFEST.json excluded"})
    return files


def read_amd() -> dict[str, bytes]:
    out = {}
    for name in ("certs.json", "report.json", "ark_sha256.txt"):
        path = HERE / "source" / "amd" / name
        if not path.exists():
            raise SystemExit("source/amd is missing: run generate.py --amd once")
        out[f"source/amd/{name}"] = path.read_bytes()
    return out


def verify_amd_material(files: dict[str, bytes]) -> None:
    """The committed chain still verifies, and its report commits to the shared binding."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    vr = load_checker()
    certs = {k: x509.load_der_x509_certificate(base64.b64decode(v))
             for k, v in json.loads(files["source/amd/certs.json"]).items()}
    vr.pss_verify(certs["ark"], certs["ark"])
    vr.pss_verify(certs["ark"], certs["ask"])
    vr.pss_verify(certs["ask"], certs["vcek"])
    ark_fp = sha(certs["ark"].public_bytes(serialization.Encoding.DER))
    if ark_fp != files["source/amd/ark_sha256.txt"].decode().strip():
        raise SystemExit("source/amd/ark_sha256.txt is not the ARK's hash")
    report = base64.b64decode(json.loads(files["source/amd/report.json"])["report_b64"])
    rep = vr.parse_report(report)
    att = shared_attestation(files["source/amd/report.json"])
    if rep["report_data"] != bytes.fromhex(att["binding_sha256"]) + bytes(32):
        raise SystemExit("the signed report does not commit to the shared binding")
    try:
        certs["vcek"].public_key().verify(encode_dss_signature(rep["sig_r"], rep["sig_s"]), report[:vr.SIGNED_LEN],
                                          ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        raise SystemExit("the signed report does not verify with the VCEK") from None
    # The checker's own offline path, the one a one-shot's file uses.
    try:
        vr.verify_amd(report, rep, "Milan", "", [ark_fp], json.loads(files["source/amd/certs.json"]))
    except vr.Fail as exc:
        raise SystemExit(f"the checker does not accept the synthetic chain: {exc}") from None


# ---------------------------------------------------------------- the exchange case

EXCHANGE = HERE.parent / "oneshot_exchange" / "good_basic"
EXCHANGE_README = """# One-shot exchange case: good_basic

One good run, the way the API sees it. The same directory is copied byte for byte into the API repository, and
neither side may change it alone: this checker's test says `expected/bundle.json` passes, and the API's test builds
the file from `machine/` and `caller/` and must get the same file.

- `machine/`: the answers as the broker hands them to the API (the API talks to the broker; the folder keeps its
  name), one file per call in call order. `NN_<call>.header` is the `X-Room-Receipt` header text (base64url of the
  canonical receipt JSON, with padding). `NN_<call>.response` is the answer body the API keeps; the first is the
  broker's 202 create document (`id` with the hotel prefix, `hotel`, `isolation`, and `create_request_b64`, the
  create bytes, which the broker returns when asked with `X-Broker-Return-Create-Request: 1`; that member is the one
  source of the create bytes). `exec_request.json` is the exec bytes the API sent; `hotel_attestation_answer.json` is the hotel's attestation
  answer; `amd/vcek_der.bin` is the VCEK as DER and `amd/cert_chain_pem.txt` is the chain as AMD's key server
  returns it (the ASK, then the ARK, as PEM).
- `caller/`: the POST body (with `content_b64`), the API's 202 answer (`oneshot_id`, `state`, `status_url`,
  `reserved_usd`), the recipe (its `create.ttl_seconds` is the timeout plus 600), the context file and the input.
  Outputs stay at or under 65,536 bytes: this version keeps them inline.
- `expected/bundle.json`: the one-shot file in the shapes of spec G4 5.5, in canonical JSON.
  `expected/check.json`: what `verify_receipts.py` prints for it (the command is in `case.json`).
- The run has one input, a context, one inline output, an exec answer, an env of one entry, a decimal-string
  `max_spend_usd`, and no `cwd` and no `user` (absent, never null).

The files are made by `tests/fixtures/receipt_lists_v2/generate.py`; `generate.py --check` rebuilds them byte for byte.
`MANIFEST.json` holds the sha256 of every other file and a root hash over the sorted `path hash` lines.
"""


def build_exchange(amd: dict[str, bytes]) -> dict[str, bytes]:
    """The files of the exchange case, by path under the case folder."""
    import subprocess
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pack = Pack(amd)
    hotel_answer = {"id": RUN_ROOM, "state": "running",
                    "network": {"mode": "deny_all", "policy": {"mode": "deny_all", "allow": []}}}
    put_answer = canonical({"written": True})

    def edit(r):
        r["request"].pop("cwd")
        r["request"]["inputs"] = [{"path": RUN_PATH, "mode": "755"}]
        r["request"]["outputs"] = [{"path": RESULT_PATH, "max_bytes": 65536, "optional": False}]

    def answered(answer):
        return {"result_sha256": sha(answer)}

    made, _ = make_run(pack, truth_edit=edit, held=(), inline=(RESULT_PATH,), overrides={
        "create": answered(canonical(hotel_answer)), "context": answered(put_answer), "in0": answered(put_answer),
        "end": answered(put_answer)})
    bundle = json.loads(made["bundle.json"])
    bundle["not_proven"] = []
    labels = ["create", "context_put", "input_put", "exec", "get_output", "end_marker_put"]
    # The broker's 202 document: the hotel's answer with the broker's members around it (broker/main.go: the id
    # gets the hotel prefix, then hotel and isolation, and create_request_b64 when the header asks for it).
    broker_answer = {**hotel_answer, "id": f"pack-hotel.{RUN_ROOM}", "hotel": "pack-hotel",
                     "isolation": {"hotel_sealed": True, "hotel_tee": "amd_sev_snp", "room_runtime": "runsc",
                                   "attested_per_room": False, "network_mode": "deny_all",
                                   "attestation_of_host": "/v1/hotels/pack-hotel/attestation"},
                     "create_request_b64": bundle["create_request_b64"]}
    answers = [canonical(broker_answer), put_answer, put_answer, base64.b64decode(bundle["exec_response_b64"]),
               FILE_BYTES[RESULT_PATH], put_answer]
    files: dict[str, bytes] = {}
    for i, (label, rc, answer) in enumerate(zip(labels, bundle["receipts"], answers), start=1):
        files[f"machine/{i:02d}_{label}.header"] = base64.urlsafe_b64encode(canonical(rc))
        files[f"machine/{i:02d}_{label}.response"] = answer
    files["machine/exec_request.json"] = base64.b64decode(bundle["exec_request_b64"])
    files["machine/hotel_attestation_answer.json"] = canonical(bundle["attestation"])
    certs = {k: x509.load_der_x509_certificate(base64.b64decode(v)) for k, v in pack.certs.items()}
    pem, der = serialization.Encoding.PEM, serialization.Encoding.DER
    files["machine/amd/vcek_der.bin"] = certs["vcek"].public_bytes(der)
    files["machine/amd/cert_chain_pem.txt"] = certs["ask"].public_bytes(pem) + certs["ark"].public_bytes(pem)
    recipe = json.loads(made["recipe.json"])["request"]
    post = {k: v for k, v in bundle["request"].items() if k != "inputs"}
    post["inputs"] = [{**i, "content_b64": b64(FILE_BYTES[i["path"]])} for i in bundle["request"]["inputs"]]
    files["caller/post_body.json"] = pretty(post)
    files["caller/response_202.json"] = pretty({"oneshot_id": RUN_ID, "state": "accepted",
                                                         "status_url": f"/v1/oneshots/{RUN_ID}",
                                                         "reserved_usd": "0.50"})
    files["caller/recipe.json"] = made["recipe.json"]
    files["caller/context.json"] = made["context.json"]
    files["caller/inputs/run.py"] = FILE_BYTES[RUN_PATH]
    files["expected/bundle.json"] = canonical(bundle)
    assert recipe["max_spend_usd"] == bundle["request"]["max_spend_usd"]
    args = ["--oneshot", "{dir}/expected/bundle.json", "--recipe", "{dir}/caller/recipe.json", "--context",
            "{dir}/caller/context.json", "--ark-sha256", pack.ark, "--expected-measurement", MEASUREMENT,
            "--input-file", f"{RUN_PATH}={{dir}}/caller/inputs/run.py"]
    files["case.json"] = pretty({"description": "One good run, as the API sees it, and the file it must build.",
                                 "args": args, "expect": {"exit_code": 0, "verdict": "PASS"}})
    with tempfile.TemporaryDirectory() as tmp:
        for path, data in files.items():
            (Path(tmp) / path).parent.mkdir(parents=True, exist_ok=True)
            (Path(tmp) / path).write_bytes(data)
        proc = subprocess.run([sys.executable, str(CHECKER), *[a.replace("{dir}", tmp) for a in args]],
                              capture_output=True, check=False)
    if proc.returncode != 0:
        raise SystemExit("the exchange run does not pass the checker: " + proc.stdout.decode())
    files["expected/check.json"] = proc.stdout
    files["README.md"] = EXCHANGE_README.encode()
    lines = "".join(f"{p} {sha(d)}\n" for p, d in sorted(files.items()))
    files["MANIFEST.json"] = pretty({"files": {p: sha(d) for p, d in sorted(files.items())},
                                     "root_sha256": sha(lines.encode()),
                                     "root_rule": "sha256 of '<path> <sha256>' lines, sorted by path, "
                                                  "MANIFEST.json excluded"})
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--amd", action="store_true")
    a = ap.parse_args()
    if a.amd:
        for path, data in make_amd().items():
            target = HERE / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        print("wrote source/amd; now run generate.py")
        return 0
    amd = read_amd()
    files = build(amd)
    exchange = build_exchange(amd)
    if a.check:
        verify_amd_material(files)
        bad = []
        for path, data in files.items():
            target = HERE / path
            if not target.is_file() or target.read_bytes() != data:
                bad.append(f"differs or missing: {path}")
        on_disk = {p.relative_to(HERE).as_posix() for p in HERE.rglob("*")
                   if p.is_file() and not (set(p.relative_to(HERE).parts) & SKIP)}
        bad += [f"extra file: {p}" for p in sorted(on_disk - set(files))]
        if (HERE / "MANIFEST.json").read_bytes() != files["MANIFEST.json"]:
            bad.append("differs or missing: MANIFEST.json")
        for path, data in exchange.items():
            target = EXCHANGE / path
            if not target.is_file() or target.read_bytes() != data:
                bad.append(f"differs or missing: oneshot_exchange/good_basic/{path}")
        held = {p.relative_to(EXCHANGE).as_posix() for p in EXCHANGE.rglob("*") if p.is_file()}
        bad += [f"extra file: oneshot_exchange/good_basic/{p}" for p in sorted(held - set(exchange))]
        if bad:
            print("\n".join(bad))
            return 1
        print(f"ok: {len(files)} files rebuilt byte for byte, and {len(exchange)} of the exchange case")
        return 0
    for path in sorted(on_disk_case_dirs()):
        for f in sorted(path.rglob("*"), reverse=True):
            if f.is_file():
                f.unlink()
            elif f.is_dir():
                f.rmdir()  # an emptied case folder must not outlive its case
    for path, data in files.items():
        target = HERE / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for f in sorted(EXCHANGE.rglob("*"), reverse=True) if EXCHANGE.is_dir() else []:
        if f.is_file():
            f.unlink()
        elif f.is_dir():
            f.rmdir()
    for path, data in exchange.items():
        target = EXCHANGE / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return 0


def on_disk_case_dirs():
    return [d for d in (HERE / "good", HERE / "bad") if d.is_dir()]


if __name__ == "__main__":
    sys.exit(main())
