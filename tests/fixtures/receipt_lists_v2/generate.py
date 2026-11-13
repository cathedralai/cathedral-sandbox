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
  generate.py            write every file
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

def make_amd() -> dict[str, bytes]:
    """ARK, ASK and VCEK (RSA-PSS SHA-384, as AMD's are) and one report signed by the VCEK."""
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


NUMBERING_PROVES = "No receipt of this room is missing from this list, between its first receipt and its last."
NUMBERING_DOES_NOT_PROVE = ("That nothing was still running in the room when the list was read, or that no receipt "
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
                   "/chain/room_numbering/proves/0": NUMBERING_PROVES,
                   "/chain/room_numbering/does_not_prove/0": NUMBERING_DOES_NOT_PROVE}})
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
                   f"{room}/room-s/alive_at_last_action": True, "/chain/room_numbering/proves/0": sentence}})

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
                   f"{pools}/pool-1/proves/0": POOL_WORDS, "/room_links/pool-1": CLAIM_ID,
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
UNICODE_PATH = "/work/in/a b+c&d=e%f~ü.txt"
CONTEXT = {"submission": "sub-0001", "note": "café"}
FILE_BYTES = {RUN_PATH: b"print('ok')\n", DATA_PATH: b"a,b\n1,2\n", UNICODE_PATH: b"unicode path input\n",
              RESULT_PATH: b'{"ok":true}\n', LOG_PATH: b"done\n"}
DEL = object()  # an override value that removes the field


def base_recipe() -> dict:
    return {
        "schema": "cathedral_oneshot_recipe_v1",
        "request": {
            "image": IMAGE_REF, "command": ["python", RUN_PATH], "env": {"MODE": "check"}, "cwd": "/work",
            "size": "small", "timeout_seconds": 60, "network": {"mode": "deny_all", "allow": []},
            "outputs": [{"path": RESULT_PATH, "max_bytes": 1048576, "optional": False},
                        {"path": LOG_PATH, "max_bytes": 65536, "optional": True}],
            "inputs": [{"path": RUN_PATH, "mode": "755"}, {"path": DATA_PATH, "mode": "644"}]},
        "create": {"resources": {"cpus": 1, "memory_mb": 512}, "ttl_seconds": 300, "broker_guest": "guest-1",
                   "image_id": IMAGE_ID},
        "file_modes": {"context": "644", "end_marker": "644"}}


def enc(pairs: dict[str, str]) -> str:
    """The query as the machine's front signs it: sorted keys, quote_plus values (Go's url.Values.Encode)."""
    from urllib.parse import quote_plus
    return "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in sorted(pairs.items()))


def put_target(room: str, mode: str, path: str) -> str:
    return f"PUT /v1/sandboxes/{room}/files?{enc({'mode': mode, 'path': path})}"


def get_target(room: str, max_bytes: int, path: str) -> str:
    return f"GET /v1/sandboxes/{room}/files?{enc({'max_bytes': str(max_bytes), 'path': path})}"


def normal_network(net) -> dict:
    if isinstance(net, dict) and net.get("mode"):
        return net
    return {"mode": "deny_all", "allow": []}


def step(role: str, action: str, target: str, status: int = 200, **fields) -> dict:
    return {"role": role, "action": action, "target": target, "status": status, "fields": fields}


def make_run(pack: Pack, *, truth_edit=None, recipe_edit=None, context=None, overrides=None, steps_edit=None,
             drop=(), create_body=None, exec_body=None, bundle_edit=None, args_edit=None, absent=(),
             held=(RESULT_PATH,), inline=(LOG_PATH,), held_bytes=None, caller_hashes=None, exec_response="proven",
             numbered=True, room=RUN_ROOM, no_context_arg=False, input_files=(), truth_context=None,
             extra_files=None):
    recipe = base_recipe()
    if truth_edit:
        truth_edit(recipe)
    checker_recipe = json.loads(json.dumps(recipe))
    if recipe_edit:
        recipe_edit(checker_recipe)
    req, cr, modes = recipe["request"], recipe["create"], recipe["file_modes"]
    ctx = CONTEXT if truth_context is None else truth_context
    outputs_bytes = {o["path"]: (None if o["path"] in absent else FILE_BYTES.get(o["path"], b"output\n"))
                     for o in req["outputs"]}
    labels = {"cathedral_sandbox_id": RUN_ID, "cathedral_serial": "1",
              "broker_guest": cr.get("broker_guest", "guest-2"), "broker_batch": BATCH_ID}
    body = {"image": req["image"], "resources": cr["resources"], "network": normal_network(req.get("network")),
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
    exec_resp = canonical({"exit_code": 0, "stdout": "", "stderr": ""})
    policy = normal_network(req.get("network"))
    policy = {"mode": policy["mode"], "allow": policy.get("allow", [])}
    steps = [step("create", "create", "POST /v1/sandboxes", 202, image=req["image"], image_digest=IMAGE_ID,
                  network_policy=policy, network_policy_sha256=sha(canonical(policy)),
                  cathedral_sandbox_id=RUN_ID, serial=True, customer_request_sha256=sha(create_bytes)),
             step("context", "file_put", put_target(room, modes.get("context", "644"), CONTEXT_PATH), 200,
                  customer_request_sha256=sha(canonical(ctx)))]
    for i, inp in enumerate(req["inputs"]):
        steps.append(step(f"in{i}", "file_put", put_target(room, inp.get("mode", "644"), inp["path"]), 200,
                          customer_request_sha256=sha(FILE_BYTES.get(inp["path"], b"input\n"))))
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
                target["fields"].pop(key, None)
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

    in_hash = {i["path"]: sha(FILE_BYTES.get(i["path"], b"input\n")) for i in req["inputs"]}
    request = {"image": req["image"], "command": req["command"], "env": req["env"], "size": req["size"],
               "timeout_seconds": req["timeout_seconds"], "outputs": req["outputs"], "context": ctx,
               "inputs": [{"path": i["path"], "mode": i.get("mode", "644"), "sha256": in_hash[i["path"]]}
                          for i in req["inputs"]], "max_spend_usd": 5}
    for key in ("cwd", "user", "network"):
        if key in req:
            request[key] = req[key]
    if "image_id" in cr:
        request["image_id"] = cr["image_id"]
    bundle = {"schema": "cathedral_oneshot_bundle_v1", "oneshot_id": RUN_ID, "request": request,
              "attestation": json.loads(json.dumps(pack.attestation)), "amd_certs": dict(pack.certs),
              "receipts": chain,
              "create_request_b64": b64(create_bytes), "exec_request_b64": b64(exec_bytes),
              "inline_outputs": {p: b64(outputs_bytes[p]) for p in inline if outputs_bytes.get(p) is not None}}
    if exec_response != "unproven":
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
            files[f"inputs/{len(hashes)}.bin"] = FILE_BYTES.get(path, b"input\n")
            args += ["--input-file", f"{path}={{dir}}/inputs/{len(hashes)}.bin"]
            hashes[path] = digest
            continue
        given = (caller_hashes or {}).get(path, digest)
        if given is not None:
            args += ["--input-sha256", f"{path}={given}"]
            hashes[path] = given
    files["inputs.json"] = pretty(hashes)
    files.update(extra_files or {})
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
    run_case(pack, "good", "run_held_output_proven_exit_code",
             "A run whose result file is held by the checker, whose log is in the file, and whose exec answer proves "
             "the exit code.", {"pointers": {
                 f"{run}/oneshot_id": RUN_ID, f"{run}/room": RUN_ROOM, f"{run}/outputs/0/state": "present",
                 f"{run}/outputs/0/sha256": sha(FILE_BYTES[RESULT_PATH]), f"{run}/outputs/0/bytes": "held",
                 f"{run}/outputs/1/bytes": "held", f"{run}/exit_code/status": "proven", f"{run}/exit_code/value": 0,
                 f"{run}/image/compared_with_recipe": True, "/room_links/run-room-1": RUN_ID,
                 "/chain/room_numbering/rooms/run-room-1/serial": True,
                 "/chain/room_numbering/rooms/run-room-1/receipts": 8}})
    run_case(pack, "good", "run_output_receipt_only",
             "No output bytes are held: each output line says receipt only.",
             {"pointers": {f"{run}/outputs/0/bytes": "receipt_only", f"{run}/outputs/1/bytes": "receipt_only"}},
             held=(), inline=())
    run_case(pack, "good", "run_optional_output_absent", "An optional output the run did not write: reported absent.",
             {"pointers": {f"{run}/outputs/1/state": "absent", f"{run}/outputs/0/state": "present"}},
             absent=(LOG_PATH,), inline=())
    run_case(pack, "good", "run_exit_code_not_proven",
             "The file holds no exec answer: the exit code is not proven and the verdict is still PASS.",
             {"pointers": {f"{run}/exit_code/status": "not proven"}}, exec_response="unproven")
    run_case(pack, "good", "run_exit_code_answer_not_the_signed_one",
             "An exec answer that does not hash to the receipt's result: not proven, still PASS.",
             {"pointers": {f"{run}/exit_code/status": "not proven"}}, exec_response="mismatch")

    def unicode_input(r):
        r["request"]["inputs"].append({"path": UNICODE_PATH, "mode": "600"})
    run_case(pack, "good", "run_path_with_space_and_unicode",
             "An input whose path holds a space, +, &, =, %, ~ and a non-ASCII letter: the signed target is the "
             "sorted, plus-for-space form.", {}, truth_edit=unicode_input)
    run_case(pack, "good", "run_input_given_as_file", "The caller gives an input as a file, not a hash.", {},
             input_files=(RUN_PATH,))
    run_case(pack, "good", "run_no_context", "A run with no context: the checker is told --no-context.", {},
             truth_context={}, no_context_arg=True)

    def no_network_no_guest(r):
        r["request"].pop("network")
        r["create"].pop("broker_guest")
        r["create"].pop("image_id")
    run_case(pack, "good", "run_network_left_out_no_image_id",
             "A recipe with no network, no broker_guest and no image_id: the network is deny_all in the broker's "
             "form, the signed image_digest is reported and not compared.",
             {"pointers": {f"{run}/image/compared_with_recipe": False}}, truth_edit=no_network_no_guest)
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
    get0 = get_target(RUN_ROOM, 1048576, RESULT_PATH)
    big = get_target(RUN_ROOM, 2097152, RESULT_PATH)
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
        recipe_edit=lambda r: r["create"].update(image_id="sha256:" + "22" * 32))
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
    bad("run_c4_size", "The create's resources are not the recipe's.", fail(4, "the create's resources are not the recipe's"),
        create_body=lambda body: {**body, "resources": {"cpus": 4, "memory_mb": 512}})
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
        fail(4, "the create bytes hold the number 300.0, which is not an integer"),
        create_body=lambda body: canonical(body).replace(b'"ttl_seconds":300', b'"ttl_seconds":300.0'))

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
        recipe_edit=lambda r: r["request"].update(timeout_seconds=61))
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
        fail(7, f"the bytes held for {LOG_PATH} do not hash to the receipt's result_sha256"),
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
    bad("run_c8_context", "The request in the file holds another context.",
        fail(8, "the request in the file differs from the recipe in context"),
        bundle_edit=lambda b: b["request"].update(context={"submission": "another"}))
    bad("run_c8_unknown_key", "The request holds a key that is not a request field.",
        fail(8, "the request holds a key that is not a request field: extra"),
        bundle_edit=lambda b: b["request"].update(extra=1))
    bad("run_c8_no_request", "The file holds no request.", fail(8, "the file holds no request"),
        bundle_edit=lambda b: b.pop("request"))


CASE_SETS = [numbering_cases, serial_cases, pool_cases, run_good_cases, run_bad_cases]


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
        if bad:
            print("\n".join(bad))
            return 1
        print(f"ok: {len(files)} files rebuilt byte for byte")
        return 0
    for path in sorted(on_disk_case_dirs()):
        for f in path.rglob("*"):
            if f.is_file():
                f.unlink()
    for path, data in files.items():
        target = HERE / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return 0


def on_disk_case_dirs():
    return [d for d in (HERE / "good", HERE / "bad") if d.is_dir()]


if __name__ == "__main__":
    sys.exit(main())
