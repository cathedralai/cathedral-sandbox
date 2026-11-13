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
                         re-verify the synthetic AMD chain with the checker
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

    def new_hotel(self) -> "Hotel":
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


def hotel_case(pack: Pack, kind: str, name: str, description: str, doc, expect: dict) -> None:
    exp = {"exit_code": 0, "verdict": "PASS"} if kind == "good" else {"exit_code": 1, "verdict": "FAIL"}
    exp.update(expect)
    pack.add(kind, name, {"attestation_doc.json": pretty(pack.attestation), "receipts.json": pretty(doc)},
             {"description": description, "args": HOTEL_ARGS, "expect": exp})


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
                   "/checked": "whole chain to the head the server named; room room-old has receipts with and "
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
    def bad_hotel(*rooms_actions):
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


CASE_SETS = [numbering_cases, serial_cases]


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
