#!/usr/bin/env python3
"""The sealed VM mailbox (AB#999 VM6, VM runtime spec r3 7.5): the 1 MiB raw disk the host and
the guest init share. This file is the one source of the layout and the record shapes; the
init's port must agree with tests/fixtures/vm_mailbox_v1.json.

Layout (offsets in bytes):
  [0, 64 KiB)         status  written by the guest init on every boot (its payload: VM1b)
  [64 KiB, 128 KiB)   offer   written by the guest init when the root disk is locked
  [128 KiB, 192 KiB)  answer  written by the host (vm-ctl.sh rewrap), only there
  [192 KiB, 1 MiB)    reserved, zero
A region is empty (every byte zero) or holds exactly one record:
  magic b"CVMMBX1\\0" (8) | kind u32 LE | length u32 LE | sha256(payload) (32) | payload | zero pad
The payload is canonical JSON: sorted keys, no spaces, printable ASCII strings, integers and
objects only. A record is written in one write of its whole region; a reader that finds a bad
sha256 (a torn write) treats the region as holding nothing and reads again later.

Guest rules: the init zeroes the offer and answer regions at the start of every boot, before
it reads the root disk, so an offer in the mailbox is always from the guest now running. The
host shows an offer only while the VM's unit is active and writes an answer only for the offer
it reads there (offer_sha256).

Everything read from the mailbox is guest-controlled: the parsers here are strict and bounded,
and a value they return is still only data (status, broker and API pass it on, never trust it)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct

MAILBOX_BYTES = 1 << 20
REGION_BYTES = 64 << 10
STATUS_OFFSET = 0
OFFER_OFFSET = 64 << 10
ANSWER_OFFSET = 128 << 10
MAGIC = b"CVMMBX1\0"
HEADER = struct.Struct("<8sII32s")  # magic, kind, payload length, sha256(payload): 48 bytes
PAYLOAD_MAX = REGION_BYTES - HEADER.size
KIND_STATUS, KIND_OFFER, KIND_ANSWER = 1, 2, 3
REGION_KIND = {STATUS_OFFSET: KIND_STATUS, OFFER_OFFSET: KIND_OFFER, ANSWER_OFFSET: KIND_ANSWER}

OFFER_SCHEMA = "cathedral.vm.rewrap-offer/v1"
ANSWER_SCHEMA = "cathedral.vm.rewrap-answer/v1"
# The hotel key install envelope (docs/SEALED_DATA_VOLUME.md, phase 2 step 4): X25519 to the
# offer key, HKDF-SHA256, AES-256-GCM over the 32-byte recovery key with the offer's sha256 as AAD.
ANSWER_ALGORITHM = "x25519-hkdf-sha256-aes-256-gcm"
# What vm-ctl.sh rewrap takes on stdin: the broker and the host both refuse a longer answer.
ANSWER_MAX = 4096
SNP_REPORT_BYTES = 1184  # an SEV-SNP attestation report (versions 2, 3 and 5)
# Field: decoded byte length (base64 fields) or None (the fixed strings and the hex digest).
OFFER_FIELDS = {"schema": None, "x25519_public_b64": 32, "offer_nonce_b64": 32, "report_b64": SNP_REPORT_BYTES}
ANSWER_FIELDS = {"schema": None, "algorithm": None, "offer_sha256": None,
                 "ephemeral_public_b64": 32, "nonce_b64": 12, "ciphertext_b64": 48}
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class Refusal(Exception):
    """A record or a document that is not exactly one of the shapes here."""


def need(condition: object, message: str) -> None:
    if not condition:
        raise Refusal(message)


def _check_value(value: object) -> None:
    if type(value) is str:
        need(all(0x20 <= ord(c) <= 0x7E for c in value), "strings must be printable ASCII")
    elif type(value) is int:
        pass
    elif type(value) is dict:
        for key, item in value.items():
            need(type(key) is str, "object keys must be strings")
            _check_value(key)
            _check_value(item)
    else:
        raise Refusal("only integers, strings and objects are allowed")


def canonical(doc: dict) -> bytes:
    """The payload bytes of a document (the vm_measure.canonical rules)."""
    need(type(doc) is dict, "a payload is a JSON object")
    _check_value(doc)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("ascii")


def _no_duplicates(pairs: list) -> dict:
    doc = {}
    for key, value in pairs:
        need(key not in doc, "a key appears twice")
        doc[key] = value
    return doc


def parse_json(raw: bytes, limit: int, label: str) -> dict:
    """One ASCII JSON object of at most limit bytes, no duplicate keys."""
    need(type(raw) is bytes and 0 < len(raw) <= limit, f"{label}: must be 1 to {limit} bytes")
    try:
        doc = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Refusal(f"{label}: not one ASCII JSON object") from exc
    need(type(doc) is dict, f"{label}: not one JSON object")
    return doc


# ---- records -----------------------------------------------------------------------

def encode_record(kind: int, payload: bytes) -> bytes:
    """The whole region holding one record: what a writer writes in one call."""
    need(kind in REGION_KIND.values(), "unknown record kind")
    need(0 < len(payload) <= PAYLOAD_MAX, "the payload does not fit a region")
    head = HEADER.pack(MAGIC, kind, len(payload), hashlib.sha256(payload).digest())
    return head + payload + bytes(REGION_BYTES - HEADER.size - len(payload))


def decode_record(region: bytes, kind: int) -> bytes | None:
    """The payload of the region's record; None for an empty region. Anything else refuses:
    a wrong size, magic, kind or length, a sha256 that does not match, or bytes after the payload."""
    need(type(region) is bytes and len(region) == REGION_BYTES, "a region is 64 KiB")
    if not any(region):
        return None
    magic, got_kind, length, digest = HEADER.unpack_from(region)
    need(magic == MAGIC, "bad magic")
    need(got_kind == kind, "another record kind")
    need(0 < length <= PAYLOAD_MAX, "bad payload length")
    payload = region[HEADER.size:HEADER.size + length]
    need(hashlib.sha256(payload).digest() == digest, "the payload does not match its sha256")
    need(not any(region[HEADER.size + length:]), "bytes after the payload")
    return payload


def _b64(value: object, size: int, label: str) -> bytes:
    need(type(value) is str, f"{label}: a base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise Refusal(f"{label}: not base64") from None
    need(len(raw) == size and base64.b64encode(raw).decode("ascii") == value,
         f"{label}: must be the padded base64 of {size} bytes")
    return raw


def _fields(doc: dict, expected: dict, label: str) -> None:
    need(set(doc) == set(expected), f"{label}: fields must be exactly {', '.join(sorted(expected))}")
    for key, size in expected.items():
        if size is not None:
            _b64(doc[key], size, f"{label} {key}")


# ---- the offer (guest to customer) ----------------------------------------------------

def parse_offer(payload: bytes) -> dict:
    """An offer payload: canonical, exactly the offer fields, every value its fixed length."""
    doc = parse_json(payload, PAYLOAD_MAX, "offer")
    need(canonical(doc) == payload, "offer: not canonical JSON")
    _fields(doc, OFFER_FIELDS, "offer")
    need(doc["schema"] == OFFER_SCHEMA, "offer: unknown schema")
    return doc


def offer_sha256(offer: dict) -> str:
    """The sha256 of the offer's report: the AAD the customer tool wraps with (spec 7.5 step 3),
    and the name an answer gives the offer it is for. The report binds the key and the nonce
    through its REPORT_DATA, so it names the whole offer."""
    return hashlib.sha256(base64.b64decode(offer["report_b64"])).hexdigest()


def read_offer(region: bytes) -> dict | None:
    """The offer in the offer region, or None (empty, torn or malformed: nothing waits)."""
    try:
        payload = decode_record(region, KIND_OFFER)
        return None if payload is None else parse_offer(payload)
    except Refusal:
        return None


# ---- the answer (customer to guest) -----------------------------------------------------

def parse_answer(raw: bytes) -> dict:
    """What rewrap takes on stdin: one JSON object of at most ANSWER_MAX bytes, any key order,
    exactly the answer fields. Its record payload is canonical(parse_answer(raw))."""
    doc = parse_json(raw, ANSWER_MAX, "answer")
    _fields(doc, ANSWER_FIELDS, "answer")
    need(doc["schema"] == ANSWER_SCHEMA, "answer: unknown schema")
    need(doc["algorithm"] == ANSWER_ALGORITHM, f"answer: algorithm must be {ANSWER_ALGORITHM}")
    need(type(doc["offer_sha256"]) is str and HEX64_RE.fullmatch(doc["offer_sha256"]),
         "answer: offer_sha256 is 64 lowercase hex")
    return doc


def answer_region(doc: dict) -> bytes:
    return encode_record(KIND_ANSWER, canonical(doc))
