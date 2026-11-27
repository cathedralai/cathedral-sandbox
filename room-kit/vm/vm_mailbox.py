#!/usr/bin/env python3
"""The sealed VM mailbox (AB#999 VM6, VM runtime spec r3 7.5): the 1 MiB raw disk the host and
the guest init share. This file is the one source of the layout and the record and body shapes;
the init's port must agree with tests/fixtures/vm_mailbox_v1.json.

Slots (offsets in bytes; the rest of the file is zero and unused):
  [0, 64 KiB)         status  written by the guest init on every boot (7.2 step 5)
  [64 KiB, 128 KiB)   offer   written by the guest init when its root disk is locked
  [128 KiB, 192 KiB)  answer  written by the host (vm-ctl.sh rewrap), only there
A slot is empty (its header all zero) or holds one record, written in one write at the slot's
offset: magic b"CVMMBX1\\0" (8) | kind (1) | body length (4, big-endian) | sha256(body) (32) | body.
The body is canonical JSON (vm_measure.canonical, D 8.1), at most 64 KiB minus the 45-byte
header for status and offer, 4096 bytes for the answer.

Everything the guest writes is untrusted. A reader checks the magic, the kind, the length bound
and the sha256 (a mismatch is a torn read: the writer is mid-write, so the host retries); then
a bounded pre-scan refuses any nesting before the parser runs; then the keys must be exactly the
schema's, each with its type and length. Any failure of any kind, after the retries, is an empty
slot (read_slot catches every exception): it never fails status, list or another VM.

Guest rules: the init zeroes the offer slot on every boot that is not waiting for an answer, and
ignores an answer whose offer_sha256 is not its current offer's."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm_measure  # noqa: E402

MAILBOX_BYTES = 1 << 20
SLOT_BYTES = 64 << 10
STATUS_OFFSET, OFFER_OFFSET, ANSWER_OFFSET = 0, 64 << 10, 128 << 10
MAGIC = b"CVMMBX1\0"
HEADER = struct.Struct(">8sBI32s")  # magic, kind, body length, sha256(body): 45 bytes
KIND_STATUS, KIND_OFFER, KIND_ANSWER = 1, 2, 3
SLOT_KIND = {STATUS_OFFSET: KIND_STATUS, OFFER_OFFSET: KIND_OFFER, ANSWER_OFFSET: KIND_ANSWER}
ANSWER_MAX = 4096  # what vm-ctl.sh rewrap takes on stdin; the broker refuses a longer answer too
BODY_MAX = {KIND_STATUS: SLOT_BYTES - HEADER.size, KIND_OFFER: SLOT_BYTES - HEADER.size, KIND_ANSWER: ANSWER_MAX}
SNP_REPORT_BYTES = 1184  # an SEV-SNP attestation report

STATUS_SCHEMA = "cathedral.vm.status/v1"
OFFER_SCHEMA = "cathedral.vm.rewrap-offer/v1"
ANSWER_SCHEMA = "cathedral.vm.rewrap-answer/v1"
HEX64_RE = re.compile(r"[0-9a-f]{64}")
STATE_RE = re.compile(r"[a-z]{1,16}")  # the init's disk state: new, open, locked, tampered, broken
KEY_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def b64(size: int):
    return ("b64", size)


# Each schema's fields: a fixed string, a regex, or ("b64", decoded byte length).
SCHEMAS = {
    KIND_STATUS: {"schema": STATUS_SCHEMA, "state": STATE_RE, "key_id": KEY_ID_RE, "report": b64(SNP_REPORT_BYTES)},
    KIND_OFFER: {"schema": OFFER_SCHEMA, "vm_id": vm_measure.VM_ID_RE, "pubkey": b64(32), "nonce": b64(32),
                 "report": b64(SNP_REPORT_BYTES)},
    KIND_ANSWER: {"schema": ANSWER_SCHEMA, "offer_sha256": HEX64_RE, "epk": b64(32), "nonce": b64(12),
                  "ct": b64(48)},
}


class Refusal(ValueError):
    """A record or a body that is not exactly one of the shapes here."""


class Torn(Refusal):
    """A header or sha256 that does not check: the writer may be mid-write; read again."""


def need(condition: object, message: str, error: type = Refusal) -> None:
    if not condition:
        raise error(message)


# ---- records -------------------------------------------------------------------------------

def encode_slot(kind: int, body: bytes) -> bytes:
    """The whole slot holding one record (zero after the body): what a writer writes in one call."""
    need(kind in BODY_MAX, "unknown record kind")
    need(0 < len(body) <= BODY_MAX[kind], "the body is over its slot's bound")
    return HEADER.pack(MAGIC, kind, len(body), hashlib.sha256(body).digest()) + body + \
        bytes(SLOT_BYTES - HEADER.size - len(body))


def decode_slot(slot: bytes, kind: int) -> bytes | None:
    """The body of the slot's record; None for an empty slot (header all zero). Raises Torn for a
    wrong magic, kind, length or sha256."""
    need(type(slot) is bytes and len(slot) == SLOT_BYTES, "a slot is 64 KiB")
    head = slot[:HEADER.size]
    if not any(head):
        return None
    magic, got_kind, length, digest = HEADER.unpack(head)
    need(magic == MAGIC, "bad magic", Torn)
    need(got_kind == kind, "another record kind", Torn)
    need(0 < length <= BODY_MAX[kind], "a length over the bound", Torn)
    body = slot[HEADER.size:HEADER.size + length]
    need(hashlib.sha256(body).digest() == digest, "the body does not match its sha256", Torn)
    return body


# ---- bodies --------------------------------------------------------------------------------

def prescan(body: bytes, limit: int) -> None:
    """One bounded pass before any parser: a flat object. Strings are printable ASCII (escapes
    tracked), and outside strings there is no '[' or '{' after the opening brace and nothing after
    the closing one. So the parser never sees nesting, whatever the body's size."""
    need(type(body) is bytes and 0 < len(body) <= limit, f"a body is 1 to {limit} bytes")
    need(body[0] == 0x7B, "a body is one JSON object")
    in_string = escaped = False
    end = len(body) - 1
    for i in range(1, len(body)):
        c = body[i]
        if in_string:
            need(0x20 <= c <= 0x7E, "strings are printable ASCII")
            if escaped:
                escaped = False
            elif c == 0x5C:
                escaped = True
            elif c == 0x22:
                in_string = False
        elif c == 0x22:
            in_string = True
        elif c in (0x5B, 0x7B):
            raise Refusal("a body has no nested array or object")
        elif c == 0x7D:
            need(i == end, "nothing follows the closing brace")
    need(not in_string and body[end] == 0x7D, "a body is one closed JSON object")


def _no_duplicates(pairs: list) -> dict:
    doc = {}
    for key, value in pairs:
        need(key not in doc, "a key appears twice")
        doc[key] = value
    return doc


def parse_body(body: bytes, kind: int) -> dict:
    """A canonical body of kind: pre-scanned, parsed, then exactly its schema's keys and values."""
    prescan(body, BODY_MAX[kind])
    try:
        doc = json.loads(body.decode("ascii"), object_pairs_hook=_no_duplicates)
        need(type(doc) is dict and vm_measure.canonical(doc) == body, "not canonical JSON")
    except Refusal:
        raise
    except Exception as exc:  # vm_measure.Refusal, ValueError, RecursionError: all one refusal
        raise Refusal(f"not one canonical JSON object ({type(exc).__name__})") from None
    schema = SCHEMAS[kind]
    need(set(doc) == set(schema), f"fields must be exactly {', '.join(sorted(schema))}")
    for key, rule in schema.items():
        value = doc[key]
        need(type(value) is str, f"{key} is a string")
        if isinstance(rule, str):
            need(value == rule, f"{key} must be {rule}")
        elif isinstance(rule, tuple):
            try:
                raw = base64.b64decode(value, validate=True)
            except (binascii.Error, ValueError):
                raise Refusal(f"{key} is not base64") from None
            need(len(raw) == rule[1] and base64.b64encode(raw).decode("ascii") == value,
                 f"{key} must be the padded base64 of {rule[1]} bytes")
        else:
            need(rule.fullmatch(value), f"{key} does not match {rule.pattern}")
    return doc


def parse_answer(raw: bytes) -> dict:
    """What rewrap takes on stdin: the answer envelope, canonical, at most ANSWER_MAX bytes. These
    exact bytes become the answer record's body."""
    return parse_body(raw, KIND_ANSWER)


def body_sha256(body: bytes) -> str:
    """An offer's name: the sha256 of its body, which holds the report (spec 7.5 step 3, the AAD),
    as in the offer record's header."""
    return hashlib.sha256(body).hexdigest()
