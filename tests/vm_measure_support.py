"""Deterministic bundle files for the VM measurement vectors (tests/fixtures/vm_measure_v1.json).

The files are made from recipes, not committed as binaries. They are not bootable:
they only have to be inputs sev-snp-measure accepts. The OVMF image is a filler
with the parts sev-snp-measure 0.0.12 reads (ovmf.py): the footer GUID table at
end - 32, the SEV hashes table entry, the SEV-ES reset block and an ASEV metadata
header with one section of each SNP type it measures.
"""
from __future__ import annotations

import hashlib
import json
import struct
import uuid
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vm_measure_v1.json"

FOOTER_GUID = "96b582de-1fb2-45f7-baea-a366c55a082d"
HASH_TABLE_GUID = "7255371f-3a3b-4b04-927b-1da6efa8d454"
RESET_BLOCK_GUID = "00f771de-1a7e-4fcb-890e-68c77e2fb44e"
METADATA_GUID = "dc886566-984a-4798-a75e-5585a7bf67cc"
OVMF_SIZE = 0x10000
METADATA_FROM_END = 0x800
# (gpa, size, type): SNP_SEC_MEM 1, SNP_SECRETS 2, CPUID 3, SNP_KERNEL_HASHES 0x10.
SECTIONS = ((0x800000, 0xC000, 1), (0x80D000, 0x1000, 2), (0x80E000, 0x1000, 3), (0x80F000, 0x1000, 0x10))
HASH_TABLE_GPA = 0x80FC00
RESET_EIP = 0xFFFFF000


def fill(label: str, size: int) -> bytes:
    """sha256(label || uint32_be(i)) for i = 0, 1, ... cut to size."""
    out = bytearray()
    i = 0
    while len(out) < size:
        out += hashlib.sha256(label.encode() + struct.pack(">I", i)).digest()
        i += 1
    return bytes(out[:size])


def _entry(guid: str, data: bytes) -> bytes:
    return data + struct.pack("<H", len(data) + 18) + uuid.UUID(guid).bytes_le


def synthetic_ovmf() -> bytes:
    image = bytearray(fill("cathedral-vm-test-ovmf", OVMF_SIZE))
    meta = b"ASEV" + struct.pack("<III", 16 + 12 * len(SECTIONS), 1, len(SECTIONS))
    meta += b"".join(struct.pack("<III", *s) for s in SECTIONS)
    start = OVMF_SIZE - METADATA_FROM_END
    image[start:start + len(meta)] = meta
    table = (_entry(METADATA_GUID, struct.pack("<I", METADATA_FROM_END))
             + _entry(RESET_BLOCK_GUID, struct.pack("<I", RESET_EIP))
             + _entry(HASH_TABLE_GUID, struct.pack("<II", HASH_TABLE_GPA, 0x400)))
    footer = struct.pack("<H", len(table) + 18) + uuid.UUID(FOOTER_GUID).bytes_le
    end = OVMF_SIZE - 32
    image[end - len(footer) - len(table):end] = table + footer
    return bytes(image)


def file_bytes(recipe: dict) -> bytes:
    if recipe["recipe"] == "synthetic-ovmf-v1":
        return synthetic_ovmf()
    if recipe["recipe"] == "fill":
        return fill(recipe["label"], recipe["bytes"])
    if recipe["recipe"] == "text":
        return recipe["text"].encode("ascii")
    raise ValueError(f"unknown recipe {recipe['recipe']}")


def load() -> dict:
    return json.loads(FIXTURE.read_text())


def materialize(vectors: dict, directory: Path, family: str) -> Path:
    """Write one bundle directory of the vectors (files and that family's manifest)."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, recipe in vectors["files"].items():
        data = file_bytes(recipe)
        assert hashlib.sha256(data).hexdigest() == recipe["sha256"], f"recipe of {name} drifted"
        assert len(data) == recipe["bytes"], f"recipe of {name} drifted"
        (directory / name).write_bytes(data)
    (directory / "manifest.json").write_bytes(vectors["bundles"][family]["manifest_utf8"].encode("ascii"))
    return directory
