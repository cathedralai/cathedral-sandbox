#!/usr/bin/env python3
"""Vectors for the sealed VM root disk key (AB#999, VM runtime spec r3 7.2 step 2).

The VM init (room-kit/custom-guest/internal/vmkey) ports sealed_data_key.py's
key derivation with another salt:

  passphrase = HKDF-SHA256(chip_key, salt "cathedral-vm-root-v1",
                           info "luks2-passphrase\\0" || field_select (8 bytes LE) || HOST_DATA, 32)
  key_id     = HKDF-SHA256(chip_key, same salt, "key-id\\0" || same context, 8), hex

This script computes them with sealed_data_key.hkdf and sealed_data_key._context,
imported read-only from room-kit/sealed/sealed_data_key.py. That file ships in the
measured kit image (build-guest.sh), so it is never edited for the VM: a byte change
there would move every hotel data key. HOST_DATA comes from the identities of
tests/fixtures/vm_measure_v1.json; the chip keys are fakes.

  make_vm_root_key_vectors.py           print the vectors
  make_vm_root_key_vectors.py --write   write tests/fixtures/vm_root_key_v1.json
  make_vm_root_key_vectors.py --check   exit 1 unless the fixture equals the vectors
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEALED_DATA_KEY = ROOT / "room-kit" / "sealed" / "sealed_data_key.py"
MEASURE_VECTORS = ROOT / "tests" / "fixtures" / "vm_measure_v1.json"
FIXTURE = ROOT / "tests" / "fixtures" / "vm_root_key_v1.json"

VM_SALT = b"cathedral-vm-root-v1"
# Fake chip keys: the 32 bytes MSG_KEY_RSP would carry. Never a real key.
CHIP_KEYS = {
    "fake-1": bytes(range(32)),
    "fake-2": bytes(range(0xA0, 0xC0)),
}


def load_sealed_data_key():
    spec = importlib.util.spec_from_file_location("sealed_data_key", SEALED_DATA_KEY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def vm_passphrase(kt, chip_key: bytes, field_select: int, host_data: bytes) -> bytes:
    """volume_key with the VM salt: the same info and context bytes."""
    return kt.hkdf(chip_key, VM_SALT, b"luks2-passphrase\0" + kt._context(field_select, host_data), 32)


def vm_key_id(kt, chip_key: bytes, field_select: int, host_data: bytes) -> str:
    return kt.hkdf(chip_key, VM_SALT, b"key-id\0" + kt._context(field_select, host_data), 8).hex()


def vectors() -> dict:
    kt = load_sealed_data_key()
    measure = json.loads(MEASURE_VECTORS.read_text())
    cases = []
    for identity in sorted(measure["identities"]):
        host_data = bytes.fromhex(measure["identities"][identity]["host_data_hex"])
        for chip in sorted(CHIP_KEYS):
            key = CHIP_KEYS[chip]
            cases.append({
                "identity": identity,
                "host_data_hex": host_data.hex(),
                "chip_key_name": chip,
                "chip_key_hex": key.hex(),
                "field_select": kt.FIELD_SELECT,
                "passphrase_hex": vm_passphrase(kt, key, kt.FIELD_SELECT, host_data).hex(),
                "key_id": vm_key_id(kt, key, kt.FIELD_SELECT, host_data),
            })
    return {
        "schema": "cathedral.vm.root-key-vectors/v1",
        "about": "Shared vectors for the sealed VM root disk key (spec r3 7.2 step 2): sealed_data_key.py's "
                 "HKDF with the salt cathedral-vm-root-v1, over the HOST_DATA of vm_measure_v1.json's "
                 "identities and fake chip keys. Made by scripts/make_vm_root_key_vectors.py.",
        "salt_utf8": VM_SALT.decode(),
        "field_select": kt.FIELD_SELECT,
        "cases": cases,
    }


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    text = render(vectors())
    if argv[1:] == ["--write"]:
        FIXTURE.write_text(text)
        return 0
    if argv[1:] == ["--check"]:
        if FIXTURE.read_text() != text:
            print(f"{FIXTURE.relative_to(ROOT)} differs from the vectors; run --write", file=sys.stderr)
            return 1
        return 0
    if argv[1:]:
        print(__doc__, file=sys.stderr)
        return 2
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
