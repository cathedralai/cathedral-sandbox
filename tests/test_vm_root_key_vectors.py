"""The sealed VM root disk key vectors (AB#999, VM runtime spec r3 7.2 step 2, test T2).

- tests/fixtures/vm_root_key_v1.json is what scripts/make_vm_root_key_vectors.py makes;
- the VM construction is sealed_data_key.py's, with only the salt changed: with the hotel
  salt the same code gives volume_key and key_id exactly;
- the field select is the hotel's (POLICY | MEASUREMENT = 0x9);
- the vectors cover both identities of vm_measure_v1.json and differ per identity and chip.

The Go side (room-kit/custom-guest/internal/vmkey) reads the same fixture.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "make_vm_root_key_vectors.py"
FIXTURE = ROOT / "tests" / "fixtures" / "vm_root_key_v1.json"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load("make_vm_root_key_vectors", SCRIPT)
kt = gen.load_sealed_data_key()


def test_fixture_is_what_the_script_makes() -> None:
    assert FIXTURE.read_text() == gen.render(gen.vectors())
    done = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_vm_construction_is_sealed_data_key_with_another_salt(monkeypatch) -> None:
    # Swap only the salt the generator uses for the hotel salt: the result must be the
    # hotel volume key and label, so info and context are byte for byte the same code.
    monkeypatch.setattr(gen, "VM_SALT", kt.SALT)
    for case in gen.vectors()["cases"]:
        chip, hd = bytes.fromhex(case["chip_key_hex"]), bytes.fromhex(case["host_data_hex"])
        assert bytes.fromhex(case["passphrase_hex"]) == kt.volume_key(chip, kt.FIELD_SELECT, hd)
        assert case["key_id"] == kt.key_id(chip, kt.FIELD_SELECT, hd)


def test_field_select_and_salt() -> None:
    doc = json.loads(FIXTURE.read_text())
    assert kt.FIELD_SELECT == kt.FIELD_POLICY | kt.FIELD_MEASUREMENT == 0x9
    assert doc["field_select"] == 0x9 and all(c["field_select"] == 0x9 for c in doc["cases"])
    assert doc["salt_utf8"] == "cathedral-vm-root-v1" and kt.SALT != b"cathedral-vm-root-v1"


def test_vectors_cover_both_identities_and_differ() -> None:
    doc = json.loads(FIXTURE.read_text())
    measure = json.loads((ROOT / "tests" / "fixtures" / "vm_measure_v1.json").read_text())
    assert {c["identity"] for c in doc["cases"]} == set(measure["identities"]) == {"a", "b"}
    assert len({c["passphrase_hex"] for c in doc["cases"]}) == len(doc["cases"]) == 4
    assert len({c["key_id"] for c in doc["cases"]}) == 4
    for c in doc["cases"]:
        assert c["host_data_hex"] == measure["identities"][c["identity"]]["host_data_hex"]
        assert len(bytes.fromhex(c["passphrase_hex"])) == 32 and len(c["key_id"]) == 16
        # The VM key is never the hotel key for the same chip key and HOST_DATA.
        chip, hd = bytes.fromhex(c["chip_key_hex"]), bytes.fromhex(c["host_data_hex"])
        assert bytes.fromhex(c["passphrase_hex"]) != kt.volume_key(chip, kt.FIELD_SELECT, hd)
