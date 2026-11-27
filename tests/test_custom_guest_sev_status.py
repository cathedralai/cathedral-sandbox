"""SEV status tool (spec-r9 5.9; test plan 14.1 "SEV compare"): the uapi struct layouts,
the ioctl number, and which fields a hold compares."""
from __future__ import annotations

import importlib.util
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "ops" / "custom-guest" / "sev_status.py"
spec = importlib.util.spec_from_file_location("sev_status", TOOL)
sev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sev)


def snp_bytes(mask_chip_id=0, mask_chip_key=0, vlek=0, guests=1, tcb="0103030800000076", build=10):
    word = mask_chip_id | (mask_chip_key << 1) | (vlek << 2)
    return (bytes([1, 58, 1, 1]) + build.to_bytes(4, "little") + word.to_bytes(4, "little")
            + guests.to_bytes(4, "little") + bytes.fromhex(tcb) + bytes.fromhex(tcb))


def sev_bytes(owner=1, build=10, guests=1):
    return bytes([1, 58, 2]) + (owner | 0x100).to_bytes(4, "little") + bytes([build]) + guests.to_bytes(4, "little")


def test_ioctl_number_and_struct_sizes():
    assert sev.SEV_ISSUE_CMD == 0xC0105300
    assert sev.SNP_PLATFORM_STATUS == 9 and sev.SEV_PLATFORM_STATUS == 1


def test_parse_snp_and_sev():
    s = sev.parse_snp(snp_bytes(mask_chip_id=1, guests=3))
    assert (s["api_major"], s["api_minor"], s["build_id"], s["mask_chip_id"], s["mask_chip_key"], s["guest_count"]) == \
        (1, 58, 10, 1, 0, 3)
    assert s["current_tcb"] == s["reported_tcb"] == "0103030800000076"
    v = sev.parse_sev(sev_bytes())
    assert (v["owner"], v["config_flags"], v["build"], v["guest_count"]) == (1, 0x100, 10, 1)


def test_compare_ignores_guest_count_and_state_but_not_chip_config():
    base = {"snp": sev.parse_snp(snp_bytes(guests=0)), "sev": sev.parse_sev(sev_bytes(guests=0))}
    same = {"snp": sev.parse_snp(snp_bytes(guests=2)), "sev": sev.parse_sev(sev_bytes(guests=2))}
    assert sev.differences(base, same) == []
    changed = {"snp": sev.parse_snp(snp_bytes(mask_chip_id=1)), "sev": sev.parse_sev(sev_bytes())}
    assert sev.differences(base, changed) == ["snp.mask_chip_id: 0 -> 1"]
    tcb = {"snp": sev.parse_snp(snp_bytes(tcb="0103030900000076")), "sev": sev.parse_sev(sev_bytes())}
    assert {d.split(":")[0] for d in sev.differences(base, tcb)} == {"snp.current_tcb", "snp.reported_tcb"}
    owner = {"snp": sev.parse_snp(snp_bytes()), "sev": sev.parse_sev(sev_bytes(owner=0))}
    assert sev.differences(base, owner) == ["sev.owner: 1 -> 0"]
