"""AB#968 plan PR 6a: verify_receipts.py --min-tcb, --expected-chip-id and the migration-agent bit.

The reports are signed by the synthetic Genoa chain of snp_floor_support, so each case changes one byte of a
report the AMD chain still verifies: the refusal comes from the floor, not from a broken signature.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import snp_floor_support as s

ROOT = Path(__file__).resolve().parents[1]
LEVEL1 = ROOT / "tests" / "fixtures" / "old_lists" / "cases" / "hotel_level1_list" / "attestation_doc.json"
EXCHANGE = ROOT / "tests" / "fixtures" / "oneshot_exchange" / "good_basic"


def _tcb(**components: int) -> bytes:
    tcb = bytearray(s.FLOOR_TCB)
    for name, value in components.items():
        tcb[s.COMPONENT_BYTES[name]] = value
    return bytes(tcb)


def test_a_report_at_the_floor_passes_and_prints_the_floor(tmp_path: Path) -> None:
    code, out, err = s.run(tmp_path, s.attestation(tmp_path / "cache"), "--min-tcb", s.FLOOR)
    assert (code, out["verdict"]) == (0, "PASS"), (out, err)
    floor = out["tcb_floor"]
    assert floor["generation"] == "genoa" and floor["cpuid"] == "family 0x19 model 0x11"
    assert floor["floor"] == {"bl": 12, "tee": 0, "snp": 30, "ucode": 88}
    assert floor["vmpl"] == 0 and floor["report_version"] == 3
    assert floor["tcbs"]["committed"] == {"bl": 12, "tee": 0, "snp": 30, "ucode": 88}


def test_without_the_new_flags_a_pass_says_not_checked(tmp_path: Path) -> None:
    code, out, err = s.run(tmp_path, s.attestation(tmp_path / "cache"))
    assert (code, out["verdict"], out["tcb_floor"]) == (0, "PASS", "not checked"), (out, err)
    assert "expected_chip_id" not in out["attestation"]


@pytest.mark.parametrize("component", ["bl", "tee", "snp", "ucode"])
def test_a_floor_one_step_above_each_component_fails(component: str, tmp_path: Path) -> None:
    floor = {"bl": 12, "tee": 0, "snp": 30, "ucode": 88}
    floor[component] += 1
    spec = "genoa:" + ",".join(f"{k}={v}" for k, v in floor.items())
    code, out, err = s.run(tmp_path, s.attestation(tmp_path / "cache"), "--min-tcb", spec)
    assert (code, out["verdict"]) == (1, "FAIL"), (out, err)
    assert out["reason"].startswith("TCB floor: current TCB ") and "is below" in out["reason"]


@pytest.mark.parametrize("tcb_name", ["current", "reported", "committed", "launch"])
@pytest.mark.parametrize("component", ["bl", "snp", "ucode"])
def test_one_component_below_on_one_tcb_fails(tcb_name: str, component: str, tmp_path: Path) -> None:
    lowered = _tcb(**{component: s.FLOOR_TCB[s.COMPONENT_BYTES[component]] - 1})
    att = s.attestation(tmp_path / "cache", tcbs={tcb_name: lowered})
    code, out, err = s.run(tmp_path, att, "--min-tcb", s.FLOOR)
    assert (code, out["verdict"]) == (1, "FAIL"), (out, err)
    names = {"bl": "boot loader", "snp": "SNP firmware", "ucode": "microcode"}
    assert out["reason"] == (f"TCB floor: {tcb_name} TCB {names[component]} "
                             f"{s.FLOOR_TCB[s.COMPONENT_BYTES[component]] - 1} is below "
                             f"{s.FLOOR_TCB[s.COMPONENT_BYTES[component]]} (genoa)")


def test_a_newer_snp_byte_does_not_make_up_for_an_older_microcode_byte(tmp_path: Path) -> None:
    att = s.attestation(tmp_path / "cache", tcbs={"committed": _tcb(snp=40, ucode=87)})
    code, out, _ = s.run(tmp_path, att, "--min-tcb", s.FLOOR)
    assert (code, out["reason"]) == (1, "TCB floor: committed TCB microcode 87 is below 88 (genoa)")


@pytest.mark.parametrize("model", [0x01, 0x0F, 0x20, 0xA0, 0xA1])
def test_a_generation_the_floor_does_not_name_fails(model: int, tmp_path: Path) -> None:
    """Milan (0x01, 0x0F), a model past the published Genoa range (0x20), Bergamo and Siena (0xA0 on). product()
    calls 0x20 and 0xA0 Genoa; the floor's model range does not. Turin's family has its own layout and chain."""
    att = s.attestation(tmp_path / "cache", model=model)
    code, out, err = s.run(tmp_path, att, "--min-tcb", s.FLOOR)
    assert (code, out["reason"]) == (1, f"TCB floor: the processor (CPUID family 0x19 model 0x{model:02x}) is not "
                                        "a generation --min-tcb names"), err


def test_report_version_2_is_refused_under_a_floor(tmp_path: Path) -> None:
    att = s.attestation(tmp_path / "cache", version=2)
    code, out, err = s.run(tmp_path, att, "--min-tcb", s.FLOOR, "--product", "Genoa")
    assert (code, out["reason"]) == (1, "TCB floor: report version 2 has no CPUID fields, so the generation is "
                                        "unknown"), err


def test_vmpl_1_is_refused_under_a_floor(tmp_path: Path) -> None:
    code, out, _ = s.run(tmp_path, s.attestation(tmp_path / "cache", vmpl=1), "--min-tcb", s.FLOOR)
    assert (code, out["reason"]) == (1, "TCB floor: the report is from VMPL 1, not VMPL 0")


def test_the_migration_agent_bit_is_refused_with_no_other_flag(tmp_path: Path) -> None:
    att = s.attestation(tmp_path / "cache", policy=s.POLICY | (1 << 18))
    code, out, err = s.run(tmp_path, att, pin=False)
    assert (code, out["reason"]) == (1, "guest policy allows a migration agent (bit 18)"), err


def test_the_expected_chip_id_passes_on_the_chip_and_fails_on_another(tmp_path: Path) -> None:
    att = s.attestation(tmp_path / "cache")
    code, out, err = s.run(tmp_path, att, "--expected-chip-id", s.CHIP_ID.upper())
    assert (code, out["attestation"]["expected_chip_id"]) == (0, "matched"), (out, err)
    code, out, _ = s.run(tmp_path, att, "--expected-chip-id", "ab" * 64)
    assert (code, out["reason"]) == (1, "report chip id differs from --expected-chip-id")


@pytest.mark.parametrize("extra,message", [
    (("--min-tcb", s.FLOOR, "--skip-amd"), "need the AMD chain and --ark-sha256"),
    (("--expected-chip-id", s.CHIP_ID, "--skip-amd"), "need the AMD chain and --ark-sha256"),
    (("--min-tcb", s.FLOOR, "--min-genoa-snp-spl", "30"), "do not go together"),
    (("--min-tcb", "list"), "approved list v2, which is not published yet (plan PR 5)"),
    (("--min-tcb", "milan:bl=1,tee=0,snp=1,ucode=1"), "unknown generation 'milan'"),
    (("--min-tcb", "genoa:bl=12,tee=0,snp=30"), "name every component (ucode missing)"),
    (("--min-tcb", "genoa:bl=12,tee=0,snp=300,ucode=88"), "snp must be from 0 to 255"),
    (("--min-tcb", s.FLOOR, "--min-tcb", s.FLOOR), "names genoa twice"),
    (("--expected-chip-id", "abcd"), "128 hex characters"),
])
def test_bad_or_unanchored_flags_are_usage_errors(extra: tuple, message: str, tmp_path: Path) -> None:
    code, _, err = s.run(tmp_path, s.attestation(tmp_path / "cache"), *extra)
    assert code == 2 and message in err, err


@pytest.mark.parametrize("flag", ["--min-tcb", "--expected-chip-id"])
def test_new_flags_without_an_ark_pin_are_refused(flag: str, tmp_path: Path) -> None:
    value = s.FLOOR if flag == "--min-tcb" else s.CHIP_ID
    code, _, err = s.run(tmp_path, s.attestation(tmp_path / "cache"), flag, value, pin=False)
    assert code == 2 and "need the AMD chain and --ark-sha256" in err, err


@pytest.mark.parametrize("extra", [("--min-tcb", s.FLOOR), ("--expected-chip-id", s.CHIP_ID)])
def test_a_level_1_answer_with_a_new_flag_fails(extra: tuple, tmp_path: Path) -> None:
    att = json.loads(LEVEL1.read_text())
    code, out, err = s.run(tmp_path, att, *extra)
    assert (code, out["verdict"]) == (1, "FAIL"), err
    assert out["reason"] == "the hotel answered a level 1 (unsealed) binding; an SEV-SNP attestation was asked for"


def _exchange_args() -> list[str]:
    case = json.loads((EXCHANGE / "case.json").read_text())
    return [a.replace("{dir}", str(EXCHANGE)) for a in case["args"]]


def test_run_mode_checks_the_floor_rather_than_ignoring_it(tmp_path: Path) -> None:
    """The exchange file's report is a synthetic Milan report: a Genoa floor must fail it."""
    import subprocess
    import sys

    proc = subprocess.run([sys.executable, str(s.CHECKER), *_exchange_args(), "--min-tcb", s.FLOOR],
                          capture_output=True, text=True, check=False)
    out = json.loads(proc.stdout)
    assert (proc.returncode, out["verdict"]) == (1, "FAIL"), proc.stderr
    assert "is not a generation --min-tcb names" in out["reason"]


def test_run_mode_checks_the_chip_id(tmp_path: Path) -> None:
    import base64
    import subprocess
    import sys

    bundle = json.loads((EXCHANGE / "expected" / "bundle.json").read_text())
    chip = base64.b64decode(bundle["attestation"]["report_b64"])[0x1A0:0x1E0].hex()
    for value, code in ((chip, 0), ("cd" * 64, 1)):
        proc = subprocess.run([sys.executable, str(s.CHECKER), *_exchange_args(), "--expected-chip-id", value],
                              capture_output=True, text=True, check=False)
        assert proc.returncode == code, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["reason"] == "check 1: report chip id differs from --expected-chip-id"


def test_fresh_report_mode_takes_the_floor_and_the_chip(tmp_path: Path) -> None:
    code, out, err = s.run_fresh(tmp_path, "--min-tcb", s.FLOOR, "--expected-chip-id", s.CHIP_ID)
    assert (code, out["verdict"]) == (0, "PASS"), (out, err)
    assert out["tcb_floor"]["generation"] == "genoa" and out["expected_chip_id"] == "matched"
    code, out, _ = s.run_fresh(tmp_path / "low", "--min-tcb", s.FLOOR, tcbs={"launch": _tcb(tee=0, bl=11)})
    assert (code, out["reason"]) == (1, "TCB floor: launch TCB boot loader 11 is below 12 (genoa)")
    code, out, _ = s.run_fresh(tmp_path / "none")
    assert (code, out["tcb_floor"]) == (0, "not checked")


def test_fresh_report_mode_refuses_the_migration_agent_bit(tmp_path: Path) -> None:
    code, out, _ = s.run_fresh(tmp_path, policy=s.POLICY | (1 << 18))
    assert (code, out["reason"]) == (1, "guest policy allows a migration agent (bit 18)")


def test_min_genoa_snp_spl_keeps_its_meaning(tmp_path: Path) -> None:
    att = s.attestation(tmp_path / "cache")
    code, out, err = s.run(tmp_path, att, "--min-genoa-snp-spl", "30")
    assert (code, out["attestation"]["amd"]["min_genoa_snp_spl_checked"]) == (0, 30), (out, err)
    code, out, _ = s.run(tmp_path, att, "--min-genoa-snp-spl", "31")
    assert code == 1 and "below Genoa floor 0x1f" in out["reason"]
