"""AB#968 plan PR 6b: verify_receipts.py --approved-list (signed list v1, the rules of verify_sealed_hotels.py).

The list is signed here with a test key named in a pin file given with --approved-list-pins, so no real key
signs anything. The reports come from the synthetic Genoa chain of snp_floor_support.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import snp_floor_support as s

ROOT = Path(__file__).resolve().parents[1]
LIST_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"ab968 test list key").digest())
HOTEL = "ab968-hotel"


def _time(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _write_list(tmp_path: Path, hotels: dict | None = None, *, age: timedelta = timedelta(minutes=1),
                release: int = 7, key: Ed25519PrivateKey = LIST_KEY) -> tuple[Path, Path]:
    now = datetime.now(UTC).replace(microsecond=0)
    generated = now - age
    if hotels is None:
        hotels = {HOTEL: {"chip_id": s.CHIP_ID, "measurements": [s.MEASUREMENT]}}
    doc = {"schema": "cathedral_sealed_hotels_v1", "release": release, "generated_at": _time(generated),
           "valid_from": _time(generated), "valid_until": _time(generated + timedelta(days=2)),
           "key_id": "ab968-test-1", "hotels": hotels}
    doc["signature"] = {"algorithm": "ed25519", "value_base64": base64.b64encode(key.sign(_canonical(doc))).decode()}
    tmp_path.mkdir(parents=True, exist_ok=True)
    listed = tmp_path / "list.json"
    listed.write_bytes(_canonical(doc))
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps({"schema": "cathedral_sealed_hotels_pins_v1", "keys": {"ab968-test-1": {
        "algorithm": "ed25519", "public_key_hex": LIST_KEY.public_key().public_bytes_raw().hex(),
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2099-01-01T00:00:00Z"}}}))
    return listed, pins


def _list_args(listed: Path, pins: Path, *extra: str, hotel: str = HOTEL) -> list[str]:
    return ["--approved-list", str(listed), "--approved-list-schema", "v1", "--approved-list-pins", str(pins),
            "--hotel", hotel, *extra]


def test_a_listed_hotel_chip_and_measurement_passes_and_prints_the_release(tmp_path: Path) -> None:
    listed, pins = _write_list(tmp_path)
    code, out, err = s.run(tmp_path, s.attestation(tmp_path / "cache"), *_list_args(listed, pins))
    assert (code, out["verdict"]) == (0, "PASS"), (out, err)
    got = out["approved_list"]
    assert got["release"] == 7 and got["schema"] == "v1"
    assert got["digest"] == "sha256:" + hashlib.sha256(listed.read_bytes()).hexdigest()
    assert got["release_id"] == "none (not reproducible)" and got["hotel"] == HOTEL
    assert "policy, tenancy and host_data" in got["not_checked"][0] and out["tcb_floor"] == "not checked"


def test_without_the_list_a_pass_says_not_checked(tmp_path: Path) -> None:
    code, out, _ = s.run(tmp_path, s.attestation(tmp_path / "cache"))
    assert (code, out["approved_list"]) == (0, "not checked")


def test_the_list_and_the_floor_together(tmp_path: Path) -> None:
    listed, pins = _write_list(tmp_path)
    code, out, err = s.run(tmp_path, s.attestation(tmp_path / "cache"), *_list_args(listed, pins),
                           "--min-tcb", s.FLOOR, "--expected-chip-id", s.CHIP_ID)
    assert code == 0 and out["tcb_floor"]["generation"] == "genoa" and out["approved_list"]["release"] == 7, err


@pytest.mark.parametrize("case,reason", [
    ("hotel_not_listed", "approved list: hotel ab968-hotel is not listed in release 7"),
    ("chip", "approved list: the report chip id is not the chip listed for hotel ab968-hotel"),
    ("measurement", "approved list: the measurement is not listed for hotel ab968-hotel"),
])
def test_a_list_that_does_not_name_this_report_fails(case: str, reason: str, tmp_path: Path) -> None:
    entry = {"chip_id": s.CHIP_ID, "measurements": [s.MEASUREMENT]}
    if case == "hotel_not_listed":
        hotels = {"another-hotel": entry}
    elif case == "chip":
        hotels = {HOTEL: {**entry, "chip_id": "ab" * 64}}
    else:
        hotels = {HOTEL: {**entry, "measurements": ["cd" * 48]}}
    listed, pins = _write_list(tmp_path, hotels)
    code, out, err = s.run(tmp_path, s.attestation(tmp_path / "cache"), *_list_args(listed, pins))
    assert (code, out["reason"]) == (1, reason), err


def test_hotel_differs_from_the_binding_fails(tmp_path: Path) -> None:
    hotels = {name: {"chip_id": s.CHIP_ID, "measurements": [s.MEASUREMENT]} for name in (HOTEL, "other-hotel")}
    listed, pins = _write_list(tmp_path, hotels)
    code, out, _ = s.run(tmp_path, s.attestation(tmp_path / "cache"), *_list_args(listed, pins, hotel="other-hotel"))
    assert (code, out["reason"]) == (1, "approved list: the binding names hotel 'ab968-hotel', not --hotel "
                                        "'other-hotel'")


def test_a_bad_signature_an_unpinned_key_and_a_stale_list_fail(tmp_path: Path) -> None:
    att = s.attestation(tmp_path / "cache")
    listed, pins = _write_list(tmp_path / "forged", key=Ed25519PrivateKey.generate())
    code, out, _ = s.run(tmp_path, att, *_list_args(listed, pins))
    assert (code, out["reason"]) == (1, "approved list: signature verification failed")
    listed, pins = _write_list(tmp_path / "stale", age=timedelta(hours=25))
    code, out, _ = s.run(tmp_path, att, *_list_args(listed, pins))
    assert (code, out["reason"]) == (1, "approved list: release is older than the 24 hour maximum policy age")
    listed, _ = _write_list(tmp_path / "builtin")
    code, out, _ = s.run(tmp_path, att, "--approved-list", str(listed), "--approved-list-schema", "v1",
                         "--hotel", HOTEL)
    assert (code, out["reason"]) == (1, "approved list: key 'ab968-test-1' is not pinned")


def test_an_unknown_field_is_refused(tmp_path: Path) -> None:
    hotels = {HOTEL: {"chip_id": s.CHIP_ID, "measurements": [s.MEASUREMENT], "tenancy": "shared"}}
    listed, pins = _write_list(tmp_path, hotels)
    code, out, _ = s.run(tmp_path, s.attestation(tmp_path / "cache"), *_list_args(listed, pins))
    assert (code, out["reason"]) == (1, "approved list: hotel 'ab968-hotel' has missing or unknown fields")


def test_previous_release_refuses_a_rollback_and_passes_forward(tmp_path: Path) -> None:
    listed, pins = _write_list(tmp_path)
    att = s.attestation(tmp_path / "cache")
    code, out, _ = s.run(tmp_path, att, *_list_args(listed, pins, "--previous-release", "8",
                                                    "--previous-digest", "sha256:" + "0" * 64))
    assert (code, out["reason"]) == (1, "approved list: rollback refused: release 7 is below previous 8")
    code, out, err = s.run(tmp_path, att, *_list_args(listed, pins, "--previous-release", "6",
                                                     "--previous-digest", "sha256:" + "0" * 64))
    assert code == 0, (out, err)


def test_require_release_fails_on_a_v1_list_and_says_why(tmp_path: Path) -> None:
    listed, pins = _write_list(tmp_path)
    code, out, _ = s.run(tmp_path, s.attestation(tmp_path / "cache"), *_list_args(listed, pins, "--require-release"))
    assert code == 1 and "every list v1 entry is legacy" in out["reason"]


def test_list_rules_refuse_vmpl_1_and_report_version_2(tmp_path: Path) -> None:
    listed, pins = _write_list(tmp_path)
    code, out, _ = s.run(tmp_path, s.attestation(tmp_path / "cache", vmpl=1), *_list_args(listed, pins))
    assert (code, out["reason"]) == (1, "approved list: the report is from VMPL 1, not VMPL 0")
    code, out, _ = s.run(tmp_path, s.attestation(tmp_path / "v2", version=2), *_list_args(listed, pins),
                         "--product", "Genoa", "--kds-cache", str(tmp_path / "v2"))
    assert (code, out["reason"]) == (1, "approved list: report version 2 has no CPUID fields, so the generation "
                                        "is unknown")


def test_a_dedicated_machine_checks_the_owner_and_the_list(tmp_path: Path) -> None:
    listed, pins = _write_list(tmp_path)
    att = s.attestation(tmp_path / "cache", tenancy="dedicated")
    code, out, err = s.run(tmp_path, att, *_list_args(listed, pins, "--owner-pubkey", s.OWNER_B64))
    assert code == 0 and out["attestation"]["owner"]["host_data"] == s.dedicated_host_data(), err


@pytest.mark.parametrize("extra,message", [
    (("--approved-list", "x.json", "--hotel", HOTEL), "--approved-list needs --approved-list-schema v1 or v2"),
    (("--approved-list", "x.json", "--approved-list-schema", "v2", "--hotel", HOTEL),
     "list v2 not published yet (plan PR 5)"),
    (("--approved-list", "x.json", "--approved-list-schema", "v1"), "--approved-list needs --hotel"),
    (("--approved-list", "x.json", "--approved-list-schema", "v1", "--hotel", HOTEL, "--skip-amd"),
     "needs the AMD chain and --ark-sha256"),
    (("--require-release",), "only go with --approved-list"),
    (("--approved-list-pins", "p.json"), "only go with --approved-list"),
    (("--previous-release", "3"), "only go with --approved-list"),
])
def test_list_flags_without_their_anchor_are_usage_errors(extra: tuple, message: str, tmp_path: Path) -> None:
    code, _, err = s.run(tmp_path, s.attestation(tmp_path / "cache"), *extra)
    assert code == 2 and message in err, err


def test_a_level_1_answer_with_the_list_fails(tmp_path: Path) -> None:
    listed, pins = _write_list(tmp_path)
    level1 = ROOT / "tests" / "fixtures" / "old_lists" / "cases" / "hotel_level1_list" / "attestation_doc.json"
    code, out, _ = s.run(tmp_path, json.loads(level1.read_text()), *_list_args(listed, pins))
    assert (code, out["reason"]) == (1, "the hotel answered a level 1 (unsealed) binding; an SEV-SNP attestation "
                                        "was asked for")


def test_run_mode_refuses_the_list() -> None:
    import subprocess
    import sys

    proc = subprocess.run([sys.executable, str(s.CHECKER), "--oneshot", "x.json", "--approved-list", "l.json",
                           "--approved-list-schema", "v1"], capture_output=True, text=True, check=False)
    assert proc.returncode == 2 and "--approved-list" in proc.stderr and "takes no" in proc.stderr


def test_fresh_report_mode_checks_the_list_and_says_what_it_cannot(tmp_path: Path) -> None:
    listed, pins = _write_list(tmp_path)
    code, out, err = s.run_fresh(tmp_path, *_list_args(listed, pins))
    assert (code, out["verdict"]) == (0, "PASS"), (out, err)
    assert out["approved_list"]["release"] == 7
    assert out["approved_list"]["not_checked"][1] == "tenancy and the debug cmdline: a fresh report has no binding"
    other, pins2 = _write_list(tmp_path / "other", {HOTEL: {"chip_id": "ab" * 64, "measurements": [s.MEASUREMENT]}})
    code, out, _ = s.run_fresh(tmp_path / "f2", *_list_args(other, pins2))
    assert (code, out["reason"]) == (1, "approved list: the report chip id is not the chip listed for hotel "
                                        "ab968-hotel")
    code, _, err = s.run_fresh(tmp_path / "f3", "--approved-list", str(listed), "--approved-list-schema", "v1",
                               "--approved-list-pins", str(pins))
    assert code == 2 and "--approved-list needs --hotel" in err
    code, _, err = s.run_fresh(tmp_path / "f4", "--hotel", HOTEL)
    assert code == 2 and "takes --hotel only with --approved-list" in err
