"""The receipt-list checker: old lists keep their output, and the v2 list pack gives its stated answers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "tests" / "fixtures" / "old_lists"
sys.path.insert(0, str(OLD))

from run_case import run_case

OLD_CASES = sorted(json.loads((OLD / "cases.json").read_text()))


@pytest.mark.parametrize("name", OLD_CASES)
def test_old_lists_output_is_byte_identical(name: str) -> None:
    """Lists without numbering, serial or pool fields print what the checker printed before they existed."""
    case = OLD / "cases" / name
    out, code = run_case(name)
    assert out == (case / "golden.stdout").read_bytes()
    assert code == int((case / "golden.exit").read_text())


PACK = ROOT / "tests" / "fixtures" / "receipt_lists_v2"
CHECKER = ROOT / "room-kit" / "verify_receipts.py"


def _pack_cases() -> list[str]:
    return sorted(f"{kind}/{p.name}" for kind in ("good", "bad") for p in (PACK / kind).iterdir() if p.is_dir())


def _pointer(doc, pointer: str):
    for part in [p for p in pointer.split("/") if p]:
        doc = doc[int(part)] if isinstance(doc, list) else doc[part]
    return doc


def _run_pack_case(name: str) -> tuple[dict, dict, int]:
    import subprocess

    folder = PACK / name
    case = json.loads((folder / "case.json").read_text())
    args = [a.replace("{dir}", str(folder)) for a in case["args"]]
    proc = subprocess.run([sys.executable, str(CHECKER), *args], capture_output=True, text=True, check=False)
    assert proc.stdout.strip(), proc.stderr
    return case, json.loads(proc.stdout), proc.returncode


@pytest.mark.parametrize("name", _pack_cases())
def test_pack_case_gives_its_stated_answer(name: str) -> None:
    case, out, code = _run_pack_case(name)
    expect = case["expect"]
    assert out["verdict"] == expect["verdict"], out
    assert code == expect["exit_code"]
    if "reason" in expect:
        assert out["reason"] == expect["reason"]
    for pointer, want in expect.get("pointers", {}).items():
        assert _pointer(out, pointer) == want, pointer


def test_good_and_bad_cases_are_each_in_their_folder() -> None:
    for name in _pack_cases():
        case = json.loads((PACK / name / "case.json").read_text())
        assert (case["expect"]["verdict"] == "PASS") == name.startswith("good/"), name


def test_pack_manifest_and_every_file_rebuild_byte_for_byte() -> None:
    import subprocess

    proc = subprocess.run([sys.executable, str(PACK / "generate.py"), "--check"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    manifest = json.loads((PACK / "MANIFEST.json").read_text())
    import hashlib

    for path, digest in manifest["files"].items():
        assert hashlib.sha256((PACK / path).read_bytes()).hexdigest() == digest, path
    lines = "".join(f"{p} {d}\n" for p, d in sorted(manifest["files"].items()))
    assert hashlib.sha256(lines.encode()).hexdigest() == manifest["root_sha256"]


def _load_checker():
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_receipts_lists_t", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _case_receipts(name: str) -> list[dict]:
    doc = json.loads((PACK / name / "receipts.json").read_text())
    return doc["receipts"] if isinstance(doc, dict) else doc


def test_room_numbering_function_reports_each_room_alone() -> None:
    vr = _load_checker()
    out = vr.room_numbering(_case_receipts("good/numbered_rooms_interleaved"))
    assert sorted(out["rooms"]) == ["room-a", "room-b"]
    assert out["rooms"]["room-b"]["receipts"] == 3 and out["warnings"] == []


def test_room_numbering_function_ignores_rooms_without_the_fields() -> None:
    vr = _load_checker()
    out = vr.room_numbering(_case_receipts("good/unnumbered_room_unchanged"))
    assert out == {"rooms": {}, "warnings": []}


def test_room_numbering_function_keeps_one_room_id_under_two_bindings_apart() -> None:
    vr = _load_checker()
    receipts = _case_receipts("good/numbered_one_room_list")
    other = json.loads(json.dumps(receipts))
    for rc in other:
        rc["statement"]["binding_sha256"] = "11" * 32
    out = vr.room_numbering(receipts + other)
    assert len(out["rooms"]) == 2 and all(k.startswith("room-a@") for k in out["rooms"])


def test_serial_words_are_only_printed_when_a_serial_room_is_present() -> None:
    _, out, _ = _run_pack_case("good/numbered_rooms_interleaved")
    assert len(out["chain"]["room_numbering"]["does_not_prove"]) == 1
    _, out, _ = _run_pack_case("good/serial_room_closed_by_file_put")
    assert len(out["chain"]["room_numbering"]["does_not_prove"]) == 4


def test_empty_per_room_list_cannot_claim_receipts_or_head() -> None:
    vr = _load_checker()
    with pytest.raises(vr.Fail):
        vr.room_numbering([], {"room_head": "a" * 64, "count": 3})
    with pytest.raises(vr.Fail):
        vr.room_numbering([], {"room_head": None, "count": 3})
    assert vr.room_numbering([], {"room_head": None, "count": 0}) == {"rooms": {}, "warnings": []}


def test_one_numbering_field_is_a_warning_not_an_uncaught_error() -> None:
    vr = _load_checker()
    receipts = _case_receipts("good/numbered_rooms_interleaved")
    for rc in receipts:
        if rc["statement"]["sandbox_id"] == "room-a":
            rc["statement"].pop("room_previous_receipt_sha256")
    out = vr.room_numbering(receipts)
    assert "room-a" not in out["rooms"]
    assert "room-b" in out["rooms"]
    assert any("room-a" in warning for warning in out["warnings"])


def test_room_links_reads_no_link_from_an_unchecked_claim() -> None:
    vr = _load_checker()
    claimed = _case_receipts("good/pool_room_claimed")
    assert vr.room_links(claimed) == {"pool-1": "5b7c1a2e-9d3f-4e6a-8b10-2c4d6e8f0a1b"}
    with pytest.raises(vr.Fail, match="pooled_from"):
        vr.room_links(_case_receipts("bad/pool_claim_pooled_from_wrong"))
    with pytest.raises(vr.Fail, match="needs numbered receipts"):
        vr.room_links(_case_receipts("bad/pool_claim_without_numbering"))


def test_pool_rooms_function_reports_states_and_stays_empty_without_a_pool_create() -> None:
    vr = _load_checker()
    states = {name: vr.pool_rooms(_case_receipts(f"good/{name}"))["pool-1"]["state"]
              for name in ("pool_room_claimed", "pool_room_unclaimed", "pool_room_claim_failed",
                           "pool_room_retired_unclaimed")}
    assert states == {"pool_room_claimed": "claimed", "pool_room_unclaimed": "unclaimed",
                      "pool_room_claim_failed": "closed", "pool_room_retired_unclaimed": "retired"}
    assert vr.pool_rooms(_case_receipts("good/numbered_rooms_interleaved")) == {}


def _run_cli(*argv: str) -> tuple[int, str, str]:
    import subprocess

    proc = subprocess.run([sys.executable, str(CHECKER), *argv], capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def test_python_create_keys_equal_the_shared_key_list() -> None:
    """The broker and every checker read one list of create keys; a missing list fails, it does not skip."""
    shared = json.loads((ROOT / "broker" / "oneshot_create_keys.json").read_text())
    vr = _load_checker()
    assert list(vr.ONESHOT_CREATE_KEYS) == shared["keys"]
    assert list(vr.ONESHOT_LABEL_KEYS) == shared["label_keys"]


def test_a_path_with_space_plus_amp_equals_percent_tilde_and_a_non_ascii_letter_has_the_go_query_form() -> None:
    """Go's url.Values.Encode: sorted keys, upper-case hex, space as +, ~ kept. The same string is in the Go pack."""
    vr = _load_checker()
    path = "/work/in/a b+c&d=e%f~ü.txt"
    want = "path=%2Fwork%2Fin%2Fa+b%2Bc%26d%3De%25f~%C3%BC.txt"
    assert vr.file_query({"path": path, "mode": "600"}) == "mode=600&" + want
    assert vr.put_target("r1", "644", path) == "PUT /v1/sandboxes/r1/files?mode=644&" + want
    assert vr.get_target("r1", 10, path) == "GET /v1/sandboxes/r1/files?max_bytes=10&" + want


def test_the_synthetic_chain_verifies_offline_and_a_changed_report_does_not() -> None:
    """verify_amd with the certificates from a file: the first offline test of the chain and report signature."""
    import base64
    import copy

    vr = _load_checker()
    amd = PACK / "source" / "amd"
    certs = json.loads((amd / "certs.json").read_text())
    report = base64.b64decode(json.loads((amd / "report.json").read_text())["report_b64"])
    pin = (amd / "ark_sha256.txt").read_text().strip()
    out = vr.verify_amd(report, vr.parse_report(report), "Milan", "", [pin], certs)
    assert out["ark_sha256"] == pin
    with pytest.raises(vr.Fail, match="differs from the pinned value"):
        vr.verify_amd(report, vr.parse_report(report), "Milan", "", ["00" * 32], certs)
    forged = bytearray(report)
    forged[0x2A0 + 5] ^= 1
    with pytest.raises(vr.Fail, match="report signature does not verify"):
        vr.verify_amd(bytes(forged), vr.parse_report(bytes(forged)), "Milan", "", [pin], certs)
    swapped = copy.deepcopy(certs)
    swapped["vcek"] = swapped["ask"]
    with pytest.raises((vr.Fail, vr.InvalidSignature)):
        vr.verify_amd(report, vr.parse_report(report), "Milan", "", [pin], swapped)


def test_run_mode_takes_no_hotel_flags_and_a_missing_oneshot_file_is_a_json_fail() -> None:
    code, _, err = _run_cli("--oneshot", "x.json", "--receipts", "y.json")
    assert code == 2 and "--oneshot checks one file" in err
    folder = PACK / "good" / "run_held_output_proven_exit_code"
    code, out, _ = _run_cli("--oneshot", str(folder / "missing.json"), "--recipe", str(folder / "recipe.json"),
                            "--no-context", "--ark-sha256", "00" * 32, "--expected-measurement", "ab" * 48)
    assert code == 1 and json.loads(out) == {"verdict": "FAIL",
                                              "reason": f"inputs: cannot read the one-shot file {folder}/missing.json"}


def test_strict_json_refuses_repeated_keys_and_numbers_that_are_not_integers() -> None:
    vr = _load_checker()
    assert vr.strict_json(b'{"a":1,"b":[2,3]}', "p", "x") == {"a": 1, "b": [2, 3]}
    for raw, text in ((b'{"a":1,"a":2}', "repeats the key 'a'"), (b'{"a":1.5}', "holds the number 1.5"),
                      (b'{"a":1e3}', "holds the number 1e3"), (b'{"a":NaN}', "holds the number NaN"),
                      (b"{", "is not JSON")):
        with pytest.raises(vr.Fail, match=text):
            vr.strict_json(raw, "p", "x")


def test_a_single_expected_measurement_keeps_its_message_and_several_use_the_list_message() -> None:
    folder = PACK / "good" / "numbered_rooms_interleaved"
    base = ["--attestation", str(folder / "attestation_doc.json"), "--receipts", str(folder / "receipts.json"),
            "--skip-amd"]
    code, out, _ = _run_cli(*base, "--expected-measurement", "00" * 48)
    assert code == 1 and json.loads(out)["reason"] == "measurement differs from the expected build"
    code, out, _ = _run_cli(*base, "--expected-measurement", "00" * 48, "--expected-measurement", "11" * 48)
    assert code == 1 and json.loads(out)["reason"] == "measurement is not one of the allowed measurements"
    trust = json.loads((PACK / "source" / "trust.json").read_text())
    code, out, _ = _run_cli(*base, "--expected-measurement", "00" * 48, "--expected-measurement",
                            trust["measurements"][0])
    assert code == 0 and json.loads(out)["verdict"] == "PASS"
