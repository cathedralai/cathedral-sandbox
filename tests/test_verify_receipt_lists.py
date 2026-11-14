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
    assert len(out["chain"]["room_numbering"]["does_not_show"]) == 1
    _, out, _ = _run_pack_case("good/serial_room_closed_by_file_put")
    assert len(out["chain"]["room_numbering"]["does_not_show"]) == 4


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
    assert vr.ONESHOT_SIZES == shared["sizes"]
    assert vr.ONESHOT_ROOM_MARGIN_SECONDS == shared["room_margin_seconds"] == 600


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
    folder = PACK / "good" / "run_held_output_confirmed_exit_code"
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


def _confused_documents() -> dict[str, tuple[str, object]]:
    """(file, mutation) pairs: each puts a value of the wrong type or shape somewhere in the bundle or recipe."""
    def at(path, value):
        def edit(doc):
            node = doc
            for part in path[:-1]:
                node = node[part]
            node[path[-1]] = value
            return doc
        return edit

    cases = {}
    for name, path, value in [
        ("receipts_ints", ["receipts"], [1, 2]), ("receipt_statement_text", ["receipts", 0, "statement"], "x"),
        ("receipt_sequence_text", ["receipts", 1, "statement", "sequence"], "two"),
        ("receipt_status_list", ["receipts", 2, "statement", "status"], []),
        ("attestation_text", ["attestation"], "x"), ("binding_list", ["attestation", "binding"], []),
        ("certs_list", ["amd_certs"], []), ("cert_number", ["amd_certs", "ark"], 5),
        ("create_bytes_number", ["create_request_b64"], 5), ("exec_bytes_list", ["exec_request_b64"], []),
        ("inline_list", ["inline_outputs"], [1]),
        ("request_text", ["request"], "x"), ("request_context_number", ["request", "context"], 7),
        ("request_context_list", ["request", "context"], []), ("request_outputs_number", ["request", "outputs"], 123),
        ("request_inputs_object", ["request", "inputs"], {}), ("request_env_list", ["request", "env"], []),
        ("request_command_number", ["request", "command"], 1),
        ("oneshot_id_number", ["oneshot_id"], 5), ("schema_list", ["schema"], []),
    ]:
        cases[f"bundle_{name}"] = ("bundle.json", at(path, value))
    for name, path, value in [
        ("request_outputs_number", ["request", "outputs"], 123), ("request_inputs_text", ["request", "inputs"], "x"),
        ("request_command_text", ["request", "command"], "run"), ("request_env_list", ["request", "env"], []),
        ("request_timeout_text", ["request", "timeout_seconds"], "60"),
        ("request_timeout_bool", ["request", "timeout_seconds"], True),
        ("request_network_list", ["request", "network"], []), ("request_image_id_number", ["request", "image_id"], 1),
        ("request_max_spend_text", ["request", "max_spend_usd"], "5"), ("request", ["request"], []),
        ("create_resources_text", ["create", "resources"], "x"), ("create_ttl_bool", ["create", "ttl_seconds"], False),
        ("file_modes_list", ["file_modes"], []), ("output_entry_number", ["request", "outputs", 0], 4),
        ("output_optional_text", ["request", "outputs", 0, "optional"], "no"),
        ("output_max_bytes_bool", ["request", "outputs", 0, "max_bytes"], True),
        ("input_entry_list", ["request", "inputs", 0], []), ("input_mode_number", ["request", "inputs", 0, "mode"], 644),
        ("top_level_list", [], None),
    ]:
        cases[f"recipe_{name}"] = ("recipe.json", None if not path else at(path, value))
    return cases


@pytest.mark.parametrize("name", sorted(_confused_documents()))
def test_a_value_of_the_wrong_type_is_a_clean_fail_never_a_traceback(name: str, tmp_path: Path) -> None:
    import shutil

    folder = tmp_path / "case"
    shutil.copytree(PACK / "good" / "run_held_output_confirmed_exit_code", folder)
    which, edit = _confused_documents()[name]
    doc = json.loads((folder / which).read_text())
    doc = [] if edit is None else edit(doc)
    (folder / which).write_text(json.dumps(doc))
    case = json.loads((folder / "case.json").read_text())
    code, out, err = _run_cli(*[a.replace("{dir}", str(folder)) for a in case["args"]])
    assert "Traceback" not in err, err
    assert code == 1, (out, err)
    result = json.loads(out)
    assert result["verdict"] == "FAIL" and isinstance(result["reason"], str) and result["reason"]


NETWORK_TABLE = [
    [], ["pypi.org"], ["PyPI.org"], ["pypi.org", "files.pythonhosted.org"], ["files.pythonhosted.org", "pypi.org"],
    ["pypi.org", "pypi.org"], ["pypi.org:443"], ["pypi.org:80", "pypi.org:443"], ["pypi.org:80"], ["pypi.org", "pypi.org:80"],
    ["*.pythonhosted.org"], ["*.PythonHosted.org."], ["*.pythonhosted.org:443", "*.pythonhosted.org:80"],
    ["example.org.", " Example.Org "], ["203.0.113.8"], ["203.0.113.0/24"], ["203.0.113.9/24"], ["203.0.113.8", "198.51.100.1", "192.0.2.0/24"],
    ["10.0.0.1"], ["192.168.0.0/16"], ["127.0.0.1"], ["::1"], ["2001:db8::/32"], ["https://pypi.org"], ["pypi.org/path"],
    ["pypi.org:8080"], ["203.0.113.8:80"], ["localhost"], ["a..b"], ["-a.org"], ["a.123"], [""], ["x" * 300], [5],
    ["*.*.org"], ["*org"], ["a.b", "A.B", "a.b:443", "*.a.b", "*.a.b:80"],
    # zero-padded and out-of-range ports: the machine API has no cap on the digits (an entry is at most 255 characters)
    *([f"example.org:{value}"] for value in (
        "000443", "00443", "443".zfill(20), "443".zfill(240), "80".zfill(6), "80".zfill(20), "80".zfill(240), "0",
        "0".zfill(20), "0".zfill(240), "65536", "65536".zfill(20), "9" * 5, "9" * 20, "9" * 243, "9" * 244)),
    ["*.example.org:" + "443".zfill(20)], ["203.0.113.8:" + "443".zfill(20)],
]


@pytest.mark.parametrize("mode", ["allowlist", "deny_all", "internet", "public"])
def test_the_checkers_copy_of_the_network_rule_equals_the_machine_apis(mode: str) -> None:
    """The checker is one file and cannot import the producer, so it copies the rule; this keeps the copies equal."""
    from cathedral import sandbox_api

    vr = _load_checker()
    for allow in NETWORK_TABLE:
        try:
            want = sandbox_api.canonical_network_policy(mode, allow)
        except sandbox_api.SandboxContractError:
            want = None
        except (TypeError, AttributeError):
            want = None
        try:
            got = vr.canonical_policy(mode, allow)
        except (vr.Fail, TypeError, AttributeError):
            got = None
        if want is not None and mode != "allowlist":
            want = {"mode": want["mode"], "allow": want["allow"]}
        assert got == want, (mode, allow, got, want)


def test_the_recipe_network_forms_map_to_one_canonical_policy_each() -> None:
    vr = _load_checker()
    assert vr.network_policy("internet") == {"mode": "internet", "allow": []}
    assert vr.network_policy({}, default_ok=True) == {"mode": "deny_all", "allow": []}
    assert vr.network_policy(None, default_ok=True) == {"mode": "deny_all", "allow": []}
    assert vr.network_policy({"mode": "allowlist", "allow": ["B.org", "a.org"]}) == {
        "mode": "allowlist", "allow": ["a.org", "b.org"]}
    for bad in (None, "", 5, [], "public", "none", "bogus", {"mode": "allowlist"}, {"mode": "allowlist", "allow": []},
                {"mode": "internet", "allow": [3]}, {"mode": "internet", "extra": 1}):
        with pytest.raises(vr.Fail):
            vr.network_policy(bad)


def _generator():
    import importlib.util

    if "pack_generate_t" not in sys.modules:
        spec = importlib.util.spec_from_file_location("pack_generate_t", PACK / "generate.py")
        gen = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = gen
        spec.loader.exec_module(gen)
    return sys.modules["pack_generate_t"]


def _generated(tmp_path: Path, **knobs) -> tuple[int, dict]:
    """Build a signed run in memory with the pack generator, write it out, and run the checker on it."""
    gen = _generator()
    files, args = gen.make_run(gen.Pack(gen.read_amd()), **knobs)
    for name, data in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(data)
    code, out, err = _run_cli(*[a.replace("{dir}", str(tmp_path)) for a in args])
    assert "Traceback" not in err, err
    return code, json.loads(out)


def _edit(**members):
    return lambda r: r["request"].update(members)


# (rule, knobs exactly at the bound, knobs one step past it, the reason the past case must give)
BOUNDS = [
    ("image is pinned by digest", {}, {"truth_edit": _edit(image="images.example.test/app:latest")},
     "recipe: image must end in @sha256: and 64 lower-case hex"),
    ("image digest is lower case", {}, {"truth_edit": _edit(image="images.example.test/app@sha256:" + "A" * 64)},
     "recipe: image must end in @sha256: and 64 lower-case hex"),
    ("image digest is 64 hex", {}, {"truth_edit": _edit(image="images.example.test/app@sha256:" + "a" * 63)},
     "recipe: image must end in @sha256: and 64 lower-case hex"),
    ("command 1 to 128 strings", {"truth_edit": _edit(command=["true"] * 128)},
     {"truth_edit": _edit(command=["true"] * 129)}, "recipe: command must hold 1 to 128 strings"),
    ("command has at least one string", {"truth_edit": _edit(command=["true"])},
     {"truth_edit": _edit(command=[])}, "recipe: command is not a list of strings"),
    ("env at most 64 entries", {"truth_edit": _edit(env={f"K{i}": "v" for i in range(64)})},
     {"truth_edit": _edit(env={f"K{i}": "v" for i in range(65)})}, "recipe: env must hold at most 64 entries"),
    ("at most 8 inputs",
     {"truth_edit": _edit(inputs=[{"path": f"/work/in/f{i}", "mode": "644"} for i in range(8)])},
     {"truth_edit": _edit(inputs=[{"path": f"/work/in/f{i}", "mode": "644"} for i in range(9)])},
     "recipe: inputs must hold at most 8 entries"),
    ("input path under /work/in/", {"truth_edit": _edit(inputs=[{"path": "/work/in/x", "mode": "644"}])},
     {"truth_edit": _edit(inputs=[{"path": "/tmp/data.csv", "mode": "644"}])},
     "recipe: an input path must be under /work/in/"),
    ("output path under /work/out/",
     {"truth_edit": _edit(outputs=[{"path": "/work/out/x", "max_bytes": 9, "optional": False}]), "held": (), "inline": ()},
     {"truth_edit": _edit(outputs=[{"path": "/tmp/log.txt", "max_bytes": 9, "optional": False}]), "held": (), "inline": ()},
     "recipe: an output path must be under /work/out/"),
    ("output max_bytes at most 64 KiB",
     {"truth_edit": _edit(outputs=[{"path": "/work/out/x", "max_bytes": 65536, "optional": False}]), "held": (), "inline": ()},
     {"truth_edit": _edit(outputs=[{"path": "/work/out/x", "max_bytes": 65537, "optional": False}]), "held": (), "inline": ()},
     "recipe: an output max_bytes must be at most 65536"),
    ("timeout_seconds at least 1", {"truth_edit": _edit(timeout_seconds=1)}, {"truth_edit": _edit(timeout_seconds=0)},
     "recipe: timeout_seconds must be at least 1"),
    ("context at most 4 KiB", {"truth_context": {"k": "a" * 4088}}, {"truth_context": {"k": "a" * 4089}},
     "inputs: the context is larger than 4 KiB (4096 canonical bytes)"),
    ("inline output at most 64 KiB", {"file_bytes": {"/work/out/log.txt": b"x" * 65536}},
     {"file_bytes": {"/work/out/log.txt": b"x" * 65537}},
     "check 7: the inline bytes of /work/out/log.txt are 65537 bytes, over the 64 KiB an inline output may have"),
]


@pytest.mark.parametrize("rule, at, past, reason", BOUNDS, ids=[b[0] for b in BOUNDS])
def test_each_request_rule_passes_at_its_bound_and_fails_one_step_past_it(rule, at, past, reason, tmp_path) -> None:
    """The evidence is signed and consistent with the recipe in both cases: only the rule can fail the second."""
    code, out = _generated(tmp_path / "at", **at)
    assert code == 0 and out["verdict"] == "PASS", (rule, out)
    code, out = _generated(tmp_path / "past", **past)
    assert code == 1 and out == {"verdict": "FAIL", "reason": reason}, (rule, out)


FORM_CASES = [(rule, case, at, knobs, reason)
              for rule, at, past in _generator().build_form_rules() for case, knobs, reason in past]


@pytest.mark.parametrize("rule", sorted({c[0] for c in FORM_CASES}))
def test_each_form_rule_accepts_its_bound(rule: str, tmp_path: Path) -> None:
    """Spec G4 5.1, Forms: a run at the bound of every form rule passes."""
    at = next(c[2] for c in FORM_CASES if c[0] == rule)
    code, out = _generated(tmp_path, **at)
    assert code == 0 and out["verdict"] == "PASS", (rule, out)


@pytest.mark.parametrize("rule, case, knobs, reason", [(c[0], c[1], c[3], c[4]) for c in FORM_CASES],
                         ids=[f"{c[0]}-{c[1]}" for c in FORM_CASES])
def test_each_form_rule_refuses_one_step_past_its_bound(rule, case, knobs, reason, tmp_path) -> None:
    """The evidence is signed and consistent with the recipe: only the form rule can fail the run."""
    code, out = _generated(tmp_path, **knobs)
    assert code == 1 and out == {"verdict": "FAIL", "reason": reason}, (rule, case, out)


RECIPE_PREFIX, FILE_PREFIX = "recipe: ", "check 8: the file's request: "
MAX_SPEND_RULE = ("max_spend_usd must be an integer from 1 to 999999999999, or a decimal string of 1 to 12 digits "
                  "and up to 6 decimals, greater than zero")


def _valid_request() -> dict:
    return {"image": "images.example.test/app@sha256:" + "a" * 64, "command": ["true"], "env": {}, "size": "sealed-1x2",
            "timeout_seconds": 5, "network": "deny_all", "max_spend_usd": 1, "inputs": [], "outputs": []}


def _nested(arrays: int):
    value = 1
    for _ in range(arrays):
        value = [value]
    return value


REQUEST_LIMIT_CASES = [
    ("image holds a tab", {"image": "images.example.test/a\tpp@sha256:" + "a" * 64},
     "image must hold no control character"),
    ("image holds a newline", {"image": "images.example.test/a\npp@sha256:" + "a" * 64},
     "image must hold no control character"),
    ("image holds a NUL", {"image": "images.example.test/a\x00pp@sha256:" + "a" * 64},
     "image must hold no control character"),
    ("image holds 0x7f", {"image": "images.example.test/a\x7fpp@sha256:" + "a" * 64},
     "image must hold no control character"),
    ("image_id form", {"image_id": "sha256:xyz"}, "image_id must be sha256: and 64 lower-case hex"),
    ("image_id case", {"image_id": "sha256:" + "A" * 64}, "image_id must be sha256: and 64 lower-case hex"),
    ("timeout is not a boolean", {"timeout_seconds": True}, "timeout_seconds must be an integer"),
    ("max_spend is not a boolean", {"max_spend_usd": True}, MAX_SPEND_RULE),
    ("max_spend zero", {"max_spend_usd": 0}, MAX_SPEND_RULE),
    ("max_spend 13 digit integer", {"max_spend_usd": 1000000000000}, MAX_SPEND_RULE),
    ("max_spend 13 digit string", {"max_spend_usd": "1000000000000"}, MAX_SPEND_RULE),
    ("max_spend double zero", {"max_spend_usd": "00.50"}, MAX_SPEND_RULE),
    ("max_spend long string", {"max_spend_usd": "9" * 5000}, MAX_SPEND_RULE),
    ("output max_bytes 65537", {"outputs": [{"path": "/work/out/x", "max_bytes": 65537}]},
     "an output max_bytes must be at most 65536"),
    ("max_spend a float", {"max_spend_usd": 1.5}, MAX_SPEND_RULE),
    ("max_spend zero string", {"max_spend_usd": "0.0"}, MAX_SPEND_RULE),
    ("max_spend exponent", {"max_spend_usd": "1e3"}, MAX_SPEND_RULE),
    ("max_spend leading zero", {"max_spend_usd": "01"}, MAX_SPEND_RULE),
    ("max_spend trailing newline", {"max_spend_usd": "1\n"}, MAX_SPEND_RULE),
    ("max_spend seven decimals", {"max_spend_usd": "0.1234567"}, MAX_SPEND_RULE),
    ("max_bytes is not a boolean", {"outputs": [{"path": "/work/out/x", "max_bytes": True}]},
     "an output max_bytes must be an integer"),
    ("input sha256 case", {"inputs": [{"path": "/work/in/x", "sha256": "A" * 64}]},
     "an input sha256 must be 64 lower-case hex"),
    ("input sha256 length", {"inputs": [{"path": "/work/in/x", "sha256": "a" * 63}]},
     "an input sha256 must be 64 lower-case hex"),
    ("context float", {"context": {"a": [{"b": 1.5}]}}, "context must hold no floating point number"),
    ("context depth", {"context": {"a": _nested(32)}}, "context nests deeper than 32 levels"),
    ("context depth 600", {"context": {"a": _nested(600)}}, "context nests deeper than 32 levels"),
]


@pytest.mark.parametrize("prefix", [RECIPE_PREFIX, FILE_PREFIX], ids=["recipe", "file"])
@pytest.mark.parametrize("rule, members, reason", REQUEST_LIMIT_CASES, ids=[c[0] for c in REQUEST_LIMIT_CASES])
def test_request_limits_alone_refuses_each_form_for_both_callers(rule, members, reason, prefix) -> None:
    """The one function is complete by itself: no later check is needed to refuse these values."""
    vr = _load_checker()
    vr.request_limits({**_valid_request(), "image_id": "sha256:" + "a" * 64}, prefix)
    with pytest.raises(vr.Fail) as caught:
        vr.request_limits({**_valid_request(), **members}, prefix)
    assert str(caught.value) == prefix + reason


def test_request_limits_accepts_a_context_at_32_levels_and_floats_nowhere() -> None:
    vr = _load_checker()
    for prefix in (RECIPE_PREFIX, FILE_PREFIX):
        vr.request_limits({**_valid_request(), "context": {"a": _nested(31)}}, prefix)


DEPTH = 1_000_000  # far past the interpreter's own limit


def test_a_deep_structure_never_reaches_a_recursion_error_in_run_mode(tmp_path: Path) -> None:
    folder = PACK / "good" / "run_held_output_confirmed_exit_code"
    case = json.loads((folder / "case.json").read_text())
    for name in ("bundle.json", "recipe.json", "context.json"):
        import shutil

        work = tmp_path / name
        shutil.copytree(folder, work)
        (work / name).write_text("[" * DEPTH + "]" * DEPTH)
        code, out, err = _run_cli(*[a.replace("{dir}", str(work)) for a in case["args"]])
        assert "Traceback" not in err and code == 1, (name, err)
        assert json.loads(out)["reason"].endswith("nests too deeply to read"), (name, out)


def test_the_words_a_customer_reads_say_shows_and_confirmed_never_proves() -> None:
    import re

    word = re.compile(r"\b(prove[sdn]?|proving|proof|unproven)\b", re.IGNORECASE)
    for name in ("good/run_held_output_confirmed_exit_code", "good/serial_room_closed_by_file_put",
                 "good/pool_room_claimed", "good/run_exit_code_not_confirmed"):
        _, out, _ = _run_pack_case(name)
        added = {k: out[k] for k in ("run", "pool_rooms") if k in out}
        added["room_numbering"] = out["chain"].get("room_numbering")
        assert not word.search(json.dumps(added)), name
        assert "proves" not in json.dumps(added) and "does_not_prove" not in json.dumps(added)
    _, out, _ = _run_pack_case("good/run_held_output_confirmed_exit_code")
    assert out["run"]["exit_code"] == {"status": "confirmed", "value": 0} and "shows" in out["run"]
    _, out, _ = _run_pack_case("good/run_exit_code_not_confirmed")
    assert out["run"]["exit_code"] == {"status": "not confirmed"}


def test_a_name_that_ends_in_a_newline_inside_a_label_is_refused_where_the_producer_accepts_it() -> None:
    """The producer's label pattern uses match with a $ anchor, so a label ending in a newline slips through it;
    the checker's copy uses fullmatch and refuses it."""
    vr = _load_checker()
    with pytest.raises(vr.Fail):
        vr.canonical_policy("allowlist", ["a\n.org"])
    assert vr.canonical_policy("allowlist", ["A.org\n"]) == {"mode": "allowlist", "allow": ["a.org"]}


def test_json_depth_is_counted_on_the_raw_text_and_skips_strings() -> None:
    vr = _load_checker()
    assert vr.json_depth('{"a": [1, {"b": []}]}') == 4
    assert vr.json_depth('"[[[[" ') == 0
    assert vr.json_depth('{"k": "[[[[[[[["}') == 1
    assert vr.json_depth('{"k": "a\\"[[["}') == 1          # an escaped quote does not end the string
    assert vr.json_depth('{"k": "a\\\\", "j": [[1]]}') == 3  # an escaped backslash does not escape the quote
    assert vr.json_depth("[" * 100_000) == 100_000
    assert vr.JSON_MAX_DEPTH == 64


@pytest.mark.parametrize("value", [1, 7, "0.50", "12", "0.000001", "100.123456", "0.1", "9", 999999999999,
                                   "999999999999.999999", "0"+".5"])
def test_request_limits_accepts_each_max_spend_form(value) -> None:
    vr = _load_checker()
    for prefix in (RECIPE_PREFIX, FILE_PREFIX):
        vr.request_limits({**_valid_request(), "max_spend_usd": value}, prefix)


# ---- the exchange case: one good run, held byte for byte in both repositories

EXCHANGE = ROOT / "tests" / "fixtures" / "oneshot_exchange" / "good_basic"


def _canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def assemble_bundle(case: Path) -> dict:
    """The reference assembler: what the one-shot file must be, built only from what the machine and the broker
    gave the API (machine/) and what the caller sent (caller/). The API's own assembler must give the same file."""
    import base64
    import hashlib
    import re

    machine, caller = case / "machine", case / "caller"
    b64 = lambda raw: base64.b64encode(raw).decode()

    def exact(doc, members, what):
        """The assembler reads only what it knows: an unknown or missing member is a failure, not a silent skip."""
        assert isinstance(doc, dict) and set(doc) == set(members), f"{what}: {sorted(doc)} is not {sorted(members)}"
        return doc

    receipts = [exact(json.loads(base64.urlsafe_b64decode(p.read_text())), ("statement", "signature_b64",
                                                                            "receipt_sha256"), "receipt")
                for p in sorted(machine.glob("[0-9][0-9]_*.header"))]
    pem = (machine / "amd" / "cert_chain_pem.txt").read_text()
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----\n(.*?)\n-----END CERTIFICATE-----", pem, re.DOTALL)
    ask, ark = (b64(base64.b64decode("".join(block.split()))) for block in blocks)
    post = exact(json.loads((caller / "post_body.json").read_text()), (
        "image", "image_id", "command", "env", "size", "timeout_seconds", "network", "inputs", "outputs", "context",
        "max_spend_usd"), "POST body")
    is_int = lambda v: isinstance(v, int) and not isinstance(v, bool)
    for member, ok in (("image", lambda v: isinstance(v, str)), ("image_id", lambda v: isinstance(v, str)),
                       ("command", lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v)),
                       ("env", lambda v: isinstance(v, dict) and all(isinstance(x, str) for x in v.values())),
                       ("size", lambda v: isinstance(v, str)), ("timeout_seconds", is_int),
                       ("network", lambda v: isinstance(v, (str, dict))), ("inputs", lambda v: isinstance(v, list)),
                       ("outputs", lambda v: isinstance(v, list)), ("context", lambda v: isinstance(v, dict)),
                       ("max_spend_usd", lambda v: is_int(v) or isinstance(v, str))):
        assert ok(post[member]), f"POST body: {member} has the wrong type"

    def input_entry(i):
        exact(i, ("path", "sha256", "content_b64", "mode"), "POST input")
        assert isinstance(i["path"], str) and isinstance(i["mode"], str) and re.fullmatch(r"[0-7]{3,4}", i["mode"])
        assert isinstance(i["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", i["sha256"])
        assert isinstance(i["content_b64"], str), "POST input: content_b64 is not a string"
        content = base64.b64decode(i["content_b64"], validate=True)   # raises on text that is not base64
        assert hashlib.sha256(content).hexdigest() == i["sha256"], "POST input: content_b64 is not the sha256"
        return {k: v for k, v in i.items() if k != "content_b64"}

    def output_entry(o):
        assert isinstance(o, dict) and set(o) <= {"path", "max_bytes", "optional"} and {"path", "max_bytes"} <= set(o), \
            f"POST output: {o} has a member outside path, max_bytes and optional"
        assert isinstance(o["path"], str) and is_int(o["max_bytes"]) and isinstance(o.get("optional", False), bool)
        return o

    for o in post["outputs"]:
        output_entry(o)
    request = {k: v for k, v in post.items() if k != "inputs"}
    request["inputs"] = [input_entry(i) for i in post["inputs"]]
    broker_answer = exact(json.loads((machine / "01_create.response").read_text()), (
        "id", "state", "network", "hotel", "isolation", "create_request_b64"), "broker 202")
    exact(broker_answer["isolation"], ("hotel_sealed", "hotel_tee", "room_runtime", "attested_per_room",
                                       "network_mode", "attestation_of_host"), "isolation")
    accepted = exact(json.loads((caller / "response_202.json").read_text()), (
        "oneshot_id", "state", "status_url", "reserved_usd"), "API 202")
    answer = (machine / "05_get_output.response").read_bytes()
    return {
        "schema": "cathedral_oneshot_bundle_v1",
        "oneshot_id": accepted["oneshot_id"],
        "request": request,
        "attestation": exact(json.loads((machine / "hotel_attestation_answer.json").read_text()),
                             ("binding", "binding_sha256", "report_b64"), "attestation"),
        "amd_certs": {"vcek": b64((machine / "amd" / "vcek_der.bin").read_bytes()), "ask": ask, "ark": ark},
        "receipts": receipts,
        "create_request_b64": broker_answer["create_request_b64"],
        "exec_request_b64": b64((machine / "exec_request.json").read_bytes()),
        "exec_response_b64": b64((machine / "04_exec.response").read_bytes()),
        "inline_outputs": {o["path"]: b64(answer) for o in post["outputs"] if len(answer) <= 64 * 1024},
        "not_proven": [],
    }


def test_the_exchange_run_passes_and_prints_exactly_the_expected_check() -> None:
    case = json.loads((EXCHANGE / "case.json").read_text())
    code, out, err = _run_cli(*[a.replace("{dir}", str(EXCHANGE)) for a in case["args"]])
    assert code == 0 and "Traceback" not in err
    assert out.encode() == (EXCHANGE / "expected" / "check.json").read_bytes()


def test_the_exchange_bundle_is_rebuilt_from_what_the_machine_and_the_caller_gave() -> None:
    expected = json.loads((EXCHANGE / "expected" / "bundle.json").read_text())
    assert _canonical(assemble_bundle(EXCHANGE)) == _canonical(expected)
    assert (EXCHANGE / "expected" / "bundle.json").read_bytes() == _canonical(expected)


def test_the_exchange_case_holds_the_forms_the_spec_names() -> None:
    expected = json.loads((EXCHANGE / "expected" / "bundle.json").read_text())
    request = expected["request"]
    assert "cwd" not in request and "user" not in request          # absent, never null
    assert isinstance(request["max_spend_usd"], str) and len(request["env"]) == 1 and len(request["inputs"]) == 1
    assert all("content_b64" not in i for i in request["inputs"]) and "context" in request
    assert all(isinstance(r, dict) and set(r) == {"statement", "signature_b64", "receipt_sha256"}
               for r in expected["receipts"])
    assert set(expected["amd_certs"]) == {"vcek", "ask", "ark"} and len(expected["inline_outputs"]) == 1
    post = json.loads((EXCHANGE / "caller" / "post_body.json").read_text())
    assert "content_b64" in post["inputs"][0]


def test_the_exchange_manifest_names_every_file() -> None:
    import hashlib

    manifest = json.loads((EXCHANGE / "MANIFEST.json").read_text())
    on_disk = {p.relative_to(EXCHANGE).as_posix() for p in EXCHANGE.rglob("*") if p.is_file()} - {"MANIFEST.json"}
    assert on_disk == set(manifest["files"])
    for path, digest in manifest["files"].items():
        assert hashlib.sha256((EXCHANGE / path).read_bytes()).hexdigest() == digest, path
    lines = "".join(f"{p} {d}\n" for p, d in sorted(manifest["files"].items()))
    assert hashlib.sha256(lines.encode()).hexdigest() == manifest["root_sha256"]


def test_the_exchange_create_answer_is_the_brokers_and_the_202_is_the_apis() -> None:
    """The API talks to the broker: its create answer is the broker's 202 document (broker/main.go: id with the
    hotel prefix, hotel, isolation, create_request_b64 when asked). The caller gets oneshot_id, state, status_url
    and reserved_usd."""
    answer = json.loads((EXCHANGE / "machine" / "01_create.response").read_text())
    assert answer["id"].startswith(answer["hotel"] + ".") and answer["hotel"] == "pack-hotel"
    assert set(answer["isolation"]) == {"hotel_sealed", "hotel_tee", "room_runtime", "attested_per_room",
                                        "network_mode", "attestation_of_host"}
    assert answer["isolation"]["attestation_of_host"] == "/v1/hotels/pack-hotel/attestation"
    assert answer["create_request_b64"] == json.loads((EXCHANGE / "expected" / "bundle.json").read_text())[
        "create_request_b64"]
    assert not (EXCHANGE / "machine" / "create_request.b64").exists()       # one source: the member above
    accepted = json.loads((EXCHANGE / "caller" / "response_202.json").read_text())
    assert set(accepted) == {"oneshot_id", "state", "status_url", "reserved_usd"}


def test_the_exchange_recipe_stays_inline_and_its_lifetime_is_the_timeout_plus_the_margin() -> None:
    recipe = json.loads((EXCHANGE / "caller" / "recipe.json").read_text())
    assert all(o["max_bytes"] <= 65536 for o in recipe["request"]["outputs"])
    assert recipe["create"]["ttl_seconds"] == recipe["request"]["timeout_seconds"] + 600
    assert recipe["request"]["network"] == {"mode": "deny_all", "allow": []}


def test_ordinary_good_runs_keep_outputs_at_or_under_the_inline_size() -> None:
    """Outputs are inline only in this version: only a list that is about a larger limit may go past 64 KiB."""
    for folder in sorted((PACK / "good").glob("run_*")):
        if folder.name.startswith(("run_rule_", "run_form_")):
            continue
        recipe = json.loads((folder / "recipe.json").read_text())
        assert all(o["max_bytes"] <= 65536 for o in recipe["request"]["outputs"]), folder.name


def _copy_exchange(tmp_path: Path) -> Path:
    import shutil

    target = tmp_path / "case"
    shutil.copytree(EXCHANGE, target)
    return target


def _rewrite(path: Path, edit) -> None:
    doc = json.loads(path.read_text())
    edit(doc)
    path.write_text(json.dumps(doc))


@pytest.mark.parametrize("path, edit", [
    ("machine/01_create.response", lambda d: d.update(extra=1)),
    ("machine/01_create.response", lambda d: d["isolation"].update(extra=1)),
    ("machine/01_create.response", lambda d: d.pop("hotel")),
    ("machine/hotel_attestation_answer.json", lambda d: d.update(extra=1)),
    ("caller/post_body.json", lambda d: d.update(extra=1)),
    ("caller/post_body.json", lambda d: d["inputs"][0].update(extra=1)),
    ("caller/post_body.json", lambda d: d["inputs"][0].pop("mode")),
    ("caller/response_202.json", lambda d: d.update(extra=1)),
    ("caller/response_202.json", lambda d: d.pop("reserved_usd")),
], ids=["create-extra", "isolation-extra", "create-missing", "attestation-extra", "post-extra", "input-extra",
        "input-missing", "202-extra", "202-missing"])
def test_the_reference_assembler_fails_on_a_member_it_does_not_know(path, edit, tmp_path) -> None:
    """A reader that skips what it does not know would pass a changed shape: this one must not."""
    case = _copy_exchange(tmp_path)
    _rewrite(case / path, edit)
    with pytest.raises(AssertionError):
        assemble_bundle(case)


def test_the_reference_assembler_fails_on_a_receipt_header_with_another_member(tmp_path) -> None:
    import base64

    case = _copy_exchange(tmp_path)
    header = case / "machine" / "01_create.header"
    doc = json.loads(base64.urlsafe_b64decode(header.read_text()))
    doc["extra"] = 1
    header.write_text(base64.urlsafe_b64encode(_canonical(doc)).decode())
    with pytest.raises(AssertionError):
        assemble_bundle(case)


def _run_exchange_with(tmp_path: Path, bundle: dict) -> tuple[int, dict]:
    case = json.loads((EXCHANGE / "case.json").read_text())
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    args = [a.replace("{dir}/expected/bundle.json", str(path)).replace("{dir}", str(EXCHANGE)) for a in case["args"]]
    code, out, err = _run_cli(*args)
    assert "Traceback" not in err, err
    return code, json.loads(out)


def _bundle() -> dict:
    return json.loads((EXCHANGE / "expected" / "bundle.json").read_text())


def _set(*path_and_value):
    *path, value = path_and_value

    def edit(b):
        node = b
        for part in path[:-1]:
            node = node[part]
        node[path[-1]] = value
    return edit


def _pop(*path):
    def edit(b):
        node = b
        for part in path[:-1]:
            node = node[part]
        del node[path[-1]]
    return edit


SHAPE_MUTATIONS = [
    ("top-level member", _set("extra", 1), "check 1: the file has an unknown member extra"),
    ("not_proven missing", _pop("not_proven"), "check 1: the file has no not_proven"),
    ("not_proven null", _set("not_proven", None), "check 1: not_proven is not a list of strings"),
    ("not_proven string", _set("not_proven", "none"), "check 1: not_proven is not a list of strings"),
    ("not_proven numbers", _set("not_proven", [1]), "check 1: not_proven is not a list of strings"),
    ("inline_outputs missing", _pop("inline_outputs"), "check 1: the file has no inline_outputs"),
    ("attestation member", _set("attestation", "extra", 1), "check 1: attestation has an unknown member extra"),
    ("attestation missing", _pop("attestation", "binding_sha256"), "check 1: attestation has no binding_sha256"),
    ("amd_certs member", _set("amd_certs", "extra", "x"), "check 1: amd_certs has an unknown member extra"),
    ("receipt member", _set("receipts", 0, "extra", 1), "check 1: a receipt has an unknown member extra"),
    ("receipt missing", _pop("receipts", 2, "receipt_sha256"), "check 1: a receipt has no receipt_sha256"),
    ("input without mode", _pop("request", "inputs", 0, "mode"),
     "check 8: the file's request: an input must hold exactly path, sha256 and mode"),
    ("input member", _set("request", "inputs", 0, "extra", 1),
     "check 8: the file's request: an input must hold exactly path, sha256 and mode"),
    ("receipts swapped", lambda b: b["receipts"].insert(1, b["receipts"].pop(2)),
     "check 2: room run-room-1: the receipts are not in the order of their room numbers"),
    ("receipts rotated", lambda b: b["receipts"].append(b["receipts"].pop(0)),
     "check 2: room run-room-1: the receipts are not in the order of their room numbers"),
]


@pytest.mark.parametrize("rule, edit, reason", SHAPE_MUTATIONS, ids=[m[0] for m in SHAPE_MUTATIONS])
def test_a_changed_exchange_file_is_refused_for_the_member_it_names(rule, edit, reason, tmp_path) -> None:
    bundle = _bundle()
    edit(bundle)
    code, out = _run_exchange_with(tmp_path, bundle)
    assert code == 1 and out == {"verdict": "FAIL", "reason": reason}, (rule, out)


def test_the_exchange_file_with_reasons_in_not_proven_still_passes(tmp_path) -> None:
    bundle = _bundle()
    bundle["not_proven"] = ["a plain reason the API saw"]
    code, out = _run_exchange_with(tmp_path, bundle)
    assert code == 0 and out["verdict"] == "PASS"


def test_digit_runs_and_depth_are_counted_on_the_raw_text() -> None:
    vr = _load_checker()
    assert vr.json_shape('{"a": 12345, "b": "99999999", "c": [1.25e10]}') == (2, 7, False)
    assert vr.json_shape("[" * 7 + "1" * 300 + "]" * 7) == (7, 300, False)
    assert vr.json_shape("[true, false, null]") == (1, 1, False)   # the e of true and false is one character
    what = "holds a number literal of more than 100 characters"
    for token in ("1" * 101, "9" * 50 + "." + "9" * 51, "1e" + "0" * 99, "-" + "1" * 49 + "e+" + "0" * 50,
                  "0." + "0" * 99, "1" * 100 + "e5"):
        with pytest.raises(vr.Fail, match=what):
            vr.strict_json(f"[{token}]".encode(), "p", "x")
    for token in ("1" * 100, "9" * 49 + "." + "9" * 50, "1e" + "0" * 98, "-" + "1" * 99):
        assert len(token) == 100 and vr.strict_json(f"[{token}, 2]".encode(), "p", "x", floats=True)


def test_a_port_of_thousands_of_digits_is_a_clean_refusal() -> None:
    vr = _load_checker()
    with pytest.raises(vr.Fail, match="not a valid allowlist entry"):
        vr.canonical_policy("allowlist", ["a.org:" + "9" * 5000])      # past the 255 characters of an entry


def test_a_zero_padded_port_is_accepted_as_the_machine_api_accepts_it() -> None:
    vr = _load_checker()
    for padded in ("000443", "443".zfill(20), "443".zfill(240)):
        assert vr.canonical_policy("allowlist", [f"example.org:{padded}"]) == {
            "mode": "allowlist", "allow": ["example.org:443"]}


@pytest.mark.parametrize("edit", [
    lambda d: d["inputs"][0].update(content_b64=None),
    lambda d: d["inputs"][0].update(content_b64=5),
    lambda d: d["inputs"][0].update(content_b64=["eA=="]),
    lambda d: d["inputs"][0].update(content_b64="not base64!"),
    lambda d: d["inputs"][0].update(content_b64="eA=="),                      # base64, but not the input's bytes
    lambda d: d["inputs"][0].update(path=5),
    lambda d: d["inputs"][0].update(mode=644),
    lambda d: d["inputs"][0].update(sha256="A" * 64),
    lambda d: d["inputs"][0].update(sha256=None),
    lambda d: d["outputs"][0].update(extra=1),
    lambda d: d["outputs"][0].update(max_bytes=True),
    lambda d: d["outputs"][0].update(max_bytes="65536"),
    lambda d: d["outputs"][0].update(optional="no"),
    lambda d: d["outputs"][0].update(path=7),
    lambda d: d["outputs"][0].pop("max_bytes"),
    lambda d: d["outputs"].append(5),
    lambda d: d.update(env={"A": 1}),
    lambda d: d.update(timeout_seconds=True),
    lambda d: d.update(context=[]),
    lambda d: d.update(command="run"),
    lambda d: d.update(max_spend_usd=1.5),
    lambda d: d.update(inputs={}),
], ids=["content-null", "content-number", "content-list", "content-not-base64", "content-other-bytes", "path-number",
        "mode-number", "sha256-upper", "sha256-null", "output-extra", "output-max-bool", "output-max-text",
        "output-optional-text", "output-path-number", "output-no-max", "output-not-object", "env-number",
        "timeout-bool", "context-list", "command-text", "spend-float", "inputs-object"])
def test_the_reference_assembler_refuses_a_caller_value_of_the_wrong_type_or_shape(edit, tmp_path) -> None:
    case = _copy_exchange(tmp_path)
    _rewrite(case / "caller" / "post_body.json", edit)
    with pytest.raises((AssertionError, ValueError)):
        assemble_bundle(case)


SURROGATE_FORMS = {
    "high alone": "\\ud800", "low alone": "\\udc00", "low before high": "\\udc00\\ud800",
    "high then other escape": "\\ud800\\u0041", "high then plain char": "\\ud800x", "high then high": "\\ud800\\ud800",
    "high upper case hex": "\\uD83D", "raw utf-8 bytes": "RAW8", "raw utf-16 unit": "RAW16",
}
DOCUMENT_KINDS = {"bundle.json": "the one-shot file", "recipe.json": "the recipe", "context.json": "the context file"}


def _surrogate_document(form: str, where: str) -> bytes:
    payload = SURROGATE_FORMS[form]
    if payload == "RAW16":
        return b"\xff\xfe" + ('{"k": "\ud800"}' if where == "value" else '{"\ud800": 1}').encode("utf-16-le",
                                                                                                    "surrogatepass")
    body = b"\xed\xa0\x80" if payload == "RAW8" else payload.encode()
    return b'{"k": "' + body + b'"}' if where == "value" else b'{"' + body + b'": 1}'


@pytest.mark.parametrize("where", ["value", "key"])
@pytest.mark.parametrize("form", sorted(SURROGATE_FORMS))
@pytest.mark.parametrize("name", sorted(DOCUMENT_KINDS))
def test_an_unpaired_surrogate_is_refused_with_one_reason_in_every_document(name, form, where, tmp_path) -> None:
    import shutil

    folder = PACK / "good" / "run_held_output_confirmed_exit_code"
    case = json.loads((folder / "case.json").read_text())
    work = tmp_path / "case"
    shutil.copytree(folder, work)
    (work / name).write_bytes(_surrogate_document(form, where))
    code, out, err = _run_cli(*[a.replace("{dir}", str(work)) for a in case["args"]])
    assert "Traceback" not in err and code == 1, (out, err)
    assert json.loads(out)["reason"] == f"inputs: {DOCUMENT_KINDS[name]} holds an unpaired surrogate"


@pytest.mark.parametrize("text", ['{"k": "\\ud83d\\ude00"}', '{"k": "\\uD83D\\uDE00"}', '{"\\ud83d\\ude00": 1}',
                                  '{"k": "\\\\ud800"}', '{"k": "\\\\\\\\ud800 \\ud83d\\ude00"}',
                                  '{"k": "\U0001F600"}', '{"k": "\\ud7ff \\ue000"}', '["\\ud83d\\ude00\\ud83d\\ude00"]'])
def test_a_proper_pair_and_a_literal_backslash_are_accepted(text) -> None:
    vr = _load_checker()
    assert vr.json_shape(text)[2] is False
    assert vr.strict_json(text.encode(), "p", "x") is not None


def test_a_proper_pair_in_utf_16_is_accepted_and_a_deep_lone_surrogate_is_refused() -> None:
    vr = _load_checker()
    assert vr.strict_json(b"\xff\xfe" + '{"k": "\U0001F600"}'.encode("utf-16-le"), "p", "x") == {"k": "\U0001F600"}
    with pytest.raises(vr.Fail, match="x holds an unpaired surrogate"):
        vr.strict_json(b'{"a": [{"b": [{"\\ud800": 1}]}]}', "p", "x")
    with pytest.raises(vr.Fail, match="x holds an unpaired surrogate"):
        vr.strict_json(b'[[[["ok", "\\udc00"]]]]', "p", "x")


@pytest.mark.parametrize("name", sorted(DOCUMENT_KINDS))
def test_the_order_of_faults_is_depth_number_length_surrogate_then_the_parse(name, tmp_path) -> None:
    import shutil

    folder = PACK / "good" / "run_held_output_confirmed_exit_code"
    case = json.loads((folder / "case.json").read_text())
    what = DOCUMENT_KINDS[name]
    documents = [
        (b'{"a": 1, "a": "\\ud800"}', f"inputs: {what} holds an unpaired surrogate"),             # surrogate, then key
        (b'{"a": 1.5, "b": "\\ud800"}', f"inputs: {what} holds an unpaired surrogate"),           # then float
        (b'{"a": ' + b"1" * 101 + b', "b": "\\ud800"}', f"inputs: {what} holds a number literal of more than 100 characters"),
        (b"[" * 65 + b'"\\ud800"' + b"]" * 65, f"inputs: {what} nests too deeply to read"),
        (b"[" * 65 + b"1" * 101 + b"]" * 65, f"inputs: {what} nests too deeply to read"),
    ]
    for i, (raw, reason) in enumerate(documents):
        work = tmp_path / f"case{i}"
        shutil.copytree(folder, work)
        (work / name).write_bytes(raw)
        code, out, err = _run_cli(*[a.replace("{dir}", str(work)) for a in case["args"]])
        assert code == 1 and "Traceback" not in err and json.loads(out)["reason"] == reason, (i, out)


# ---- a receipt that carries only ONE of the two numbering fields (PR 529's rule, in every mode)

ONE_FIELD = {"only room_sequence": {"numbered": False, "room_sequence": "SEQ"},
             "only room_previous_receipt_sha256": {"numbered": False, "room_previous_receipt_sha256": "PREV"}}


def _room_with_one_field(gen, pack, variant: str, which: int, pool: bool):
    """A room's list (pre-made or ordinary) whose receipt number `which` has one numbering field only."""
    hotel = pack.new_hotel()
    steps = ([("create", 202, {"pool": True}), ("claim", 200, None), ("exec", 200, {})] if pool
             else [("create", 202, {}), ("exec", 200, {}), ("exec", 200, {})])
    receipts = []
    for i, (action, status, extra) in enumerate(steps):
        extra = gen.claim_fields(receipts[0]) if action == "claim" else dict(extra)
        if i == which:
            extra.update({"numbered": False, **({"room_sequence": i + 1} if variant == "only room_sequence" else
                                                {"room_previous_receipt_sha256": receipts[-1]["receipt_sha256"]
                                                 if receipts else None})})
        receipts.append(hotel.sign(action, "pool-1" if pool else "room-a", status, **extra))
    return {"receipts": receipts, "head": hotel.head}


def _list_mode(tmp_path: Path, doc: dict, *more: str) -> tuple[int, dict, str]:
    gen = _generator()
    pack = gen.Pack(gen.read_amd())
    (tmp_path / "att.json").write_bytes(gen.pretty(pack.attestation))
    (tmp_path / "r.json").write_text(json.dumps(doc))
    code, out, err = _run_cli("--attestation", str(tmp_path / "att.json"), "--receipts", str(tmp_path / "r.json"),
                              "--skip-amd", "--expected-measurement", gen.MEASUREMENT, *more)
    return code, json.loads(out) if out.strip() else {}, err


@pytest.mark.parametrize("which", [0, 1, 2])
@pytest.mark.parametrize("variant", sorted(ONE_FIELD))
def test_a_pre_made_room_with_a_one_field_receipt_ends_in_a_reason_and_gives_no_link(variant, which, tmp_path) -> None:
    gen = _generator()
    doc = _room_with_one_field(gen, gen.Pack(gen.read_amd()), variant, which, pool=True)
    code, out, err = _list_mode(tmp_path, doc, "--cathedral-sandbox", gen.CLAIM_ID)
    assert "Traceback" not in err, err
    assert code == 1 and out["verdict"] == "FAIL" and out["reason"], out
    assert "room_links" not in out and "sandbox_link" not in out


@pytest.mark.parametrize("which", [0, 1, 2])
@pytest.mark.parametrize("variant", sorted(ONE_FIELD))
def test_an_ordinary_room_with_a_one_field_receipt_gets_the_warning_and_no_numbering_claim(variant, which,
                                                                                         tmp_path) -> None:
    gen = _generator()
    doc = _room_with_one_field(gen, gen.Pack(gen.read_amd()), variant, which, pool=False)
    code, out, err = _list_mode(tmp_path, doc)
    assert "Traceback" not in err, err
    assert code == 0 and out["verdict"] == "PASS"
    assert "room-a has receipts with incomplete numbering: no numbering claim for it" in out["checked"]
    assert "room_numbering" not in out["chain"]


@pytest.mark.parametrize("drop", ["room_previous_receipt_sha256", "room_sequence"])
def test_run_mode_fails_with_a_reason_when_a_receipt_carries_one_numbering_field(drop, tmp_path) -> None:
    gen = _generator()
    pack = gen.Pack(gen.read_amd())

    def resign_last(bundle):
        receipt = bundle["receipts"][-1]
        receipt["statement"].pop(drop)
        receipt["receipt_sha256"] = gen.sha(gen.canonical(receipt["statement"]))
        receipt["signature_b64"] = gen.b64(pack.key.sign(gen.canonical(receipt["statement"])))

    files, args = gen.make_run(pack, bundle_edit=resign_last)
    for name, data in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(data)
    code, out, err = _run_cli(*[a.replace("{dir}", str(tmp_path)) for a in args])
    assert "Traceback" not in err, err
    assert code == 1 and json.loads(out) == {
        "verdict": "FAIL", "reason": "check 2: room run-room-1: the receipts are not numbered (room_sequence)"}


# ---- the list's count is an integer as written (a boolean or a float equals 0 or 1 in Python, not in Go)

COUNT_REASON = "the list's count is not an integer"


def _one_receipt_list(extra: dict, count_member: dict) -> dict:
    gen = _generator()
    hotel = gen.Pack(gen.read_amd()).new_hotel()
    receipt = hotel.sign("create", "room-a", 202)
    return {"receipts": [receipt], **extra(receipt), **count_member}


@pytest.mark.parametrize("count", [False, True, 0.0, 1.0, "1", None, [], {}], ids=repr)
@pytest.mark.parametrize("with_head", [True, False], ids=["head", "no-head"])
@pytest.mark.parametrize("shape", ["empty", "one"])
def test_a_count_that_is_not_an_integer_fails_with_one_reason(shape, with_head, count, tmp_path) -> None:
    if shape == "empty":
        doc = {"receipts": [], **({"room_head": None} if with_head else {}), "count": count}
    else:
        doc = _one_receipt_list(lambda rc: {"room_head": rc["receipt_sha256"]} if with_head else {}, {"count": count})
    code, out, err = _list_mode(tmp_path, doc)
    assert "Traceback" not in err, err
    assert code == 1 and out == {"verdict": "FAIL", "reason": COUNT_REASON}, out


@pytest.mark.parametrize("with_head", [True, False], ids=["head", "no-head"])
def test_the_right_integer_count_passes_and_a_wrong_integer_keeps_the_numbering_reason(with_head, tmp_path) -> None:
    head = {"room_head": None} if with_head else {}
    assert _list_mode(tmp_path, {"receipts": [], **head, "count": 0})[0] == 0
    doc = _one_receipt_list(lambda rc: {"room_head": rc["receipt_sha256"]} if with_head else {}, {"count": 1})
    assert _list_mode(tmp_path, doc)[0] == 0
    code, out, _ = _list_mode(tmp_path, {"receipts": [], **head, "count": 5})
    if with_head:
        assert code == 1 and out["reason"] == "an empty room list names a nonzero count"
    else:
        assert code == 0                        # without a room_head the value is still ignored
    doc = _one_receipt_list(lambda rc: {"room_head": rc["receipt_sha256"]} if with_head else {}, {"count": 5})
    code, out, _ = _list_mode(tmp_path, doc)
    if with_head:
        assert code == 1 and out["reason"] == "room room-a: the list names 5 receipts but holds 1"
    else:
        assert code == 0


def test_the_count_check_is_in_the_function_too() -> None:
    vr = _load_checker()
    for bad in (False, True, 0.0, 1.0, "1", None, [], {}):
        with pytest.raises(vr.Fail, match="the list's count is not an integer"):
            vr.room_numbering([], {"count": bad})
        with pytest.raises(vr.Fail, match="the list's count is not an integer"):
            vr.room_numbering([], {"room_head": None, "count": bad})
    assert vr.room_numbering([], {"count": 7}) == {"rooms": {}, "warnings": []}


# ---- a version-2 SNP report has no CPUID fields: run mode must honour --product, as list mode does

def _version_2_run(tmp_path: Path, *product_args: str) -> tuple[int, dict, str]:
    """A run file whose chip report is version 2 (its own synthetic chain, the same binding and receipts)."""
    gen = _generator()
    pack = gen.Pack(gen.read_amd())
    amd = gen.make_amd(report_version=2)
    certs = json.loads(amd["source/amd/certs.json"])
    report = json.loads(amd["source/amd/report.json"])["report_b64"]
    ark = amd["source/amd/ark_sha256.txt"].decode().strip()

    def edit(bundle):
        bundle["attestation"]["report_b64"] = report
        bundle["amd_certs"] = certs

    files, args = gen.make_run(pack, bundle_edit=edit)
    args[args.index("--ark-sha256") + 1] = ark
    for name, data in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(data)
    code, out, err = _run_cli(*[a.replace("{dir}", str(tmp_path)) for a in args], *product_args)
    return code, json.loads(out), err


def test_a_version_2_report_passes_in_run_mode_with_the_product_named(tmp_path) -> None:
    code, out, err = _version_2_run(tmp_path, "--product", "Milan")
    assert "Traceback" not in err and code == 0 and out["verdict"] == "PASS", out
    assert out["attestation"]["amd"]["product"] == "Milan" and out["attestation"]["report_version"] == 2


def test_a_version_2_report_without_the_product_fails_with_the_instruction(tmp_path) -> None:
    code, out, err = _version_2_run(tmp_path)
    assert "Traceback" not in err and code == 1
    assert out == {"verdict": "FAIL", "reason": "check 1: cannot tell the product from cpuid family None model None; "
                                                "pass --product"}


def test_a_version_2_report_with_a_product_that_has_no_layout_fails(tmp_path) -> None:
    code, out, err = _version_2_run(tmp_path, "--product", "Rome")
    assert "Traceback" not in err and code == 1
    assert out == {"verdict": "FAIL", "reason": "check 1: only Milan and Genoa TCB layouts are handled"}


def test_the_product_only_names_the_layout_when_the_certificates_come_with_the_file(tmp_path) -> None:
    """The chain is the file's own, so the other known product still verifies it: --product never fetches here."""
    code, out, _ = _version_2_run(tmp_path, "--product", "Genoa")
    assert code == 0 and out["attestation"]["amd"]["product"] == "Genoa"
