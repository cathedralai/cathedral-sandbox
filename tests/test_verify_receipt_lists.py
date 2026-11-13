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
    assert vr.ONESHOT_SIZES == shared["sizes"]


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
    shutil.copytree(PACK / "good" / "run_held_output_proven_exit_code", folder)
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


def _log_roomy(r):
    r["request"]["outputs"][1]["max_bytes"] = 1048576


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
    ("output max_bytes at most 200 MiB",
     {"truth_edit": _edit(outputs=[{"path": "/work/out/x", "max_bytes": 209715200, "optional": False}]), "held": (), "inline": ()},
     {"truth_edit": _edit(outputs=[{"path": "/work/out/x", "max_bytes": 209715201, "optional": False}]), "held": (), "inline": ()},
     "recipe: an output max_bytes must be at most 200 MiB"),
    ("timeout_seconds at least 1", {"truth_edit": _edit(timeout_seconds=1)}, {"truth_edit": _edit(timeout_seconds=0)},
     "recipe: timeout_seconds must be at least 1"),
    ("context at most 4 KiB", {"truth_context": {"k": "a" * 4088}}, {"truth_context": {"k": "a" * 4089}},
     "inputs: the context is larger than 4 KiB (4096 canonical bytes)"),
    ("inline output at most 64 KiB", {"truth_edit": _log_roomy, "file_bytes": {"/work/out/log.txt": b"x" * 65536}},
     {"truth_edit": _log_roomy, "file_bytes": {"/work/out/log.txt": b"x" * 65537}},
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
