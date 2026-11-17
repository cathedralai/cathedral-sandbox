"""AB#444 sealed_bench.py against a fake customer API on loopback and a fake ctcli. No real network."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("sealed_bench", ROOT / "scripts" / "sealed_bench.py")
sealed_bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sealed_bench)

IMAGE = "ghcr.io/cathedralai/room-lfm3-omni-2b@sha256:" + "a" * 64
TIMING = "lfm3-timing load_ms=800 prompt_tok_s=77.5 gen_tok_s=24.1 wall_ms=9000 threads=2 max_tokens=64 reasoning=off"
MODEL_SHA = "9f" * 32
SID = "11111111-1111-1111-1111-111111111111"


def canon(prompts: list[str]) -> str:
    return json.dumps(prompts, separators=(",", ":"), ensure_ascii=False)


def bench_line(prompt_set: str, index: int, **over) -> dict:
    line = {"harness": "lfm3-bench-1", "ttft_ms": 412, "prompt_tok_s": 77.5, "decode_tok_s": 24.1,
            "wall_ms": 9000, "prompt_ms": 120.4, "prompt_n": 14, "decode_n": 64, "load_ms": 800, "threads": 2,
            "model_sha256": MODEL_SHA, "mmproj_sha256": None, "model_file": "m.gguf", "max_tokens": 256,
            "prompt_set_sha256": hashlib.sha256(prompt_set.encode()).hexdigest(), "prompt_index": index}
    line.update(over)
    return line


def stdout_for_command(command: list[str], **over) -> str:
    """What the room prints for this exec: lfm3-bench's line, or lfm3-ask's timing line."""
    if command[0] == "lfm3-ask":
        return f"answer to {command[1]}\n{TIMING}\n"
    index, prompt_set = int(command[4]), command[5]
    prompt = json.loads(prompt_set)[index]
    return f"answer to {prompt}\nlfm3-bench {json.dumps(bench_line(prompt_set, index, **over), sort_keys=True)}\n"


def bench_command(prompts: list[str], index: int, max_tokens: int = 256) -> list[str]:
    return ["lfm3-bench", "--max-tokens", str(max_tokens), "--index", str(index), canon(prompts)]


def stdout_for(prompts: list[str], index: int) -> str:
    return stdout_for_command(bench_command(prompts, index))


def guest_create(image: str = IMAGE, sandbox_id: str | None = SID, status: int = 201) -> dict:
    st = {"action": "create", "status": status, "image": image, "image_digest": "sha256:" + "e" * 64}
    if sandbox_id:
        st["cathedral_sandbox_id"] = sandbox_id
    raw = json.dumps({"statement": st, "signature_b64": "sig", "receipt_sha256": "x"}).encode()
    return {"hotel_receipt_b64": base64.urlsafe_b64encode(raw).decode().rstrip("=")}


class FakeApi(BaseHTTPRequestHandler):
    log: list = []
    states: list = []
    exit_code = 0
    override: dict = {}

    def log_message(self, *a):
        pass

    def _send(self, doc, status=200):
        raw = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else None

    def do_POST(self):
        body = self._body()
        FakeApi.log.append(("POST", self.path, body, self.headers.get("Authorization")))
        if self.path == "/v1/sandboxes":
            return self._send({"id": SID, "state": "creating"}, 202)
        return self._send({"exit_code": FakeApi.exit_code,
                           "stdout": stdout_for_command(body["command"], **FakeApi.override), "stderr": "",
                           "room_receipt_id": "r1"})

    def do_GET(self):
        FakeApi.log.append(("GET", self.path, None, None))
        self._send({"state": FakeApi.states.pop(0) if FakeApi.states else "running"})

    def do_DELETE(self):
        FakeApi.log.append(("DELETE", self.path, None, None))
        self._send({"state": "deleting"})


@pytest.fixture
def api(monkeypatch):
    FakeApi.log, FakeApi.states, FakeApi.exit_code, FakeApi.override = [], ["running"], 0, {}
    server = HTTPServer(("127.0.0.1", 0), FakeApi)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("CATHEDRAL_API_URL", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("CATHEDRAL_API_KEY", "test-key")
    yield FakeApi
    server.shutdown()


def command_hash(prompts: list[str], index: int) -> str:
    return sealed_bench.command_sha256(bench_command(prompts, index))


def fake_ctcli(tmp_path: Path, prompts: list[str], *, drop_last=False, fail=False, verdict="PASS", receipts=None,
               guest=None, commands=None) -> str:
    """Fake ctcli: `sandbox evidence` copies a canned bundle, `receipt verify` logs its argv and answers."""
    if receipts is None:
        commands = commands or [bench_command(prompts, i) for i in range(len(prompts))]
        receipts = [{"n": i + 2, "action": "sandbox.exec", "command_sha256": sealed_bench.command_sha256(c),
                     "stdout_sha256": hashlib.sha256(stdout_for_command(c).encode()).hexdigest()}
                    for i, c in enumerate(commands)]
    if drop_last:
        receipts = receipts[:-1]
    bundle = tmp_path / "fake-bundle.json"
    bundle.write_text(json.dumps({"cathedral_receipts": {"receipts": receipts},
                                  "guest_receipts": {"receipts": [guest_create()] if guest is None else guest}}))
    script = tmp_path / "ctcli"
    script.write_text("""#!/usr/bin/env python3
import json, shutil, sys
argv = sys.argv[1:]
if argv[:2] == ["receipt", "verify"]:
    open(%r, "a").write(json.dumps(argv) + "\\n")
    print(json.dumps({"verdict": %r}))
    sys.exit(0 if %r == "PASS" else 3)
if %r:
    sys.exit(1)
shutil.copy(%r, argv[argv.index("-o") + 1])
""" % (str(tmp_path / "verify.log"), verdict, verdict, fail, str(bundle)))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


PINS = ["--cathedral-key", "ab" * 32, "--expected-measurement", "cd" * 48]


def prompts_file(tmp_path: Path, prompts: list[str]) -> str:
    path = tmp_path / "prompts.json"
    path.write_text(json.dumps(prompts))
    return str(path)


def args(tmp_path, prompts, extra=()):
    return ["--image", IMAGE, "--prompts", prompts_file(tmp_path, prompts), "--out-dir", str(tmp_path / "out"),
            "--poll-seconds", "0", *PINS, *extra]


def result_of(tmp_path: Path) -> dict:
    return json.loads(next((tmp_path / "out").glob("*-result.json")).read_text())


def test_one_run_binds_each_exec_to_a_receipt_and_deletes(api, tmp_path, monkeypatch):
    prompts = ["p one", "p two"]
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, prompts))
    assert sealed_bench.main(args(tmp_path, prompts)) == 0
    res = result_of(tmp_path)
    assert res["deleted"] is True and res["error"] is None
    assert [r["receipt_n"] for r in res["runs"]] == [2, 3]
    assert res["runs"][0]["decode_tok_s"] == 24.1 and res["runs"][0]["prompt_tok_s"] == 77.5
    assert res["runs"][0]["ttft_ms"] == 412 and res["runs"][0]["model_sha256"] == MODEL_SHA
    assert res["model_sha256"] == MODEL_SHA and res["room_harness"] == "lfm3-bench-1"
    assert res["prompt_set_sha256"] == hashlib.sha256(canon(prompts).encode()).hexdigest()
    assert res["image_bound"] is True and res["guest_image"] == IMAGE
    assert res["guest_image_digest"] == "sha256:" + "e" * 64
    execs = [e[2] for e in api.log if e[1].endswith("/exec")]
    assert [e["command"] for e in execs] == [bench_command(prompts, 0), bench_command(prompts, 1)]
    assert Path(res["bundle_path"]).exists()
    saved = Path(res["runs"][0]["stdout_file"]).read_bytes()
    assert hashlib.sha256(saved).hexdigest() == res["runs"][0]["stdout_sha256"]
    create = next(e for e in api.log if e[1] == "/v1/sandboxes")[2]
    assert create["required_hardware"] == "amd_sev_snp" and create["network"] == "deny_all" and create["image"] == IMAGE
    assert api.log[-1][0] == "DELETE"
    assert res["verification"] == {"verdict": "PASS", "exit_code": 0}
    verify_argv = json.loads((tmp_path / "verify.log").read_text().splitlines()[0])
    assert "--require-outputs" in verify_argv and verify_argv[verify_argv.index("--cathedral-key") + 1] == "ab" * 32
    assert verify_argv[verify_argv.index("--expected-measurement") + 1] == "cd" * 48
    assert [verify_argv[i + 1].split("=")[0] for i, v in enumerate(verify_argv) if v == "--stdout"] == ["2", "3"]
    assert all(e[3] == "Bearer test-key" for e in api.log if e[0] == "POST")


def test_missing_receipt_is_reported_and_exit_3(api, tmp_path, monkeypatch):
    prompts = ["p one", "p two"]
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, prompts, drop_last=True))
    assert sealed_bench.main(args(tmp_path, prompts)) == 3
    assert [r["receipt_n"] for r in result_of(tmp_path)["runs"]] == [2, None]


def test_exec_failure_still_deletes_the_sandbox(api, tmp_path, monkeypatch):
    api.exit_code = 7
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"]))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 1
    res = result_of(tmp_path)
    assert res["deleted"] is True and "exit 7" in res["error"]


def test_evidence_failure_still_deletes(api, tmp_path, monkeypatch):
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], fail=True))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 1
    assert result_of(tmp_path)["deleted"] is True


def test_sandbox_that_never_runs_is_deleted(api, tmp_path, monkeypatch):
    api.states = ["failed"]
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"]))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 1
    assert result_of(tmp_path)["deleted"] is True


def test_tag_image_and_missing_key_are_refused_before_any_call(api, tmp_path, monkeypatch, capsys):
    bad = ["--image", "ghcr.io/cathedralai/room-lfm3-omni-2b:latest", "--prompts", prompts_file(tmp_path, ["p"]),
           "--out-dir", str(tmp_path / "o")]
    assert sealed_bench.main(bad) == 2
    monkeypatch.delenv("CATHEDRAL_API_KEY")
    assert sealed_bench.main(args(tmp_path, ["p"])) == 2
    assert api.log == []


def test_verify_not_pass_fails_closed_after_receipts_match(api, tmp_path, monkeypatch):
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], verdict="NOT PROVEN"))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 1
    res = result_of(tmp_path)
    assert "did not PASS" in res["error"] and res["verification"]["verdict"] == "NOT PROVEN" and res["deleted"] is True


def test_forged_bundle_with_wrong_verify_never_exits_zero(api, tmp_path, monkeypatch):
    # receipts match by hash, but the offline verify (signatures, attestation) says FAIL
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], verdict="FAIL"))
    assert sealed_bench.main(args(tmp_path, ["p"])) != 0


def test_missing_pins_are_refused_before_any_call(api, tmp_path, monkeypatch):
    base = ["--image", IMAGE, "--prompts", prompts_file(tmp_path, ["p"]), "--out-dir", str(tmp_path / "o")]
    assert sealed_bench.main(base) == 2
    assert sealed_bench.main([*base, "--cathedral-key", "ab" * 32]) == 2
    assert sealed_bench.main([*base, "--expected-measurement", "cd" * 48]) == 2
    assert api.log == []


def test_identical_outputs_bind_to_distinct_receipts(api, tmp_path, monkeypatch):
    # same prompt twice: same stdout, same command; receipts n=2 and n=3 must each be used once
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["same", "same"]))
    assert sealed_bench.main(args(tmp_path, ["same", "same"])) == 0
    assert [r["receipt_n"] for r in result_of(tmp_path)["runs"]] == [2, 3]


def test_one_receipt_cannot_back_two_identical_runs(api, tmp_path, monkeypatch):
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["same", "same"], drop_last=True))
    assert sealed_bench.main(args(tmp_path, ["same", "same"])) == 3
    assert [r["receipt_n"] for r in result_of(tmp_path)["runs"]] == [2, None]


def test_receipt_with_other_command_hash_does_not_bind(api, tmp_path, monkeypatch):
    out = hashlib.sha256(stdout_for(["p"], 0).encode()).hexdigest()
    other = [{"n": 2, "action": "sandbox.exec", "command_sha256": command_hash(["different"], 0), "stdout_sha256": out}]
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], receipts=other))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 3


def test_finish_receipt_takes_command_from_its_start(api, tmp_path, monkeypatch):
    out = hashlib.sha256(stdout_for(["p"], 0).encode()).hexdigest()
    pair = [{"n": 2, "action": "sandbox.exec.start", "exec_id": "e1", "command_sha256": command_hash(["p"], 0)},
            {"n": 3, "action": "sandbox.exec.finish", "exec_id": "e1", "stdout_sha256": out}]
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], receipts=pair))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 0
    assert result_of(tmp_path)["runs"][0]["receipt_n"] == 3


def test_evidence_timeout_or_missing_ctcli_still_writes_result_and_deletes(api, tmp_path, monkeypatch):
    monkeypatch.setenv("CTCLI", str(tmp_path / "no-such-ctcli"))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 1
    res = result_of(tmp_path)
    assert res["deleted"] is True and "FileNotFoundError" in res["error"]


def test_api_sends_a_non_urllib_user_agent():
    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen["ua"] = self.headers.get("User-Agent")
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    server = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    sealed_bench.Api(f"http://127.0.0.1:{server.server_port}", "k").call("GET", "/x")
    server.shutdown()
    assert seen["ua"] and not seen["ua"].startswith("Python-urllib")


def test_create_to_running_includes_slow_create(api, tmp_path, monkeypatch):
    real = sealed_bench.Api.call

    def slow(self, method, path, *a, **k):
        if method == "POST" and path == "/v1/sandboxes":
            sealed_bench.time.sleep(0.3)
        return real(self, method, path, *a, **k)

    monkeypatch.setattr(sealed_bench.Api, "call", slow)
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"]))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 0
    assert result_of(tmp_path)["create_to_running_s"] >= 0.3


def test_lfm3_ask_harness_still_runs_older_images(api, tmp_path, monkeypatch):
    prompts = ["p one"]
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, prompts, commands=[["lfm3-ask", "p one"]]))
    assert sealed_bench.main(args(tmp_path, prompts, ["--harness", "lfm3-ask"])) == 0
    res = result_of(tmp_path)
    assert res["runs"][0]["ttft_ms"] is None and res["model_sha256"] is None and res["room_harness"] == "lfm3-ask"
    assert res["runs"][0]["decode_tok_s"] == 24.1
    execs = [e[2] for e in api.log if e[1].endswith("/exec")]
    assert execs[0]["command"] == ["lfm3-ask", "p one"] and execs[0]["env"] == {"LFM3_MAX_TOKENS": "256"}


def test_guest_create_with_other_image_digest_is_unbound(api, tmp_path, monkeypatch):
    other = "ghcr.io/cathedralai/room-lfm3-omni-2b@sha256:" + "b" * 64
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], guest=[guest_create(other)]))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 3
    res = result_of(tmp_path)
    assert res["image_bound"] is False and res["guest_image"] == other and res["verification"] is None
    assert not (tmp_path / "verify.log").exists()


def test_no_guest_create_receipt_is_unbound(api, tmp_path, monkeypatch):
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], guest=[]))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 3
    assert result_of(tmp_path)["image_bound"] is False


def test_guest_create_of_another_sandbox_or_failed_does_not_bind(api, tmp_path, monkeypatch):
    guest = [guest_create(sandbox_id="22222222-2222-2222-2222-222222222222"), guest_create(status=500)]
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], guest=guest))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 3
    assert result_of(tmp_path)["guest_create_receipts"] == 0


def test_guest_create_without_sandbox_link_binds_on_digest(api, tmp_path, monkeypatch):
    unlinked = "registry.local/room-lfm3-omni-2b@sha256:" + "a" * 64
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], guest=[guest_create(unlinked, sandbox_id=None)]))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 0
    assert result_of(tmp_path)["image_bound"] is True


def test_in_room_prompt_set_hash_must_match(api, tmp_path, monkeypatch):
    api.override = {"prompt_set_sha256": "0" * 64}
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"]))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 1
    res = result_of(tmp_path)
    assert "different prompt set" in res["error"] and res["deleted"] is True


def test_missing_ttft_or_model_hash_fails(api, tmp_path, monkeypatch):
    for override, message in (({"ttft_ms": None}, "ttft_ms"), ({"model_sha256": "nope"}, "model_sha256"),
                              ({"harness": "lfm3-bench-0"}, "harness"), ({"prompt_index": 5}, "asked 0")):
        api.override = override
        monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"]))
        out = tmp_path / "out"
        for f in out.glob("*"):
            f.unlink()
        assert sealed_bench.main(args(tmp_path, ["p"])) == 1
        assert message in result_of(tmp_path)["error"]


def test_runs_naming_two_models_fail(api, tmp_path, monkeypatch):
    real = sealed_bench.parse_bench
    seen = []

    def flip(stdout, prompt_set_sha256, index):
        line = dict(real(stdout, prompt_set_sha256, index))
        seen.append(1)
        if len(seen) == 2:
            line["model_sha256"] = "aa" * 32
        return line

    monkeypatch.setattr(sealed_bench, "parse_bench", flip)
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["a", "b"]))
    assert sealed_bench.main(args(tmp_path, ["a", "b"])) == 1
    assert "different model sha256" in result_of(tmp_path)["error"]


def test_prompt_set_hash_ignores_file_formatting(api, tmp_path, monkeypatch):
    path = tmp_path / "prompts.json"
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p", "q"]))
    path.write_text('[\n  "p",\n  "q"\n]\n')
    argv = ["--image", IMAGE, "--prompts", str(path), "--out-dir", str(tmp_path / "out"), "--poll-seconds", "0", *PINS]
    assert sealed_bench.main(argv) == 0
    assert result_of(tmp_path)["prompt_set_sha256"] == hashlib.sha256(b'["p","q"]').hexdigest()


def test_oversized_prompt_set_is_refused_before_any_call(api, tmp_path, monkeypatch):
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"]))
    assert sealed_bench.main(args(tmp_path, ["x" * 120_000])) == 2
    assert api.log == []
