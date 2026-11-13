"""AB#444 sealed_bench.py against a fake customer API on loopback and a fake ctcli. No real network."""
from __future__ import annotations

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


def stdout_for(prompt: str) -> str:
    return f"answer to {prompt}\n{TIMING}\n"


class FakeApi(BaseHTTPRequestHandler):
    log: list = []
    states: list = []
    exit_code = 0

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
            return self._send({"id": "11111111-1111-1111-1111-111111111111", "state": "creating"}, 202)
        return self._send({"exit_code": FakeApi.exit_code, "stdout": stdout_for(body["command"][1]), "stderr": "",
                           "room_receipt_id": "r1"})

    def do_GET(self):
        FakeApi.log.append(("GET", self.path, None, None))
        self._send({"state": FakeApi.states.pop(0) if FakeApi.states else "running"})

    def do_DELETE(self):
        FakeApi.log.append(("DELETE", self.path, None, None))
        self._send({"state": "deleting"})


@pytest.fixture
def api(monkeypatch):
    FakeApi.log, FakeApi.states, FakeApi.exit_code = [], ["running"], 0
    server = HTTPServer(("127.0.0.1", 0), FakeApi)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("CATHEDRAL_API_URL", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("CATHEDRAL_API_KEY", "test-key")
    yield FakeApi
    server.shutdown()


def command_hash(prompt: str) -> str:
    return sealed_bench.command_sha256(["lfm3-ask", prompt])


def fake_ctcli(tmp_path: Path, prompts: list[str], *, drop_last=False, fail=False, verdict="PASS", receipts=None) -> str:
    """Fake ctcli: `sandbox evidence` copies a canned bundle, `receipt verify` logs its argv and answers."""
    if receipts is None:
        receipts = [{"n": i + 2, "action": "sandbox.exec", "command_sha256": command_hash(p),
                     "stdout_sha256": hashlib.sha256(stdout_for(p).encode()).hexdigest()}
                    for i, p in enumerate(prompts)]
    if drop_last:
        receipts = receipts[:-1]
    bundle = tmp_path / "fake-bundle.json"
    bundle.write_text(json.dumps({"cathedral_receipts": {"receipts": receipts}}))
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
    assert res["prompt_set_sha256"] == hashlib.sha256(Path(tmp_path / "prompts.json").read_bytes()).hexdigest()
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
    out = hashlib.sha256(stdout_for("p").encode()).hexdigest()
    other = [{"n": 2, "action": "sandbox.exec", "command_sha256": command_hash("different"), "stdout_sha256": out}]
    monkeypatch.setenv("CTCLI", fake_ctcli(tmp_path, ["p"], receipts=other))
    assert sealed_bench.main(args(tmp_path, ["p"])) == 3


def test_finish_receipt_takes_command_from_its_start(api, tmp_path, monkeypatch):
    out = hashlib.sha256(stdout_for("p").encode()).hexdigest()
    pair = [{"n": 2, "action": "sandbox.exec.start", "exec_id": "e1", "command_sha256": command_hash("p")},
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
