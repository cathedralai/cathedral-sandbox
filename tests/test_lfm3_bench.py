"""AB#444 lfm3-bench against a fake streaming llama-server on loopback.

Needs bash 4+, jq and curl, no model. The fake answers /health and a streamed
/v1/chat/completions: a role-only chunk, content chunks, a final chunk with
llama-server timings, then data: [DONE].
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "images" / "room-lfm3-suite" / "lfm3-bench"
TIMINGS = {"prompt_n": 14, "prompt_ms": 120.44, "prompt_per_second": 116.25,
           "predicted_n": 3, "predicted_ms": 124.0, "predicted_per_second": 24.19}


def _bash_ok() -> bool:
    bash = shutil.which("bash")
    if not bash:
        return False
    out = subprocess.run([bash, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True)
    return out.stdout.strip().isdigit() and int(out.stdout.strip()) >= 4


pytestmark = pytest.mark.skipif(
    not (_bash_ok() and shutil.which("jq") and shutil.which("curl") and shutil.which("sha256sum")),
    reason="lfm3-bench needs bash 4+, jq, curl and sha256sum",
)


class FakeServer(BaseHTTPRequestHandler):
    requests: list = []
    chunks: list = []
    first_delay = 0.0
    status = 200

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeServer.requests.append(body)
        if FakeServer.status != 200:
            raw = b'{"error": {"message": "boom"}}'
            self.send_response(FakeServer.status)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for i, chunk in enumerate(FakeServer.chunks):
            if i == 1:
                time.sleep(FakeServer.first_delay)
            line = chunk if isinstance(chunk, str) else "data: " + json.dumps(chunk)
            self.wfile.write((line + "\r\n\r\n").encode())
            self.wfile.flush()


def delta(text: str | None = None, role: str | None = None, **extra) -> dict:
    d = {k: v for k, v in (("role", role), ("content", text)) if k == "content" or v is not None}
    return {"choices": [{"index": 0, "delta": d, "finish_reason": None}], **extra}


def normal_stream(timings: dict | None = TIMINGS) -> list:
    final = {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
    if timings is not None:
        final["timings"] = timings
    return [delta(None, role="assistant"), delta("Fo"), delta("ur"), final, "data: [DONE]"]


@pytest.fixture
def room(tmp_path):
    FakeServer.requests, FakeServer.chunks, FakeServer.first_delay, FakeServer.status = [], normal_stream(), 0.0, 200
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    model = tmp_path / "LFM3-Test-Q4_K_M.gguf"
    model.write_bytes(b"weights" * 1000)
    mmproj = tmp_path / "mmproj-Test.gguf"
    mmproj.write_bytes(b"projector")
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in (model, mmproj)))
    env = {
        "PATH": os.environ["PATH"], "HOME": str(tmp_path),
        "MODEL_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1", "MODEL": "lfm3-test",
        "LFM3_MODEL": str(model), "LFM3_MMPROJ": str(mmproj), "LFM3_SUMS": str(sums),
        "LFM3_LOG_DIR": str(tmp_path / "log"), "LFM3_WAIT": "5", "LFM3_THREADS": "2",
    }
    yield {"env": env, "model": model, "mmproj": mmproj, "sums": sums}
    server.shutdown()


def bench(room, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(BENCH), *args], capture_output=True, text=True, timeout=60,
                          env={**room["env"], **(env or {})})


def result_line(out: str) -> dict:
    lines = [ln for ln in out.splitlines() if ln.startswith("lfm3-bench {")]
    assert len(lines) == 1, out
    return json.loads(lines[0][len("lfm3-bench "):])


def canon(prompts: list[str]) -> str:
    return json.dumps(prompts, separators=(",", ":"), ensure_ascii=False)


def test_prints_answer_then_one_line_with_ttft_rates_and_hashes(room):
    FakeServer.first_delay = 0.25
    prompts = canon(["What is 2+2?", "Name a river: ñ"])
    done = bench(room, "--max-tokens", "64", "--index", "1", prompts)
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[0] == "Four"
    line = result_line(done.stdout)
    assert line["ttft_ms"] >= 250 and line["wall_ms"] >= line["ttft_ms"]
    assert line["prompt_tok_s"] == 116.2 or line["prompt_tok_s"] == 116.3
    assert line["decode_tok_s"] == 24.2 and line["decode_n"] == 3 and line["prompt_n"] == 14
    assert line["prompt_ms"] == 120.4
    assert line["model_sha256"] == hashlib.sha256(room["model"].read_bytes()).hexdigest()
    assert line["mmproj_sha256"] == hashlib.sha256(room["mmproj"].read_bytes()).hexdigest()
    assert line["model_file"] == room["model"].name and line["model"] == "lfm3-test"
    # The client hashes the bytes it sends: the in-room hash must be the same.
    assert line["prompt_set_sha256"] == hashlib.sha256(prompts.encode()).hexdigest()
    assert line["prompt_index"] == 1 and line["max_tokens"] == 64 and line["harness"] == "lfm3-bench-1"
    assert line["threads"] == 2 and line["load_ms"] is None
    sent = FakeServer.requests[-1]
    assert sent["messages"] == [{"role": "user", "content": "Name a river: ñ"}]
    assert sent["stream"] is True and sent["cache_prompt"] is False and sent["max_tokens"] == 64
    assert sent["temperature"] == 0


def test_prompt_with_trailing_newline_is_sent_byte_for_byte(room):
    done = bench(room, "--index", "0", canon(["line one\n\n"]))
    assert done.returncode == 0, done.stderr
    assert FakeServer.requests[-1]["messages"][0]["content"] == "line one\n\n"


def test_reasoning_token_counts_as_first_token(room):
    FakeServer.chunks = [delta(None, role="assistant"),
                         {"choices": [{"index": 0, "delta": {"reasoning_content": "hmm"}}]},
                         *normal_stream()[1:]]
    done = bench(room, "--index", "0", canon(["p"]))
    assert done.returncode == 0, done.stderr
    assert result_line(done.stdout)["ttft_ms"] >= 0


def test_model_not_matching_sha256sums_gives_no_result(room):
    room["model"].write_bytes(b"swapped weights")
    done = bench(room, "--index", "0", canon(["p"]))
    assert done.returncode == 1 and "lfm3-bench {" not in done.stdout
    assert "SHA256SUMS says" in done.stderr
    assert FakeServer.requests == []


def test_model_missing_from_sha256sums_gives_no_result(room):
    room["sums"].write_text("")
    done = bench(room, "--index", "0", canon(["p"]))
    assert done.returncode == 1 and "has no entry" in done.stderr


def test_no_mmproj_is_null(room):
    done = bench(room, "--index", "0", canon(["p"]), env={"LFM3_MMPROJ": ""})
    assert done.returncode == 0, done.stderr
    assert result_line(done.stdout)["mmproj_sha256"] is None


def test_stream_without_timings_fails(room):
    FakeServer.chunks = normal_stream(timings=None)
    done = bench(room, "--index", "0", canon(["p"]))
    assert done.returncode == 1 and "no timings" in done.stderr and "lfm3-bench {" not in done.stdout


def test_stream_without_a_token_fails(room):
    FakeServer.chunks = [delta(None, role="assistant"), "data: [DONE]"]
    done = bench(room, "--index", "0", canon(["p"]))
    assert done.returncode == 1 and "no token" in done.stderr


def test_error_chunk_after_200_fails(room):
    FakeServer.chunks = [delta(None, role="assistant"), delta("x"), {"error": {"message": "context"}},
                         "data: [DONE]"]
    done = bench(room, "--index", "0", canon(["p"]))
    assert done.returncode == 1 and "error" in done.stderr


def test_http_error_fails(room):
    FakeServer.status = 500
    done = bench(room, "--index", "0", canon(["p"]))
    assert done.returncode == 1 and "answered 500" in done.stderr


@pytest.mark.parametrize("args", [
    ["--index", "2", '["a","b"]'],
    ["--index", "0", "[]"],
    ["--index", "0", '["a",""]'],
    ["--index", "0", '{"a":1}'],
    ["--index", "0", "not json"],
    ["--index", "-1", '["a"]'],
    ["--max-tokens", "0", "--index", "0", '["a"]'],
    ['["a"]'],
    ["--index", "0"],
])
def test_bad_usage_exits_2_before_any_request(room, args):
    done = bench(room, *args)
    assert done.returncode == 2, done.stdout + done.stderr
    assert FakeServer.requests == []


def test_decision_model_is_refused(room):
    done = bench(room, "--index", "0", canon(["p"]), env={"LFM3_KIND": "decision"})
    assert done.returncode == 2 and "decision model" in done.stderr


def test_dockerfile_installs_lfm3_bench():
    dockerfile = (ROOT / "images" / "room-lfm3-suite" / "Dockerfile").read_text()
    copy = next(ln for ln in dockerfile.splitlines() if ln.startswith("COPY lfm3-serve "))
    assert " lfm3-bench " in copy
    assert "chmod 0755 /usr/local/bin/lfm3-serve /usr/local/bin/lfm3-ask /usr/local/bin/lfm3-bench " in dockerfile


def test_sealed_bench_parses_the_real_line(room):
    import importlib.util

    spec = importlib.util.spec_from_file_location("sealed_bench_for_lfm3_bench", ROOT / "scripts" / "sealed_bench.py")
    sealed_bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sealed_bench)
    prompts = canon(["a", "b"])
    done = bench(room, "--index", "1", prompts)
    assert done.returncode == 0, done.stderr
    line = sealed_bench.parse_bench(done.stdout, hashlib.sha256(prompts.encode()).hexdigest(), 1)
    assert line["harness"] == sealed_bench.ROOM_HARNESS and line["ttft_ms"] >= 0
