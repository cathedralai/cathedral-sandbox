"""lfm3-agent --events against a scripted streaming llama-server (AB#541, AB#542).

Checks the producer side of the chat stream contract: one ASCII JSON line per
event on stdout, one terminal line, tool events with no raw arguments or
output, nothing chat-related on stderr. The fake server speaks SSE like
llama-server with stream: true. No network, no model. The golden fixtures in
images/room-lfm3-suite/test/chat-events/ are the room's share of the contract's
conformance set (section 10, checks 1 to 7); the console and API copy them.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "images" / "room-lfm3-suite"
AGENT = SUITE / "lfm3-agent"
LIQUID = SUITE / "liquid"
FIXTURES = SUITE / "test" / "chat-events"
TURN = "0b8f3c9e-5d1a-4f6e-9a7b-2c4d6e8f0a1b"


def _bash_ok() -> bool:
    bash = shutil.which("bash")
    if not bash:
        return False
    out = subprocess.run([bash, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True)
    return out.stdout.strip().isdigit() and int(out.stdout.strip()) >= 4


pytestmark = pytest.mark.skipif(
    not (_bash_ok() and shutil.which("jq") and shutil.which("curl")),
    reason="lfm3-agent needs bash 4+, jq and curl",
)


class StreamModel:
    """A llama-server stand-in. Each scripted reply answers one chat request.

    reply keys: pieces (content deltas), tool_calls ([{id, name, arguments}]),
    finish (finish_reason, default stop), delay (seconds before each piece),
    status + body (a plain HTTP error), raw (SSE lines sent as they are).
    """

    def __init__(self) -> None:
        self.replies: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []
        self.health_failures = 0
        self.health_always_down = False
        model = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _json(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                if self.path != "/health":
                    self._json(404, {})
                elif model.health_always_down or model.health_failures > 0:
                    model.health_failures -= 1
                    self._json(503, {"error": {"message": "Loading model"}})
                else:
                    self._json(200, {"status": "ok"})

            def _chunk(self, delta: dict[str, Any], finish: str | None = None) -> bytes:
                body = {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
                return f"data: {json.dumps(body)}\n\n".encode()

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                model.requests.append(body)
                if body.get("max_tokens") == 2 and not body.get("stream"):
                    self._json(200, {"choices": [{"message": {"role": "assistant", "content": "ok"}}]})
                    return
                reply = model.replies.pop(0) if model.replies else {"pieces": ["(script ended)"]}
                if "status" in reply:
                    self._json(reply["status"], reply.get("body", {"error": {"message": "scripted failure"}}))
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()

                def send(data: bytes) -> None:
                    self.wfile.write(data)
                    self.wfile.flush()

                for line in reply.get("raw", []):
                    send(line.encode() + b"\n")
                if "raw" in reply:
                    self.close_connection = True
                    return
                send(self._chunk({"role": "assistant"}))
                send(self._chunk({"reasoning_content": "secret reasoning"}))
                for piece in reply.get("pieces", []):
                    time.sleep(reply.get("delay", 0))
                    send(self._chunk({"content": piece}))
                for index, call in enumerate(reply.get("tool_calls", [])):
                    args = call["arguments"] if isinstance(call["arguments"], str) else json.dumps(call["arguments"])
                    head = {"index": index, "id": call["id"], "type": "function", "function": {"name": call["name"], "arguments": ""}}
                    send(self._chunk({"tool_calls": [head]}))
                    half = len(args) // 2
                    for part in (args[:half], args[half:]):
                        send(self._chunk({"tool_calls": [{"index": index, "function": {"arguments": part}}]}))
                send(self._chunk({}, reply.get("finish", "tool_calls" if reply.get("tool_calls") else "stop")))
                send(b"data: [DONE]\n\n")
                self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def model() -> Iterator[StreamModel]:
    m = StreamModel()
    yield m
    m.close()


@pytest.fixture
def room(tmp_path: Path, model: StreamModel):
    work = tmp_path / "work"
    work.mkdir()
    state = tmp_path / "state"
    base_env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "MODEL_BASE_URL": model.base_url,
        "MODEL": "lfm3-vl-2b",
        "LFM3_AGENT_DIR": str(state),
        "LFM3_AGENT_CWD": str(work),
        "LFM3_WAIT": "5",
    }

    def run(*args: str, script: Path = AGENT, **env: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["bash", str(script), *args], input=b"", capture_output=True,
            env={**base_env, **env}, timeout=60,
        )

    run.work = work  # type: ignore[attr-defined]
    run.state = state  # type: ignore[attr-defined]
    run.env = base_env  # type: ignore[attr-defined]
    return run


def events_of(done: subprocess.CompletedProcess[bytes]) -> list[dict[str, Any]]:
    out = done.stdout
    assert out.endswith(b"\n"), out[-200:]
    out.decode("ascii")  # every byte is ASCII
    lines = out.decode("ascii").split("\n")[:-1]
    for line in lines:
        assert line, "blank line in events output"
        limit = 262144 if json.loads(line).get("type") == "answer" else 16384
        assert len(line) + 1 <= limit, f"line of {len(line) + 1} bytes"
    return [json.loads(line) for line in lines]


def turn(room: Any, *message: str, extra: tuple[str, ...] = (), **env: str) -> tuple[subprocess.CompletedProcess[bytes], list[dict[str, Any]]]:
    done = room("--events", "--turn", TURN, *extra, *message, **env)
    return done, events_of(done)


def check_envelope(events: list[dict[str, Any]]) -> None:
    for i, ev in enumerate(events, start=1):
        assert ev["version"] == 1
        assert ev["turn_id"] == TURN
        assert ev["seq"] == i
    terminal = [i for i, ev in enumerate(events) if ev["type"] in ("answer", "error")]
    assert terminal == [len(events) - 1], "exactly one terminal line, and it is the last"
    assert events[0]["type"] in ("start", "error")


def types(events: list[dict[str, Any]]) -> list[str]:
    return [ev["type"] for ev in events]


def test_plain_turn_streams_start_thinking_deltas_answer(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["Hel", "lo ", "from ", "the ", "room."]}]
    done, events = turn(room, "hi there")
    assert done.returncode == 0
    assert done.stderr == b""
    check_envelope(events)
    assert types(events) == ["start", "thinking"] + ["delta"] * 5 + ["answer"]
    assert events[0]["model"] == "lfm3-vl-2b" and events[0]["tools"] is True
    assert events[1]["round"] == 1 and events[1]["phase"] == "working"
    assert "".join(ev["text"] for ev in events if ev["type"] == "delta") == "Hello from the room."
    last = events[-1]
    assert last["text"] == "Hello from the room."
    assert last["stop_reason"] == "stop" and last["rounds"] == 1 and last["tool_calls"] == 0
    assert model.requests[0]["stream"] is True


def test_first_words_arrive_before_the_model_finishes(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["one ", "two ", "three ", "four"], "delay": 0.5}]
    proc = subprocess.Popen(
        ["bash", str(AGENT), "--events", "--turn", TURN, "count"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=room.env,
    )
    start = time.monotonic()
    seen: list[tuple[float, str]] = []
    assert proc.stdout is not None
    for raw in proc.stdout:
        seen.append((time.monotonic() - start, json.loads(raw)["type"]))
    proc.wait(timeout=30)
    first_delta = next(t for t, kind in seen if kind == "delta")
    answer_at = next(t for t, kind in seen if kind == "answer")
    assert first_delta < answer_at - 1.0, seen


def test_non_ascii_text_is_escaped_and_astral_characters_are_surrogate_pairs(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["café ", "\U0001f600 ok"]}]
    done, events = turn(room, "hi")
    assert b"\\u00e9" in done.stdout and b"\\ud83d\\ude00" in done.stdout
    assert events[-1]["text"] == "café \U0001f600 ok"
    assert "".join(ev["text"] for ev in events if ev["type"] == "delta") == "café \U0001f600 ok"


def test_a_tool_round_has_narration_call_result_and_no_raw_output(model: StreamModel, room: Any) -> None:
    (room.work / "notes.txt").write_text("SECRETFILECONTENT\n")
    model.replies = [
        {"pieces": ["Let me look."], "tool_calls": [{"id": "call_1", "name": "run", "arguments": {"command": "cat notes.txt"}}]},
        {"pieces": ["It says ", "something."]},
    ]
    done, events = turn(room, "what is in notes")
    assert done.returncode == 0 and done.stderr == b""
    check_envelope(events)
    assert types(events) == [
        "start", "thinking", "delta", "tool_call", "tool_result", "thinking", "delta", "delta", "answer",
    ]
    call, result = events[3], events[4]
    assert call["round"] == 1 and call["name"] == "run" and call["summary"] == "cat notes.txt" and call["redacted"] is False
    assert call["call_id"] == "call_1"
    assert result["call_id"] == "call_1" and result["status"] == "ok" and result["exit_code"] == 0
    assert isinstance(result["duration_ms"], int) and result["output_bytes"] == len(b"SECRETFILECONTENT\n")
    assert result["output_cut"] is False
    assert events[5]["round"] == 2 and events[6]["round"] == 2
    assert events[-1]["rounds"] == 2 and events[-1]["tool_calls"] == 1
    assert b"SECRETFILECONTENT" not in done.stdout
    assert b'"arguments"' not in done.stdout


def test_tool_result_statuses(model: StreamModel, room: Any) -> None:
    (room.work / "big.txt").write_text("x" * 5000)
    model.replies = [
        {"tool_calls": [
            {"id": "a", "name": "run", "arguments": {"command": "exit 3"}},
            {"id": "b", "name": "run", "arguments": {"command": "sleep 5"}},
            {"id": "c", "name": "read_file", "arguments": {"path": "big.txt"}},
            {"id": "d", "name": "read_file", "arguments": {"path": "missing.txt"}},
            {"id": "e", "name": "launch_missiles", "arguments": {"target": "x"}},
            {"id": "f", "name": "run", "arguments": "not json"},
        ]},
        {"pieces": ["done"]},
    ]
    done, events = turn(room, "go", LFM3_AGENT_CMD_TIMEOUT="1")
    check_envelope(events)
    calls = {ev["call_id"]: ev for ev in events if ev["type"] == "tool_call"}
    results = {ev["call_id"]: ev for ev in events if ev["type"] == "tool_result"}
    assert set(calls) == set(results) == set("abcdef")
    assert (results["a"]["status"], results["a"]["exit_code"]) == ("error", 3)
    assert results["b"]["status"] == "timeout"
    assert (results["c"]["status"], results["c"]["output_bytes"], results["c"]["output_cut"]) == ("ok", 5000, True)
    assert results["d"]["status"] == "error" and results["d"]["exit_code"] is None
    assert results["e"]["status"] == "refused" and calls["e"]["name"] == "other" and calls["e"]["summary"] == "launch_missiles"
    assert results["f"]["status"] == "refused"
    # The tool_result for each call sits between its tool_call and the next thinking.
    order = [(ev["type"], ev.get("call_id")) for ev in events if ev["type"] in ("tool_call", "tool_result")]
    assert order == [(k, c) for c in "abcdef" for k in ("tool_call", "tool_result")]


def test_repeated_or_bad_call_ids_are_made_unique_and_safe(model: StreamModel, room: Any) -> None:
    model.replies = [
        {"tool_calls": [{"id": "call_1", "name": "run", "arguments": {"command": "true"}}]},
        {"tool_calls": [{"id": "call_1", "name": "run", "arguments": {"command": "true"}}]},
        {"tool_calls": [{"id": "has space/and$", "name": "run", "arguments": {"command": "true"}}]},
        {"pieces": ["ok"]},
    ]
    done, events = turn(room, "go")
    ids = [ev["call_id"] for ev in events if ev["type"] == "tool_call"]
    assert len(set(ids)) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", i) for i in ids)


def test_tool_summaries_are_redacted_before_they_reach_stdout(model: StreamModel, room: Any) -> None:
    planted = ["abc123secretvalue", "xyzbearertoken", "hunter2hunter2", "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ", "sk-live-9999", "ghp_abcdefghij", "pw-in-flag", "cookie-val"]
    command = (
        "curl -H 'Authorization: Bearer xyzbearertoken' -u x --api-key pw-in-flag --session-cookie=cookie-val "
        "https://x/?k=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ; API_KEY=abc123secretvalue run.sh; "
        "echo hunter2hunter2 sk-live-9999 ghp_abcdefghij"
    )
    model.replies = [
        {"tool_calls": [{"id": "r1", "name": "run", "arguments": {"command": command}}]},
        {"pieces": ["finished"]},
    ]
    done, events = turn(room, "go", LFM3_TEST_PRIVATE="hunter2hunter2")
    call = next(ev for ev in events if ev["type"] == "tool_call")
    assert call["redacted"] is True and "[redacted]" in call["summary"]
    for value in planted:
        assert value.encode() not in done.stdout, value
    assert len(call["summary"]) <= 160
    # Names stay so a reader can see what kind of value was removed.
    assert "API_KEY=[redacted]" in call["summary"] or "API_KEY=[redacted]" in json.dumps(call)


def test_a_plain_summary_is_not_marked_redacted_and_long_ones_are_cut_to_160(model: StreamModel, room: Any) -> None:
    long = "echo " + " ".join(["word"] * 80)
    model.replies = [
        {"tool_calls": [{"id": "s1", "name": "run", "arguments": {"command": "echo\thi\nthere"}}]},
        {"tool_calls": [{"id": "s2", "name": "run", "arguments": {"command": long}}]},
        {"pieces": ["ok"]},
    ]
    _, events = turn(room, "go")
    first, second = [ev for ev in events if ev["type"] == "tool_call"]
    assert first["summary"] == "echo hi there" and first["redacted"] is False
    assert len(second["summary"]) == 160 and second["summary"].endswith("...")


def test_markup_in_the_stream_never_reaches_a_delta(model: StreamModel, room: Any) -> None:
    model.replies = [
        {"pieces": ["Checking. <tool", "_call>\n<function=", "run>\n<parameter=command>\necho hi\n</parameter>\n</function>\n</tool_call>"]},
        {"pieces": ["Done."]},
    ]
    done, events = turn(room, "go")
    check_envelope(events)
    deltas = [ev["text"] for ev in events if ev["type"] == "delta"]
    for text in deltas:
        for bad in ("<tool_call", "</tool_call", "<function=", "<parameter=", "<|", "<think"):
            assert bad not in text
    assert deltas[0] == "Checking. "
    # The call the server missed still runs, as in the non-streaming path.
    assert [ev["summary"] for ev in events if ev["type"] == "tool_call"] == ["echo hi"]
    assert events[-1]["text"] == "Done."


def test_a_lone_less_than_sign_is_text_and_reasoning_is_never_forwarded(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["1 < 2 and <", "b> and <think>hidden</think>shown"]}]
    done, events = turn(room, "go")
    assert b"secret reasoning" not in done.stdout and b"hidden" not in done.stdout
    text = "".join(ev["text"] for ev in events if ev["type"] == "delta")
    assert text == "1 < 2 and <b> and shown"
    assert events[-1]["text"] == "1 < 2 and <b> and shown"


@pytest.mark.parametrize("script,expected", [
    ({"pieces": ["cut off"], "finish": "length"}, "length"),
    ({"pieces": ["I will say this over and over. " * 12]}, "loop"),
])
def test_stop_reasons_length_and_loop(model: StreamModel, room: Any, script: dict[str, Any], expected: str) -> None:
    model.replies = [script]
    done, events = turn(room, "go")
    assert events[-1]["stop_reason"] == expected
    assert "Stopped" not in events[-1]["text"] and "repeating" not in events[-1]["text"]
    assert done.returncode == 0


def test_stop_reason_steps_when_tool_rounds_run_out(model: StreamModel, room: Any) -> None:
    call = {"tool_calls": [{"id": "x", "name": "run", "arguments": {"command": "true"}}]}
    model.replies = [call, call, {"pieces": ["enough"]}]
    done, events = turn(room, "go", LFM3_AGENT_STEPS="2")
    assert events[-1]["stop_reason"] == "steps" and events[-1]["tool_calls"] == 2
    assert model.requests[-1].get("tools") is None


def test_the_empty_answer_is_one_clean_line(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["   \n"]}]
    _, events = turn(room, "go")
    assert events[-1]["text"] == "(the model gave no answer)"


def test_server_never_ready_is_model_unavailable_after_a_warming_round(model: StreamModel, room: Any) -> None:
    model.health_always_down = True
    done, events = turn(room, "hi", LFM3_WAIT="1")
    assert done.returncode == 1
    assert types(events) == ["start", "thinking", "error"]
    assert events[1]["phase"] == "warming"
    assert events[2]["code"] == "model_unavailable" and events[2]["retryable"] is True
    check_envelope(events)
    assert len(done.stderr) <= 201 and done.stderr.count(b"\n") <= 1


def test_a_server_that_is_slow_to_start_warms_then_works(model: StreamModel, room: Any) -> None:
    model.health_failures = 2
    model.replies = [{"pieces": ["up"]}]
    _, events = turn(room, "hi")
    assert [(ev["type"], ev.get("phase")) for ev in events[:3]] == [("start", None), ("thinking", "warming"), ("thinking", "working")]
    assert events[-1]["text"] == "up"


def test_server_error_is_model_failed_with_fixed_text_and_no_body(model: StreamModel, room: Any) -> None:
    model.replies = [{"status": 503, "body": {"error": {"message": "BACKEND-INTERNALS-LEAK"}}}]
    done, events = turn(room, "hi")
    assert done.returncode == 1
    assert events[-1]["type"] == "error" and events[-1]["code"] == "model_failed"
    assert b"BACKEND-INTERNALS-LEAK" not in done.stdout + done.stderr
    assert len(events[-1]["message"]) <= 200
    assert done.stderr.count(b"\n") <= 1 and len(done.stderr) <= 201


def test_context_overflow_is_context_too_long(model: StreamModel, room: Any) -> None:
    model.replies = [{"status": 400, "body": {"error": {"message": "request exceeds the available context size"}}}]
    done, events = turn(room, "hi")
    assert events[-1]["code"] == "context_too_long" and events[-1]["retryable"] is False


def test_a_stream_cut_off_before_the_end_is_model_failed(model: StreamModel, room: Any) -> None:
    chunk = json.dumps({"choices": [{"index": 0, "delta": {"content": "half"}, "finish_reason": None}]})
    model.replies = [{"raw": [f"data: {chunk}", ""]}]
    done, events = turn(room, "hi")
    assert events[-1]["code"] == "model_failed" and done.returncode == 1
    check_envelope(events)


def test_a_tool_call_the_server_cannot_parse_is_answered_without_tools(model: StreamModel, room: Any) -> None:
    model.replies = [
        {"status": 500, "body": {"error": {"message": "Failed to parse tool call arguments"}}},
        {"pieces": ["plain answer"]},
    ]
    done, events = turn(room, "go")
    assert events[-1]["text"] == "plain answer" and done.returncode == 0
    assert "tools" not in model.requests[-1]


@pytest.mark.parametrize("env,script", [
    ({"MODEL": "d1-2b", "LFM3_KIND": "decision"}, AGENT),
    ({"MODEL": "lfm3-1.7b-base"}, AGENT),
    ({"MODEL": "d1-2b", "LFM3_KIND": "decision"}, LIQUID),
    ({"MODEL": "lfm3-1.7b-base"}, LIQUID),
])
def test_models_that_do_not_chat_give_one_error_line(room: Any, env: dict[str, str], script: Path) -> None:
    done = room("--events", "--turn", TURN, "hi", script=script, **env)
    events = events_of(done)
    assert done.returncode == 2
    assert types(events) == ["error"] and events[0]["code"] == "not_chat_model" and events[0]["seq"] == 1
    assert events[0]["turn_id"] == TURN
    assert done.stderr.count(b"\n") <= 1 and len(done.stderr) <= 201


@pytest.mark.parametrize("args", [
    ("--events", "--turn", TURN),                       # no message
    ("--events", "hello"),                              # no turn id
    ("--events", "--turn", "not-a-uuid", "hello"),      # bad turn id
    ("--events", "--turn", TURN, "--json", "hello"),    # modes the room keeps off the chat path
    ("--events", "--turn", TURN, "--speak", "a.wav", "hello"),
    ("--events", "--turn", TURN, "--history"),
    ("--events", "--turn", TURN, "--bogus", "hello"),
])
def test_bad_requests_are_one_error_line_and_exit_2(model: StreamModel, room: Any, args: tuple[str, ...]) -> None:
    done = room(*args)
    events = events_of(done)
    assert done.returncode == 2
    assert types(events) == ["error"] and events[0]["code"] == "bad_request" and events[0]["seq"] == 1
    assert done.stderr.count(b"\n") <= 1 and len(done.stderr) <= 201
    assert model.requests == []


def test_turn_without_events_is_a_usage_error(model: StreamModel, room: Any) -> None:
    done = room("--turn", TURN, "hello")
    assert done.returncode == 2 and b"usage:" in done.stderr and done.stdout == b""


def test_an_upper_case_turn_id_is_written_lower_case(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["hi"]}]
    done = room("--events", "--turn", TURN.upper(), "hello")
    assert {ev["turn_id"] for ev in events_of(done)} == {TURN}


def test_liquid_passes_events_through(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["via liquid"]}]
    done = room("--events", "--turn", TURN, "hello", "there", script=LIQUID)
    events = events_of(done)
    assert events[-1]["text"] == "via liquid"
    assert model.requests[0]["messages"][-1]["content"] == "hello there"


def test_long_answers_and_deltas_respect_the_line_caps(model: StreamModel, room: Any) -> None:
    pieces = ["\U0001f600" * 3000, "plain " * 200] + ["unique line %d here, different words %d\n" % (i, i * 7919) for i in range(800)]
    model.replies = [{"pieces": pieces}]
    done, events = turn(room, "go", LFM3_MAX_TOKENS="100000")
    check_envelope(events)
    for ev in events:
        if ev["type"] == "delta":
            assert len(ev["text"]) <= 2048
    answer = events[-1]
    assert len(answer["text"]) <= 32768
    assert max(len(line) for line in done.stdout.split(b"\n")) < 262144


def test_the_turn_is_kept_in_the_conversation_like_a_normal_turn(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["first answer"]}, {"pieces": ["second answer"]}]
    turn(room, "first question")
    done, events = turn(room, "second question")
    roles = [(m["role"], m["content"]) for m in model.requests[1]["messages"] if m["role"] != "system"]
    assert roles == [("user", "first question"), ("assistant", "first answer"), ("user", "second question")]
    history = json.loads((room.state / "history.json").read_text())
    assert history[-1] == {"role": "assistant", "content": "second answer"}


def test_without_the_flag_nothing_streams_and_nothing_changes(model: StreamModel, room: Any) -> None:
    # The non-streaming path is covered end to end by tests/test_lfm3_agent.py; this
    # pins the one thing a streaming fake can see: no stream flag, no event lines.
    model.replies = [{"status": 500}]
    done = room("hello")
    assert done.returncode == 1
    assert "stream" not in model.requests[0]
    assert b'"version"' not in done.stdout


def fixture_names() -> list[str]:
    return sorted(p.stem for p in FIXTURES.glob("*.json"))


def mask_durations(data: bytes) -> bytes:
    return re.sub(rb'"duration_ms":\d+', b'"duration_ms":0', data)


@pytest.mark.parametrize("name", fixture_names())
def test_conformance_fixture(model: StreamModel, room: Any, name: str) -> None:
    spec = json.loads((FIXTURES / f"{name}.json").read_text())
    for rel, content in spec.get("files", {}).items():
        (room.work / rel).write_text(content)
    model.replies = spec.get("replies", [])
    model.health_always_down = spec.get("server_down", False)
    done = room("--events", "--turn", TURN, *spec["args"], **spec.get("env", {}))
    assert done.returncode == spec["exit"]
    assert len(done.stderr) <= 201 and done.stderr.count(b"\n") <= 1
    events = events_of(done)
    check_envelope(events)
    for value in spec.get("planted", []):
        assert value.encode() not in done.stdout, value
    golden = FIXTURES / f"{name}.stdout"
    actual = mask_durations(done.stdout)
    if os.environ.get("UPDATE_CHAT_FIXTURES"):
        golden.write_bytes(actual)
    assert actual == golden.read_bytes()


def test_the_fixture_set_covers_the_room_checks() -> None:
    wanted = {"plain", "unicode", "tool-round", "redaction", "markup", "length", "loop", "steps", "model-down", "not-chat-model"}
    assert wanted <= set(fixture_names())


def sse(delta: dict[str, Any], finish: str | None = None) -> str:
    return "data: " + json.dumps({"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]})


@pytest.mark.parametrize("tail", [["data: [DONE]  "], ["data: [DONE]\r"], ["data:[DONE]"], ["data: [DONE]", ""]])
def test_done_sentinel_is_a_normal_end_of_stream(model: StreamModel, room: Any, tail: list[str]) -> None:
    # No finish_reason chunk: the sentinel alone ends the stream, with or without
    # trailing spaces, a carriage return or a final newline.
    model.replies = [{"raw": [sse({"content": "hi"}), "", *tail]}]
    done, events = turn(room, "hi")
    assert done.returncode == 0
    check_envelope(events)
    assert events[-1]["type"] == "answer" and events[-1]["text"] == "hi"


def test_held_back_text_is_drained_at_end_of_stream(model: StreamModel, room: Any) -> None:
    model.replies = [{"pieces": ["a ", "b <"], "finish": "length"}, {"pieces": ["x <to"]}]
    done, events = turn(room, "hi")
    deltas = "".join(ev["text"] for ev in events if ev["type"] == "delta")
    assert deltas == "a b <" == events[-1]["text"]
    model.replies = [{"pieces": ["see <tool_c"]}]
    _, events = turn(room, "again")
    deltas = "".join(ev["text"] for ev in events if ev["type"] == "delta")
    assert deltas == events[-1]["text"] == "see <tool_c"


def test_a_short_key_value_never_reaches_stdout(model: StreamModel, room: Any) -> None:
    short = "k7q"
    command = f"curl -H 'X-API-Key: {short}' https://x; echo {short}; curl -H 'X-Auth-Thing: other-short' https://y"
    model.replies = [
        {"tool_calls": [{"id": "h1", "name": "run", "arguments": {"command": command}}]},
        {"pieces": ["the key is k", "7q and again ", "k7", "q"]},
    ]
    done, events = turn(room, "go", MODEL_API_KEY=short)
    call = next(ev for ev in events if ev["type"] == "tool_call")
    assert call["redacted"] is True
    assert short.encode() not in done.stdout
    assert b"other-short" not in done.stdout
    assert "X-API-Key: [redacted]" in call["summary"]
    assert events[-1]["type"] == "answer" and short not in events[-1]["text"]


def test_a_header_style_secret_is_redacted_without_any_configured_value(model: StreamModel, room: Any) -> None:
    model.replies = [
        {"tool_calls": [{"id": "h2", "name": "run", "arguments": {"command": "curl -H \"X-API-Key: short-real-secret\" https://x"}}]},
        {"pieces": ["done"]},
    ]
    done, events = turn(room, "go")
    call = next(ev for ev in events if ev["type"] == "tool_call")
    assert b"short-real-secret" not in done.stdout and call["redacted"] is True


def test_non_credential_env_prefixes_are_held_across_stream_pieces(model: StreamModel, room: Any) -> None:
    # SpockChaser HOLD: FOO is in secrets (>=8) but was not in credentials, so
    # hold() emitted prefixes as deltas before the full value assembled.
    secret = "abcdefghijklmno"
    model.replies = [{"pieces": ["abcde", "fghij", "klmno"]}]
    done, events = turn(room, "go", FOO=secret)
    assert done.returncode == 0
    deltas = "".join(ev["text"] for ev in events if ev["type"] == "delta")
    assert secret not in deltas
    assert secret.encode() not in done.stdout
    for line in done.stdout.splitlines():
        assert secret.encode() not in line
    assert events[-1]["type"] == "answer" and events[-1]["text"] == "[redacted]"


def test_the_plain_path_does_not_echo_the_key_or_request_headers(model: StreamModel, room: Any) -> None:
    short = "k7q"
    model.replies = [{"status": 500, "body": {"error": {"message": "scripted failure"}}}]
    done = room("hello", MODEL_API_KEY=short)
    assert short.encode() not in done.stdout and b"Authorization" not in done.stdout
    assert b"Authorization" not in done.stderr
