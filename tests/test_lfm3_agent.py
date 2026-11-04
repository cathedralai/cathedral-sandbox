"""lfm3-agent against a scripted OpenAI-compatible server.

The server stands in for llama-server: it records every request and answers
with the next scripted message, so these checks need bash 4+, jq and curl but
no model.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
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


def tool_call(name: str, arguments: Any, call_id: str = "call_1") -> dict[str, Any]:
    args = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": args}}],
    }


def answer(text: str) -> dict[str, Any]:
    return {"role": "assistant", "content": text}


class FakeModel:
    def __init__(self) -> None:
        self.replies: list[Any] = []
        self.requests: list[dict[str, Any]] = []
        model = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, body: dict[str, Any]) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                self._send(200 if self.path == "/health" else 404, {"status": "ok"})

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                model.requests.append(body)
                reply = model.replies.pop(0) if model.replies else answer("(script ended)")
                if isinstance(reply, int):
                    self._send(reply, {"error": {"message": "scripted failure"}})
                    return
                self._send(200, {"choices": [{"index": 0, "message": reply, "finish_reason": "stop"}]})

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
def fake() -> Iterator[FakeModel]:
    model = FakeModel()
    yield model
    model.close()


@pytest.fixture
def room(tmp_path: Path, fake: FakeModel):
    work = tmp_path / "work"
    work.mkdir()
    state = tmp_path / "state"

    base_env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "MODEL_BASE_URL": fake.base_url,
        "MODEL": "lfm3-omni-2b",
        "LFM3_AGENT_DIR": str(state),
        "LFM3_AGENT_CWD": str(work),
        "LFM3_WAIT": "5",
    }

    def run(*args: str, stdin: str | None = None, script: Path = AGENT, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(script), *args], input=stdin if stdin is not None else "",
            capture_output=True, text=True, env={**base_env, **env}, timeout=60,
        )

    run.work = work  # type: ignore[attr-defined]
    run.state = state  # type: ignore[attr-defined]
    run.env = base_env  # type: ignore[attr-defined]
    return run


def messages(request: dict[str, Any]) -> list[dict[str, Any]]:
    return request["messages"]


def history(room: Any) -> list[dict[str, Any]]:
    return json.loads((room.state / "history.json").read_text())


def test_runs_the_tool_the_model_asks_for_and_returns_the_answer(fake: FakeModel, room: Any) -> None:
    fake.replies = [tool_call("run", {"command": "echo cathedral-$((6*7))"}), answer("It printed cathedral-42.")]
    out = room("What does the command print?")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "It printed cathedral-42."
    assert "$ echo cathedral-$((6*7))" in out.stderr

    first, second = fake.requests
    assert [t["function"]["name"] for t in first["tools"]] == ["run", "read_file"]
    assert first["temperature"] == 0 and first["frequency_penalty"] == 0.3 and first["max_tokens"] == 512
    system = messages(first)[0]
    assert system["role"] == "system" and "lfm3-omni-2b" in system["content"] and str(room.work) in system["content"]
    tool = messages(second)[-1]
    assert tool["role"] == "tool" and tool["tool_call_id"] == "call_1"
    assert tool["content"].startswith("exit code: 0\n") and "cathedral-42" in tool["content"]
    assert messages(second)[-2]["tool_calls"][0]["function"]["name"] == "run"


@pytest.mark.parametrize(
    ("model", "sampling"),
    [
        ("lfm3-omni-2b", {"temperature": 0, "frequency_penalty": 0.3}),
        ("lfm3-audio-2b", {"temperature": 0}),
        ("lfm3-vl-2b", {"temperature": 0.1, "top_k": 50, "repeat_penalty": 1.1}),
    ],
)
def test_sampling_follows_the_model(fake: FakeModel, room: Any, model: str, sampling: dict[str, Any]) -> None:
    fake.replies = [answer("Hi.")]
    assert room("Hello.", MODEL=model).returncode == 0
    body = fake.requests[0]
    assert {k: body[k] for k in body if k in ("temperature", "top_k", "repeat_penalty", "frequency_penalty", "min_p")} == sampling
    # DRY with the repetition penalty broke verbatim copies of IDs (ADO 523).
    assert not any(key.startswith("dry_") for key in body)


def test_sampling_can_be_replaced(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("Hi."), answer("Hi again.")]
    assert room("Hello.").returncode == 0
    assert room("Hello.", LFM3_AGENT_SAMPLING='{"temperature": 0.7}').returncode == 0
    assert fake.requests[1]["temperature"] == 0.7 and "top_k" not in fake.requests[1]
    out = room("Hello.", LFM3_AGENT_SAMPLING="[1]")
    assert out.returncode == 2 and "JSON object" in out.stderr


LOOP_NOTE = "(Stopped: the model kept repeating itself. Ask again, or start over with --new.)"


def test_a_looping_answer_is_cut_and_said_once(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("Glow, shine, sing, bloom, " + "bloom, " * 200)]
    out = room("rhyme with me")
    assert out.returncode == 0
    lines = out.stdout.strip().splitlines()
    assert lines == ["Glow, shine, sing, bloom", LOOP_NOTE]
    assert history(room)[-1]["content"] == "Glow, shine, sing, bloom"


def test_a_looping_line_keeps_its_first_copy(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("Here is a chorus:\n\n" + "We'll sing it loud and clear,\n" * 30)]
    out = room("write a chorus")
    assert out.stdout.strip().splitlines() == ["Here is a chorus:", "", "We'll sing it loud and clear", LOOP_NOTE]


def test_a_poem_with_a_short_refrain_is_left_alone(fake: FakeModel, room: Any) -> None:
    poem = ("The sea is wide, the sea is deep,\nRow, row, row the boat,\nThe stars above us softly sleep,\n"
            "Row, row, row the boat.\nThe moon is high, the tide is low,\nRow, row, row the boat.")
    fake.replies = [answer(poem)]
    out = room("a poem please")
    assert out.stdout.strip() == poem and LOOP_NOTE not in out.stdout


def test_tool_call_markup_the_server_missed_is_run(fake: FakeModel, room: Any) -> None:
    raw = "<tool_call>\n<function=run>\n<parameter=command>\necho raw-ok\n</parameter>\n</function>\n</tool_call>"
    fake.replies = [{"role": "assistant", "content": raw}, answer("It printed raw-ok.")]
    out = room("Transcribe and act.")
    assert out.returncode == 0 and out.stdout.strip() == "It printed raw-ok."
    assert "$ echo raw-ok" in out.stderr and "<tool_call>" not in out.stdout
    tool = messages(fake.requests[1])[-1]
    assert tool["role"] == "tool" and "raw-ok" in tool["content"]
    assert json.loads(messages(fake.requests[1])[-2]["tool_calls"][0]["function"]["arguments"]) == {"command": "echo raw-ok"}


def test_json_tool_call_markup_is_run(fake: FakeModel, room: Any) -> None:
    raw = 'Let me check. <tool_call>{"name": "run", "arguments": {"command": "echo json-ok"}}</tool_call>'
    fake.replies = [{"role": "assistant", "content": raw}, answer("json-ok")]
    out = room("Check.")
    assert "$ echo json-ok" in out.stderr and out.stdout.strip() == "json-ok"


def test_unreadable_tool_call_markup_becomes_one_clean_line(fake: FakeModel, room: Any) -> None:
    fake.replies = [{"role": "assistant", "content": "<tool_call>\n<function=run>\n<parameter=command>\nls"}]
    out = room("Do it.")
    assert out.stdout.strip() == "(The model tried to call a tool, but the call could not be read.)"
    assert len(fake.requests) == 1


def test_markup_after_text_shows_only_the_text_when_tools_are_off(fake: FakeModel, room: Any) -> None:
    raw = "Sure, here you go.\n<tool_call>\n<function=run>\n<parameter=command>\nls\n</parameter>\n</function>\n</tool_call>"
    fake.replies = [{"role": "assistant", "content": raw}]
    out = room("--no-tools", "List files.")
    assert out.stdout.strip() == "Sure, here you go."


def test_each_call_continues_the_conversation_until_new(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("4"), answer("40"), answer("Paris")]
    assert room("What is 2+2?").stdout.strip() == "4"
    assert room("Times ten?").stdout.strip() == "40"
    roles = [(m["role"], m["content"]) for m in messages(fake.requests[1])[1:]]
    assert roles == [("user", "What is 2+2?"), ("assistant", "4"), ("user", "Times ten?")]

    assert room("--new", "Capital of France?").stdout.strip() == "Paris"
    assert [m["role"] for m in messages(fake.requests[2])] == ["system", "user"]
    assert [m["content"] for m in history(room)] == ["Capital of France?", "Paris"]


def test_stdin_message_and_history_view(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("Hello.")]
    assert room("-", stdin="Say hello.\n").stdout.strip() == "Hello."
    shown = room("--history").stdout
    assert "you: Say hello." in shown and "model: Hello." in shown
    assert room("--reset").returncode == 0
    assert not (room.state / "history.json").exists()


def test_no_tools_sends_no_tool_list(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("Fine.")]
    assert room("--no-tools", "How are you?").returncode == 0
    assert "tools" not in fake.requests[0]


def test_tool_rounds_are_capped_then_the_model_must_answer(fake: FakeModel, room: Any) -> None:
    fake.replies = [tool_call("run", {"command": "true"}), tool_call("run", {"command": "true"}), answer("Done.")]
    out = room("Keep going.", LFM3_AGENT_STEPS="2")
    assert out.returncode == 0 and out.stdout.strip() == "Done."
    assert ["tools" in r for r in fake.requests] == [True, True, False]


def test_picture_is_sent_and_kept_for_follow_up_questions(fake: FakeModel, room: Any, tmp_path: Path) -> None:
    picture = tmp_path / "pic.png"
    picture.write_bytes(b"\x89PNG\r\n\x1a\nfake")
    fake.replies = [answer("A blue circle."), answer("Red.")]
    assert room("--image", str(picture), "What is this?").returncode == 0
    sent = messages(fake.requests[0])[-1]["content"]
    assert sent[0]["type"] == "image_url" and sent[0]["image_url"]["url"].startswith("data:image/png;base64,")
    assert sent[-1] == {"type": "text", "text": "What is this?"}

    assert room("And the background?").returncode == 0
    earlier, current = messages(fake.requests[1])[1], messages(fake.requests[1])[-1]
    assert earlier["content"][0]["type"] == "image_url", "the picture goes back on the turn that brought it"
    assert current == {"role": "user", "content": "And the background?"}
    assert "media" not in json.dumps(fake.requests[1]["messages"])
    stored = history(room)
    assert stored[0]["content"] == "[image: pic.png] What is this?"
    assert "base64" not in (room.state / "history.json").read_text()


def test_audio_clip_is_an_input_audio_part(fake: FakeModel, room: Any, tmp_path: Path) -> None:
    clip = tmp_path / "clip.wav"
    clip.write_bytes(b"RIFFfakeWAVE")
    fake.replies = [answer("The train to Paris leaves at nine.")]
    assert room("--audio", str(clip)).returncode == 0
    part = messages(fake.requests[0])[-1]["content"][0]
    assert part["type"] == "input_audio" and part["input_audio"]["format"] == "wav"


def test_long_output_is_clipped(fake: FakeModel, room: Any) -> None:
    fake.replies = [tool_call("run", {"command": "seq 1 5000"}), answer("Many numbers.")]
    assert room("Count.", LFM3_AGENT_OUTPUT_CHARS="100").returncode == 0
    content = messages(fake.requests[1])[-1]["content"]
    assert "more bytes not shown]" in content and len(content) < 200


@pytest.mark.skipif(not shutil.which("timeout"), reason="needs coreutils timeout")
def test_slow_command_is_stopped(fake: FakeModel, room: Any) -> None:
    fake.replies = [tool_call("run", {"command": "sleep 10"}), answer("It was too slow.")]
    out = room("Sleep.", LFM3_AGENT_CMD_TIMEOUT="1")
    assert out.returncode == 0
    assert messages(fake.requests[1])[-1]["content"].startswith("exit code: 124 (stopped after 1s)")


def test_read_file_is_relative_to_the_working_directory(fake: FakeModel, room: Any) -> None:
    (room.work / "notes.txt").write_text("alpha\n")
    fake.replies = [tool_call("read_file", {"path": "notes.txt"}), answer("alpha")]
    assert room("Read notes.txt.").returncode == 0
    assert messages(fake.requests[1])[-1]["content"] == "alpha"


def test_bad_tool_calls_are_reported_to_the_model(fake: FakeModel, room: Any) -> None:
    fake.replies = [tool_call("delete_everything", {}), tool_call("run", "not json"), answer("Sorry.")]
    assert room("Do it.").returncode == 0
    assert "there is no tool named delete_everything" in messages(fake.requests[1])[-1]["content"]
    assert "not a JSON object" in messages(fake.requests[2])[-1]["content"]


def test_old_turns_are_dropped_whole_past_the_context_size(fake: FakeModel, room: Any) -> None:
    # About 480 characters a turn; 1200 holds the system prompt, this message
    # and one earlier turn, not two.
    filler = "x" * 400
    fake.replies = [answer("one"), answer("two"), answer("three")]
    assert room("--system", "Be brief.", f"first {filler}", LFM3_AGENT_CONTEXT_CHARS="1200").returncode == 0
    for n in ("second", "third"):
        assert room(f"{n} {filler}", LFM3_AGENT_CONTEXT_CHARS="1200").returncode == 0
    sent = messages(fake.requests[2])
    assert [m["content"].split(" ")[0] for m in sent] == ["Be", "second", "two", "third"]
    assert [m["content"].split(" ")[0] for m in history(room)] == ["second", "two", "third", "three"]


def test_a_failed_request_leaves_the_conversation_as_it_was(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("4"), 500]
    assert room("What is 2+2?").returncode == 0
    before = history(room)
    out = room("And 3+3?")
    assert out.returncode == 1 and "answered 500" in out.stderr
    assert history(room) == before


def test_decision_models_are_sent_to_lfm3_decide(fake: FakeModel, room: Any) -> None:
    out = room("Hello", LFM3_KIND="decision")
    assert out.returncode == 2 and "lfm3-decide" in out.stderr
    assert fake.requests == []


def test_new_with_no_message_just_forgets(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("4")]
    assert room("What is 2+2?").returncode == 0
    out = room("--new")
    assert out.returncode == 0 and "new conversation" in out.stderr
    assert history(room) == []
    assert len(fake.requests) == 1


def test_image_ships_the_agent_and_liquid() -> None:
    dockerfile = (SUITE / "Dockerfile").read_text(encoding="utf-8")
    copied = dockerfile.split("COPY lfm3-serve", 1)[1].splitlines()[0].split()
    assert "lfm3-agent" in copied and "liquid" in copied
    assert "/usr/local/bin/lfm3-agent" in dockerfile and "/usr/local/bin/liquid" in dockerfile


# liquid: the friendly name for lfm3-agent.


def test_liquid_alone_without_a_terminal_greets_and_exits(fake: FakeModel, room: Any) -> None:
    out = room(script=LIQUID)
    assert out.returncode == 0, out.stderr
    assert "lfm3-omni-2b" in out.stdout and "liquid what can you do" in out.stdout
    assert fake.requests == []


def test_liquid_joins_its_words_into_one_message(fake: FakeModel, room: Any) -> None:
    fake.replies = [answer("Two files."), answer("notes.txt."), answer("Hello.")]
    assert room("what", "is", "in", "/work", script=LIQUID).stdout.strip() == "Two files."
    assert room("which one is larger", script=LIQUID).stdout.strip() == "notes.txt."
    first, second = fake.requests[0], fake.requests[1]
    assert messages(first)[-1] == {"role": "user", "content": "what is in /work"}
    assert [m["content"] for m in messages(second)[1:]] == ["what is in /work", "Two files.", "which one is larger"]
    # A leading "hey" is only part of the message.
    assert room("hey", "what", "can", "you", "do", script=LIQUID).returncode == 0
    assert messages(fake.requests[2])[-1]["content"] == "hey what can you do"


@pytest.mark.parametrize(
    ("model", "example"),
    [
        ("lfm3-omni-2b", "liquid --image photo.png"),
        ("lfm3-vl-2b", "liquid --image photo.png"),
        ("lfm3-audio-2b", "liquid --audio clip.wav"),
        ("some-text-model", None),
    ],
)
def test_liquid_greeting_shows_the_attachment_this_room_takes(
    fake: FakeModel, room: Any, model: str, example: str | None
) -> None:
    out = room(script=LIQUID, MODEL=model)
    assert out.returncode == 0, out.stderr
    assert model in out.stdout and "liquid what is in /work" in out.stdout
    attachments = [line.strip() for line in out.stdout.splitlines() if "--image" in line or "--audio" in line]
    if example is None:
        assert attachments == []
    else:
        assert len(attachments) == 1 and attachments[0].startswith(example)
    assert fake.requests == []


@pytest.mark.parametrize("script", [LIQUID, AGENT], ids=["liquid", "lfm3-agent"])
def test_base_models_are_refused_with_a_pointer_to_lfm3_ask(fake: FakeModel, room: Any, script: Path) -> None:
    # LFM3-1.7B-Base called no tool for 8 sandbox questions and made answers up
    # (checked on the published GGUF), so it gets no chat harness.
    for args in ((), ("what", "is", "in", "/work")):
        out = room(*args, script=script, MODEL="lfm3-1.7b-base")
        assert out.returncode == 2, out.stderr
        assert "base model" in out.stderr and "lfm3-ask --raw" in out.stderr
        assert len(out.stderr.strip().splitlines()) == 1
    assert fake.requests == []
    assert not (room.state / "history.json").exists()


def test_liquid_refuses_decision_models(fake: FakeModel, room: Any) -> None:
    for args in ((), ("what", "is", "this")):
        out = room(*args, script=LIQUID, LFM3_KIND="decision")
        assert out.returncode == 2 and "liquid:" in out.stderr and "lfm3-decide" in out.stderr
    assert fake.requests == []


@pytest.mark.skipif(sys.platform == "win32", reason="needs a pseudo-terminal")
def test_liquid_alone_on_a_terminal_opens_the_chat(fake: FakeModel, room: Any) -> None:
    import pty
    import select

    fake.replies = [answer("Hi there.")]
    # openpty and Popen, not pty.fork: forking this multi-threaded process (the
    # fake server runs in a thread) can deadlock the child before it execs.
    fd, terminal = pty.openpty()
    child = subprocess.Popen(
        ["bash", str(LIQUID)], stdin=terminal, stdout=terminal, stderr=terminal,
        env={**room.env, "TERM": "dumb"}, start_new_session=True,
    )
    os.close(terminal)
    seen = b""

    def read_until(marker: bytes, seconds: float = 20) -> None:
        # Keep draining the terminal: liquid blocks if nobody reads it.
        nonlocal seen
        deadline = time.monotonic() + seconds
        while marker not in seen and time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    seen += os.read(fd, 4096)
                except OSError:
                    return

    try:
        read_until(b"you> ")
        os.write(fd, b"hello\n")
        read_until(b"Hi there.")
        os.write(fd, b"/exit\n")
        deadline = time.monotonic() + 20
        while child.poll() is None and time.monotonic() < deadline:
            read_until(b"\0", 0.2)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        os.close(fd)
    text = seen.decode(errors="replace")
    assert child.returncode == 0, f"liquid did not exit cleanly after /exit: {text!r}"
    assert "liquid: chatting with lfm3-omni-2b" in text
    assert "Hi there." in text
    assert messages(fake.requests[0])[-1] == {"role": "user", "content": "hello"}


SELFTEST = SUITE / "lfm3-selftest"


@pytest.mark.parametrize(("check", "code", "warned"), [("json?", 0, True), ("json", 1, False)])
def test_an_advisory_check_warns_instead_of_failing(
    fake: FakeModel, room: Any, check: str, code: int, warned: bool
) -> None:
    # Audio's real answer: valid-looking JSON with a // comment inside the array.
    bad = '[\n  {"id": 1, "name": "Apple", "color": "red"},  // a comment\n  {"id": 2, "name": "Kiwi", "color": "green"}\n]'
    fake.replies = [answer(bad)]
    out = subprocess.run(
        ["bash", str(SELFTEST), check], capture_output=True, text=True, timeout=60,
        env={**room.env, "PATH": f"{SUITE}:{os.environ['PATH']}"},
    )
    assert out.returncode == code, out.stdout + out.stderr
    assert ("WARN json" in out.stdout) is warned
    assert "FAIL json" in out.stdout
