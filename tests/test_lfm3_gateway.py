"""lfm3-gateway end to end: the real lfm3-agent behind it, a scripted model server (AB#539).

The Go tests in images/room-lfm3-suite/gateway replay the chat event fixtures
through the gateway with a stand-in agent. This checks the joint: the gateway
runs the real lfm3-agent --events, and what comes out is the Polaris runtime
format (agent_os/hermes_chat.py, hermes-next): content chunks, one
hermes.tool.progress per tool start and end with the redacted summary only,
a finish chunk, then data: [DONE].
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterator

import pytest
from test_lfm3_agent_events import AGENT, StreamModel, _bash_ok

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_SRC = ROOT / "images" / "room-lfm3-suite" / "gateway"

pytestmark = pytest.mark.skipif(
    not (shutil.which("go") and _bash_ok() and shutil.which("jq") and shutil.which("curl")),
    reason="needs go to build the gateway, and bash 4+, jq and curl for lfm3-agent",
)


@pytest.fixture(scope="module")
def gateway_bin(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("gateway") / "lfm3-gateway"
    env = {**os.environ, "CGO_ENABLED": "0"}
    subprocess.run(["go", "build", "-o", str(out), "."], cwd=GATEWAY_SRC, env=env, check=True, timeout=300)
    return out


@pytest.fixture
def model() -> Iterator[StreamModel]:
    m = StreamModel()
    yield m
    m.close()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def gateway(tmp_path: Path, model: StreamModel, gateway_bin: Path) -> Iterator[Any]:
    work = tmp_path / "work"
    work.mkdir()
    port = _free_port()
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "MODEL_BASE_URL": model.base_url,
        "MODEL": "lfm3-vl-2b",
        "LFM3_AGENT_DIR": str(tmp_path / "state"),
        "LFM3_AGENT_CWD": str(work),
        "LFM3_WAIT": "5",
        "LFM3_GATEWAY_ADDR": f"127.0.0.1:{port}",
        "LFM3_GATEWAY_AGENT": str(AGENT),
    }
    proc = subprocess.Popen([str(gateway_bin)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    proc.url = url  # type: ignore[attr-defined]
    proc.work = work  # type: ignore[attr-defined]
    yield proc
    proc.terminate()
    proc.wait(timeout=10)


def _post(url: str, body: dict[str, Any]) -> tuple[int, str]:
    req = urllib.request.Request(
        url + "/v1/chat/completions", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def polaris_events(body: str) -> list[tuple[str, dict[str, Any]]]:
    """hermes_chat_events (hermes-next) over a whole SSE body."""
    frames: list[tuple[str, str]] = []
    event, data = "message", []
    for line in body.split("\n"):
        if not line:
            if data:
                frames.append((event, "\n".join(data)))
            event, data = "message", []
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
    out: list[tuple[str, dict[str, Any]]] = []
    finish = None
    for event, raw in frames:
        if raw == "[DONE]" and event != "error":
            out.append(("done", {"finish_reason": finish}) if finish else ("error", {"message": "no status"}))
            return out
        frame = json.loads(raw)
        if frame.get("error") or event == "error":
            out.append(("error", frame.get("error") or frame))
            return out
        if event == "hermes.tool.progress":
            status = frame.get("status", "running")
            kind = {"completed": "tool-result", "error": "tool-error", "failed": "tool-error"}.get(status, "tool-start")
            out.append((kind, frame))
            continue
        for choice in frame["choices"]:
            if choice["delta"].get("content"):
                out.append(("token", {"content": choice["delta"]["content"]}))
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
    out.append(("error", {"message": "ended before completion"}))
    return out


def test_a_tool_turn_reaches_polaris_with_safe_tool_fields(model: StreamModel, gateway: Any) -> None:
    (gateway.work / "notes.txt").write_text("SECRETFILECONTENT\n")
    model.replies = [
        {"pieces": ["Let me look."], "tool_calls": [{"id": "call_1", "name": "run", "arguments": {"command": "cat notes.txt"}}]},
        {"pieces": ["It says ", "something."]},
    ]
    status, body = _post(gateway.url, {"stream": True, "messages": [{"role": "user", "content": "what is in notes"}]})
    assert status == 200, body
    assert "SECRETFILECONTENT" not in body and "secret reasoning" not in body
    events = polaris_events(body)
    assert [kind for kind, _ in events if kind != "token"] == ["tool-start", "tool-result", "done"]
    start = next(frame for kind, frame in events if kind == "tool-start")
    assert start["toolCallId"] == "call_1" and start["tool"] == "run"
    assert start["arguments"] == {"summary": "cat notes.txt"} and start["output"] == ""
    assert "".join(frame["content"] for kind, frame in events if kind == "token") == "Let me look.\n\nIt says something."
    assert events[-1] == ("done", {"finish_reason": "stop"})
    assert body.endswith("data: [DONE]\n\n")


def test_the_message_is_text_even_when_it_looks_like_an_option(model: StreamModel, gateway: Any) -> None:
    model.replies = [{"pieces": ["ok"]}]
    status, body = _post(gateway.url, {"stream": False, "messages": [{"role": "user", "content": "--reset now"}]})
    assert status == 200, body
    reply = json.loads(body)
    assert reply["object"] == "chat.completion"
    assert reply["choices"][0]["message"] == {"role": "assistant", "content": "ok"}
    sent = model.requests[-1]["messages"][-1]["content"]
    assert "--reset now" in json.dumps(sent)


def test_model_down_is_an_error_event_without_done(model: StreamModel, gateway: Any) -> None:
    model.health_always_down = True
    status, body = _post(gateway.url, {"stream": True, "messages": [{"role": "user", "content": "hi"}]})
    assert status == 200
    events = polaris_events(body)
    assert events[-1][0] == "error" and events[-1][1]["code"] == "model_unavailable"
    assert "[DONE]" not in body


def test_health_follows_the_model_server(model: StreamModel, gateway: Any) -> None:
    with urllib.request.urlopen(gateway.url + "/health", timeout=10) as resp:
        assert resp.status == 200 and json.load(resp)["status"] == "live"
    model.health_always_down = True
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(gateway.url + "/health", timeout=10)
    assert err.value.code == 503
