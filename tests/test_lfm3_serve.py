"""lfm3-serve: the llama-server flags and the boot warm-up, with a stand-in server."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVE = ROOT / "images" / "room-lfm3-suite" / "lfm3-serve"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="lfm3-serve needs bash")


def _wait_for(path: Path) -> str:
    for _ in range(100):
        if path.exists() and path.read_text():
            return path.read_text()
        time.sleep(0.05)
    return ""


def _serve(tmp_path: Path, **env: str) -> tuple[list[str], str]:
    """Run lfm3-serve with a command; return llama-server's arguments and what lfm3-agent was asked."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shutil.copy(SERVE, bin_dir / "lfm3-serve")
    (bin_dir / "llama-server").write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" > {tmp_path}/server-args\n')
    (bin_dir / "lfm3-agent").write_text(f'#!/usr/bin/env bash\necho "$@" > {tmp_path}/agent-args\n')
    for name in ("lfm3-serve", "llama-server", "lfm3-agent"):
        (bin_dir / name).chmod(0o755)
    run_env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "LFM3_MODEL": "/opt/lfm3/model.gguf",
        "LFM3_THREADS": "2",
        "LFM3_LOG_DIR": str(tmp_path / "log"),
        **env,
    }
    out = subprocess.run(["bash", str(bin_dir / "lfm3-serve"), "true"], env=run_env, capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    args = _wait_for(tmp_path / "server-args").splitlines()
    time.sleep(0.3)
    return args, (tmp_path / "agent-args").read_text().strip() if (tmp_path / "agent-args").exists() else ""


def test_chat_models_keep_a_full_window_cache_and_warm_the_agent_prompt(tmp_path: Path) -> None:
    # Without --swa-full llama-server b11960 re-read the whole prompt on every
    # request for LFM3 (sliding window attention): cache_n 0, 4 Nov 2026.
    args, agent = _serve(tmp_path, MODEL="lfm3-omni-2b", LFM3_KIND="chat")
    assert "--swa-full" in args and "--cache-ram" in args
    assert agent == "--warm"


def test_base_models_are_not_warmed(tmp_path: Path) -> None:
    args, agent = _serve(tmp_path, MODEL="lfm3-1.7b-base", LFM3_KIND="chat")
    assert "--swa-full" in args
    assert agent == ""


def test_decision_models_keep_their_flags_and_are_not_warmed(tmp_path: Path) -> None:
    args, agent = _serve(tmp_path, MODEL="d1-2b", LFM3_KIND="decision")
    assert "--swa-full" not in args and "--batch-size" in args
    assert agent == ""


def test_chat_models_serve_the_saved_prompt_cache_directory(tmp_path: Path) -> None:
    slots = tmp_path / "cache"
    slots.mkdir()
    args, _ = _serve(tmp_path, MODEL="lfm3-omni-2b", LFM3_KIND="chat", LFM3_SLOT_DIR=str(slots))
    assert args[args.index("--slot-save-path") + 1] == str(slots)


def test_no_slot_directory_means_no_slot_flag(tmp_path: Path) -> None:
    args, _ = _serve(tmp_path, MODEL="lfm3-omni-2b", LFM3_KIND="chat", LFM3_SLOT_DIR=str(tmp_path / "missing"))
    assert "--slot-save-path" not in args


def test_the_image_saves_the_warm_cache_for_chat_models_only() -> None:
    dockerfile = (SERVE.parent / "Dockerfile").read_text(encoding="utf-8")
    assert "lfm3-prewarm" in dockerfile.split("COPY lfm3-serve", 1)[1].splitlines()[0]
    step = "\n      lfm3-prewarm; \\"
    run = dockerfile.split(step, 1)[0].rsplit("RUN", 1)[1]
    assert '"${LFM3_KIND}" = chat' in run and '"${MODEL_NAME%-base}" = "${MODEL_NAME}"' in run
    # The model settings the room boots with are in place before the cache is saved.
    assert dockerfile.index("ENV LFM3_MODEL=") < dockerfile.index(step)


def _serve_with_gateway(tmp_path: Path, *command: str, **env: str) -> str:
    """Run lfm3-serve beside a stand-in lfm3-gateway; return the agent path it was given, or ""."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shutil.copy(SERVE, bin_dir / "lfm3-serve")
    (bin_dir / "llama-server").write_text("#!/usr/bin/env bash\nexit 0\n")
    (bin_dir / "lfm3-agent").write_text("#!/usr/bin/env bash\nexit 0\n")
    (bin_dir / "lfm3-gateway").write_text(f'#!/usr/bin/env bash\necho "$LFM3_GATEWAY_AGENT" > {tmp_path}/gateway-agent\n')
    for name in ("lfm3-serve", "llama-server", "lfm3-agent", "lfm3-gateway"):
        (bin_dir / name).chmod(0o755)
    run_env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "LFM3_MODEL": "/opt/lfm3/model.gguf",
        "LFM3_THREADS": "2",
        "LFM3_LOG_DIR": str(tmp_path / "log"),
        **env,
    }
    out = subprocess.run(["bash", str(bin_dir / "lfm3-serve"), *command], env=run_env, capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    marker = tmp_path / "gateway-agent"
    if _wait_for(marker):
        return marker.read_text().strip()
    return ""


@pytest.mark.parametrize("command", [("true",), ()], ids=["with a command", "foreground"])
def test_chat_models_start_the_chat_gateway_with_the_room_agent(tmp_path: Path, command: tuple[str, ...]) -> None:
    agent = _serve_with_gateway(tmp_path, *command, MODEL="lfm3-omni-2b", LFM3_KIND="chat")
    assert agent == str(tmp_path / "bin" / "lfm3-agent")


@pytest.mark.parametrize(
    "env",
    [
        {"MODEL": "lfm3-1.7b-base", "LFM3_KIND": "chat"},
        {"MODEL": "lfm3-d1-1b", "LFM3_KIND": "decision"},
        {"MODEL": "lfm3-omni-2b", "LFM3_KIND": "chat", "LFM3_GATEWAY": "off"},
    ],
    ids=["base", "decision", "off"],
)
def test_no_chat_gateway_without_a_chat_harness_or_when_off(tmp_path: Path, env: dict[str, str]) -> None:
    assert _serve_with_gateway(tmp_path, "true", **env) == ""


def test_the_image_build_warms_the_cache_without_the_gateway() -> None:
    prewarm = (SERVE.parent / "lfm3-prewarm").read_text(encoding="utf-8")
    line = next(line for line in prewarm.splitlines() if line.rstrip().endswith("lfm3-serve >\"$tmp/server.log\" 2>&1 &"))
    assert "LFM3_GATEWAY=off" in line
