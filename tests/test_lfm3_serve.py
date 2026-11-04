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
