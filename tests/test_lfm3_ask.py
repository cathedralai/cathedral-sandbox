"""images/room-lfm3/lfm3-ask against a fake llama-cli (AB#589).

The fake prints stdout the way llama-cli b11960 does with --simple-io and no
TTY: a banner, the echoed prompt (cut to 500 bytes plus " ... (truncated)" when
longer, tools/cli/cli-ui.h user_turn::echo), the answer, the stats line and
"Exiting...". It unescapes -p unless --no-escape is passed, like
common/arg.cpp. lfm3-ask must print the answer and the timing line only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ASK = ROOT / "images" / "room-lfm3" / "lfm3-ask"

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="lfm3-ask needs bash")

ANSWER = "Four.\nThat is the answer."

FAKE_CLI = r'''
import os, sys

args = sys.argv[1:]
prompt = args[args.index("-p") + 1].encode()
if "--no-escape" not in args:
    prompt = (prompt.replace(b"\\\\", b"\x00").replace(b"\\n", b"\n")
              .replace(b"\\t", b"\t").replace(b"\x00", b"\\"))

err = sys.stderr
err.write("0.00.012.345 I load_model: loading model '/opt/lfm3/x.gguf'\n")
err.write("0.01.215.345 I server_run_i: model loaded\n")
if os.environ.get("FAKE_EXIT", "0") != "0":
    err.write("fatal: something broke\n")
    sys.exit(int(os.environ["FAKE_EXIT"]))

out = sys.stdout.buffer
out.write(b"\n\nLoading model... \n\n\xe2\x96\x84\xe2\x96\x84 llama.cpp banner\n\nbuild : b11960\nmodel : x.gguf\n")
if len(prompt) > 500:
    out.write(b"\n> " + prompt[:500] + b" ... (truncated)\n")
else:
    out.write(b"\n> " + prompt + b"\n")
if os.environ.get("FAKE_ERROR"):
    out.write(b"Error: " + os.environ["FAKE_ERROR"].encode() + b"\n")
    out.write(b"\n[ Prompt: 0.0 t/s | Generation: 0.0 t/s ]\n")
else:
    out.write(os.environ["FAKE_ANSWER"].encode() + b"\n")
    out.write(b"\n[ Prompt: 118.0 t/s | Generation: 52.8 t/s ]\n")
out.write(b"\n\nExiting...\n")
'''


@pytest.fixture
def fake_cli(tmp_path: Path) -> Path:
    path = tmp_path / "llama-cli"
    path.write_text(f"#!{sys.executable}\n{FAKE_CLI}")
    path.chmod(0o755)
    return path


def ask(fake_cli: Path, *args: str, stdin: str | None = None, **env: str) -> subprocess.CompletedProcess[bytes]:
    full_env = {
        **os.environ,
        "LC_ALL": "C.UTF-8",
        "LFM3_LLAMA_CLI": str(fake_cli),
        "LFM3_MODEL": "/nonexistent.gguf",
        "LFM3_THREADS": "2",
        "FAKE_ANSWER": ANSWER,
        **env,
    }
    return subprocess.run(
        ["bash", str(ASK), *args],
        input=None if stdin is None else stdin.encode(),
        capture_output=True,
        env=full_env,
        timeout=60,
    )


def answer_and_timing(out: bytes) -> tuple[str, str]:
    text = out.decode()
    body, _, timing = text.rstrip("\n").rpartition("\n")
    return body, timing


LONG = "Summarise this headline for a newsletter. " * 50  # about 2,100 bytes


@pytest.mark.parametrize(
    "prompt",
    [
        "What is 2+2? Answer in one word.",
        LONG,
        "x" * 500,
        "x" * 501,
        # A two-byte character straddles byte 500: llama-cli cuts it in half.
        "x" * 499 + "\u00e9" * 40,
        "line one\nline two\n" * 60,
        r"Parse C:\new\table and the JSON {\"a\": 1} " * 20,
        r"short with a backslash \n in it",
    ],
    ids=["short", "long", "500-bytes", "501-bytes", "utf8-split", "newlines", "backslashes-long", "backslash-short"],
)
def test_prints_only_the_answer(fake_cli: Path, prompt: str) -> None:
    out = ask(fake_cli, prompt)
    assert out.returncode == 0, out.stderr
    body, timing = answer_and_timing(out.stdout)
    assert body == ANSWER
    assert timing.startswith("lfm3-timing load_ms=1203 prompt_tok_s=118.0 gen_tok_s=52.8 ")
    assert b"did not echo" not in out.stderr


def test_long_prompt_on_stdin(fake_cli: Path) -> None:
    """The pilot's shape: `lfm3-ask -` with a long prompt piped in."""
    out = ask(fake_cli, "-", stdin=LONG + "\n")
    assert out.returncode == 0, out.stderr
    body, _ = answer_and_timing(out.stdout)
    assert body == ANSWER
    assert b"llama.cpp banner" not in out.stdout and b"truncated" not in out.stdout


def test_prompt_over_context_fails(fake_cli: Path) -> None:
    msg = "request (2600 tokens) exceeds the available context size (2048 tokens), try increasing it"
    out = ask(fake_cli, LONG * 5, FAKE_ERROR=msg)
    assert out.returncode == 1
    assert out.stdout == b""
    assert msg.encode() in out.stderr and b"LFM3_CTX" in out.stderr


def test_llama_cli_failure_keeps_its_status(fake_cli: Path) -> None:
    out = ask(fake_cli, LONG, FAKE_EXIT="3")
    assert out.returncode == 3
    assert out.stdout == b""
    assert b"llama-cli exited 3" in out.stderr


def test_unmatched_echo_still_drops_the_stats_line(fake_cli: Path, tmp_path: Path) -> None:
    """If a future llama-cli changes the echo, say so and keep stats off stdout."""
    odd = tmp_path / "odd-cli"
    odd.write_text(f"#!{sys.executable}\n" + FAKE_CLI.replace('b"\\n> "', 'b"\\n>> "'))
    odd.chmod(0o755)
    out = ask(odd, "hi")
    assert out.returncode == 0
    assert b"did not echo" in out.stderr
    assert b"[ Prompt:" not in out.stdout and b"Exiting" not in out.stdout
