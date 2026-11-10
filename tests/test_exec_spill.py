"""Mid-run exec output for follow (AB#654).

A follow client reads the spill with the files route while POST /exec is still
open. The bytes are a prefix of the capped stdout the exec answer returns.
"""

from __future__ import annotations

import sys
import threading

import pytest

from cathedral.exec_spill import (
    StreamSpill,
    close_spill,
    open_spill,
    read_spill,
    spill_path,
    spill_path_parts,
)
from cathedral.sandbox_api import (
    CreateSandboxRequest,
    ExecRequest,
    FileGet,
    ImageSource,
    Resources,
    SandboxContractError,
)
from cathedral.sandbox_guest import DockerClient, DockerGuestProvider, _run_bounded
from cathedral.sandbox_provider import SandboxOpError
from tests.fake_docker_cli import install


def test_spill_token_is_32_lowercase_hex():
    assert ExecRequest(cmd=["true"], spill_token="ab" * 16).spill_token == "ab" * 16
    with pytest.raises(SandboxContractError):
        ExecRequest(cmd=["true"], spill_token="nope")
    with pytest.raises(SandboxContractError):
        ExecRequest(cmd=["true"], spill_token="AB" * 16)


def test_spill_path_names_one_stream():
    token = "cd" * 16
    assert spill_path_parts(spill_path(token, "stdout")) == (token, "stdout")
    assert spill_path_parts(spill_path(token, "stderr")) == (token, "stderr")
    assert spill_path_parts("/work/.cathedral-spill/../stdout") is None
    assert spill_path_parts("/etc/passwd") is None


def test_spill_stops_at_the_cap_and_a_reader_sees_a_prefix():
    spill = StreamSpill(4)
    spill.add("stdout", b"abc")
    assert spill.read("stdout") == b"abc"
    spill.add("stdout", b"DEFGH")
    assert spill.read("stdout") == b"abcD"


def test_a_missing_spill_reads_as_absent_and_close_drops_it():
    token = "ef" * 16
    assert read_spill("sbx", token, "stdout") is None
    opened = open_spill("sbx", token, 8)
    assert opened is not None
    opened.add("stdout", b"hi")
    assert read_spill("sbx", token, "stdout") == b"hi"
    assert read_spill("other", token, "stdout") is None
    close_spill("sbx", token)
    assert read_spill("sbx", token, "stdout") is None


def test_drainer_publishes_each_chunk_before_the_process_exits(tmp_path):
    flag = tmp_path / "go"
    script = (
        "import os, sys, time\n"
        "sys.stdout.buffer.write(b'a\\n'); sys.stdout.buffer.flush()\n"
        "deadline = time.time() + 3\n"
        f"while not os.path.exists({str(flag)!r}):\n"
        "    if time.time() > deadline: sys.exit(2)\n"
        "    time.sleep(0.01)\n"
        "sys.stdout.buffer.write(b'b\\n'); sys.stdout.buffer.flush()\n"
    )
    seen: list[bytes] = []
    started = threading.Event()

    def on_stdout(chunk: bytes) -> None:
        seen.append(chunk)
        if b"a\n" in b"".join(seen):
            started.set()

    holder: list = []

    def run() -> None:
        holder.append(
            _run_bounded(
                [sys.executable, "-c", script],
                timeout=5,
                input_bytes=None,
                env=None,
                cap=1024,
                on_stdout=on_stdout,
            )
        )

    thread = threading.Thread(target=run)
    thread.start()
    assert started.wait(3)
    assert b"b\n" not in b"".join(seen)
    flag.write_text("go")
    thread.join(5)
    assert holder and holder[0].returncode == 0
    assert holder[0].stdout == b"a\nb\n"
    assert b"".join(seen) == b"a\nb\n"


def test_drainer_does_not_publish_the_overflow_byte():
    seen: list[bytes] = []
    result = _run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'abcdefgh')"],
        timeout=5,
        input_bytes=None,
        env=None,
        cap=4,
        on_stdout=seen.append,
    )
    assert b"".join(seen) == b"abcd"
    assert result.stdout == b"abcde"


def test_files_route_serves_the_spill_only_while_exec_runs(tmp_path, monkeypatch):
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.set(exec_model=True)
    provider = DockerGuestProvider()
    sid = provider.create(
        CreateSandboxRequest(
            image=ImageSource(image="alpine:3.20"),
            resources=Resources(vcpu=1, memory_gib=1, disk_gib=5),
        ),
        api_key="k",
        idempotency=None,
        body_digest="x",
    )["id"]
    token = "12" * 16
    path = spill_path(token, "stdout")
    observed: dict[str, bytes] = {}

    def fake_exec(container_id, argv, **kwargs):
        spill = kwargs.get("spill")
        if spill is None:
            return 0, "", "", False
        spill.add("stdout", b"line\n")
        data, total = provider.read_file(sid, FileGet(path=path))
        assert total == len(data)
        observed["during"] = data
        return 0, "line\n", "", False

    monkeypatch.setattr(provider._client, "exec", fake_exec)
    result = provider.exec(sid, ExecRequest(cmd=["echo", "line"], spill_token=token))
    assert observed["during"] == b"line\n"
    assert result.stdout == "line\n"
    with pytest.raises(SandboxOpError) as raised:
        provider.read_file(sid, FileGet(path=path))
    assert raised.value.code == "file_not_found"


def test_docker_run_forwards_chunks_when_capped():
    client = DockerClient()
    seen: list[bytes] = []
    result = client.run(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'xyz')"],
        timeout=5,
        output_cap=8,
        on_stdout=seen.append,
    )
    assert result.returncode == 0
    assert b"".join(seen) == b"xyz"
    assert result.stdout == "xyz"
