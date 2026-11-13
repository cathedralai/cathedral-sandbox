"""AB#394 hippius_restic_bench.py against a fake restic on PATH. No network."""
from __future__ import annotations

import importlib.util
import json
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("hippius_restic_bench", ROOT / "scripts" / "hippius_restic_bench.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)

SECRETS = {
    "AWS_ACCESS_KEY_ID": "AKIDSECRETVALUE0001",
    "AWS_SECRET_ACCESS_KEY": "s3cr3t-access-key-value",
    "RESTIC_PASSWORD": "repo-password-value",
}

# The stub stores the backed-up file in a state dir and serves it back on restore,
# so the sha compare is real. It finds the subcommand after restic's global flags.
FAKE_RESTIC = r'''#!{python}
import json, os, shutil, sys
from pathlib import Path
state = Path(os.environ["FAKE_RESTIC_STATE"])
with open(state / "argv.log", "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
with_value = {{"-r", "-o", "--cache-dir"}}
i = 0
while i < len(args) and args[i].startswith("-"):
    i += 2 if args[i] in with_value else 1
cmd, rest = args[i], args[i + 1:]
if cmd == os.environ.get("FAKE_RESTIC_FAIL"):
    print("Fatal: injected failure", file=sys.stderr)
    sys.exit(1)
if cmd == "version":
    print(json.dumps({{"message_type": "version", "version": os.environ.get("FAKE_RESTIC_VERSION", "0.19.1")}}))
elif cmd == "init":
    (state / "repo").mkdir()
elif cmd == "backup":
    shutil.copy(Path.cwd() / rest[-1], state / "repo" / "data.bin")
    size = (state / "repo" / "data.bin").stat().st_size
    print(json.dumps({{"message_type": "status", "percent_done": 0.5}}))
    print(json.dumps({{"message_type": "summary", "snapshot_id": "abc123", "total_bytes_processed": size, "data_added": size}}))
elif cmd == "restore":
    target = Path(rest[rest.index("--target") + 1])
    target.mkdir(parents=True)
    data = state / "repo" / "data.bin"
    if os.environ.get("FAKE_RESTIC_CORRUPT"):
        (target / "data.bin").write_bytes(b"corrupt")
    else:
        shutil.copy(data, target / "data.bin")
elif cmd == "stats":
    data = state / "repo" / "data.bin"
    print(json.dumps({{"total_size": data.stat().st_size if data.exists() else 0}}))
elif cmd == "forget":
    (state / "repo" / "data.bin").unlink()
'''


@pytest.fixture
def fake(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    exe = tmp_path / "bin" / "restic"
    exe.parent.mkdir()
    exe.write_text(FAKE_RESTIC.format(python=sys.executable))
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{exe.parent}:{Path(sys.executable).parent}:/usr/bin:/bin")
    monkeypatch.setenv("FAKE_RESTIC_STATE", str(state))
    monkeypatch.delenv("RESTIC", raising=False)
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    return state


def run_bench(tmp_path, *extra):
    out = tmp_path / "result.json"
    code = bench.main(["--bucket", "bench-bucket", "--hotel-region", "region-a", "--out", str(out),
                       "--size-mib", "1", "--latency-runs", "3", *extra])
    return code, out


def commands(state):
    return [json.loads(line) for line in (state / "argv.log").read_text().splitlines()]


def assert_no_secrets(*texts):
    for text in texts:
        for value in SECRETS.values():
            assert value not in text


def test_happy_path_records_every_step(fake, tmp_path, capsys):
    code, out = run_bench(tmp_path)
    assert code == 0
    result = json.loads(out.read_text())
    assert [n for n, s in result["steps"].items() if s["ok"]] == list(bench.STEPS)
    assert result["prefix"].startswith("ab394-")
    assert result["s3_connections"] == 5
    assert result["steps"]["backup"]["bytes_processed"] == 1024 * 1024
    assert result["steps"]["backup"]["snapshot_id"] == "abc123"
    assert result["steps"]["latency"]["runs"] == 3
    assert result["steps"]["restore"]["sha256_match"] is True
    assert result["steps"]["delete"]["raw_bytes_before"] == 1024 * 1024
    assert result["steps"]["delete"]["raw_bytes_after"] == 0

    argv = commands(fake)
    repo_args = argv[1]
    assert repo_args[:2] == ["-r", f"s3:https://s3.hippius.com/bench-bucket/{result['prefix']}"]
    assert "s3.bucket-lookup=path" in repo_args and "s3.region=decentralized" in repo_args
    assert any("--no-cache" in a and "cat" in a for a in argv)
    assert any("--read-data" in a for a in argv)
    assert any("forget" in a and "abc123" in a and "--prune" in a for a in argv)

    captured = capsys.readouterr()
    assert_no_secrets(out.read_text(), captured.out, captured.err, (fake / "argv.log").read_text())


def test_wrong_restic_version_refuses_before_any_repo_call(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_RESTIC_VERSION", "0.18.1")
    code, out = run_bench(tmp_path)
    assert code == 2
    assert not out.exists()
    assert [a[-2:] for a in commands(fake)] == [["version", "--json"]]


def test_missing_credentials_is_bad_usage(fake, tmp_path, monkeypatch):
    monkeypatch.delenv("RESTIC_PASSWORD")
    code, out = run_bench(tmp_path)
    assert code == 2
    assert not (fake / "argv.log").exists()


def test_init_failure_skips_everything_including_cleanup(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_RESTIC_FAIL", "init")
    code, out = run_bench(tmp_path)
    assert code == 1
    steps = json.loads(out.read_text())["steps"]
    assert steps["init"]["ok"] is False and "injected failure" in steps["init"]["error"]
    assert all(steps[n] == {"ok": False, "skipped": True} for n in bench.STEPS[1:])


def test_check_failure_skips_restore_but_still_cleans_up(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_RESTIC_FAIL", "check")
    code, out = run_bench(tmp_path)
    assert code == 1
    steps = json.loads(out.read_text())["steps"]
    assert steps["check"]["ok"] is False
    assert steps["restore"] == {"ok": False, "skipped": True}
    assert steps["delete"]["ok"] is True and steps["delete"]["raw_bytes_after"] == 0


def test_restore_mismatch_fails(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_RESTIC_CORRUPT", "1")
    code, out = run_bench(tmp_path)
    assert code == 1
    steps = json.loads(out.read_text())["steps"]
    assert "does not match" in steps["restore"]["error"]
    assert steps["delete"]["ok"] is True
