"""AB#546: a broker swap refuses a binary or a live catalog that differs from main.

On 4 Nov a broker built from 0932838 (older than the #388 pins) was swapped in and
template creates got the old LFM images. scripts/broker_catalog_pin_check.sh compares
the new binary's -print-catalog-digest (or a catalog readback) with
broker/catalog.digest on main. Fake binaries and a local "origin" stand in for the
broker and GitHub; nothing here touches a network or a host.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "broker_catalog_pin_check.sh"
BASH = shutil.which("bash")
GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(BASH is None or GIT is None, reason="needs bash and git")

NEW = "sha256:" + "a" * 64  # main's pins
OLD = "sha256:" + "0" * 64  # the pre-#388 build


def _git(*args: str, cwd: Path | None = None) -> str:
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PATH": "/usr/bin:/bin"}
    return subprocess.run([GIT, *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout


def _commit_digest(work: Path, digest: str) -> None:
    (work / "broker").mkdir(exist_ok=True)
    (work / "broker" / "catalog.digest").write_text(digest + "\n")
    _git("add", "-A", cwd=work)
    _git("commit", "-q", "-m", "pins " + digest[7:15], cwd=work)
    _git("push", "-q", "origin", "HEAD:main", cwd=work)


@pytest.fixture
def repos(tmp_path: Path) -> tuple[Path, Path]:
    """(upstream work tree, operator clone). Upstream path ends in cathedralai/cathedral-sandbox.git."""
    origin = tmp_path / "cathedralai" / "cathedral-sandbox.git"
    origin.parent.mkdir()
    _git("init", "-q", "--bare", "-b", "main", str(origin))
    up = tmp_path / "upstream"
    _git("clone", "-q", str(origin), str(up))
    _commit_digest(up, NEW)
    op = tmp_path / "operator"
    _git("clone", "-q", str(origin), str(op))
    return up, op


def _fake_binary(tmp_path: Path, body: str, name: str = "thin-broker.new") -> Path:
    p = tmp_path / name
    p.write_text("#!/bin/bash\n" + body + "\n")
    p.chmod(0o755)
    return p


def _binary_that_prints(tmp_path: Path, digest: str) -> Path:
    # Like the real flag: prints the digest only for -print-catalog-digest.
    return _fake_binary(tmp_path, f'[ "$1" = -print-catalog-digest ] && {{ echo {digest}; exit 0; }}; echo "would serve" >&2; exit 9')


def _run(*args: str | Path, allow: str | None = None) -> subprocess.CompletedProcess[str]:
    env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    if allow is not None:
        env["ALLOW_CATALOG_DIGEST"] = allow
    return subprocess.run([BASH, str(CHECK), *map(str, args)], env=env, capture_output=True, text=True, timeout=60)


def _catalog(templates: list[dict]) -> dict:
    return {"available": True, "templates": templates}


def _digest(templates: list[dict]) -> str:
    """The documented line format (broker/catalog_digest.go), computed independently."""
    def b(v: bool) -> str:
        return "true" if v else "false"
    text = "".join(
        f"{t['name']}\t{t['image']}\t{b(t['live'])}\t{t['sealed']}\t{b(t.get('sealed_only', False))}\t"
        f"{t['resources']['cpu']}\t{t['resources']['memory_gib']}\t{t['disk_gib']}\n" for t in templates)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


TEMPLATES = [
    {"name": "room-1x4", "image": "alpine:3.20", "live": True, "sealed": "ready",
     "resources": {"cpu": 1, "memory_gib": 4}, "disk_gib": 10},
    {"name": "lfm3-base-2b", "image": "ghcr.io/cathedralai/room-lfm3-1.7b-base@sha256:" + "8" * 64, "live": True,
     "sealed": "ready", "sealed_only": True, "hardware_class": "amd_sev_snp",
     "resources": {"cpu": 2, "memory_gib": 4}, "disk_gib": 20},
]


# binary mode

def test_binary_with_main_pins_passes(tmp_path, repos):
    _, op = repos
    r = _run("binary", op, _binary_that_prints(tmp_path, NEW), "-print-catalog-digest")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "CATALOG PIN: PASS" in r.stdout and "ROLLBACK" not in r.stdout


def test_binary_with_older_pins_is_refused(tmp_path, repos):
    _, op = repos
    r = _run("binary", op, _binary_that_prints(tmp_path, OLD), "-print-catalog-digest")
    assert r.returncode == 1
    assert "REFUSE" in r.stdout and OLD in r.stdout and NEW in r.stdout


def test_binary_older_than_the_flag_is_refused(tmp_path, repos):
    # The 4 Nov binary: Go's flag package rejects an unknown flag with exit 2.
    _, op = repos
    old = _fake_binary(tmp_path, 'echo "flag provided but not defined: -print-catalog-digest" >&2; exit 2')
    r = _run("binary", op, old, "-print-catalog-digest")
    assert r.returncode == 1
    assert "did not report a catalog digest (exit 2)" in r.stdout


@pytest.mark.parametrize("body", [f"echo {NEW}; echo extra", "echo hello", f"echo ' {NEW}'", "true"])
def test_binary_output_must_be_exactly_one_digest(tmp_path, repos, body):
    _, op = repos
    r = _run("binary", op, _fake_binary(tmp_path, body), "-print-catalog-digest")
    assert r.returncode == 1, r.stdout


def test_binary_that_cannot_run_here_is_refused(tmp_path, repos):
    _, op = repos
    r = _run("binary", op, tmp_path / "no-such-binary", "-print-catalog-digest")
    assert r.returncode == 1


# rollback path

def test_rollback_to_a_named_older_catalog_passes_loudly(tmp_path, repos):
    _, op = repos
    r = _run("binary", op, _binary_that_prints(tmp_path, OLD), "-print-catalog-digest", allow=OLD)
    assert r.returncode == 0, r.stdout
    assert "PASS ROLLBACK" in r.stdout and OLD in r.stdout and NEW in r.stdout


def test_rollback_override_naming_another_digest_still_refuses(tmp_path, repos):
    _, op = repos
    r = _run("binary", op, _binary_that_prints(tmp_path, OLD), "-print-catalog-digest", allow="sha256:" + "b" * 64)
    assert r.returncode == 1


def test_rollback_override_must_be_a_digest(tmp_path, repos):
    _, op = repos
    r = _run("binary", op, _binary_that_prints(tmp_path, OLD), "-print-catalog-digest", allow="yes")
    assert r.returncode == 2


def test_rollback_override_does_not_change_a_matching_pass(tmp_path, repos):
    _, op = repos
    r = _run("binary", op, _binary_that_prints(tmp_path, NEW), "-print-catalog-digest", allow=OLD)
    assert r.returncode == 0 and "ROLLBACK" not in r.stdout


# expected digest comes from a fresh main

def test_main_moved_after_the_clone_uses_the_new_main(tmp_path, repos):
    up, op = repos
    newer = "sha256:" + "c" * 64
    _commit_digest(up, newer)
    r = _run("binary", op, _binary_that_prints(tmp_path, NEW), "-print-catalog-digest")
    assert r.returncode == 1, "a binary matching the stale local origin/main must not pass"
    assert newer in r.stdout


def test_failed_fetch_refuses_even_if_the_stale_ref_matches(tmp_path, repos):
    _, op = repos
    origin = tmp_path / "cathedralai" / "cathedral-sandbox.git"
    origin.rename(tmp_path / "gone.git")
    r = _run("binary", op, _binary_that_prints(tmp_path, NEW), "-print-catalog-digest")
    assert r.returncode == 1
    assert "could not fetch main" in r.stdout


def test_origin_must_be_cathedral_sandbox(tmp_path, repos):
    _, op = repos
    _git("remote", "set-url", "origin", str(tmp_path / "fork" / "cathedral-sandbox-fork.git"), cwd=op)
    r = _run("binary", op, _binary_that_prints(tmp_path, NEW), "-print-catalog-digest")
    assert r.returncode == 1 and "not cathedralai/cathedral-sandbox" in r.stdout


def test_main_without_a_catalog_digest_refuses(tmp_path, repos):
    up, op = repos
    _git("rm", "-q", "broker/catalog.digest", cwd=up)
    _git("commit", "-q", "-m", "drop", cwd=up)
    _git("push", "-q", "origin", "HEAD:main", cwd=up)
    r = _run("binary", op, _binary_that_prints(tmp_path, NEW), "-print-catalog-digest")
    assert r.returncode == 1 and "no valid broker/catalog.digest" in r.stdout


# readback mode (trial port or live catalog, works on a broker older than the flag)

def test_readback_matching_main_passes(tmp_path, repos):
    up, op = repos
    _commit_digest(up, _digest(TEMPLATES))
    f = tmp_path / "catalog.json"
    f.write_text(json.dumps(_catalog(TEMPLATES)))
    r = _run("readback", op, f)
    assert r.returncode == 0, r.stdout + r.stderr


def test_readback_absent_sealed_only_is_false(tmp_path, repos):
    up, op = repos
    explicit = [dict(TEMPLATES[0], sealed_only=False), TEMPLATES[1]]
    _commit_digest(up, _digest(explicit))
    f = tmp_path / "catalog.json"
    f.write_text(json.dumps(_catalog(TEMPLATES)))  # room-1x4 has no sealed_only key
    assert _run("readback", op, f).returncode == 0


@pytest.mark.parametrize("field,value", [
    ("image", "ghcr.io/cathedralai/room-lfm3-1.7b-base@sha256:" + "1" * 64),
    ("live", False), ("sealed", "pending"), ("sealed_only", False), ("disk_gib", 30),
    ("resources", {"cpu": 4, "memory_gib": 4}),
])
def test_readback_with_any_create_field_changed_is_refused(tmp_path, repos, field, value):
    up, op = repos
    _commit_digest(up, _digest(TEMPLATES))
    rolled = [TEMPLATES[0], dict(TEMPLATES[1], **{field: value})]
    f = tmp_path / "catalog.json"
    f.write_text(json.dumps(_catalog(rolled)))
    r = _run("readback", op, f)
    assert r.returncode == 1 and "REFUSE" in r.stdout


@pytest.mark.parametrize("text", ["not json", "{}", json.dumps({"templates": [{"name": "x"}]}),
                                  json.dumps({"templates": [dict(TEMPLATES[0], live="true")]})])
def test_readback_of_an_unreadable_catalog_is_refused(tmp_path, repos, text):
    _, op = repos
    f = tmp_path / "catalog.json"
    f.write_text(text)
    assert _run("readback", op, f).returncode == 1


def test_usage_errors_exit_2(tmp_path, repos):
    _, op = repos
    assert _run("binary", op).returncode == 2
    assert _run("swap", op, "x").returncode == 2
    assert _run("readback", op, "a", "b").returncode == 2
