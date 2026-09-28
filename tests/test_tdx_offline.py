"""Offline process boundary tests. These do not simulate a vendor-chain proof."""

import base64
import hashlib
import importlib
import json
from pathlib import Path

import pytest

import cathedral.verify.tdx_offline as tdx_offline
from cathedral.verify.tdx_offline import (
    TdxOfflineUnavailable,
    persist_tdx_capture,
    verify_tdx_offline,
)

EXPECTED = bytes(range(64))


def test_offline_tdx_rejects_exit_zero_script(tmp_path):
    executable = tmp_path / "verifier"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o500)
    with pytest.raises(TdxOfflineUnavailable):
        verify_tdx_offline(
            b"quote",
            b"x" * 64,
            b"{}",
            executable=str(executable),
            implementation_digest="sha256:" + "0" * 64,
        )


def test_offline_tdx_rejects_symlink_to_executable(tmp_path):
    executable = tmp_path / "verifier"
    executable.symlink_to("/usr/bin/true")
    with pytest.raises(TdxOfflineUnavailable):
        verify_tdx_offline(
            b"quote",
            b"x" * 64,
            b"{}",
            executable=str(executable),
            implementation_digest="sha256:" + "0" * 64,
        )


def _good_claims():
    return {
        "intel_verified": True,
        "report_data_match": True,
        "claims_bound_to_quote": True,
        "platform_identity_verified": True,
        "report_data": EXPECTED.hex(),
        "tcb_status": "UpToDate",
        "advisory_ids": [],
        "debug_enabled": False,
        "collateral_current": False,
        "collateral_current_reason": "offline replay did not check the latest Intel publication",
    }


class _FakeVerifier:
    """A shell script that prints controlled JSON in place of the Go verifier.

    The static-ELF implementation digest cannot describe a script, so the
    digest function is replaced by a plain SHA-256 of the executable bytes. The
    comparison against the locally trusted digest is still the real one.
    """

    def __init__(self, tmp_path, monkeypatch, claims):
        self.claims_path = tmp_path / "claims.json"
        self.argv_path = tmp_path / "argv.txt"
        self.claims_path.write_text(json.dumps(claims))
        self.executable = tmp_path / "verifier"
        self.executable.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{self.argv_path}'\ncat '{self.claims_path}'\n"
        )
        self.executable.chmod(0o500)
        self.digest = "sha256:" + hashlib.sha256(self.executable.read_bytes()).hexdigest()
        monkeypatch.setattr(
            tdx_offline,
            "tdx_implementation_digest_from_bytes",
            lambda command, artifacts, blobs: (
                "sha256:" + hashlib.sha256(blobs[command[0]]).hexdigest()
            ),
        )

    def run(self, digest=None, expected=EXPECTED):
        return verify_tdx_offline(
            b"quote",
            expected,
            b'{"bundle":true}',
            executable=str(self.executable),
            implementation_digest=self.digest if digest is None else digest,
        )


def test_offline_tdx_accepts_complete_claims(tmp_path, monkeypatch):
    fake = _FakeVerifier(tmp_path, monkeypatch, _good_claims())
    assert fake.run() == _good_claims()
    argv = fake.argv_path.read_text().splitlines()
    assert argv[1:] == [EXPECTED.hex(), "--collateral-bundle", argv[3]]


def test_offline_tdx_wrong_implementation_digest_never_executes(tmp_path, monkeypatch):
    fake = _FakeVerifier(tmp_path, monkeypatch, _good_claims())
    with pytest.raises(TdxOfflineUnavailable):
        fake.run(digest="sha256:" + "0" * 64)
    assert not fake.argv_path.exists()


@pytest.mark.parametrize(
    "change",
    [
        {"tcb_status": "OutOfDate"},
        {"tcb_status": "SWHardeningNeeded"},
        {"tcb_status": "ConfigurationNeeded"},
        {"report_data": bytes(64).hex()},
        {"intel_verified": False},
        {"intel_verified": "true"},
        {"report_data_match": False},
        {"claims_bound_to_quote": False},
        {"platform_identity_verified": False},
        {"advisory_ids": ["INTEL-SA-00837"]},
        {"debug_enabled": True},
        {"collateral_current": True},
        {"collateral_current_reason": ""},
    ],
    ids=lambda change: "-".join(f"{key}={value}" for key, value in change.items()),
)
def test_offline_tdx_rejects_each_failed_claim(tmp_path, monkeypatch, change):
    fake = _FakeVerifier(tmp_path, monkeypatch, {**_good_claims(), **change})
    assert fake.run() == {}
    assert fake.argv_path.exists()


def test_offline_tdx_rejects_claims_for_other_report_data(tmp_path, monkeypatch):
    # The verifier echoes REPORT_DATA from a different quote than the one asked for.
    fake = _FakeVerifier(tmp_path, monkeypatch, _good_claims())
    assert fake.run(expected=bytes(reversed(EXPECTED))) == {}


def test_offline_tdx_rejects_nonzero_exit(tmp_path, monkeypatch):
    fake = _FakeVerifier(tmp_path, monkeypatch, _good_claims())
    fake.executable.chmod(0o700)
    fake.executable.write_text(fake.executable.read_text() + "exit 3\n")
    fake.executable.chmod(0o500)
    fake.digest = "sha256:" + hashlib.sha256(fake.executable.read_bytes()).hexdigest()
    assert fake.run() == {}


def _capture_files(directory):
    files = sorted(directory.iterdir())
    captures = [path for path in files if not path.name.endswith(".meta.json")]
    sidecars = [path for path in files if path.name.endswith(".meta.json")]
    return captures, sidecars


def test_capture_pairs_exact_quote_and_collateral_privately(tmp_path):
    path = persist_tdx_capture(
        b"quote", b"collateral", tmp_path / "captures", admission_nonce=b"n" * 32, box_id="box-1"
    )
    document = json.loads(path.read_bytes())
    assert base64.b64decode(document["quote_base64"]) == b"quote"
    assert base64.b64decode(document["collateral_base64"]) == b"collateral"
    assert path.stat().st_mode & 0o077 == 0
    assert path.name == hashlib.sha256(path.read_bytes()).hexdigest() + ".json"
    sidecar = path.with_name(path.stem + ".meta.json")
    metadata = json.loads(sidecar.read_bytes())
    assert metadata["schema"] == "cathedral_capture_metadata_v1"
    assert metadata["capture"] == path.name
    assert metadata["admission_nonce_hex"] == (b"n" * 32).hex()
    assert metadata["box_id"] == "box-1"
    assert metadata["captured_at"].endswith("Z")
    assert sidecar.stat().st_mode & 0o077 == 0
    # Identical evidence keeps its name and its first metadata record.
    assert persist_tdx_capture(b"quote", b"collateral", path.parent, box_id="box-2") == path
    assert json.loads(sidecar.read_bytes())["box_id"] == "box-1"
    assert _capture_files(path.parent) == ([path], [sidecar])


def test_capture_metadata_is_optional(tmp_path):
    path = persist_tdx_capture(b"quote", b"collateral", tmp_path)
    metadata = json.loads(path.with_name(path.stem + ".meta.json").read_bytes())
    assert metadata["admission_nonce_hex"] is None
    assert metadata["box_id"] is None


@pytest.mark.parametrize(
    "kwargs",
    [{"collateral": b""}, {"box_id": "box\n1"}, {"box_id": ""}, {"admission_nonce": b""}],
)
def test_invalid_capture_is_not_written(tmp_path, kwargs):
    arguments = {"collateral": b"collateral", **kwargs}
    collateral = arguments.pop("collateral")
    with pytest.raises(ValueError):
        persist_tdx_capture(b"quote", collateral, tmp_path, **arguments)
    assert list(tmp_path.iterdir()) == []


def test_online_capture_hook_retains_pair_only_after_success(monkeypatch, tmp_path):
    verifier = importlib.import_module("cathedral.verify")
    monkeypatch.setenv("CATHEDRAL_TDX_CAPTURE_DIR", str(tmp_path / "captures"))
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", "/test/verifier")
    monkeypatch.setattr(verifier, "_production_tdx_command", lambda _: ["/test/verifier"])

    def child(argv, *args, **kwargs):
        assert argv[-2] == "--capture-collateral"
        Path(argv[-1]).write_bytes(b"vendor collateral")
        return '{"intel_verified":true}', "", 0

    monkeypatch.setattr(verifier, "_read_bounded_subprocess", child)
    claims = verifier._run_tdx_verifier(
        b"quote",
        production_mode=True,
        expected_report_data=b"x" * 64,
        capture_nonce=b"a" * 32,
        capture_box_id="box-9",
    )
    assert claims["intel_verified"] is True
    captures, sidecars = _capture_files(tmp_path / "captures")
    assert len(captures) == 1 and len(sidecars) == 1
    assert json.loads(captures[0].read_bytes())["schema"] == "cathedral_tdx_capture_v1"
    metadata = json.loads(sidecars[0].read_bytes())
    assert metadata["admission_nonce_hex"] == (b"a" * 32).hex()
    assert metadata["box_id"] == "box-9"
    monkeypatch.setattr(verifier, "_read_bounded_subprocess", lambda *a, **k: ("", "", 1))
    assert (
        verifier._run_tdx_verifier(
            b"failed quote", production_mode=True, expected_report_data=b"x" * 64
        )
        == {}
    )
    assert _capture_files(tmp_path / "captures") == (captures, sidecars)
