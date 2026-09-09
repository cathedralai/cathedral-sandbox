"""Offline process boundary tests. These do not simulate a vendor-chain proof."""
from pathlib import Path

import pytest

from cathedral.verify.tdx_offline import TdxOfflineUnavailable, persist_tdx_capture, verify_tdx_offline


def test_offline_tdx_rejects_exit_zero_script(tmp_path):
    executable = tmp_path / "verifier"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o500)
    with pytest.raises(TdxOfflineUnavailable):
        verify_tdx_offline(b"quote", b"x" * 64, b"{}", executable=str(executable), implementation_digest="sha256:" + "0" * 64)


def test_offline_tdx_rejects_symlink_to_executable(tmp_path):
    executable = tmp_path / "verifier"
    executable.symlink_to("/usr/bin/true")
    with pytest.raises(TdxOfflineUnavailable):
        verify_tdx_offline(b"quote", b"x" * 64, b"{}", executable=str(executable), implementation_digest="sha256:" + "0" * 64)


def test_capture_pairs_exact_quote_and_collateral_privately(tmp_path):
    import base64
    import json
    path = persist_tdx_capture(b"quote", b"collateral", tmp_path / "captures")
    document = json.loads(path.read_bytes())
    assert base64.b64decode(document["quote_base64"]) == b"quote"
    assert base64.b64decode(document["collateral_base64"]) == b"collateral"
    assert path.stat().st_mode & 0o077 == 0
    assert persist_tdx_capture(b"quote", b"collateral", path.parent) == path
    assert len(list(path.parent.iterdir())) == 1


def test_invalid_capture_is_not_written(tmp_path):
    with pytest.raises(ValueError):
        persist_tdx_capture(b"quote", b"", tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_online_capture_hook_retains_pair_only_after_success(monkeypatch, tmp_path):
    import importlib
    import json
    verifier = importlib.import_module("cathedral.verify")
    monkeypatch.setenv("CATHEDRAL_TDX_CAPTURE_DIR", str(tmp_path / "captures"))
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", "/test/verifier")
    monkeypatch.setattr(verifier, "_production_tdx_command", lambda _: ["/test/verifier"])
    def child(argv, *args, **kwargs):
        assert argv[-2] == "--capture-collateral"
        Path(argv[-1]).write_bytes(b"vendor collateral")
        return '{"intel_verified":true}', "", 0
    monkeypatch.setattr(verifier, "_read_bounded_subprocess", child)
    assert verifier._run_tdx_verifier(b"quote", production_mode=True, expected_report_data=b"x" * 64)["intel_verified"] is True
    saved = list((tmp_path / "captures").iterdir())
    assert len(saved) == 1
    assert json.loads(saved[0].read_bytes())["schema"] == "cathedral_tdx_capture_v1"
    monkeypatch.setattr(verifier, "_read_bounded_subprocess", lambda *a, **k: ("", "", 1))
    assert verifier._run_tdx_verifier(b"failed quote", production_mode=True, expected_report_data=b"x" * 64) == {}
    assert list((tmp_path / "captures").iterdir()) == saved
