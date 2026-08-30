"""Tests for the public, loopback-only miner onboarding rehearsal."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from cathedral.remote import RemoteError
from scripts import rehearse_sn39_miner as rehearsal

ROOT = Path(__file__).resolve().parents[1]


def test_public_miner_rehearsal_runs_from_an_installed_checkout():
    completed = subprocess.run(
        [sys.executable, "scripts/rehearse_sn39_miner.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    result = json.loads(completed.stdout)
    assert result["schema"] == "cathedral_miner_onboarding_rehearsal_v1"
    assert result["status"] == "PASS"
    assert result["fresh_temporary_state_removed"] is True
    assert result["checks"]["fleet_primary_plus_secondary"] == "PASS"
    assert result["checks"]["duplicate_fleet_rejected"] == "PASS"

    protocol = result["checks"]["protocol"]
    assert [check["evidence_kind"] for check in protocol] == ["tdx", "sev_snp"]
    for check in protocol:
        assert check["health"] == "PASS"
        assert check["synthetic_evidence_round_trip"] == "PASS"
        assert check["capabilities"] == "PASS"
        assert check["canonical_sat"] == "PASS"


def test_public_miner_rehearsal_ignores_ambient_network_proxies():
    environment = dict(os.environ)
    environment.update(
        {
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )
    completed = subprocess.run(
        [sys.executable, "scripts/rehearse_sn39_miner.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert json.loads(completed.stdout)["status"] == "PASS"


def test_public_miner_rehearsal_reports_protocol_failure_as_json(monkeypatch, capsys) -> None:
    def fail_rehearsal():
        raise RemoteError("protocol response changed")

    monkeypatch.setattr(rehearsal, "run_rehearsal", fail_rehearsal)

    assert rehearsal.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "schema": "cathedral_miner_onboarding_rehearsal_v1",
        "status": "FAIL",
        "error": "protocol response changed",
    }


def test_public_readme_scopes_the_rehearsal_and_help_path():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "scripts/rehearse_sn39_miner.py" in readme
    assert "for run in 1 2 3" in readme
    assert "loopback with clearly synthetic TDX and SEV-SNP evidence" in readme
    assert "0dc8db081dc35a993e8d59936c3ad036b39e68da84751282d9bba4ef16db2255" in readme
    assert "The published image pin\ndoes not prove" in readme
    assert "https://github.com/cathedralai/cathedral-sandbox/issues" in readme
    assert "Do not paste a coldkey, seed phrase, wallet file" in readme
