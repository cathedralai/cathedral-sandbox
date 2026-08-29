"""Hardware-free command contract for the SEV-SNP collector."""

from __future__ import annotations

from pathlib import Path

import cathedral.attest as attest_module


def test_snp_collection_requests_vmpl_zero(monkeypatch, tmp_path: Path):
    guest_device = tmp_path / "sev-guest"
    guest_device.touch()
    seen: list[list[str]] = []

    def fake_run(command, **_kwargs):
        encoded = list(command)
        seen.append(encoded)
        Path(encoded[2]).write_bytes(b"r" * 1184)

    monkeypatch.setattr(attest_module, "_resolve_snpguest", lambda: "/test/snpguest")
    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    monkeypatch.setattr(attest_module, "_fetch_snp_cert_chain", lambda *_args: [])

    quote, chain = attest_module._collect_snpguest_report(b"d" * 64, dev=guest_device)

    assert quote == b"r" * 1184
    assert chain == []
    assert seen[0][1] == "report"
    assert seen[0][-2:] == ["--vmpl", "0"]


def test_snp_collection_timeout_override_is_globally_capped(monkeypatch):
    monkeypatch.setenv("CATHEDRAL_SNPGUEST_TIMEOUT", "86400")
    assert attest_module._snpguest_timeout() == 300.0
