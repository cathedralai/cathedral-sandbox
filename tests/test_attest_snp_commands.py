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


def test_production_snp_collection_never_fetches_collateral(monkeypatch, tmp_path: Path):
    guest_device = tmp_path / "sev-guest"
    guest_device.touch()
    seen: list[list[str]] = []

    def fake_run(command, **_kwargs):
        encoded = list(command)
        seen.append(encoded)
        Path(encoded[2]).write_bytes(b"r" * 1184)

    monkeypatch.setenv("CATHEDRAL_SEV_GUEST_DEV", str(guest_device))
    monkeypatch.setattr(attest_module, "_resolve_snpguest", lambda: "/test/snpguest")
    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)

    evidence = attest_module.collect_snp_report_only(b"n" * 32, "miner")

    assert evidence.quote == b"r" * 1184
    assert evidence.cert_chain == []
    assert [command[1] for command in seen] == ["report"]


def test_diagnostic_collateral_fetch_uses_exact_pinned_ca_interface(monkeypatch, tmp_path: Path):
    report = tmp_path / "report.bin"
    report.write_bytes(b"r" * 1184)
    seen: list[list[str]] = []

    def fake_run(command, **_kwargs):
        seen.append(list(command))

    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)

    attest_module._fetch_snp_cert_chain("/test/snpguest", report, tmp_path)

    certs = str(tmp_path / "certs")
    assert seen == [
        ["/test/snpguest", "fetch", "vcek", "DER", certs, str(report)],
        [
            "/test/snpguest",
            "fetch",
            "ca",
            "DER",
            certs,
            "--report",
            str(report),
        ],
    ]
