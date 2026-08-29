"""Hardware-free contracts for the friend-owned SEV-SNP self-test tool."""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import subprocess
import threading

import pytest

import cathedral.snp_friend_probe as probe
from cathedral.channel import tls_spki_binding
from cathedral.common import Evidence, EvidenceKind
from cathedral.remote import RemoteMiner
from cathedral.worker import WorkerServer


def test_pinned_snpguest_preflight_checks_version_and_binary_digest(monkeypatch, tmp_path):
    binary = tmp_path / "snpguest"
    binary.write_text("#!/bin/sh\necho 'snpguest 0.10.0'\n", encoding="ascii")
    binary.chmod(0o755)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    monkeypatch.setenv("CATHEDRAL_SNPGUEST", str(binary))
    monkeypatch.setattr(probe, "PINNED_SNPGUEST_SHA256", digest)

    private_directory = tmp_path / "private"
    private_directory.mkdir()
    path, version, actual_digest = probe._resolve_snpguest(private_directory)

    assert path == private_directory / "snpguest"
    assert path != binary
    assert path.read_bytes() == binary.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o500
    assert version == "snpguest 0.10.0"
    assert actual_digest == digest


def test_pinned_snpguest_preflight_rejects_symlink_source(monkeypatch, tmp_path):
    binary = tmp_path / "real-snpguest"
    binary.write_text("#!/bin/sh\necho 'snpguest 0.10.0'\n", encoding="ascii")
    binary.chmod(0o755)
    link = tmp_path / "snpguest-link"
    link.symlink_to(binary)
    private_directory = tmp_path / "private"
    private_directory.mkdir()
    monkeypatch.setenv("CATHEDRAL_SNPGUEST", str(link))

    with pytest.raises(probe.ProbeError, match="copied safely"):
        probe._resolve_snpguest(private_directory)


def test_wrong_digest_is_rejected_before_any_binary_execution(monkeypatch, tmp_path):
    binary = tmp_path / "unreviewed-snpguest"
    binary.write_text("#!/bin/sh\necho 'snpguest 0.10.0'\n", encoding="ascii")
    binary.chmod(0o755)
    private_directory = tmp_path / "private"
    private_directory.mkdir()
    monkeypatch.setenv("CATHEDRAL_SNPGUEST", str(binary))

    def forbidden_execution(*_args, **_kwargs):
        raise AssertionError("unreviewed binary executed before its digest passed")

    monkeypatch.setattr(probe.subprocess, "run", forbidden_execution)
    with pytest.raises(probe.ProbeError, match="digest does not match"):
        probe._resolve_snpguest(private_directory)


def test_source_commit_comes_from_clean_executing_checkout(monkeypatch, tmp_path):
    expected = "a" * 40
    package = tmp_path / "cathedral" / "__init__.py"
    package.parent.mkdir()
    package.touch()
    responses = iter(
        [
            subprocess.CompletedProcess([], 0, stdout=expected + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
    )
    monkeypatch.setattr(probe, "_source_root", lambda: tmp_path)
    monkeypatch.setattr(probe, "_package_file", lambda: package)
    monkeypatch.setattr(probe.subprocess, "run", lambda *_args, **_kwargs: next(responses))

    assert probe._source_commit() == expected


def test_source_commit_rejects_dirty_checkout(monkeypatch, tmp_path):
    package = tmp_path / "cathedral" / "__init__.py"
    package.parent.mkdir()
    package.touch()
    responses = iter(
        [
            subprocess.CompletedProcess([], 0, stdout="a" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="?? local-change\n", stderr=""),
        ]
    )
    monkeypatch.setattr(probe, "_source_root", lambda: tmp_path)
    monkeypatch.setattr(probe, "_package_file", lambda: package)
    monkeypatch.setattr(probe.subprocess, "run", lambda *_args, **_kwargs: next(responses))

    with pytest.raises(probe.ProbeError, match="not clean"):
        probe._source_commit()


def test_review_challenge_is_exact_nonzero_32_bytes():
    expected = bytes.fromhex("01" * 32)
    assert probe._parse_review_challenge("01" * 32) == expected
    with pytest.raises(argparse.ArgumentTypeError):
        probe._parse_review_challenge("01" * 31)
    with pytest.raises(argparse.ArgumentTypeError):
        probe._parse_review_challenge("00" * 32)


def test_generated_tls_identity_serves_v2_evidence_over_verified_https(tmp_path):
    cert_path, key_path, certificate_der = probe._tls_material(tmp_path)
    binding = tls_spki_binding(certificate_der)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cafile=str(cert_path))

    def collector(nonce, hotkey, *, channel_binding, report_data_version):
        return Evidence(
            kind=EvidenceKind.SEV_SNP,
            quote=b"signed-snp-report-placeholder",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=report_data_version,
            channel_binding=channel_binding,
        )

    with WorkerServer(
        "127.0.0.1",
        0,
        configured_hotkey=probe.HOTKEY,
        evidence_collector=collector,
        channel_binding=binding,
        tls_context=server_context,
    ) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        evidence = RemoteMiner(
            server.base_url,
            probe.HOTKEY,
            ssl_context=client_context,
        ).fetch_evidence(b"n" * 32)

    assert evidence.kind is EvidenceKind.SEV_SNP
    assert evidence.report_data_version == 2
    assert evidence.channel_binding == binding


def test_transcript_output_is_owner_only_and_never_overwritten(tmp_path):
    output = tmp_path / "transcript.json"
    document = {"schema": probe.TRANSCRIPT_SCHEMA, "status": "LOCAL_PASS"}

    probe._write_new(output, document)

    assert json.loads(output.read_text(encoding="utf-8")) == document
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        probe._write_new(output, {"status": "FAIL"})


def test_cli_failure_does_not_create_a_success_artifact(monkeypatch, tmp_path, capsys):
    output = tmp_path / "must-not-exist.json"
    monkeypatch.setattr(
        probe,
        "run_probe",
        lambda _challenge: (_ for _ in ()).throw(probe.ProbeError("no SNP")),
    )

    assert probe.main(["--challenge", "01" * 32, "--output", str(output)]) == 1

    failure = json.loads(capsys.readouterr().err)
    assert failure == {
        "schema": probe.TRANSCRIPT_SCHEMA,
        "status": "FAIL",
        "error_type": "ProbeError",
        "error": "no SNP",
    }
    assert not output.exists()


def test_cli_success_prints_only_a_minimal_transcript_pointer(monkeypatch, tmp_path, capsys):
    output = tmp_path / "transcript.json"
    result = {
        "schema": probe.TRANSCRIPT_SCHEMA,
        "status": "LOCAL_PASS",
        "source_commit": "a" * 40,
        "report": {"review_scoped_platform_pseudonym": "must-stay-in-file"},
    }
    monkeypatch.setattr(probe, "run_probe", lambda _challenge: result)

    assert probe.main(["--challenge", "01" * 32, "--output", str(output)]) == 0

    printed = json.loads(capsys.readouterr().out)
    assert printed == {
        "schema": probe.TRANSCRIPT_SCHEMA,
        "status": "LOCAL_PASS",
        "source_commit": "a" * 40,
        "output": str(output),
    }
    assert json.loads(output.read_text(encoding="utf-8")) == result
