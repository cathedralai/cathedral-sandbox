"""The serve path's key store, quota and stale-base sweep (review round 6, reader L)."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from cathedral.sandbox_api import QuotaLimits, SandboxContractError
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError, parse_sandbox_keys, provider_from_environment
from cathedral.sandbox_runtime import build_sandbox_provider
from tests.fake_docker_cli import install

KEY = "k" * 40


@pytest.fixture
def fake(tmp_path, monkeypatch):
    f = install(tmp_path, monkeypatch)
    f.add_image("alpine:3.20")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_AUTH_PULLED_FILE", str(tmp_path / "auth-pulled.json"))
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RUNTIME", "docker")
    return f


@pytest.mark.parametrize("raw", ["", "   "])
def test_the_docker_runtime_refuses_to_start_with_no_keys(fake, monkeypatch, raw) -> None:
    # A blank store built a permissive provider: any bearer was its own tenant.
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", raw)
    monkeypatch.delenv("CATHEDRAL_ALLOW_OPEN_KEYS", raising=False)
    with pytest.raises(SandboxOpError) as err:
        build_sandbox_provider(runtime="docker")
    assert err.value.http_status == 503 and "CATHEDRAL_SANDBOX_KEYS" in str(err.value)


def test_a_configured_store_refuses_unknown_bearers(fake, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", f"{KEY}:acme:48")
    provider = build_sandbox_provider(runtime="docker")
    try:
        provider.authorize(KEY)
        with pytest.raises(SandboxOpError) as err:
            provider.authorize("anything-goes")
        assert err.value.http_status == 401
    finally:
        provider.close()


@pytest.mark.parametrize("raw", [f"{KEY}::48", f"{KEY}:acme:48:extra", f"{KEY}:acme:lots", f"{KEY}", f" :acme:48"])
def test_a_malformed_key_entry_is_refused_not_skipped(raw) -> None:
    # Skipping an empty project left zero keys (401 for everyone, the broker
    # too). A comma in the project splits into two entries before this parser
    # sees them, so the installer refuses it in ROOM_CUSTOMER (tested there).
    with pytest.raises(SandboxContractError) as err:
        parse_sandbox_keys(raw)
    assert err.value.code == "invalid_key_store"


def test_well_formed_keys_parse() -> None:
    keys = parse_sandbox_keys(f"{KEY}:acme:48, other-key-of-32-chars-xxxxxxxxxx:beta")
    assert [(k.project, k.max_running) for k in keys] == [("acme", 48), ("beta", None)]


@pytest.mark.parametrize("raw", ["48:48:192:10", "48,48,192", "48:48", "-1:48:192", "48:x:192"])
def test_a_malformed_quota_is_refused_not_defaulted(monkeypatch, raw) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_QUOTA", raw)
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", f"{KEY}:acme:48")
    with pytest.raises(SandboxContractError) as err:
        provider_from_environment()
    assert err.value.code == "invalid_quota"


def test_a_well_formed_quota_is_applied(monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_QUOTA", "48:48:192")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", f"{KEY}:acme:48")
    provider = provider_from_environment()
    try:
        assert provider._limits == QuotaLimits(running_sandboxes=48, vcpu=48, memory_gib=192)  # noqa: SLF001
    finally:
        provider.close()


def test_stale_work_bases_are_removed_at_start_when_the_kit_asks(fake, monkeypatch, tmp_path) -> None:
    # An instance killed mid-stop left its rooms' work directories on the data
    # volume for good; the next instance now removes bases older than a minute.
    import tempfile

    work = tmp_path / "work"
    work.mkdir()
    # The kit sets TMPDIR in the unit; a fresh process honours it. In this
    # process tempfile already cached a tempdir, so point it there directly.
    monkeypatch.setenv("TMPDIR", str(work))
    monkeypatch.setattr(tempfile, "tempdir", str(work))
    stale = work / "cathedral-sandbox-stale"
    (stale / "sbx_old" / "work").mkdir(parents=True)
    old = time.time() - 120
    os.utime(stale, (old, old))
    fresh = work / "cathedral-sandbox-fresh"
    fresh.mkdir()
    monkeypatch.setenv("CATHEDRAL_SANDBOX_SWEEP_STALE_BASES", "1")
    provider = DockerGuestProvider()
    try:
        assert not stale.exists()
        assert fresh.exists()  # younger than a minute: maybe another instance starting
        assert Path(provider._inner._base).exists()  # noqa: SLF001
    finally:
        provider.close()


@pytest.mark.parametrize("bad", [[], {}, 7, True, ["snap_1"]])
def test_a_wrong_shaped_snapshot_id_is_a_400_not_a_500(bad) -> None:
    # Review round 6 property pass (B148): every other wrong-shaped field was
    # already a 400; this one raised AttributeError out of the request.
    from cathedral.sandbox_api import CreateSandboxRequest, SandboxContractError

    with pytest.raises(SandboxContractError) as err:
        CreateSandboxRequest(snapshot_id=bad)
    assert err.value.code == "invalid_snapshot_id"
