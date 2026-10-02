"""The localnet stub evidence stays off everywhere but the local chain."""

from __future__ import annotations

import pytest

from cathedral import validator_access
from cathedral.attest.localnet_stub import (
    LOCALNET_STUB_EVIDENCE_ENV,
    STUB_QUOTE_MAGIC,
    LocalnetStubRefused,
    collect_localnet_stub_tdx,
    localnet_stub_requested,
    require_localnet_stub_context,
    stub_platform,
)
from cathedral.cli import build_parser, cmd_worker_serve
from cathedral.common import ChannelBinding, ChannelBindingType, EvidenceKind, report_data_v2

BINDING = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, bytes(range(32)))
NONCE = bytes(range(32, 64))
HOTKEY = "5Fn7VLVTV5xrMNQY8WVGxwubq1Ptc5m5YXGQ2v2sMKsH6Dvh"


@pytest.fixture(autouse=True)
def _private_endpoints_off(monkeypatch):
    monkeypatch.setattr(validator_access, "_LOCALNET_PRIVATE_ENDPOINTS", False)


def _signed_serve_args(network: str) -> list[str]:
    return [
        "worker", "serve", "--hotkey", HOTKEY,
        "--validator-access-snapshot", "/nonexistent/validator-access.json",
        "--validator-access-keys", "/nonexistent/snapshot-keys.json",
        "--validator-access-keys-digest", "sha256:" + "0" * 64,
        "--validator-access-state", "/nonexistent/state.sqlite",
        "--validator-minimum-stake-rao", "0",
        "--validator-network", network,
        "--public-endpoint", "https://10.10.20.17:8091",
    ]


def test_stub_is_off_unless_exactly_one(monkeypatch):
    monkeypatch.delenv(LOCALNET_STUB_EVIDENCE_ENV, raising=False)
    assert localnet_stub_requested() is False
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "")
    assert localnet_stub_requested() is False
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "1")
    assert localnet_stub_requested() is True
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "true")
    with pytest.raises(LocalnetStubRefused):
        localnet_stub_requested()


@pytest.mark.parametrize("network", ["finney", "test", "archive", "localnet", ""])
def test_stub_context_refuses_every_network_but_local(network):
    with pytest.raises(LocalnetStubRefused):
        require_localnet_stub_context(posture="production", network=network, signed_access=True)


@pytest.mark.parametrize("posture", ["development", "migration", "snp-production"])
def test_stub_context_refuses_other_postures(posture):
    with pytest.raises(LocalnetStubRefused):
        require_localnet_stub_context(posture=posture, network="local", signed_access=True)


def test_stub_context_requires_signed_access():
    with pytest.raises(LocalnetStubRefused):
        require_localnet_stub_context(posture="production", network="local", signed_access=False)


def test_stub_quote_binds_the_real_v2_report_data(monkeypatch):
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "1")
    evidence = collect_localnet_stub_tdx(
        NONCE, HOTKEY, channel_binding=BINDING, report_data_version=2
    )
    assert evidence.kind is EvidenceKind.TDX
    assert evidence.quote == (
        STUB_QUOTE_MAGIC + report_data_v2(NONCE, HOTKEY, BINDING) + stub_platform(BINDING)
    )
    assert evidence.channel_binding == BINDING
    assert evidence.cert_chain == []


def test_stub_refuses_v1_and_an_unset_gate(monkeypatch):
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "1")
    with pytest.raises(ValueError):
        collect_localnet_stub_tdx(NONCE, HOTKEY)
    monkeypatch.delenv(LOCALNET_STUB_EVIDENCE_ENV)
    with pytest.raises(LocalnetStubRefused):
        collect_localnet_stub_tdx(NONCE, HOTKEY, channel_binding=BINDING, report_data_version=2)


def test_private_endpoints_stay_refused_without_the_localnet_gate(monkeypatch):
    with pytest.raises(validator_access.ValidatorAccessError):
        validator_access.validate_public_worker_endpoint("https://10.10.20.17:8091")
    monkeypatch.delenv(LOCALNET_STUB_EVIDENCE_ENV, raising=False)
    with pytest.raises(LocalnetStubRefused):
        validator_access.allow_localnet_private_endpoints(network="local")
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "1")
    with pytest.raises(LocalnetStubRefused):
        validator_access.allow_localnet_private_endpoints(network="finney")
    with pytest.raises(validator_access.ValidatorAccessError):
        validator_access.validate_public_worker_endpoint("https://10.10.20.17:8091")


def test_private_endpoints_open_only_for_localnet(monkeypatch):
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "1")
    validator_access.allow_localnet_private_endpoints(network="local")
    assert (
        validator_access.validate_public_worker_endpoint("https://10.10.20.17:8091")
        == "https://10.10.20.17:8091"
    )
    assert (
        validator_access.validate_public_worker_endpoint("https://100.103.39.86:8091")
        == "https://100.103.39.86:8091"
    )
    for refused in ("https://0.0.0.0:8091", "https://[fd00::1]:8091"):
        with pytest.raises(validator_access.ValidatorAccessError):
            validator_access.validate_public_worker_endpoint(refused)


@pytest.mark.parametrize("network", ["finney", "test"])
def test_worker_serve_refuses_stub_evidence_on_a_real_network(monkeypatch, network):
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "1")
    args = build_parser().parse_args(_signed_serve_args(network))
    with pytest.raises(LocalnetStubRefused):
        cmd_worker_serve(args)
    assert validator_access._LOCALNET_PRIVATE_ENDPOINTS is False


def test_worker_serve_refuses_stub_evidence_without_signed_access(monkeypatch):
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "1")
    args = build_parser().parse_args(
        ["worker", "serve", "--hotkey", HOTKEY, "--validator-network", "local"]
    )
    with pytest.raises(LocalnetStubRefused):
        cmd_worker_serve(args)


def test_worker_develop_refuses_stub_evidence(monkeypatch):
    monkeypatch.setenv(LOCALNET_STUB_EVIDENCE_ENV, "1")
    args = build_parser().parse_args(
        ["worker", "develop", "--hotkey", HOTKEY, "--development-no-auth",
         "--validator-network", "local"]
    )
    with pytest.raises(LocalnetStubRefused):
        cmd_worker_serve(args)
