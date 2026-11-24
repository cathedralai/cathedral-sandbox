"""URnetwork TUN gate: hotel config decides tenancy, never a request label; no room gets /dev/sev-guest."""
from __future__ import annotations

from pathlib import Path

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError


def _req(**over) -> CreateSandboxRequest:
    values = {"image": ImageSource(image="alpine:3.20"), "resources": Resources(vcpu=1, memory_gib=1, disk_gib=5)}
    values.update(over)
    return CreateSandboxRequest(**values)


def _args(request):
    provider = DockerGuestProvider.__new__(DockerGuestProvider)  # _run_args_for reads only env and the request
    return provider._run_args_for(request)


@pytest.fixture()
def tun_device(monkeypatch):
    real = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: True if str(self) == "/dev/net/tun" else real(self))


@pytest.mark.parametrize("env", [{}, {"ROOM_ALLOW_TUN": "1"}, {"CATHEDRAL_HOTEL_TENANCY": "dedicated"}])
def test_tun_is_refused_unless_the_hotel_is_dedicated_and_allows_it(monkeypatch, tun_device, env):
    for key in ("ROOM_ALLOW_TUN", "CATHEDRAL_HOTEL_TENANCY", "ROOM_EXPOSE_SEV_GUEST"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(SandboxOpError) as refused:
        _args(_req(network_capability="tun"))
    assert refused.value.code == "tun_requires_dedicated"


def test_a_request_label_cannot_make_a_shared_hotel_dedicated(monkeypatch, tun_device):
    monkeypatch.delenv("CATHEDRAL_HOTEL_TENANCY", raising=False)
    monkeypatch.setenv("ROOM_ALLOW_TUN", "1")
    monkeypatch.setenv("ROOM_EXPOSE_SEV_GUEST", "1")
    request = _req(network_capability="tun", labels={"cathedral.tenancy": "dedicated",
                                                     "cathedral.attestation_device": "sev_guest"})
    with pytest.raises(SandboxOpError):
        _args(request)
    assert _args(_req(labels={"cathedral.tenancy": "dedicated", "cathedral.attestation_device": "sev_guest"})) == ()


def test_a_dedicated_hotel_that_allows_tun_gets_it_and_never_sev_guest(monkeypatch, tun_device):
    monkeypatch.setenv("CATHEDRAL_HOTEL_TENANCY", "dedicated")
    monkeypatch.setenv("ROOM_ALLOW_TUN", "1")
    monkeypatch.setenv("ROOM_EXPOSE_SEV_GUEST", "1")
    args = _args(_req(network_capability="tun", labels={"cathedral.attestation_device": "sev_guest"}))
    assert "--cap-add=NET_ADMIN" in args and "--device=/dev/net/tun:/dev/net/tun" in args
    assert not any("sev-guest" in a for a in args)
