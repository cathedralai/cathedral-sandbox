"""Dedicated hotel gates: hotel env decides tenancy; shared pool never gets TUN or /dev/sev-guest."""
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
def tun_and_sev(monkeypatch):
    real = Path.exists

    def exists(self):
        path = str(self)
        if path in ("/dev/net/tun", "/dev/sev-guest"):
            return True
        return real(self)

    monkeypatch.setattr(Path, "exists", exists)


@pytest.mark.parametrize("env", [{}, {"ROOM_ALLOW_TUN": "1"}, {"CATHEDRAL_HOTEL_TENANCY": "dedicated"}])
def test_tun_is_refused_unless_the_hotel_is_dedicated_and_allows_it(monkeypatch, tun_and_sev, env):
    for key in ("ROOM_ALLOW_TUN", "CATHEDRAL_HOTEL_TENANCY", "ROOM_EXPOSE_SEV_GUEST"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(SandboxOpError) as refused:
        _args(_req(network_capability="tun"))
    assert refused.value.code == "tun_requires_dedicated"


def test_a_request_label_cannot_make_a_shared_hotel_dedicated(monkeypatch, tun_and_sev):
    monkeypatch.delenv("CATHEDRAL_HOTEL_TENANCY", raising=False)
    monkeypatch.setenv("ROOM_ALLOW_TUN", "1")
    monkeypatch.delenv("ROOM_EXPOSE_SEV_GUEST", raising=False)
    request = _req(
        network_capability="tun",
        labels={"cathedral.tenancy": "dedicated", "cathedral.attestation_device": "sev_guest"},
    )
    with pytest.raises(SandboxOpError):
        _args(request)
    # Labels alone never expose TUN or sev-guest on a shared hotel.
    assert _args(_req(labels={"cathedral.tenancy": "dedicated", "cathedral.attestation_device": "sev_guest"})) == ()


def test_dedicated_hotel_gets_tun_and_sev_guest(monkeypatch, tun_and_sev):
    monkeypatch.setenv("CATHEDRAL_HOTEL_TENANCY", "dedicated")
    monkeypatch.setenv("ROOM_ALLOW_TUN", "1")
    monkeypatch.delenv("ROOM_EXPOSE_SEV_GUEST", raising=False)
    args = _args(_req(network_capability="tun", image=ImageSource(image="ghcr.io/you/app@sha256:" + "ab" * 32)))
    assert "--cap-add=NET_ADMIN" in args and "--device=/dev/net/tun:/dev/net/tun" in args
    # Bind mount (not --device): runsc sentry /dev stubs ENXIO for sev-guest.
    assert "--mount" in args
    assert "type=bind,source=/dev/sev-guest,target=/dev/sev-guest" in args


def test_dedicated_sev_guest_can_be_opted_out(monkeypatch, tun_and_sev):
    monkeypatch.setenv("CATHEDRAL_HOTEL_TENANCY", "dedicated")
    monkeypatch.setenv("ROOM_EXPOSE_SEV_GUEST", "0")
    args = _args(_req())
    assert not any("sev-guest" in a for a in args)


def test_shared_hotel_never_gets_sev_guest_even_if_device_exists(monkeypatch, tun_and_sev):
    monkeypatch.delenv("CATHEDRAL_HOTEL_TENANCY", raising=False)
    monkeypatch.delenv("ROOM_EXPOSE_SEV_GUEST", raising=False)
    assert _args(_req()) == ()
