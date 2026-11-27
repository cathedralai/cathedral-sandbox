"""Dedicated hotel gates: hotel env decides tenancy; shared pool never gets TUN; no room gets /dev/sev-guest."""
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
    for key in ("ROOM_ALLOW_TUN", "CATHEDRAL_HOTEL_TENANCY"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(SandboxOpError) as refused:
        _args(_req(network_capability="tun"))
    assert refused.value.code == "tun_requires_dedicated"


def test_a_request_label_cannot_make_a_shared_hotel_dedicated(monkeypatch, tun_and_sev):
    monkeypatch.delenv("CATHEDRAL_HOTEL_TENANCY", raising=False)
    monkeypatch.setenv("ROOM_ALLOW_TUN", "1")
    request = _req(
        network_capability="tun",
        labels={"cathedral.tenancy": "dedicated", "cathedral.attestation_device": "sev_guest"},
    )
    with pytest.raises(SandboxOpError):
        _args(request)
    # Labels alone never expose TUN or sev-guest on a shared hotel.
    assert _args(_req(labels={"cathedral.tenancy": "dedicated", "cathedral.attestation_device": "sev_guest"})) == ()


def test_dedicated_hotel_gets_tun_and_no_sev_guest(monkeypatch, tun_and_sev):
    monkeypatch.setenv("CATHEDRAL_HOTEL_TENANCY", "dedicated")
    monkeypatch.setenv("ROOM_ALLOW_TUN", "1")
    args = _args(_req(network_capability="tun", image=ImageSource(image="ghcr.io/you/app@sha256:" + "ab" * 32)))
    assert args == ("--cap-add=NET_ADMIN", "--device=/dev/net/tun:/dev/net/tun")


@pytest.mark.parametrize("expose", [None, "1"])
def test_dedicated_room_never_gets_sev_guest_even_with_the_old_switch(monkeypatch, tun_and_sev, expose):
    # The room report socket replaced the device; the old ROOM_EXPOSE_SEV_GUEST switch does nothing.
    monkeypatch.setenv("CATHEDRAL_HOTEL_TENANCY", "dedicated")
    if expose is None:
        monkeypatch.delenv("ROOM_EXPOSE_SEV_GUEST", raising=False)
    else:
        monkeypatch.setenv("ROOM_EXPOSE_SEV_GUEST", expose)
    assert not any("sev-guest" in a for a in _args(_req()))


def test_shared_hotel_never_gets_sev_guest_even_if_device_exists(monkeypatch, tun_and_sev):
    monkeypatch.delenv("CATHEDRAL_HOTEL_TENANCY", raising=False)
    assert _args(_req()) == ()
