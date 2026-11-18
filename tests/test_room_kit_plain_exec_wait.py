"""AB#696: the front waits for a plain exec as long as the command may run.

A plain background exec (Harbor, ctcli) goes through the guest front to the room
API. The front used to wait 1800 s for every plain request, so a command that
ran longer was answered 502 hotel_api_no_answer at 1800 s while it still ran.
"""
from __future__ import annotations

import http.client
import json

import pytest

import test_room_kit_sealed_exec as base
from test_room_kit_sealed_exec import guest  # noqa: F401  (fixture)

rr = base.rr
EXEC_PATH = f"/v1/sandboxes/{base.ROOM}/exec"


@pytest.fixture
def waits(monkeypatch):
    """The read timeout the front sets on each connection it opens to the room API."""
    seen: list[float] = []
    real = http.client.HTTPConnection

    def recording(host, port=None, timeout=None, **kw):
        if port != base_port[0]:
            return real(host, port, timeout=timeout, **kw)
        seen.append(timeout)
        return real(host, port, timeout=timeout, **kw)

    base_port = [None]
    monkeypatch.setattr(rr.http.client, "HTTPConnection", recording)
    return seen, base_port


def _exec(guest_parts, waits, body: dict):
    ledger, api, port, _client = guest_parts
    seen, api_port = waits
    api_port[0] = api.port
    status, _h, _out = base._request(port, "POST", EXEC_PATH, json.dumps(body).encode())
    assert status == 200
    return seen[-1]


@pytest.mark.parametrize("timeout_seconds", [45, 1801, 7200, 14400])
def test_the_front_waits_for_the_commands_timeout_plus_a_margin(guest, waits, timeout_seconds) -> None:
    wait = _exec(guest, waits, {"cmd": ["true"], "timeout_seconds": timeout_seconds})
    assert wait >= timeout_seconds + rr.EXEC_ANSWER_MARGIN_SECONDS


def test_a_plain_exec_without_a_usable_timeout_still_waits_the_room_api_maximum(guest, waits) -> None:
    wait = _exec(guest, waits, {"cmd": ["true"]})
    assert wait >= 14400
