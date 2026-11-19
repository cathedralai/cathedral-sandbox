"""Anchor hotel re-offer (room-kit/hotel-offer-refresh, AB#822 R1).

The attestation fetch and the POST are stubbed; everything between them is
the real hotel_offer.py: attestation checks, hotkey file rule, signing.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest
import sr25519

KIT = Path(__file__).resolve().parents[1] / "room-kit"
spec = importlib.util.spec_from_file_location("hotel_offer_refresh", KIT / "hotel-offer-refresh" / "hotel_offer_refresh.py")
refresh_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh_mod)

ALICE_SEED = "e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"
ALICE_SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
SPKI = "cd" * 32
CHIP = "01" * 64
T0 = 1_795_000_000


def attestation(ho, boot: str) -> dict:
    """A sealed miner hotel attestation hotel_offer.check_attestation accepts; boot changes the binding."""
    binding = {"schema": "cathedral_sealed_hotel_binding_v1", "hotel": "miner-anchor", "boot_id": boot,
               "level": "sealed", "measurement": "aa" * 48, "chip_id": CHIP, "tls_spki_sha256": SPKI}
    digest = hashlib.sha256(ho.room_kit_canonical(binding)).hexdigest()
    raw = bytearray(ho.SNP_REPORT_BYTES)
    raw[ho.CPUID_FAMILY_OFFSET], raw[ho.CPUID_MODEL_OFFSET] = 0x19, 0x11
    raw[ho.REPORT_DATA_OFFSET:ho.REPORT_DATA_OFFSET + 64] = bytes.fromhex(digest) + bytes(32)
    raw[ho.CHIP_ID_OFFSET:ho.CHIP_ID_OFFSET + 64] = bytes.fromhex(CHIP)
    return {"binding": binding, "binding_sha256": digest, "report_b64": base64.b64encode(bytes(raw)).decode()}


class Host:
    """One hotel host: a guest whose boot can change, an API that can refuse, a clock."""

    def __init__(self, tmp: Path, monkeypatch) -> None:
        self.ho = refresh_mod.load_hotel_offer()
        self.hotkey = tmp / "etc" / "hotkey"
        self.hotkey.parent.mkdir()
        self.hotkey.write_text("0x" + ALICE_SEED + "\n")
        self.hotkey.chmod(0o600)
        self.state = tmp / "var" / "offer-state.json"
        self.cfg = refresh_mod.Config({
            "HOTEL_OFFER_ORIGIN": "https://8.8.8.8:9443", "HOTEL_OFFER_ATTESTATION_URL": "https://10.215.0.2:18443",
            "HOTEL_OFFER_POST_URL": "https://api.example/v1/cathedral/snp/hotel-offers",
            "HOTEL_OFFER_HOTKEY_FILE": str(self.hotkey), "HOTEL_OFFER_STATE_FILE": str(self.state),
            "HOTEL_OFFER_POST_ATTEMPTS": "3", "HOTEL_OFFER_BACKOFF_SECONDS": "10"})
        self.boot = "boot-1"
        self.fetches = 0
        self.posts: list[dict] = []
        self.refusals: list[str] = []  # popped per POST; empty: accepted
        self.sleeps: list[float] = []
        self.now = T0
        monkeypatch.setattr(self.ho, "fetch_attestation", self._fetch)
        monkeypatch.setattr(self.ho, "post", self._post)

    def _fetch(self, url):
        assert url == "https://10.215.0.2:18443"
        self.fetches += 1
        return attestation(self.ho, self.boot), SPKI

    def _post(self, url, offer):
        self.posts.append(offer)
        if self.refusals:
            raise self.ho.OfferError(f"the API refused the offer: HTTP 422 {self.refusals.pop(0)}")
        return 'HTTP 200 {"state":"pending"}'

    def binding(self) -> str:
        return attestation(self.ho, self.boot)["binding_sha256"]

    def run(self) -> int:
        def sleep(seconds):
            self.sleeps.append(seconds)
            self.now += int(seconds)
        return refresh_mod.refresh(self.cfg, self.ho, clock=lambda: self.now, sleep=sleep)


@pytest.fixture
def host(tmp_path, monkeypatch):
    return Host(tmp_path, monkeypatch)


def events(out: str) -> list[str]:
    return [line.split()[0] for line in out.splitlines() if line.strip()]


def verify(offer: dict) -> bool:
    message = b"cathedral-hotel-offer-v1\x00" + offer["offer_id"].encode()
    public = sr25519.pair_from_seed(bytes.fromhex(ALICE_SEED))[0]
    return sr25519.verify(base64.b64decode(offer["signature"]["value_base64"]), message, public)


def test_no_change_posts_nothing(host, capsys):
    host.state.parent.mkdir()
    host.state.write_text(json.dumps({"binding_sha256": host.binding(), "sequence": T0 - 600}))
    assert host.run() == 0
    assert host.fetches == 1 and host.posts == []
    assert capsys.readouterr().out == ""


def test_a_change_posts_once_then_nothing(host, capsys):
    host.state.parent.mkdir()
    host.state.write_text(json.dumps({"binding_sha256": "ee" * 32, "sequence": T0 - 600}))
    assert host.run() == 0
    assert len(host.posts) == 1
    offer = host.posts[0]
    assert offer["binding_sha256"] == host.binding() and offer["sequence"] == T0 and offer["withdraw"] is False
    assert offer["hotkey"] == ALICE_SS58 and offer["api"] == "https://8.8.8.8:9443" and verify(offer)
    out = capsys.readouterr().out
    assert events(out) == ["binding_changed", "offer_posted"]
    assert f"old={'ee' * 32} new={host.binding()}" in out
    assert json.loads(host.state.read_text())["binding_sha256"] == host.binding()

    host.now += 300
    assert host.run() == 0
    assert len(host.posts) == 1 and capsys.readouterr().out == ""

    host.boot, host.now = "boot-2", host.now + 300  # a reboot: a new binding
    assert host.run() == 0
    assert len(host.posts) == 2 and host.posts[1]["binding_sha256"] == host.binding()
    assert host.posts[1]["sequence"] == T0 + 600
    assert events(capsys.readouterr().out) == ["binding_changed", "offer_posted"]


def test_a_refused_post_is_retried_with_backoff_and_a_newer_sequence(host, capsys):
    host.refusals = ["hotel_offer_attestation_unreachable", "hotel_offer_attestation_unreachable"]
    assert host.run() == 0
    assert len(host.posts) == 3 and host.sleeps == [10, 20]
    sequences = [o["sequence"] for o in host.posts]
    assert sequences == sorted(set(sequences)) and sequences[0] == T0
    assert all(verify(o) for o in host.posts)
    assert events(capsys.readouterr().out) == ["binding_changed", "offer_refused", "offer_refused", "offer_posted"]
    assert json.loads(host.state.read_text())["sequence"] == sequences[-1]


def test_every_post_refused_exits_3_and_the_next_run_tries_again(host, capsys):
    host.refusals = ["not_on_roster"] * 3
    assert host.run() == refresh_mod.EXIT_POST
    assert len(host.posts) == 3 and host.sleeps == [10, 20] and not host.state.exists()
    out = capsys.readouterr().out
    assert events(out)[-1] == "offer_failed" and "not_on_roster" in out
    host.now += 300
    assert host.run() == 0
    assert len(host.posts) == 4 and host.posts[-1]["sequence"] > host.posts[2]["sequence"]


def test_a_lost_state_file_still_posts_a_newer_sequence(host, capsys):
    assert host.run() == 0
    first = host.posts[-1]["sequence"]
    host.state.unlink()
    host.now += 1
    assert host.run() == 0
    assert len(host.posts) == 2 and host.posts[1]["sequence"] > first
    assert host.posts[1]["binding_sha256"] == host.posts[0]["binding_sha256"]
    out = capsys.readouterr().out
    assert "binding_changed old=none" in out


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_a_hotkey_file_readable_by_others_is_refused_before_any_fetch(host, capsys, mode):
    host.hotkey.chmod(mode)
    assert host.run() == refresh_mod.EXIT_CONFIG
    assert host.fetches == 0 and host.posts == []
    out = capsys.readouterr().out
    assert events(out) == ["hotkey_file_refused"] and "chmod 600" in out


def test_a_guest_that_does_not_answer_posts_nothing(host, capsys, monkeypatch):
    def down(url):
        raise host.ho.OfferError(f"cannot reach {url}: ConnectionRefusedError")
    monkeypatch.setattr(host.ho, "fetch_attestation", down)
    assert host.run() == refresh_mod.EXIT_ATTESTATION
    assert host.posts == [] and events(capsys.readouterr().out) == ["attestation_unavailable"]


def test_no_journal_line_carries_key_material(host, capsys):
    host.refusals = ["x"]
    host.run()
    host.hotkey.chmod(0o644)
    host.run()
    out = capsys.readouterr()
    for text in (out.out, out.err, host.state.read_text()):
        assert ALICE_SEED not in text.lower()


def test_main_reads_its_config_from_the_environment(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", {"HOTEL_OFFER_ORIGIN": "https://8.8.8.8:9443"})
    assert refresh_mod.main() == refresh_mod.EXIT_CONFIG
    assert "config_refused" in capsys.readouterr().out


def test_the_timer_runs_every_five_minutes_and_the_unit_reads_the_env_file():
    unit_dir = KIT / "hotel-offer-refresh"
    timer = (unit_dir / "hotel-offer-refresh.timer").read_text()
    assert "OnUnitActiveSec=5min" in timer and "WantedBy=timers.target" in timer
    service = (unit_dir / "hotel-offer-refresh.service").read_text()
    assert "Type=oneshot" in service and "EnvironmentFile=/etc/cathedral-anchor/refresh.env" in service
    example = (unit_dir / "hotel-offer-refresh.env.example").read_text()
    assert "HOTEL_OFFER_HOTKEY_FILE=/etc/cathedral-anchor/hotkey" in example
    keys = {line.split("=", 1)[0].lstrip("#") for line in example.splitlines() if "=" in line and not line.startswith("# ")}
    assert keys <= set(refresh_mod.Config.REQUIRED) | {"HOTEL_OFFER_NETWORK", "HOTEL_OFFER_NETUID",
                                                        "HOTEL_OFFER_POST_ATTEMPTS", "HOTEL_OFFER_BACKOFF_SECONDS"}
