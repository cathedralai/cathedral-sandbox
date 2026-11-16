"""Miner hotel offer signer (room-kit/hotel_offer.py, AB#347).

The golden values were produced by polariscomputer
polaris/services/cathedral_hotel_offers.py (offer_id, signature_message,
parse_offer): that module accepted the offer built here, with the same inputs.
sr25519 signatures are randomized, so the signature is checked by verifying
it, not by comparing bytes.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import struct
from pathlib import Path

import pytest
import sr25519

from cathedral.validator_access import bittensor_account_id, load_sr25519_verifier
import cathedral.verify.snp as snp

KIT = Path(__file__).resolve().parents[1] / "room-kit"
spec = importlib.util.spec_from_file_location("hotel_offer", KIT / "hotel_offer.py")
ho = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ho)

# //Alice's mini secret, the standard Substrate dev key.
ALICE_SEED = "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a"
ALICE_SS58 = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
CHIP = "01" * 64
SPKI = "cd" * 32
ORIGIN = "https://8.8.4.1:9443"
GOLDEN_MACHINE = "8ea2d4956f571ef1ee3aed269302d8e38e0ab431f499b8f44410a02829e0ef77"
GOLDEN_OFFER_ID = "sha256:d89a52829b32111ebda028b80b145cd852e5c32574dcd2ed215029507ba41885"


def attestation(*, binding_changes=None, family=0x19, model=0x11, report_data=None, chip=CHIP):
    binding = {"schema": "cathedral_sealed_hotel_binding_v1", "hotel": "miner-box-0", "boot_id": "boot-0",
               "level": "sealed", "measurement": "aa" * 48, "chip_id": chip, "tls_spki_sha256": SPKI,
               "kernel_cmdline": "console=ttyS0 cathedral.debug=0", **(binding_changes or {})}
    binding = {k: v for k, v in binding.items() if v is not None}
    digest = hashlib.sha256(ho.room_kit_canonical(binding)).hexdigest()
    raw = bytearray(snp.SNP_REPORT_SIZE)
    struct.pack_into("<I", raw, 0, 2)
    raw[0x188], raw[0x189] = family, model
    raw[snp.REPORT_DATA_OFFSET:snp.REPORT_DATA_OFFSET + 64] = report_data or bytes.fromhex(digest) + bytes(32)
    raw[snp.CHIP_ID_OFFSET:snp.CHIP_ID_OFFSET + 64] = bytes.fromhex(CHIP)
    raw[snp.SIGNATURE_OFFSET:snp.SIGNATURE_OFFSET + 8] = b"\x01" * 8
    return {"binding": binding, "binding_sha256": digest, "report_b64": base64.b64encode(bytes(raw)).decode()}


def build(**changes):
    args = dict(seed=bytes.fromhex(ALICE_SEED[2:]), network="finney", netuid=94, origin=ORIGIN,
                binding_sha256="ab" * 32, machine=ho.machine_id("genoa", CHIP), sequence=7,
                issued_at="2026-11-16T12:00:00Z", withdraw=False)
    args.update(changes)
    return ho.build_offer(**args)


def test_ss58_matches_the_known_address_and_the_decoder():
    public = sr25519.pair_from_seed(bytes.fromhex(ALICE_SEED[2:]))[0]
    assert ho.ss58_address(public) == ALICE_SS58
    assert bittensor_account_id(ALICE_SS58) == public


def test_machine_id_golden_vector():
    # sha256("cathedral.amd-sev-snp.hardware-v1\0" || "genoa" || "\0" || chip), as validator_machine_id.
    assert ho.machine_id("genoa", CHIP) == GOLDEN_MACHINE
    assert ho.machine_id("milan", CHIP) != GOLDEN_MACHINE
    with pytest.raises(ho.OfferError):
        ho.machine_id("genoa", "AB" * 64)


def test_offer_golden_vector_and_signature():
    offer = build()
    assert offer["offer_id"] == GOLDEN_OFFER_ID
    assert offer["hotkey"] == ALICE_SS58
    assert set(offer) == {"schema", "network", "netuid", "hotkey", "machine_id", "api", "health", "binding_sha256",
                          "sequence", "issued_at", "withdraw", "offer_id", "signature"}
    body = {k: v for k, v in offer.items() if k not in {"offer_id", "signature"}}
    assert offer["offer_id"] == "sha256:" + hashlib.sha256(ho.canonical(body)).hexdigest()
    sig = base64.b64decode(offer["signature"]["value_base64"], validate=True)
    assert offer["signature"]["algorithm"] == "sr25519" and len(sig) == 64
    message = b"cathedral-hotel-offer-v1\x00" + offer["offer_id"].encode()
    verify = load_sr25519_verifier()
    public = bittensor_account_id(offer["hotkey"])
    assert verify(sig, message, public) is True
    assert verify(sig, message + b"x", public) is False


def test_each_field_changes_the_offer_id():
    base = build()["offer_id"]
    for change in ({"sequence": 8}, {"withdraw": True}, {"origin": "https://8.8.4.2:9443"},
                   {"binding_sha256": "ac" * 32}, {"netuid": 95}, {"network": "test"}):
        assert build(**change)["offer_id"] != base


@pytest.mark.parametrize("origin", ["http://8.8.4.1:9443", "https://10.0.0.5:9443", "https://miner.example:9443",
                                    "https://8.8.4.1", "https://8.8.4.1:9443/x", "https://u:p@8.8.4.1:9443",
                                    " https://8.8.4.1:9443"])
def test_origin_refusals(origin):
    with pytest.raises(ho.OfferError):
        ho.check_origin(origin)


def test_origin_accepts_a_public_ip_literal():
    assert ho.check_origin(ORIGIN) == ORIGIN


def test_a_sealed_miner_attestation_gives_digest_and_machine():
    att = attestation()
    digest, machine, _ = ho.check_attestation(att, peer_spki=SPKI)
    assert digest == att["binding_sha256"]
    assert machine == ho.machine_id("genoa", CHIP)
    # An offline file has no TLS peer to compare; the other checks still run.
    assert ho.check_attestation(att, peer_spki=None)[0] == digest


@pytest.mark.parametrize("make,reason", [
    (lambda: {**attestation(), "binding_sha256": "00" * 32}, "not the digest"),
    (lambda: {k: v for k, v in attestation().items() if k != "report_b64"}, "not sealed"),
    (lambda: attestation(binding_changes={"level": "hotel"}), "not sealed"),
    (lambda: attestation(report_data=bytes(64)), "REPORT_DATA"),
    (lambda: attestation(binding_changes={"chip_id": "02" * 64}), "chip_id"),
    (lambda: attestation(binding_changes={"tls_spki_sha256": None}), "not a miner hotel"),
    (lambda: attestation(family=0x17, model=0x01), "generation"),
    (lambda: {"binding": "x"}, "no binding"),
])
def test_attestation_refusals(make, reason):
    with pytest.raises(ho.OfferError, match=reason):
        ho.check_attestation(make(), peer_spki=SPKI)


def test_tls_peer_that_is_not_the_attested_key_is_refused():
    with pytest.raises(ho.OfferError, match="not the key in the binding"):
        ho.check_attestation(attestation(), peer_spki="ee" * 32)


@pytest.mark.parametrize("family,model,name", [(0x19, 0x01, "milan"), (0x19, 0x11, "genoa"), (0x19, 0xA0, "genoa"),
                                               (0x1A, 0x02, "turin")])
def test_generation_table_matches_the_verifier(family, model, name):
    att = attestation(family=family, model=model)
    report = base64.b64decode(att["report_b64"])
    assert ho.generation(report) == name == snp.snp_generation(snp.parse_snp_report(report))


def write(tmp_path, text, mode=0o600):
    path = tmp_path / "hotkey"
    path.write_text(text)
    os.chmod(path, mode)
    return str(path)


def test_hotkey_file_forms(tmp_path):
    seed = bytes.fromhex(ALICE_SEED[2:])
    assert ho.load_seed(write(tmp_path, json.dumps({"accountId": "0x01", "secretSeed": ALICE_SEED}))) == seed
    assert ho.load_seed(write(tmp_path, ALICE_SEED + "\n")) == seed
    assert ho.load_seed(write(tmp_path, ALICE_SEED[2:])) == seed


def test_hotkey_file_refusals(tmp_path):
    with pytest.raises(ho.OfferError, match="chmod 600"):
        ho.load_seed(write(tmp_path, ALICE_SEED, mode=0o644))
    with pytest.raises(ho.OfferError, match="encrypted"):
        ho.load_seed(write(tmp_path, json.dumps({"data": "ciphertext"})))
    with pytest.raises(ho.OfferError, match="encrypted"):
        ho.load_seed(write(tmp_path, "$NACL\x00binary"))
    with pytest.raises(ho.OfferError, match="32 bytes"):
        ho.load_seed(write(tmp_path, "0x1234"))


def test_cli_prints_a_verifiable_offer(tmp_path, capsys):
    att = tmp_path / "att.json"
    att.write_text(json.dumps(attestation()))
    key = write(tmp_path, ALICE_SEED)
    assert ho.main(["--origin", ORIGIN, "--attestation", str(att), "--hotkey-file", key, "--sequence", "9"]) == 0
    offer = json.loads(capsys.readouterr().out)
    assert offer["sequence"] == 9 and offer["withdraw"] is False and offer["api"] == offer["health"] == ORIGIN
    assert offer["machine_id"] == ho.machine_id("genoa", CHIP)
    assert offer["binding_sha256"] == attestation()["binding_sha256"]
    assert load_sr25519_verifier()(base64.b64decode(offer["signature"]["value_base64"]),
                                   b"cathedral-hotel-offer-v1\x00" + offer["offer_id"].encode(),
                                   bittensor_account_id(offer["hotkey"])) is True
    assert ho.main(["--origin", ORIGIN, "--attestation", str(att), "--hotkey-file", key, "--withdraw"]) == 0
    assert json.loads(capsys.readouterr().out)["withdraw"] is True


def test_cli_signs_nothing_when_a_check_fails(tmp_path, capsys):
    att = tmp_path / "att.json"
    att.write_text(json.dumps(attestation(report_data=bytes(64))))
    key = write(tmp_path, ALICE_SEED)
    assert ho.main(["--origin", ORIGIN, "--attestation", str(att), "--hotkey-file", key]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "REPORT_DATA" in captured.err and ALICE_SEED[2:] not in captured.err
