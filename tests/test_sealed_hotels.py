"""cathedral_sealed_hotels_v1 (AB#382 WP1): schema, pins, golden vector, both verifiers, publisher.

Every key here is a throwaway: the golden vector seed is a public label, the
publisher tests generate keys in-test.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.sealed_hotels import (
    SealedHotelsError,
    canonical_json,
    canonical_signed_bytes,
    check_successor,
    parse_pins,
    verify_envelope,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "sealed_hotels"
VERIFY_AT = datetime(2026, 11, 17, 18, 0, 0, tzinfo=UTC)
PUBLISHER = ROOT / "scripts" / "cathedral_sealed_hotels_publish.py"
STANDALONE = ROOT / "room-kit" / "verify_sealed_hotels.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


golden = _load(FIXTURES / "make_golden.py", "sealed_hotels_make_golden")
standalone = _load(STANDALONE, "verify_sealed_hotels_standalone")

GOLDEN = (FIXTURES / "golden-v1.json").read_bytes()
GOLDEN_PINS_BYTES = (FIXTURES / "golden-pins.json").read_bytes()
PINS = parse_pins(GOLDEN_PINS_BYTES)
STANDALONE_PINS = standalone.load_pins(json.loads(GOLDEN_PINS_BYTES))
SEED_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(golden.SEED_LABEL).digest())


def _sign(document: dict, key: Ed25519PrivateKey = SEED_KEY) -> bytes:
    document = {k: v for k, v in document.items() if k != "signature"}
    signature = key.sign(canonical_signed_bytes(document))
    document["signature"] = {"algorithm": "ed25519", "value_base64": base64.b64encode(signature).decode()}
    return canonical_json(document)


def _golden_doc() -> dict:
    return json.loads(GOLDEN)


def _both_refuse(data: bytes, *, now: datetime = VERIFY_AT, at: datetime | None = None, match: str = "") -> None:
    with pytest.raises(SealedHotelsError, match=match):
        verify_envelope(data, PINS, now=now, historical_at=at)
    with pytest.raises(standalone.Refused, match=match):
        standalone.verify(data, STANDALONE_PINS, now, at)


# ------------------------------------------------------------- golden vector


def test_golden_vector_is_reproducible_byte_for_byte() -> None:
    for name, payload in golden.build().items():
        assert (FIXTURES / name).read_bytes() == payload, name


def test_golden_vector_fields() -> None:
    vector = json.loads((FIXTURES / "golden-v1.vector.json").read_bytes())
    document = _golden_doc()
    assert canonical_signed_bytes(document).decode() == vector["signed_bytes"]
    assert hashlib.sha256(vector["signed_bytes"].encode()).hexdigest() == vector["signed_bytes_sha256"]
    assert document["signature"]["value_base64"] == vector["signature_base64"]
    assert hashlib.sha256(GOLDEN).hexdigest() == vector["envelope_sha256"]
    assert sorted(document) == sorted(
        ["schema", "release", "generated_at", "valid_from", "valid_until", "key_id", "hotels", "signature"]
    )


def test_golden_vector_verifies_in_both_verifiers() -> None:
    release = verify_envelope(GOLDEN, PINS, now=VERIFY_AT)
    result = standalone.verify(GOLDEN, STANDALONE_PINS, VERIFY_AT)
    assert release.release == result["release"] == 7
    assert release.digest == result["digest"] == "sha256:" + hashlib.sha256(GOLDEN).hexdigest()
    assert release.key_fingerprint == result["key_fingerprint_sha256"]
    chip_a = "a1" * 64
    # Two hotels share one chip, each approved only for its own measurements.
    assert release.approves("golden-hotel-a", chip_a, "11" * 48)
    assert release.approves("golden-hotel-a-2", chip_a, "33" * 48)
    assert not release.approves("golden-hotel-a-2", chip_a, "11" * 48)
    assert not release.approves("golden-hotel-a", "b2" * 64, "11" * 48)
    assert not release.approves("golden-hotel-a", chip_a[:32], "11" * 48)
    assert not release.approves("unknown-hotel", chip_a, "11" * 48)


# --------------------------------------------- refusals the contract lists


def _mutated(mutate) -> bytes:
    document = _golden_doc()
    mutate(document)
    return _sign(document)


@pytest.mark.parametrize(
    "field, value",
    [
        ("release", 8),
        ("generated_at", "2026-11-17T12:00:01Z"),
        ("valid_until", "2026-11-18T11:00:00Z"),
        ("key_id", "sealed-hotels-golden-test"),
    ],
)
def test_changed_signed_field_without_resigning_refuses(field: str, value) -> None:
    document = _golden_doc()
    if document[field] == value:
        value = "other-key"
    document[field] = value
    _both_refuse(canonical_json(document), match="signature verification failed|not pinned")


def test_changed_hotel_or_measurement_without_resigning_refuses() -> None:
    for mutate in (
        lambda d: d["hotels"]["golden-hotel-a"]["measurements"].__setitem__(0, "66" * 48),
        lambda d: d["hotels"]["golden-hotel-a"].__setitem__("chip_id", "c3" * 64),
        lambda d: d["hotels"].__setitem__("golden-hotel-c", d["hotels"].pop("golden-hotel-b")),
    ):
        document = _golden_doc()
        mutate(document)
        _both_refuse(canonical_json(document), match="signature verification failed")


def test_bad_signature_value_refuses() -> None:
    document = _golden_doc()
    document["signature"]["value_base64"] = base64.b64encode(bytes(64)).decode()
    _both_refuse(canonical_json(document), match="signature verification failed")
    document["signature"]["value_base64"] = "not base64!"
    _both_refuse(canonical_json(document), match="base64")
    document["signature"] = {"algorithm": "ed448", "value_base64": "AA=="}
    _both_refuse(canonical_json(document), match="algorithm")


def test_unknown_key_and_key_from_document_grant_no_trust() -> None:
    attacker = Ed25519PrivateKey.generate()
    document = _golden_doc()
    _both_refuse(_sign(document, attacker), match="signature verification failed")
    document["key_id"] = "attacker-key"
    _both_refuse(_sign(document, attacker), match="not pinned")


@pytest.mark.parametrize(
    "mutate, match",
    [
        (lambda d: d.__setitem__("extra", 1), "unknown"),
        (lambda d: d.pop("valid_from"), "missing"),
        (lambda d: d.__setitem__("schema", "cathedral_sealed_hotels_v2"), "schema"),
        (lambda d: d.__setitem__("release", 0), "positive"),
        (lambda d: d.__setitem__("release", -3), "positive"),
        (lambda d: d.__setitem__("release", True), "positive"),
        (lambda d: d.__setitem__("release", "7"), "positive"),
        (lambda d: d.__setitem__("generated_at", "2026-11-17 12:00:00"), "canonical UTC"),
        (lambda d: d.__setitem__("hotels", {}), "non-empty"),
        (lambda d: d.__setitem__("hotels", []), "non-empty"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("note", "x"), "unknown fields"),
        (lambda d: d["hotels"]["golden-hotel-a"].pop("chip_id"), "unknown fields"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("chip_id", "a1" * 32), "128 lowercase hex"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("chip_id", "A1" * 64), "128 lowercase hex"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("chip_id", "0" * 128), "all zero"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("measurements", []), "non-empty"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("measurements", ["11" * 48, "11" * 48]), "twice"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("measurements", ["11" * 47]), "96 lowercase"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("measurements", ["XY" * 48]), "96 lowercase"),
        (lambda d: d["hotels"]["golden-hotel-a"].__setitem__("measurements", "11" * 48), "non-empty list"),
        (lambda d: d["hotels"].__setitem__("Bad Hotel", d["hotels"]["golden-hotel-b"]), "malformed"),
        (lambda d: d.__setitem__("valid_until", d["valid_from"]), "empty or inverted"),
        (lambda d: d.__setitem__("generated_at", "2026-11-18T12:00:00Z"), "precede valid_until|future"),
    ],
)
def test_schema_refusals_even_when_signed(mutate, match: str) -> None:
    _both_refuse(_mutated(mutate), match=match)


def test_duplicate_hotel_id_and_duplicate_keys_refuse() -> None:
    text = GOLDEN.decode()
    entry = '"golden-hotel-b":'
    duplicated = text.replace(entry, entry + json.dumps(_golden_doc()["hotels"]["golden-hotel-b"]).replace(" ", "") + "," + entry, 1)
    _both_refuse(duplicated.encode(), match="duplicate JSON key")
    _both_refuse(GOLDEN.replace(b'"release":7', b'"release":7,"release":7', 1), match="duplicate JSON key")


def test_non_canonical_bytes_refuse() -> None:
    pretty = json.dumps(_golden_doc(), indent=2, sort_keys=True).encode()
    _both_refuse(pretty, match="not canonical")
    _both_refuse(GOLDEN + b"\n", match="not canonical")
    _both_refuse(GOLDEN.replace(b'"release":7', b'"release":7.0'), match="floating-point")
    _both_refuse(b"[]", match="JSON object")
    _both_refuse(b"\xff", match="UTF-8")


def test_time_refusals() -> None:
    _both_refuse(GOLDEN, now=datetime(2026, 11, 18, 12, 0, 1, tzinfo=UTC), match="expired|24 hour")
    # Within valid_until but over 24 hours after generated_at.
    long_lived = _mutated(lambda d: d.__setitem__("valid_until", "2026-11-25T12:00:00Z"))
    _both_refuse(long_lived, now=datetime(2026, 11, 18, 12, 0, 1, tzinfo=UTC), match="24 hour")
    verify_envelope(long_lived, PINS, now=datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC))
    _both_refuse(GOLDEN, now=datetime(2026, 11, 17, 11, 50, 0, tzinfo=UTC), match="future")
    not_yet = _mutated(lambda d: d.__setitem__("valid_from", "2026-11-17T20:00:00Z"))
    _both_refuse(not_yet, match="not yet valid")


def test_pin_window_is_enforced() -> None:
    def pins_with(not_before: str, not_after: str) -> bytes:
        document = json.loads(GOLDEN_PINS_BYTES)
        pin = document["keys"]["sealed-hotels-golden-test"]
        pin["not_before"], pin["not_after"] = not_before, not_after
        return json.dumps(document).encode()

    for window, match in (
        (("2026-11-17T13:00:00Z", "2027-01-01T00:00:00Z"), "does not contain generated_at"),
        (("2026-11-01T00:00:00Z", "2026-11-17T17:00:00Z"), "does not contain the verification time"),
    ):
        raw = pins_with(*window)
        with pytest.raises(SealedHotelsError, match=match):
            verify_envelope(GOLDEN, parse_pins(raw), now=VERIFY_AT)
        with pytest.raises(standalone.Refused, match=match):
            standalone.verify(GOLDEN, standalone.load_pins(json.loads(raw)), VERIFY_AT)


def test_historical_verification() -> None:
    later = datetime(2026, 12, 1, tzinfo=UTC)
    release = verify_envelope(GOLDEN, PINS, now=later, historical_at=VERIFY_AT)
    assert release.release == 7
    standalone.verify(GOLDEN, STANDALONE_PINS, later, VERIFY_AT)
    _both_refuse(GOLDEN, now=later, at=datetime(2026, 11, 17, 11, 0, tzinfo=UTC), match="not yet valid|generated")


# ------------------------------------------------------------------ pin file


@pytest.mark.parametrize(
    "mutate, match",
    [
        (lambda p: p["keys"]["k"].pop("not_after"), "missing or unknown"),
        (lambda p: p["keys"]["k"].__setitem__("not_after", None), "open not_after"),
        (lambda p: p["keys"]["k"].__setitem__("not_after", p["keys"]["k"]["not_before"]), "empty or inverted"),
        (lambda p: p["keys"]["k"].__setitem__("extra", 1), "missing or unknown"),
        (lambda p: p["keys"]["k"].__setitem__("algorithm", "ecdsa"), "algorithm"),
        (lambda p: p["keys"]["k"].__setitem__("public_key_hex", "AB" * 32), "64 lowercase hex"),
        (lambda p: p["keys"].__setitem__("k2", dict(p["keys"]["k"])), "two key ids"),
        (lambda p: p.__setitem__("schema", "other"), "schema"),
        (lambda p: p.__setitem__("keys", {}), "non-empty"),
    ],
)
def test_pin_file_refusals(mutate, match: str) -> None:
    document = {
        "schema": "cathedral_sealed_hotels_pins_v1",
        "keys": {
            "k": {
                "algorithm": "ed25519",
                "public_key_hex": json.loads(GOLDEN_PINS_BYTES)["keys"]["sealed-hotels-golden-test"]["public_key_hex"],
                "not_before": "2026-11-01T00:00:00Z",
                "not_after": "2027-11-01T00:00:00Z",
            }
        },
    }
    mutate(document)
    with pytest.raises(SealedHotelsError, match=match):
        parse_pins(json.dumps(document).encode())
    with pytest.raises(standalone.Refused):
        standalone.load_pins(document)


def test_repository_pin_matches_published_key_and_standalone_verifier() -> None:
    pins = parse_pins((ROOT / "docs" / "keys" / "sealed-hotels-pins.json").read_bytes())
    pin = pins["sealed-hotels-local-1"]
    pem = serialization.load_pem_public_key((ROOT / "docs" / "keys" / "sealed-hotels-local-1.pub.pem").read_bytes())
    raw = pem.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert raw == pin.public_key
    assert pin.fingerprint == "626c66e4c5ccacf20da7a95ef519f6372903ddcdadbe816d234e0932b7087f92"
    assert pin.not_before == datetime(2026, 11, 17, 15, 59, 33, tzinfo=UTC)
    assert pin.not_after == datetime(2027, 2, 15, tzinfo=UTC)
    assert json.loads((ROOT / "docs" / "keys" / "sealed-hotels-pins.json").read_bytes())["keys"] == standalone.PINNED_KEYS
    assert pin.fingerprint in (ROOT / "docs" / "keys" / "README.md").read_text()


# ------------------------------------------------------------------ rollback


def test_check_successor() -> None:
    release = verify_envelope(GOLDEN, PINS, now=VERIFY_AT)
    assert check_successor(None, release) is True
    assert check_successor((6, "sha256:" + "0" * 64), release) is True
    assert check_successor((7, release.digest), release) is False
    with pytest.raises(SealedHotelsError, match="equivocation"):
        check_successor((7, "sha256:" + "0" * 64), release)
    with pytest.raises(SealedHotelsError, match="rollback"):
        check_successor((8, "sha256:" + "0" * 64), release)
    with pytest.raises(standalone.Refused, match="rollback"):
        standalone.check_previous(standalone.verify(GOLDEN, STANDALONE_PINS, VERIFY_AT), 8, "sha256:" + "0" * 64)
    with pytest.raises(standalone.Refused, match="equivocation"):
        standalone.check_previous(standalone.verify(GOLDEN, STANDALONE_PINS, VERIFY_AT), 7, "sha256:" + "0" * 64)


# --------------------------------------------------------- standalone CLI


def test_standalone_cli(tmp_path: Path) -> None:
    pins = str(FIXTURES / "golden-pins.json")
    envelope = str(FIXTURES / "golden-v1.json")
    run = lambda *args: subprocess.run(  # noqa: E731
        [sys.executable, "-I", str(STANDALONE), *args], capture_output=True, text=True
    )
    ok = run(envelope, "--pins", pins, "--now", "2026-11-17T18:00:00Z")
    assert ok.returncode == 0 and ok.stdout.startswith("PASS release 7"), ok.stdout + ok.stderr
    builtin = run(envelope, "--now", "2026-11-17T18:00:00Z")
    assert builtin.returncode == 1 and "not pinned" in builtin.stdout
    wrong_digest = run(envelope, "--pins", pins, "--now", "2026-11-17T18:00:00Z", "--expect-digest", "0" * 64)
    assert wrong_digest.returncode == 1 and wrong_digest.stdout.startswith("FAIL digest")
    stale = run(envelope, "--pins", pins, "--now", "2026-11-19T00:00:00Z")
    assert stale.returncode == 1 and stale.stdout.startswith("FAIL")


# ---------------------------------------------------------------- publisher


def _write_private(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o600)
    return path


@pytest.fixture
def publisher_env(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    passphrase = b"throwaway"
    keydir = tmp_path / "keys"
    keydir.mkdir(mode=0o700)
    pem = _write_private(
        keydir / "k.pem",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        ),
    )
    pass_path = _write_private(keydir / "k.pass", passphrase)
    config = _write_private(
        keydir / "signers.json",
        json.dumps(
            {
                "sealed_hotels": {
                    "backend": "local_file",
                    "key_id": "sealed-hotels-test-1",
                    "path": str(pem),
                    "passphrase_path": str(pass_path),
                }
            }
        ).encode(),
    )
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    now = datetime.now(UTC)
    pins = tmp_path / "pins.json"
    pins.write_text(
        json.dumps(
            {
                "schema": "cathedral_sealed_hotels_pins_v1",
                "keys": {
                    "sealed-hotels-test-1": {
                        "algorithm": "ed25519",
                        "public_key_hex": public.hex(),
                        "not_before": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "not_after": (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                },
            }
        )
    )
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"hotels": golden.HOTELS}))
    out = tmp_path / "out"
    out.mkdir()
    state = tmp_path / "state" / "publisher-state.json"
    base = [
        sys.executable,
        str(PUBLISHER),
        "--signer-config", str(config),
        "--pins", str(pins),
        "--inventory", str(inventory),
        "--state", str(state),
        "--out-dir", str(out),
    ]  # fmt: skip
    return {"base": base, "state": state, "out": out, "pins": pins, "inventory": inventory}


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, cwd=ROOT)


def test_publisher_signs_and_keeps_durable_state(publisher_env) -> None:
    base, state, out = publisher_env["base"], publisher_env["state"], publisher_env["out"]
    first_refused = _run(base)
    assert first_refused.returncode != 0 and "--init-state" in first_refused.stderr
    first = _run([*base, "--init-state"])
    assert first.returncode == 0, first.stderr
    summary = json.loads(first.stdout)
    assert summary["release"] == 1
    envelope = (out / "release-1.json").read_bytes()
    digest_hex = hashlib.sha256(envelope).hexdigest()
    assert (out / f"{digest_hex}.json").read_bytes() == envelope
    assert summary["digest"] == "sha256:" + digest_hex
    release = verify_envelope(envelope, parse_pins(publisher_env["pins"].read_bytes()))
    assert release.hotels["golden-hotel-a"].measurements == ("11" * 48, "22" * 48)
    recorded = json.loads(state.read_text())
    assert recorded["last_release"] == 1 and recorded["last_digest"] == "sha256:" + digest_hex
    assert os.stat(state).st_mode & 0o777 == 0o600

    assert _run([*base, "--init-state"]).returncode != 0
    second = _run(base)
    assert second.returncode == 0, second.stderr
    assert json.loads(second.stdout)["release"] == 2
    lower = _run([*base, "--release", "2"])
    assert lower.returncode != 0 and "not above" in lower.stderr
    assert json.loads(state.read_text())["last_release"] == 2


def test_publisher_refuses_corrupt_state_and_state_in_repo(publisher_env) -> None:
    base, state = publisher_env["base"], publisher_env["state"]
    assert _run([*base, "--init-state"]).returncode == 0
    state.write_text("{}")
    state.chmod(0o600)
    corrupt = _run(base)
    assert corrupt.returncode != 0 and "never reset" in corrupt.stderr
    in_repo = [*base]
    in_repo[in_repo.index("--state") + 1] = str(ROOT / "publisher-state.json")
    refused = _run(in_repo)
    assert refused.returncode != 0 and "outside the repository" in refused.stderr
    assert not (ROOT / "publisher-state.json").exists()


def test_publisher_refuses_bad_inventory_and_oversized_release(publisher_env) -> None:
    base, inventory = publisher_env["base"], publisher_env["inventory"]
    bad = copy.deepcopy(golden.HOTELS)
    bad["golden-hotel-a"]["chip_id"] = "0" * 128
    inventory.write_text(json.dumps({"hotels": bad}))
    refused = _run([*base, "--init-state"])
    assert refused.returncode != 0 and "all zero" in refused.stderr
    assert not publisher_env["state"].exists()
    many = {
        f"hotel-{i:02d}": {"chip_id": f"{i + 1:02x}" * 64, "measurements": [f"{i + 1:02x}" * 48, "ab" * 48]}
        for i in range(12)
    }
    inventory.write_text(json.dumps({"hotels": many}))
    too_big = _run([*base, "--init-state"])
    assert too_big.returncode != 0 and "4096" in too_big.stderr
    assert not publisher_env["state"].exists()
