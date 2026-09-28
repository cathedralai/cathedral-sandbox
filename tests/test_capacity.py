"""The capacity challenge, prober receipts and market pricing (docs/CAPACITY.md)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.capacity import challenge as ch
from cathedral.capacity import pricing, receipt

SEED = bytes(range(32))
NONCE_A = bytes([7]) * 32
SMALL = ch.ChallengeSpec(SEED, lanes=6, blocks=64, steps=128)
NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
VALIDATOR_NONCE = "ab" * 32
FINGERPRINT = "f0" * 32


# -- challenge -------------------------------------------------------------------


def test_lanes_are_deterministic_distinct_and_seed_bound():
    outputs = ch.run(SMALL, workers=1)
    assert outputs == ch.run(SMALL, workers=1)
    assert len(set(outputs)) == SMALL.lanes
    other = ch.run(ch.ChallengeSpec(bytes(32), 6, 64, 128), workers=1)
    assert not set(outputs) & set(other)


def test_parallel_and_sequential_runs_agree():
    assert ch.run(SMALL, workers=3) == ch.run(SMALL, workers=1)


def test_every_parameter_changes_the_answer():
    base = ch.lane_output(SMALL, 0)
    assert ch.lane_output(ch.ChallengeSpec(SEED, 6, 65, 128), 0) != base
    assert ch.lane_output(ch.ChallengeSpec(SEED, 6, 64, 129), 0) != base
    assert ch.lane_output(SMALL, 1) != base


def test_a_correct_answer_verifies_and_every_faked_lane_is_caught_when_sampled():
    outputs = ch.run(SMALL, workers=1)
    assert ch.verify(SMALL, outputs, nonce=NONCE_A, sample=SMALL.lanes)
    for lane in range(SMALL.lanes):
        faked = list(outputs)
        faked[lane] = bytes(32)
        assert not ch.verify(SMALL, faked, nonce=NONCE_A, sample=SMALL.lanes)


def test_a_box_cannot_steer_the_sample_onto_its_honest_lanes():
    # 4 honest lanes of 16, the rest garbage: with the nonce drawn after the
    # commitment, a pass needs all 4 sampled lanes to be honest, 1 in 1820.
    spec = ch.ChallengeSpec(SEED, lanes=16, blocks=8, steps=16)
    honest = ch.run(spec, workers=1)
    outputs = [honest[i] if i < 4 else bytes([i]) * 32 for i in range(16)]
    digest = ch.result_digest(spec, outputs)
    passes = 0
    samples = set()
    for i in range(300):
        nonce = os.urandom(32)
        samples.add(tuple(ch.sample_lanes(spec, digest, nonce, ch.MIN_SAMPLES)))
        passes += ch.verify(spec, outputs, nonce=nonce)
    assert passes <= 2
    assert len(samples) > 100  # the nonce, not the box, decides the sample


def test_the_sample_is_recomputable_from_the_receipt_fields():
    digest = ch.result_digest(SMALL, ch.run(SMALL, workers=1))
    lanes = ch.sample_lanes(SMALL, digest, NONCE_A, 3)
    assert lanes == ch.sample_lanes(SMALL, digest, NONCE_A, 3)
    assert len(lanes) == 3 and lanes == sorted(set(lanes))
    assert ch.sample_lanes(SMALL, digest, NONCE_A, 99) == list(range(SMALL.lanes))
    with pytest.raises(ch.ChallengeError):
        ch.sample_lanes(SMALL, digest, b"short", 3)


def test_malformed_answers_do_not_verify():
    outputs = ch.run(SMALL, workers=1)
    assert not ch.verify(SMALL, outputs[:-1], nonce=NONCE_A)
    assert not ch.verify(SMALL, [*outputs[:-1], b"short"], nonce=NONCE_A)
    assert not ch.verify(SMALL, outputs, nonce=b"short")
    with pytest.raises(ch.ChallengeError):
        ch.result_digest(SMALL, outputs + [bytes(32)])


def test_the_spec_proves_the_whole_claim_or_refuses_it():
    spec = ch.spec_for(SEED, vcpus=8, memory_gib=32)
    assert spec.lanes == 8
    assert spec.memory_bytes == 8 * (32 * (1 << 30) * 4 // 5 // 8 // 32) * 32
    assert spec.steps == 2 * spec.blocks
    assert ch.spec_for(SEED, vcpus=16, memory_gib=64).memory_bytes > 51 * (1 << 30)
    with pytest.raises(ch.ChallengeError, match="more than 1024"):
        ch.spec_for(SEED, vcpus=1025, memory_gib=4096)
    with pytest.raises(ch.ChallengeError, match="per vCPU"):
        ch.spec_for(SEED, vcpus=1, memory_gib=11)  # more than one lane can hold
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ch.ChallengeError):
            ch.spec_for(SEED, vcpus=bad, memory_gib=8)


def test_a_memory_heavy_claim_is_probed_at_what_can_be_proven():
    assert ch.provable_memory_gib(4, 256) == 40
    assert ch.provable_memory_gib(8, 32) == 32
    ch.spec_for(SEED, vcpus=4, memory_gib=ch.provable_memory_gib(4, 256))  # does not raise
    with pytest.raises(ch.ChallengeError):
        ch.spec_for(SEED, vcpus=4, memory_gib=ch.provable_memory_gib(4, 256) + 1)


@pytest.mark.parametrize(
    "args",
    [
        (b"short", 1, 1, 1),
        (SEED, 0, 1, 1),
        (SEED, 1, 0, 1),
        (SEED, 1, 1, 0),
        (SEED, ch.MAX_LANES + 1, 1, 1),
        (SEED, True, 1, 1),
        (SEED, 1.5, 1, 1),
    ],
)
def test_bad_specs_are_refused(args):
    with pytest.raises(ch.ChallengeError):
        ch.ChallengeSpec(*args)


def test_spec_json_round_trip_is_strict():
    assert ch.ChallengeSpec.from_json(SMALL.to_json()) == SMALL
    for bad in (
        {**SMALL.to_json(), "x": 1},
        {**SMALL.to_json(), "seed": "AB" * 32},
        {**SMALL.to_json(), "seed": "zz" * 32},
        [1],
    ):
        with pytest.raises(ch.ChallengeError):
            ch.ChallengeSpec.from_json(bad)


def test_the_sandbox_command_prints_the_answer():
    done = subprocess.run(
        [sys.executable, "-m", "cathedral.capacity.challenge", "--workers", "2"],
        input=json.dumps(SMALL.to_json()),
        capture_output=True,
        text=True,
        check=True,
    )
    answer = json.loads(done.stdout)
    outputs = [bytes.fromhex(item) for item in answer["outputs"]]
    assert outputs == ch.run(SMALL, workers=1)
    assert answer["result_digest"] == ch.result_digest(SMALL, outputs).hex()
    bad = subprocess.run(
        [sys.executable, "-m", "cathedral.capacity.challenge"],
        input="{}",
        capture_output=True,
        text=True,
    )
    assert bad.returncode == 2 and "error" in json.loads(bad.stdout)


# -- receipts ---------------------------------------------------------------------

DIGEST = bytes([3]) * 32


def _body(**changes):
    vcpus = changes.pop("vcpus", 6)
    memory_gib = changes.pop("memory_gib", 24)
    spec = changes.pop("challenge", ch.spec_for(SEED, vcpus=vcpus, memory_gib=memory_gib))
    lanes = ch.sample_lanes(spec, DIGEST, NONCE_A, ch.MIN_SAMPLES)
    fields = dict(
        netuid=94,
        round=7,
        validator_nonce=VALIDATOR_NONCE,
        box_id="box-1",
        miner_hotkey=HOTKEY,
        kind="bare_metal",
        hardware_id=FINGERPRINT,
        hardware_id_kind="probe_fingerprint",
        vcpus=vcpus,
        memory_gib=memory_gib,
        challenge=spec,
        result_digest=DIGEST,
        sample_nonce=NONCE_A,
        sampled_outputs={lane: bytes([lane % 256]) * 32 for lane in lanes},
        deadline_ms=60_000,
        timings_ms={"create": 900, "exec": 40_000, "delete": 300},
        issued_at=NOW,
        valid_for=timedelta(minutes=30),
        prober_key_id="sn94-prober-1",
    )
    fields.update(changes)
    return receipt.make_body(**fields)


@pytest.fixture
def prober():
    key = Ed25519PrivateKey.generate()
    return key, {"sn94-prober-1": key.public_key()}


def _verify(signed, keys, **changes):
    args = dict(
        prober_keys=keys,
        netuid=94,
        validator_nonce=VALIDATOR_NONCE,
        now=NOW + timedelta(minutes=1),
    )
    args.update(changes)
    return receipt.verify_receipt(signed, **args)


def test_a_signed_receipt_verifies_on_any_netuid(prober):
    key, keys = prober
    verified = _verify(receipt.sign_receipt(_body(), key), keys, expected_round=7)
    assert (verified.box_id, verified.vcpus, verified.memory_gib) == ("box-1", 6, 24)
    assert (verified.kind, verified.hardware_id_kind) == ("bare_metal", "probe_fingerprint")
    assert sorted(verified.sampled_outputs) == ch.sample_lanes(
        verified.challenge, DIGEST, NONCE_A, ch.MIN_SAMPLES
    )
    assert _verify(receipt.sign_receipt(_body(netuid=39), key), keys, netuid=39).round == 7


def test_a_validator_can_recompute_the_sampled_lanes(prober):
    # A small real run standing in for a probe: the receipt's samples recompute.
    key, keys = prober
    spec = ch.spec_for(SEED, vcpus=2, memory_gib=1)
    small = ch.ChallengeSpec(spec.seed, spec.lanes, 64, 128)
    outputs = ch.run(small, workers=1)
    digest = ch.result_digest(small, outputs)
    assert all(
        ch.lane_output(small, lane) == outputs[lane]
        for lane in ch.sample_lanes(small, digest, NONCE_A, ch.MIN_SAMPLES)
    )


def test_receipts_for_someone_else_or_another_round_are_refused(prober):
    key, keys = prober
    signed = receipt.sign_receipt(_body(), key)
    for changes, message in (
        ({"validator_nonce": "cd" * 32}, "another validator"),
        ({"netuid": 39}, "another netuid"),
        ({"expected_round": 8}, "another round"),
        ({"now": NOW + timedelta(hours=1)}, "not currently valid"),
        ({"now": NOW - timedelta(hours=1)}, "not currently valid"),
        ({"prober_keys": {"other": key.public_key()}}, "unknown prober key"),
        (
            {"prober_keys": {"sn94-prober-1": Ed25519PrivateKey.generate().public_key()}},
            "does not verify",
        ),
    ):
        with pytest.raises(receipt.ReceiptError, match=message):
            _verify(signed, keys, **changes)


def test_a_tampered_receipt_is_refused(prober):
    key, keys = prober
    signed = receipt.sign_receipt(_body(), key)
    tampered = json.loads(json.dumps(signed))
    tampered["box"]["miner_hotkey"] = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
    with pytest.raises(receipt.ReceiptError, match="does not verify"):
        _verify(tampered, keys)
    unsigned = {k: v for k, v in signed.items() if k != "signature"}
    with pytest.raises(receipt.ReceiptError, match="not a signed object"):
        _verify(unsigned, keys)


def test_capacity_must_be_exactly_what_the_challenge_proved(prober):
    key, _keys = prober
    # A receipt paying for a million vCPUs over a tiny challenge is refused.
    with pytest.raises(receipt.ReceiptError, match="does not prove the capacity"):
        receipt.sign_receipt(_body(vcpus=6, memory_gib=24, challenge=SMALL), key)
    body = _body()
    body["capacity"]["memory_gib"] = 48
    with pytest.raises(receipt.ReceiptError, match="does not prove the capacity"):
        receipt.sign_receipt(body, key)
    with pytest.raises(receipt.ReceiptError, match="more than 1024"):
        spec = ch.spec_for(SEED, vcpus=1024, memory_gib=1024)
        body = _body(vcpus=1024, memory_gib=1024, challenge=spec)
        body["capacity"]["vcpus"] = 2048
        receipt.sign_receipt(body, key)


def test_samples_must_be_exactly_the_lanes_the_nonce_picks(prober):
    key, _keys = prober
    body = _body()
    lanes = sorted(int(lane) for lane in body["challenge"]["sampled_outputs"])
    other = next(lane for lane in range(6) if lane not in lanes)
    moved = dict(body["challenge"]["sampled_outputs"])
    moved.pop(str(lanes[0]))
    moved[str(other)] = "00" * 32
    body["challenge"]["sampled_outputs"] = moved
    with pytest.raises(receipt.ReceiptError, match="exactly the lanes"):
        receipt.sign_receipt(body, key)
    body["challenge"]["sampled_outputs"] = {}
    with pytest.raises(receipt.ReceiptError, match="exactly the lanes"):
        receipt.sign_receipt(body, key)


@pytest.mark.parametrize("alias", ["03", "٣", "²", "-1", " 3"])
def test_lane_keys_are_plain_decimal(prober, alias):
    key, _keys = prober
    body = _body()
    sampled = dict(body["challenge"]["sampled_outputs"])
    sampled[alias] = "00" * 32
    body["challenge"]["sampled_outputs"] = sampled
    with pytest.raises(receipt.ReceiptError):
        receipt.sign_receipt(body, key)


def test_a_late_answer_is_refused(prober):
    key, _keys = prober
    with pytest.raises(receipt.ReceiptError, match="after its deadline"):
        receipt.sign_receipt(
            _body(deadline_ms=30_000, timings_ms={"create": 1, "exec": 30_001, "delete": 1}),
            key,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "tee"},  # a tee box names a ppid or chip_id, not a probe fingerprint
        {"hardware_id_kind": "ppid"},  # and bare metal a probe fingerprint
        {"hardware_id": "short"},
        {"miner_hotkey": "not-an-address"},
        {"box_id": "bad box id"},
        {"validator_nonce": "short"},
        {"valid_for": timedelta(hours=3)},
        {"valid_for": timedelta(0)},
        {"timings_ms": {"create": 1}},
        {"deadline_ms": 0},
    ],
)
def test_the_prober_never_signs_a_malformed_body(prober, changes):
    key, _keys = prober
    with pytest.raises(receipt.ReceiptError):
        receipt.sign_receipt(_body(**changes), key)


@pytest.mark.parametrize("hardware_id_kind", ["ppid", "chip_id"])
def test_a_tee_receipt_carries_its_hardware_identity(prober, hardware_id_kind):
    key, keys = prober
    signed = receipt.sign_receipt(
        _body(kind="tee", hardware_id="aa" * 32, hardware_id_kind=hardware_id_kind), key
    )
    verified = _verify(signed, keys)
    assert (verified.hardware_id, verified.hardware_id_kind) == ("aa" * 32, hardware_id_kind)


# -- pricing -----------------------------------------------------------------------


def _table(**changes):
    table = {
        "schema": pricing.SCHEMA,
        "currency": "usd",
        "rates": {
            "tee": {"vcpu_hour": 30_000, "gib_hour": 4_000},
            "bare_metal": {"vcpu_hour": 18_000, "gib_hour": 2_500},
        },
        "consumer_profiles": {
            "sn120": {"min_vcpus": 2, "min_memory_gib": 4},
            "sn81": {"min_vcpus": 8, "min_memory_gib": 32},
        },
        "effective_from": "2026-09-28T00:00:00Z",
        "key_id": "sn94-owner-1",
        "sequence": 3,
    }
    table.update(changes)
    return table


@pytest.fixture
def owner():
    key = Ed25519PrivateKey.generate()
    return key, {"sn94-owner-1": key.public_key()}


def _load(signed, keys, **changes):
    return pricing.load_price_table(signed, owner_keys=keys, now=NOW, **changes)


def test_value_follows_the_market_rates_for_each_kind(owner):
    key, keys = owner
    table = _load(pricing.sign_price_table(_table(), key), keys)
    assert table.sequence == 3
    bare = table.value(kind="bare_metal", vcpus=8, memory_gib=32)
    tee = table.value(kind="tee", vcpus=8, memory_gib=32)
    assert bare == 8 * 18_000 + 32 * 2_500
    assert tee == 8 * 30_000 + 32 * 4_000
    assert tee > bare


def test_a_box_below_every_consumer_profile_earns_zero(owner):
    key, keys = owner
    table = _load(pricing.sign_price_table(_table(), key), keys)
    assert table.value(kind="tee", vcpus=1, memory_gib=64) == 0
    assert table.value(kind="tee", vcpus=16, memory_gib=2) == 0
    assert table.value(kind="bare_metal", vcpus=2, memory_gib=4) == 2 * 18_000 + 4 * 2_500


def test_a_table_must_be_signed_pinned_effective_and_not_rolled_back(owner):
    key, keys = owner
    signed = pricing.sign_price_table(_table(), key)
    with pytest.raises(pricing.PriceTableError, match="unknown key"):
        _load(signed, {"other": key.public_key()})
    forged = {
        **signed,
        "rates": {**signed["rates"], "bare_metal": {"vcpu_hour": 10**9, "gib_hour": 0}},
    }
    with pytest.raises(pricing.PriceTableError, match="does not verify"):
        _load(forged, keys)
    future = pricing.sign_price_table(_table(effective_from="2027-01-01T00:00:00Z"), key)
    with pytest.raises(pricing.PriceTableError, match="not effective"):
        _load(future, keys)
    with pytest.raises(pricing.PriceTableError, match="older than"):
        _load(signed, keys, minimum_sequence=4)
    assert _load(json.dumps(signed), keys, minimum_sequence=3).currency == "usd"


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": "other"},
        {"rates": {"tee": {"vcpu_hour": 1, "gib_hour": 1}}},
        {
            "rates": {
                "tee": {"vcpu_hour": -1, "gib_hour": 1},
                "bare_metal": {"vcpu_hour": 1, "gib_hour": 1},
            }
        },
        {
            "rates": {
                "tee": {"vcpu_hour": 1.5, "gib_hour": 1},
                "bare_metal": {"vcpu_hour": 1, "gib_hour": 1},
            }
        },
        {"consumer_profiles": {}},
        {"consumer_profiles": {"SN120": {"min_vcpus": 2, "min_memory_gib": 4}}},
        {"consumer_profiles": {"sn120": {"min_vcpus": 0, "min_memory_gib": 4}}},
        {"currency": "US Dollars"},
        {"effective_from": "tomorrow"},
        {"sequence": 0},
        {"sequence": True},
    ],
)
def test_malformed_tables_are_refused(owner, changes):
    key, _keys = owner
    with pytest.raises(pricing.PriceTableError):
        pricing.sign_price_table(_table(**changes), key)
