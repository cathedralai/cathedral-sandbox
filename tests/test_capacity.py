"""The capacity challenge, prober receipts and market pricing (docs/CAPACITY.md)."""

from __future__ import annotations

import json
import math
import os
import random
import re
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
NETUID = random.SystemRandom().randrange(1, 65536)
OTHER_NETUID = NETUID % 65535 + 1


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
    # 12 honest lanes of 16, the rest garbage: with the nonce drawn after the
    # commitment, a pass needs all 8 sampled lanes to be honest, 495 in 12870.
    spec = ch.ChallengeSpec(SEED, lanes=16, blocks=8, steps=16)
    honest = ch.run(spec, workers=1)
    outputs = [honest[i] if i < 12 else bytes([i]) * 32 for i in range(16)]
    digest = ch.result_digest(spec, outputs)
    passes = 0
    samples = set()
    for i in range(300):
        nonce = os.urandom(32)
        samples.add(tuple(ch.sample_lanes(spec, digest, nonce, ch.required_samples(16))))
        passes += ch.verify(spec, outputs, nonce=nonce)
    assert passes <= 40  # 11.5 expected
    assert len(samples) > 100  # the nonce, not the box, decides the sample


@pytest.mark.parametrize(
    "lanes, required", [(1, 1), (3, 3), (4, 4), (5, 4), (8, 4), (9, 5), (16, 8), (1024, 512)]
)
def test_the_sample_floor_covers_small_boxes_and_half_of_large_ones(lanes, required):
    assert ch.required_samples(lanes) == required


def test_the_documented_pass_probabilities_hold():
    # docs/CAPACITY.md: faking f of n lanes passes a k-lane sample with
    # C(n - f, k) / C(n, k), at most (1 - k / n) ** f, so at most 2 ** -f.
    def passes(n, f):
        k = ch.required_samples(n)
        return math.comb(n - f, k) / math.comb(n, k)

    assert passes(8, 1) == 0.5 and passes(8, 2) == 15 / 70 and passes(4, 1) == 0
    assert passes(5, 1) == 0.2 and passes(9, 1) == 4 / 9 and passes(64, 1) == 0.5
    for n in range(1, 129):
        for f in range(1, n + 1):
            k = ch.required_samples(n)
            assert passes(n, f) <= (1 - k / n) ** f + 1e-12 <= 2.0**-f + 2e-12


def test_a_box_one_lane_short_passes_about_half_the_time_at_the_floor():
    spec = ch.ChallengeSpec(SEED, lanes=8, blocks=8, steps=16)
    outputs = ch.run(spec, workers=1)
    outputs[5] = bytes(32)
    passes = sum(ch.verify(spec, outputs, nonce=os.urandom(32)) for _ in range(400))
    assert 140 <= passes <= 260  # 200 expected
    assert not any(
        ch.verify(spec, outputs, nonce=os.urandom(32), sample=spec.lanes) for _ in range(20)
    )


def test_verify_refuses_a_sample_below_the_floor():
    outputs = ch.run(SMALL, workers=1)
    assert ch.verify(SMALL, outputs, nonce=NONCE_A, sample=ch.required_samples(SMALL.lanes))
    assert not ch.verify(SMALL, outputs, nonce=NONCE_A, sample=ch.required_samples(SMALL.lanes) - 1)


def test_the_deadline_bound_follows_the_spec():
    small = ch.ChallengeSpec(SEED, 1, 1, 1)
    assert ch.max_deadline_ms(small) == ch.DEADLINE_BASE_MS + 1
    big = ch.spec_for(SEED, vcpus=8, memory_gib=32)
    assert ch.max_deadline_ms(big) == ch.DEADLINE_BASE_MS + math.ceil(
        big.steps * ch.DEADLINE_NS_PER_STEP / 1_000_000
    )
    assert ch.max_deadline_ms(big) == 1_193_742  # a 32 GiB, 8 vCPU box: about 20 minutes


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
    sample_count = changes.pop("sample_count", ch.required_samples(spec.lanes))
    lanes = ch.sample_lanes(spec, DIGEST, NONCE_A, sample_count)
    fields = dict(
        netuid=NETUID,
        round=7,
        validator_nonce=VALIDATOR_NONCE,
        box_id="box-1",
        miner_hotkey=HOTKEY,
        kind="bare_metal",
        tee_kind=None,
        hardware_id=FINGERPRINT,
        vcpus=vcpus,
        memory_gib=memory_gib,
        challenge=spec,
        result_digest=DIGEST,
        sample_nonce=NONCE_A,
        sample_count=sample_count,
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
        netuid=NETUID,
        validator_nonce=VALIDATOR_NONCE,
        now=NOW + timedelta(minutes=1),
        expected_round=7,
    )
    args.update(changes)
    return receipt.verify_receipt(signed, **args)


def test_a_signed_receipt_verifies_on_any_netuid(prober):
    key, keys = prober
    verified = _verify(receipt.sign_receipt(_body(), key), keys)
    assert (verified.box_id, verified.vcpus, verified.memory_gib) == ("box-1", 6, 24)
    assert (verified.kind, verified.tee_kind, verified.hardware_id_kind) == (
        "bare_metal",
        None,
        "probe_fingerprint",
    )
    assert verified.sample_count == ch.required_samples(6) == 4
    assert sorted(verified.sampled_outputs) == ch.sample_lanes(
        verified.challenge, DIGEST, NONCE_A, verified.sample_count
    )
    other = receipt.sign_receipt(_body(netuid=OTHER_NETUID), key)
    assert _verify(other, keys, netuid=OTHER_NETUID).round == 7


def test_verify_receipt_requires_the_round(prober):
    key, keys = prober
    signed = receipt.sign_receipt(_body(), key)
    with pytest.raises(TypeError):
        receipt.verify_receipt(
            signed, prober_keys=keys, netuid=NETUID, validator_nonce=VALIDATOR_NONCE, now=NOW
        )
    for bad in (None, -1, True, "7"):
        with pytest.raises(receipt.ReceiptError, match="expected_round"):
            _verify(signed, keys, expected_round=bad)


def test_a_validator_can_recompute_the_sampled_lanes(prober):
    # A small real run standing in for a probe: the receipt's samples recompute.
    key, keys = prober
    spec = ch.spec_for(SEED, vcpus=2, memory_gib=1)
    small = ch.ChallengeSpec(spec.seed, spec.lanes, 64, 128)
    outputs = ch.run(small, workers=1)
    digest = ch.result_digest(small, outputs)
    assert all(
        ch.lane_output(small, lane) == outputs[lane]
        for lane in ch.sample_lanes(small, digest, NONCE_A, ch.required_samples(small.lanes))
    )


def test_receipts_for_someone_else_or_another_round_are_refused(prober):
    key, keys = prober
    signed = receipt.sign_receipt(_body(), key)
    for changes, message in (
        ({"validator_nonce": "cd" * 32}, "another validator"),
        ({"netuid": OTHER_NETUID}, "another netuid"),
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


def test_a_loose_deadline_is_refused(prober):
    key, keys = prober
    spec = ch.spec_for(SEED, vcpus=6, memory_gib=24)
    top = ch.max_deadline_ms(spec)
    assert _verify(receipt.sign_receipt(_body(deadline_ms=top), key), keys).deadline_ms == top
    for loose in (top + 1, 10**15):
        with pytest.raises(receipt.ReceiptError, match="looser than"):
            receipt.sign_receipt(
                _body(deadline_ms=loose, timings_ms={"create": 1, "exec": 10**14, "delete": 1}),
                key,
            )


def test_the_sample_count_is_bound_to_the_lane_count(prober):
    key, keys = prober
    everything = receipt.sign_receipt(_body(sample_count=6), key)
    assert sorted(_verify(everything, keys).sampled_outputs) == list(range(6))
    for bad in (3, 7):  # below required_samples(6) == 4, or above the lanes
        with pytest.raises(receipt.ReceiptError, match="sample_count must be from 4 to 6"):
            receipt.sign_receipt(_body(sample_count=bad), key)
    for bad in (0, True, 4.0, "4"):
        body = _body()
        body["challenge"]["sample_count"] = bad
        with pytest.raises(receipt.ReceiptError, match="sample_count"):
            receipt.sign_receipt(body, key)
    # A count the outputs do not match: 5 lanes' outputs, but a count of 4.
    body = _body(sample_count=5)
    body["challenge"]["sample_count"] = 4
    with pytest.raises(receipt.ReceiptError, match="exactly the lanes"):
        receipt.sign_receipt(body, key)


@pytest.mark.parametrize(
    "field, value",
    [
        ("issued_at", "2026-02-30T00:00:00Z"),
        ("issued_at", "2026-09-28T24:00:00Z"),
        ("expires_at", "2026-13-01T00:00:00Z"),
        ("expires_at", "0000-01-01T00:00:00Z"),
    ],
)
def test_an_impossible_date_is_a_receipt_error_before_the_signature(prober, field, value):
    key, keys = prober
    body = _body()
    body[field] = value
    with pytest.raises(receipt.ReceiptError, match="not a real date"):
        receipt.sign_receipt(body, key)
    with pytest.raises(receipt.ReceiptError, match="not a real date"):
        _verify({**body, "signature": "AAAA"}, keys)


def test_extreme_dates_do_not_overflow(prober):
    key, keys = prober
    body = _body()
    body["issued_at"], body["expires_at"] = "9999-12-31T23:00:00Z", "9999-12-31T23:30:00Z"
    signed = receipt.sign_receipt(body, key)
    with pytest.raises(receipt.ReceiptError, match="not currently valid"):
        _verify(signed, keys)
    body["issued_at"], body["expires_at"] = "0001-01-01T00:00:00Z", "0001-01-01T00:30:00Z"
    with pytest.raises(receipt.ReceiptError, match="not currently valid"):
        _verify(receipt.sign_receipt(body, key), keys)


def test_a_naive_now_is_refused(prober):
    key, keys = prober
    signed = receipt.sign_receipt(_body(), key)
    for bad in (NOW.replace(tzinfo=None), NOW.timestamp(), None):
        with pytest.raises(receipt.ReceiptError, match="timezone-aware"):
            _verify(signed, keys, now=bad)


def test_the_prober_never_signs_twice(prober):
    key, _keys = prober
    signed = receipt.sign_receipt(_body(), key)
    with pytest.raises(receipt.ReceiptError, match="already carries a signature"):
        receipt.sign_receipt(signed, key)


@pytest.mark.parametrize(
    "path, value, message",
    [
        (("schema",), "cathedral_capacity_receipt_v0", "wrong fields or schema"),
        (("netuid",), "1", "netuid"),
        (("netuid",), -1, "netuid"),
        (("netuid",), True, "netuid"),
        (("round",), -1, "round"),
        (("prober_key_id",), "bad key id", "prober_key_id"),
        (("prober_key_id",), 7, "prober_key_id"),
        (("challenge", "sampled_outputs"), [], "sampled_outputs must be an object"),
        (("capacity", "memory_gib"), 0, "^memory_gib must be an integer"),
        (("capacity", "memory_gib"), 24.0, "^memory_gib must be an integer"),
        (("capacity", "vcpus"), 0, "^vcpus must be an integer"),
        (("timings_ms", "create"), -1, "timings_ms.create"),
        (("timings_ms", "delete"), 1.5, "timings_ms.delete"),
        (("timings_ms", "exec"), -1, "timings_ms.exec"),
        (("timings_ms", "exec"), True, "timings_ms.exec"),
        (("box", "tee_kind"), "tdx", "tee_kind"),
        (("box", "tee_kind"), ["tdx"], "tee_kind"),
        (("box", "hardware_id_kind"), "chip_id", "hardware_id_kind"),
    ],
)
def test_each_field_check_refuses_its_bad_input(prober, path, value, message):
    key, _keys = prober
    body = _body()
    target = body
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    with pytest.raises(receipt.ReceiptError, match=message):
        receipt.sign_receipt(body, key)


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "tee"},  # a tee box names its tee kind
        {"kind": "tee", "tee_kind": "sgx"},
        {"tee_kind": "tdx"},  # and bare metal has none
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


@pytest.mark.parametrize("tee_kind, hardware_id_kind", [("tdx", "ppid"), ("sev_snp", "chip_id")])
def test_a_tee_receipt_carries_its_one_hardware_identity(prober, tee_kind, hardware_id_kind):
    key, keys = prober
    signed = receipt.sign_receipt(_body(kind="tee", tee_kind=tee_kind, hardware_id="aa" * 32), key)
    verified = _verify(signed, keys)
    assert (verified.tee_kind, verified.hardware_id, verified.hardware_id_kind) == (
        tee_kind,
        "aa" * 32,
        hardware_id_kind,
    )
    # The other TEE's id kind is refused: one machine, one hardware id.
    other = "chip_id" if hardware_id_kind == "ppid" else "ppid"
    body = _body(kind="tee", tee_kind=tee_kind, hardware_id="aa" * 32)
    body["box"]["hardware_id_kind"] = other
    with pytest.raises(receipt.ReceiptError, match="hardware_id_kind"):
        receipt.sign_receipt(body, key)


def test_hardware_ids_are_derived_one_way_per_kind():
    ppid = bytes(range(1, 17))
    assert receipt.derive_hardware_id("ppid", ppid) == receipt.derive_hardware_id("ppid", ppid)
    assert receipt.derive_hardware_id("ppid", ppid) != receipt.derive_hardware_id(
        "chip_id", ppid * 4
    )
    for kind, raw in (
        ("ppid", bytes(15)),
        ("ppid", bytes(16)),  # all zeros: missing
        ("chip_id", bytes(64)),  # all zeros: SEV-SNP's MASK_CHIP_ID
        ("chip_id", ppid),
        ("probe_fingerprint", b"x" * 17),
        ("serial", ppid),
    ):
        with pytest.raises(receipt.ReceiptError):
            receipt.derive_hardware_id(kind, raw)


def test_a_probe_fingerprint_names_the_endpoint_the_prober_reached():
    v4 = receipt.probe_fingerprint("203.0.113.7", 8443)
    assert v4 == receipt.probe_fingerprint("::ffff:203.0.113.7", 8443)
    assert v4 != receipt.probe_fingerprint("203.0.113.7", 8444)
    assert v4 != receipt.probe_fingerprint("203.0.113.8", 8443)
    assert receipt.probe_fingerprint("2001:db8::1", 443) == receipt.probe_fingerprint(
        "2001:0db8:0:0::1", 443
    )
    assert re.fullmatch(r"[0-9a-f]{64}", v4)
    for address, port in (("box.example", 443), ("203.0.113.7", 0), ("203.0.113.7", True)):
        with pytest.raises(receipt.ReceiptError):
            receipt.probe_fingerprint(address, port)


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
    args = dict(owner_keys=keys, now=NOW, minimum_sequence=3)
    args.update(changes)
    return pricing.load_price_table(signed, **args)


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


def test_load_price_table_requires_the_minimum_sequence(owner):
    key, keys = owner
    signed = pricing.sign_price_table(_table(), key)
    with pytest.raises(TypeError):
        pricing.load_price_table(signed, owner_keys=keys, now=NOW)
    for bad in (None, 0, True, "3"):
        with pytest.raises(pricing.PriceTableError, match="minimum_sequence"):
            _load(signed, keys, minimum_sequence=bad)


def test_a_different_table_at_the_pinned_sequence_is_refused(owner):
    key, keys = owner
    pinned = pricing.sign_price_table(_table(), key)
    digest = _load(pinned, keys).digest
    assert digest == pricing.table_digest(pinned) == pricing.table_digest(_table())
    assert _load(pinned, keys, pinned_digest=digest).sequence == 3
    rates = {
        "tee": {"vcpu_hour": 30_000, "gib_hour": 4_000},
        "bare_metal": {"vcpu_hour": 90_000, "gib_hour": 2_500},
    }
    swapped = pricing.sign_price_table(_table(rates=rates), key)
    assert _load(swapped, keys).sequence == 3  # without the digest, only the sequence is pinned
    with pytest.raises(pricing.PriceTableError, match="differs from the one pinned"):
        _load(swapped, keys, pinned_digest=digest)
    newer = pricing.sign_price_table(_table(rates=rates, sequence=4), key)
    assert _load(newer, keys, pinned_digest=digest).sequence == 4  # a newer table moves on
    for bad in ("AB" * 32, "ab", 7):
        with pytest.raises(pricing.PriceTableError, match="pinned_digest"):
            _load(pinned, keys, pinned_digest=bad)


def test_a_table_with_an_impossible_date_or_a_naive_now_is_a_table_error(owner):
    key, keys = owner
    with pytest.raises(pricing.PriceTableError, match="not a real date"):
        pricing.sign_price_table(_table(effective_from="2026-02-30T00:00:00Z"), key)
    unsigned = {**_table(effective_from="2026-02-30T00:00:00Z"), "signature": "AAAA"}
    with pytest.raises(pricing.PriceTableError, match="not a real date"):
        _load(unsigned, keys)
    signed = pricing.sign_price_table(_table(), key)
    for bad in (NOW.replace(tzinfo=None), NOW.timestamp()):
        with pytest.raises(pricing.PriceTableError, match="timezone-aware"):
            _load(signed, keys, now=bad)


def test_value_refuses_a_non_positive_shape(owner):
    key, keys = owner
    table = _load(pricing.sign_price_table(_table(), key), keys)
    for vcpus, memory_gib in ((0, 32), (8, 0), (-8, 32), (True, 32), (8, 32.0)):
        with pytest.raises(pricing.PriceTableError, match="positive integer"):
            table.value(kind="tee", vcpus=vcpus, memory_gib=memory_gib)
    with pytest.raises(pricing.PriceTableError, match="no rate"):
        table.value(kind="gpu", vcpus=8, memory_gib=32)


def test_a_profile_may_not_ask_for_more_vcpus_than_can_be_proven(owner):
    key, _keys = owner
    top = {"sn81": {"min_vcpus": ch.MAX_LANES, "min_memory_gib": 4096}}
    pricing.sign_price_table(_table(consumer_profiles=top), key)
    over = {"sn81": {"min_vcpus": ch.MAX_LANES + 1, "min_memory_gib": 32}}
    with pytest.raises(pricing.PriceTableError, match=f"from 1 to {ch.MAX_LANES}"):
        pricing.sign_price_table(_table(consumer_profiles=over), key)


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
        {"key_id": "bad key id"},
        {"key_id": 7},
        {
            "rates": {
                "tee": {"vcpu_hour": pricing.MAX_MICRO + 1, "gib_hour": 1},
                "bare_metal": {"vcpu_hour": 1, "gib_hour": 1},
            }
        },
        {"consumer_profiles": {"sn81": {"min_vcpus": 8, "min_memory_gib": 4097}}},
    ],
)
def test_malformed_tables_are_refused(owner, changes):
    key, _keys = owner
    with pytest.raises(pricing.PriceTableError):
        pricing.sign_price_table(_table(**changes), key)


@pytest.mark.parametrize(
    "raw",
    [
        '{"sequence": ' + "1" * 5000 + "}",
        "[" * 100_000,
        b"\xff\xfe",
    ],
)
def test_unsigned_table_bytes_never_escape_as_other_errors(owner, raw):
    _key, keys = owner
    with pytest.raises(pricing.PriceTableError, match="not JSON"):
        _load(raw, keys, minimum_sequence=1)


def test_a_huge_sequence_is_refused_before_the_signature_check(owner):
    key, keys = owner
    signed = pricing.sign_price_table(_table(), key)
    signed["sequence"] = 10**5000
    with pytest.raises(pricing.PriceTableError, match="sequence"):
        _load(signed, keys, minimum_sequence=1)
