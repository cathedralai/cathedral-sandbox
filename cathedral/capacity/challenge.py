"""Verifiable parallel-work challenge for a box's claimed CPU and memory.

The prober runs this inside a sandbox it creates on a miner's box. It proves
real parallel capacity: one memory-hard hash chain ("lane") per claimed vCPU,
together holding 80% of the claimed memory, answered within a deadline the
prober sets. A box with fewer cores or less memory cannot finish in time.

Protocol (commit, then sample):

1. the prober sends ``spec_for(seed, vcpus=, memory_gib=)`` with a fresh seed;
2. the box returns every lane's 32-byte output, which commits it
   (``result_digest``);
3. only then does the prober draw a fresh 32-byte ``nonce`` and recompute the
   ``count`` lanes ``sample_lanes(spec, digest, nonce, count)`` picks, with
   ``count`` at least ``required_samples(lanes)``. Because the nonce comes after
   the commitment, a box cannot steer the sample onto the few lanes it computed
   honestly, however it arranges the rest.

A lane is scrypt-like over SHA-256: fill ``blocks`` 32-byte blocks, then take
``steps`` (two per block) data-dependent reads, each writing back, so it cannot
be computed with much less memory or skipped ahead.

The pure-Python reference defines the outputs exactly. The prober and the
sandbox should run a native implementation of the same function (see
docs/CAPACITY.md for cost).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass

DOMAIN = b"cathedral.capacity.challenge.v1\x00"
BLOCK_BYTES = 32
MAX_LANES = 1024
MAX_BLOCKS = 1 << 28  # 8 GiB per lane: up to 10 GiB of claimed memory per vCPU
MAX_STEPS = 1 << 29
# Fixed protocol parameters: a receipt's spec must be exactly spec_for(...) with these.
MEMORY_NUMERATOR, MEMORY_DENOMINATOR = 4, 5  # the lanes hold 80% of the claimed memory
STEPS_PER_BLOCK = 2
MIN_SAMPLES = 4
# The most time a prober may allow for the challenge (max_deadline_ms): a fixed
# base for creating the sandbox and starting the worker, plus a per-step budget
# about three times the pure-Python reference on a slow core. Deliberately loose
# until it is benchmarked (docs/CAPACITY.md).
DEADLINE_BASE_MS = 120_000
DEADLINE_NS_PER_STEP = 5_000


class ChallengeError(ValueError):
    """A challenge spec or answer is malformed."""


@dataclass(frozen=True)
class ChallengeSpec:
    seed: bytes
    lanes: int
    blocks: int
    steps: int

    def __post_init__(self) -> None:
        if not isinstance(self.seed, bytes) or len(self.seed) != 32:
            raise ChallengeError("seed must be 32 bytes")
        for name, value, top in (
            ("lanes", self.lanes, MAX_LANES),
            ("blocks", self.blocks, MAX_BLOCKS),
            ("steps", self.steps, MAX_STEPS),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= top:
                raise ChallengeError(f"{name} must be an integer from 1 to {top}")

    @property
    def memory_bytes(self) -> int:
        return self.lanes * self.blocks * BLOCK_BYTES

    def to_json(self) -> dict:
        return {
            "seed": self.seed.hex(),
            "lanes": self.lanes,
            "blocks": self.blocks,
            "steps": self.steps,
        }

    @classmethod
    def from_json(cls, value: object) -> ChallengeSpec:
        if not isinstance(value, dict) or set(value) != {"seed", "lanes", "blocks", "steps"}:
            raise ChallengeError("challenge spec must have exactly seed, lanes, blocks, steps")
        seed = value["seed"]
        if not isinstance(seed, str) or len(seed) != 64 or seed != seed.lower():
            raise ChallengeError("seed must be 64 lowercase hex characters")
        try:
            raw = bytes.fromhex(seed)
        except ValueError as exc:
            raise ChallengeError("seed must be 64 lowercase hex characters") from exc
        return cls(raw, value["lanes"], value["blocks"], value["steps"])


def spec_for(seed: bytes, *, vcpus: int, memory_gib: int) -> ChallengeSpec:
    """The challenge for a claim: one lane per vCPU, together holding 80% of the
    claimed memory (the rest is left for the guest and the runtime). A claim the
    challenge cannot prove (more than MAX_LANES vCPUs, or more memory per vCPU
    than one lane can hold) is refused rather than proven only in part."""

    for name, value in (("vcpus", vcpus), ("memory_gib", memory_gib)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ChallengeError(f"{name} must be a positive integer")
    if vcpus > MAX_LANES:
        raise ChallengeError(f"a claim of more than {MAX_LANES} vCPUs cannot be proven")
    per_lane = memory_gib * (1 << 30) * MEMORY_NUMERATOR // (MEMORY_DENOMINATOR * vcpus)
    blocks = per_lane // BLOCK_BYTES
    if blocks < 1 or blocks > MAX_BLOCKS:
        raise ChallengeError("the claimed memory per vCPU is outside what one lane can prove")
    return ChallengeSpec(seed, vcpus, blocks, blocks * STEPS_PER_BLOCK)


def provable_memory_gib(vcpus: int, memory_gib: int) -> int:
    """The most memory ``spec_for`` can prove for ``vcpus``: a memory-heavy box
    is probed, and paid, for this much rather than refused outright."""

    limit = MAX_BLOCKS * BLOCK_BYTES * vcpus * MEMORY_DENOMINATOR // (MEMORY_NUMERATOR * (1 << 30))
    return max(0, min(memory_gib, limit))


def required_samples(lanes: int) -> int:
    """The fewest lanes a prober may recompute for a ``lanes``-lane challenge:
    every lane up to MIN_SAMPLES, then at least half of them."""

    if not isinstance(lanes, int) or isinstance(lanes, bool) or not 1 <= lanes <= MAX_LANES:
        raise ChallengeError(f"lanes must be an integer from 1 to {MAX_LANES}")
    return min(lanes, max(MIN_SAMPLES, math.ceil(lanes / 2)))


def max_deadline_ms(spec: ChallengeSpec) -> int:
    """The loosest deadline a receipt may carry for ``spec``. Lanes run in
    parallel, so the bound follows one lane's steps (the fill is half as many
    hashes again, and is covered by the per-step budget)."""

    return DEADLINE_BASE_MS + math.ceil(spec.steps * DEADLINE_NS_PER_STEP / 1_000_000)


def lane_output(spec: ChallengeSpec, lane: int) -> bytes:
    """The one 32-byte answer of ``lane``."""

    if not 0 <= lane < spec.lanes:
        raise ChallengeError("lane out of range")
    sha256 = hashlib.sha256
    x = sha256(DOMAIN + spec.seed + lane.to_bytes(4, "big")).digest()
    buf = bytearray(spec.blocks * BLOCK_BYTES)
    for j in range(spec.blocks):
        x = sha256(x).digest()
        buf[j * BLOCK_BYTES : (j + 1) * BLOCK_BYTES] = x
    blocks = spec.blocks
    for _ in range(spec.steps):
        offset = (int.from_bytes(x[:8], "little") % blocks) * BLOCK_BYTES
        x = sha256(x + buf[offset : offset + BLOCK_BYTES]).digest()
        buf[offset : offset + BLOCK_BYTES] = x
    return x


def _lane(args: tuple[ChallengeSpec, int]) -> bytes:
    return lane_output(*args)


def run(spec: ChallengeSpec, *, workers: int | None = None) -> list[bytes]:
    """Every lane's answer, computed in parallel (the sandbox side)."""

    workers = max(1, min(spec.lanes, workers or os.cpu_count() or 1))
    if workers == 1:
        return [lane_output(spec, lane) for lane in range(spec.lanes)]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_lane, [(spec, lane) for lane in range(spec.lanes)]))


def result_digest(spec: ChallengeSpec, outputs: list[bytes]) -> bytes:
    """Commit to the whole answer."""

    _check_outputs(spec, outputs)
    return hashlib.sha256(DOMAIN + b"result\x00" + spec.seed + b"".join(outputs)).digest()


def sample_lanes(spec: ChallengeSpec, digest: bytes, nonce: bytes, count: int) -> list[int]:
    """The lanes to recompute: ``min(count, lanes)`` distinct lanes, sorted, drawn
    from the committed answer's ``digest`` and a ``nonce`` the prober chose
    after receiving it. Anyone holding the receipt can recompute the choice."""

    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise ChallengeError("sample count must be a positive integer")
    for name, value in (("digest", digest), ("nonce", nonce)):
        if not isinstance(value, bytes) or len(value) != 32:
            raise ChallengeError(f"{name} must be 32 bytes")
    chosen: set[int] = set()
    counter = 0
    target = min(count, spec.lanes)
    while len(chosen) < target:
        block = hashlib.sha256(
            DOMAIN + b"sample\x00" + digest + nonce + counter.to_bytes(4, "big")
        ).digest()
        chosen.add(int.from_bytes(block[:8], "big") % spec.lanes)
        counter += 1
    return sorted(chosen)


def verify(
    spec: ChallengeSpec, outputs: list[bytes], *, nonce: bytes, sample: int | None = None
) -> bool:
    """True when every lane the post-commitment ``nonce`` samples recomputes to
    the committed answer. ``sample`` defaults to ``required_samples(lanes)``; a
    smaller count is refused."""

    try:
        count = required_samples(spec.lanes) if sample is None else sample
        if not isinstance(count, int) or count < required_samples(spec.lanes):
            return False
        lanes = sample_lanes(spec, result_digest(spec, outputs), nonce, count)
    except ChallengeError:
        return False
    return all(lane_output(spec, lane) == outputs[lane] for lane in lanes)


def _check_outputs(spec: ChallengeSpec, outputs: list[bytes]) -> None:
    if (
        not isinstance(outputs, list)
        or len(outputs) != spec.lanes
        or any(not isinstance(item, bytes) or len(item) != 32 for item in outputs)
    ):
        raise ChallengeError("outputs must be one 32-byte value per lane")


def main(argv: list[str] | None = None) -> int:
    """Sandbox side: read a spec as JSON on stdin, print the answer as JSON."""

    parser = argparse.ArgumentParser(prog="python -m cathedral.capacity.challenge")
    parser.add_argument("--workers", type=int, default=None)
    options = parser.parse_args(argv)
    try:
        spec = ChallengeSpec.from_json(json.loads(sys.stdin.read()))
    except (ChallengeError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
    outputs = run(spec, workers=options.workers)
    print(
        json.dumps(
            {
                "outputs": [item.hex() for item in outputs],
                "result_digest": result_digest(spec, outputs).hex(),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
