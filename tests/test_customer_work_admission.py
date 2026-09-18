"""Tests for the customer-work admission decision."""

from __future__ import annotations

import pytest

from cathedral.common import Attested, Policy, Tier
from cathedral.customer_work_admission import admits_customer_work
from cathedral.verify.snp import STRUCTURE_OK_CHAIN_UNVERIFIED

_MEASUREMENT = "sha256:" + "a" * 64
_OTHER = "sha256:" + "b" * 64


def _attested(tier: Tier = Tier.CC_CPU_TDX, measurement: str | None = _MEASUREMENT):
    return Attested(
        tier=tier,
        chip_id=b"c" * 32,
        measurement=measurement,
        tcb=1,
        tcb_status="UpToDate",
        advisory_ids=(),
        debug_enabled=False,
    )


def _policy(measurements: frozenset[str] = frozenset({_MEASUREMENT})) -> Policy:
    return Policy(allowed_measurements=measurements)


def test_listed_measurement_is_admitted() -> None:
    assert admits_customer_work(_policy(), _attested())


def test_unlisted_measurement_is_refused() -> None:
    assert not admits_customer_work(_policy(), _attested(measurement=_OTHER))


def test_absent_measurement_is_refused() -> None:
    """A machine that cannot produce a measurement must not receive work."""

    assert not admits_customer_work(_policy(), _attested(measurement=None))


def test_empty_measurement_is_refused() -> None:
    assert not admits_customer_work(_policy(), _attested(measurement=""))


def test_empty_allowlist_denies_everything() -> None:
    """An empty allowlist must never mean 'any measurement'."""

    assert not admits_customer_work(_policy(frozenset()), _attested())


def test_missing_evidence_is_refused() -> None:
    assert not admits_customer_work(_policy(), None)


def test_non_confidential_tier_is_refused() -> None:
    """A GPU tier is not a confidential CPU profile."""

    assert not admits_customer_work(_policy(), _attested(tier=Tier.CC_GPU))


def test_snp_tier_is_admitted_when_measurement_matches() -> None:
    assert admits_customer_work(_policy(), _attested(tier=Tier.CC_CPU_SNP))


def test_required_tier_pins_the_family() -> None:
    """A caller that needs TDX must not accept an SNP machine."""

    policy = _policy()
    assert admits_customer_work(
        policy, _attested(tier=Tier.CC_CPU_TDX), required_tier=Tier.CC_CPU_TDX
    )
    assert not admits_customer_work(
        policy, _attested(tier=Tier.CC_CPU_SNP), required_tier=Tier.CC_CPU_TDX
    )


def test_capability_flag_cannot_influence_the_decision() -> None:
    """Only the verified measurement matters.

    This is the property that makes the gate meaningful: nothing a worker
    reports about itself appears in this call.
    """

    policy = _policy()
    assert not admits_customer_work(policy, _attested(measurement=_OTHER))
    assert admits_customer_work(policy, _attested(measurement=_MEASUREMENT))


# --- verdict provenance -----------------------------------------------------
# A first version of this module accepted any object with the right
# attributes, and ignored the verdict's own verification fields. These tests
# exist because an adversarial review demonstrated both bypasses.


def test_unverified_chain_verdict_is_refused() -> None:
    """STRUCTURE_OK_CHAIN_UNVERIFIED must never be used for admission.

    The SNP verifier can return this verdict with an allowlisted measurement,
    and its own docstring says it must not be used for admission.
    """

    from dataclasses import replace

    attested = replace(
        _attested(),
        chain_verified=False,
        verification_status=STRUCTURE_OK_CHAIN_UNVERIFIED,
    )
    assert not admits_customer_work(_policy(), attested)


def test_chain_unverified_alone_is_refused() -> None:
    from dataclasses import replace

    assert not admits_customer_work(
        _policy(), replace(_attested(), chain_verified=False)
    )


def test_non_verified_status_alone_is_refused() -> None:
    from dataclasses import replace

    assert not admits_customer_work(
        _policy(), replace(_attested(), verification_status="SOMETHING_ELSE")
    )


def test_duck_typed_attested_is_refused() -> None:
    """Attested carries no provenance, so the type itself must be checked."""

    from types import SimpleNamespace

    forged = SimpleNamespace(tier=Tier.CC_CPU_TDX, measurement=_MEASUREMENT)
    assert not admits_customer_work(_policy(), forged)


def test_non_policy_object_is_refused() -> None:
    from types import SimpleNamespace

    assert not admits_customer_work(SimpleNamespace(allowed_measurements={_MEASUREMENT}), _attested())


def test_hand_built_attested_with_low_tcb_is_still_admitted_only_on_measurement() -> None:
    """TCB floors are the verifier's job, not this gate's.

    Recorded so the division of responsibility is explicit rather than
    accidental.
    """

    from dataclasses import replace

    assert admits_customer_work(_policy(), replace(_attested(), tcb=0))


def test_non_confidential_required_tier_is_refused() -> None:
    """Naming a tier must not become a way to admit a non-confidential one."""

    from dataclasses import replace

    assert not admits_customer_work(
        _policy(), replace(_attested(), tier=Tier.CC_GPU), required_tier=Tier.CC_GPU
    )
    assert not admits_customer_work(_policy(), _attested(), required_tier=Tier.CC_GPU)


# --- malformed verdicts must refuse, not crash ------------------------------


def test_bare_string_tier_is_refused() -> None:
    """Tier is a str enum, so a bare string compares equal to a member."""

    from dataclasses import replace

    assert not admits_customer_work(_policy(), replace(_attested(), tier="cc_cpu_tdx"))


@pytest.mark.parametrize("bad", [[_MEASUREMENT], {"a": 1}, 0, b"x", object()])
def test_non_string_measurement_is_refused_not_raised(bad: object) -> None:
    """An unhashable measurement must refuse, not raise from set membership."""

    from dataclasses import replace

    assert not admits_customer_work(_policy(), replace(_attested(), measurement=bad))


def test_non_enum_required_tier_is_refused() -> None:
    assert not admits_customer_work(_policy(), _attested(), required_tier="cc_cpu_tdx")


def test_missing_tier_is_refused() -> None:
    from dataclasses import replace

    assert not admits_customer_work(_policy(), replace(_attested(), tier=None))


def test_attested_subclass_with_shadowed_fields_is_refused() -> None:
    """isinstance validates the type, not the values.

    A subclass can shadow ``tier`` and ``measurement`` with properties, so the
    gate sees an allowlisted confidential verdict while the stored fields say
    something else. The exact-type check is what closes this.
    """

    real_tier, real_measurement = Tier.CC_GPU, "sha256:" + "d" * 64

    class Shadowed(Attested):
        @property
        def tier(self):
            return Tier.CC_CPU_TDX

        @property
        def measurement(self):
            return _MEASUREMENT

    shadowed = Attested.__new__(Shadowed)
    shadowed.__dict__.update(
        tier=real_tier,
        chip_id=b"c" * 32,
        measurement=real_measurement,
        tcb=1,
        verification_status="VERIFIED",
        chain_verified=True,
    )
    assert shadowed.tier is Tier.CC_CPU_TDX  # the lie the gate must not believe
    assert shadowed.__dict__["tier"] is real_tier
    assert not admits_customer_work(_policy(), shadowed)
