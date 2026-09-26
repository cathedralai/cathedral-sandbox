"""Contract: real attestation evidence can drive the SAT lane end to end."""

from __future__ import annotations

from dataclasses import dataclass

from cathedral.assurance import attestation_claims
from cathedral.common import Attested, Evidence, EvidenceKind, Policy, Tier
from cathedral.lanes.sat import solve_sat
from cathedral.lanes.sat_types import SatCertificate, SatWorkItem
from cathedral.neuron.miner import MockMiner
from cathedral.neuron.validator import attested_epoch, epoch


@dataclass
class EvidenceBackedMiner:
    uid: str
    hotkey: str
    chip_id: str
    measurement: str = "tdx-measurement-1"
    tcb: int = 7

    def collect_evidence(self, nonce: bytes) -> Evidence:
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=f"quote:{self.uid}".encode(),
            nonce=nonce,
            miner_hotkey=self.hotkey,
        )

    def do_sat_work(self, item: SatWorkItem) -> SatCertificate:
        assignment = solve_sat(item.instance)
        if assignment is None:
            return SatCertificate(
                satisfiable=False,
                assignment=None,
                work_units=1.0,
                challenge_id=item.challenge_id,
                assigned_hotkey=self.uid,
            )
        return SatCertificate(
            satisfiable=True,
            assignment=assignment,
            work_units=float(len(item.instance.clauses)),
            challenge_id=item.challenge_id,
            assigned_hotkey=self.uid,
        )


def _verifier(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
    uid = evidence.quote.decode().split(":", 1)[1]
    miner = _MINERS_BY_UID[uid]
    if evidence.nonce != nonce:
        return None
    if miner.measurement not in policy.allowed_measurements:
        return None
    if miner.tcb < policy.min_tcb:
        return None
    return Attested(
        tier=Tier.CC_CPU_TDX,
        chip_id=miner.chip_id,
        measurement=miner.measurement,
        tcb=miner.tcb,
        verification_status="VERIFIED",
        chain_verified=True,
        assurance=attestation_claims(evidence.quote, policy),
    )


_MINERS_BY_UID: dict[str, EvidenceBackedMiner] = {}


def test_attested_epoch_admits_tdx_runs_sat_and_conserves_weights():
    miners = [
        EvidenceBackedMiner("uid-1", "hotkey-1", "chip-1"),
        EvidenceBackedMiner("uid-2", "hotkey-2", "chip-2"),
    ]
    _MINERS_BY_UID.clear()
    _MINERS_BY_UID.update({m.uid: m for m in miners})

    result = attested_epoch(
        miners,
        Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7),
        routing={"sat_benchmark": 1.0},
        verifier=_verifier,
    )

    assert result.admitted == ["uid-1", "uid-2"]
    assert set(result.weights) == {"uid-1", "uid-2"}
    assert all(weight > 0 for weight in result.weights.values())
    assert abs(sum(result.weights.values()) + result.burn - 1.0) < 1e-9


def test_attested_epoch_dedupes_same_tdx_platform_id():
    miners = [
        EvidenceBackedMiner("uid-1", "hotkey-1", "shared-chip"),
        EvidenceBackedMiner("uid-2", "hotkey-2", "shared-chip"),
    ]
    _MINERS_BY_UID.clear()
    _MINERS_BY_UID.update({m.uid: m for m in miners})

    result = attested_epoch(
        miners,
        Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=0),
        routing={"sat_benchmark": 1.0},
        verifier=_verifier,
    )

    assert result.admitted == ["uid-1"]
    assert set(result.weights) == {"uid-1"}


def test_attested_epoch_rejects_bad_measurement_before_work():
    miner = EvidenceBackedMiner("uid-1", "hotkey-1", "chip-1")
    _MINERS_BY_UID.clear()
    _MINERS_BY_UID[miner.uid] = miner

    result = attested_epoch(
        [miner],
        Policy(allowed_measurements={"other-measurement"}, min_tcb=0),
        routing={"sat_benchmark": 1.0},
        verifier=_verifier,
    )

    assert result.admitted == []
    assert result.weights == {}
    assert result.burn == 1.0


def test_attested_epoch_rejects_legacy_verified_flag_without_assurance():
    miner = EvidenceBackedMiner("uid-1", "hotkey-1", "chip-1")

    def legacy_verifier(
        evidence: Evidence, nonce: bytes, policy: Policy
    ) -> Attested:
        assert evidence.nonce == nonce
        return Attested(
            Tier.CC_CPU_TDX,
            "chip-1",
            "tdx-measurement-1",
            7,
            "VERIFIED",
        )

    result = attested_epoch(
        [miner],
        Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7),
        routing={"sat_benchmark": 1.0},
        verifier=legacy_verifier,
    )

    assert result.admitted == []
    assert result.weights == {}
    assert result.burn == 1.0


def test_attested_epoch_refuses_verdict_that_does_not_declare_itself_verified():
    # The first miner's verdict is built without verification_status and
    # chain_verified, so it takes the fail-closed defaults. Its typed claims
    # pass, so the refusal comes from the verdict alone. It shares a chip with
    # the second miner and must not reserve that chip by being seen first.
    undeclared_miner = EvidenceBackedMiner("uid-1", "hotkey-1", "shared-chip")
    declared_miner = EvidenceBackedMiner("uid-2", "hotkey-2", "shared-chip")
    _MINERS_BY_UID.clear()
    _MINERS_BY_UID.update({m.uid: m for m in (undeclared_miner, declared_miner)})

    def mixed_verifier(evidence: Evidence, nonce: bytes, policy: Policy) -> Attested | None:
        declared = _verifier(evidence, nonce, policy)
        if declared is None or not evidence.quote.endswith(b":uid-1"):
            return declared
        undeclared = Attested(
            declared.tier,
            declared.chip_id,
            declared.measurement,
            declared.tcb,
            assurance=declared.assurance,
        )
        assert undeclared.verification_status == "UNVERIFIED"
        assert undeclared.chain_verified is False
        return undeclared

    result = attested_epoch(
        [undeclared_miner, declared_miner],
        Policy(allowed_measurements={"tdx-measurement-1"}, min_tcb=7),
        routing={"sat_benchmark": 1.0},
        verifier=mixed_verifier,
    )

    assert result.admitted == ["uid-2"]
    assert set(result.weights) == {"uid-2"}


def test_mock_epoch_admits_declared_mock_verdict_and_refuses_an_undeclared_one():
    # verify_mock declares its verdict. A miner that serves the same verdict
    # without the two fields gets the fail-closed defaults and is refused, and
    # it does not reserve the chip it shares with the declared miner.
    @dataclass
    class UndeclaredMockMiner(MockMiner):
        def serve_evidence(self, nonce: bytes, policy: Policy) -> Attested | None:
            declared = super().serve_evidence(nonce, policy)
            assert declared is not None
            assert declared.verification_status == "VERIFIED"
            return Attested(
                declared.tier,
                declared.chip_id,
                declared.measurement,
                declared.tcb,
                assurance=declared.assurance,
            )

    miners = [
        UndeclaredMockMiner("uid-1", "hotkey-1", chip_id="shared-chip"),
        MockMiner("uid-2", "hotkey-2", chip_id="shared-chip"),
    ]

    result = epoch(
        miners,
        Policy(allowed_measurements={"mock-measurement-0"}, min_tcb=0),
        routing={"sat_benchmark": 1.0},
    )

    assert result.admitted == ["uid-2"]
    assert set(result.weights) == {"uid-2"}
