"""Shared TDX/SNP root-bind honesty for admit."""

from __future__ import annotations

import hashlib

import pytest

from cathedral.capacity import admission as adm
from cathedral.capacity import tee_honesty
from cathedral.tee_box.measured_root import host_data_for_root_keys, mrconfigid_for_root_keys
from tests.test_tee_admission import (
    _admit,
    _policy,
    _snp,
    _snp_report,
    _tdx,
    _tdx_quote,
)
from cathedral.verify import snp
from cathedral.verify.tdx_quote import parse_tdx_quote


ROOT_BYTES = b'{"keys":["test-central-root"]}'
ROOT_DIGEST = "sha256:" + hashlib.sha256(ROOT_BYTES).hexdigest()
HOST_DATA = host_data_for_root_keys(ROOT_BYTES)
MRCONFIGID = mrconfigid_for_root_keys(ROOT_BYTES)


def _snp_with_host_data(host_data: bytes = HOST_DATA):
    report = bytearray(_snp_report())
    report[snp.HOST_DATA_OFFSET : snp.HOST_DATA_OFFSET + snp.HOST_DATA_SIZE] = host_data
    return _snp(bytes(report))


def _tdx_with_mrconfigid(mrconfigid: bytes = MRCONFIGID):
    return _tdx(_tdx_quote(mr_config_id=mrconfigid))


def _tdx_policy_for(quote: bytes):
    return _policy("tdx", allowed=[parse_tdx_quote(quote).measurement])


def test_snp_root_bind_matches():
    assert tee_honesty.quote_root_digest("sev_snp", _snp_with_host_data()[1]) == ROOT_DIGEST
    assert (
        tee_honesty.check_root_binding("sev_snp", _snp_with_host_data()[1], ROOT_DIGEST) is None
    )


def test_tdx_root_bind_matches():
    assert tee_honesty.quote_root_digest("tdx", _tdx_with_mrconfigid()[1]) == ROOT_DIGEST
    assert tee_honesty.check_root_binding("tdx", _tdx_with_mrconfigid()[1], ROOT_DIGEST) is None


def test_admit_snp_refuses_wrong_root():
    result = _admit(
        _snp_with_host_data(b"\x11" * 32),
        policy=_policy("sev_snp"),
        expected_root_digest=ROOT_DIGEST,
    )
    assert not result.admitted
    assert tee_honesty.ROOT_BINDING_MISMATCH in result.reasons


def test_admit_snp_accepts_matching_root():
    result = _admit(
        _snp_with_host_data(),
        policy=_policy("sev_snp"),
        expected_root_digest=ROOT_DIGEST,
    )
    assert result.admitted


def test_admit_tdx_accepts_matching_root():
    pair = _tdx_with_mrconfigid()
    result = _admit(
        pair,
        policy=_tdx_policy_for(pair[1]),
        expected_root_digest=ROOT_DIGEST,
    )
    assert result.admitted


def test_admit_tdx_refuses_zero_root_when_pinned():
    pair = _tdx(_tdx_quote(mr_config_id=bytes(48)))
    result = _admit(
        pair,
        policy=_tdx_policy_for(pair[1]),
        expected_root_digest=ROOT_DIGEST,
    )
    assert not result.admitted
    assert tee_honesty.ROOT_BINDING_ZERO in result.reasons


def test_admit_without_pin_still_works_legacy():
    # Default synthetic quotes have non-official MRCONFIGID / zero HOST_DATA.
    assert _admit(_tdx()).admitted
    assert _admit(_snp(), policy=_policy("sev_snp")).admitted


def test_malformed_pin_is_error():
    with pytest.raises(adm.AdmissionError, match="expected_root_digest"):
        _admit(_snp(), policy=_policy("sev_snp"), expected_root_digest="not-a-digest")
