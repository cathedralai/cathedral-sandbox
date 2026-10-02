"""The v2 TDX image identity (docs/MRTD.md, "Image identity"; cathedral-sandbox #265).

On GCP the host sets MROWNER per VM, so the v1 ``tdx-measurement-sha256``
value differs between two honest VMs booted from one image. The v2
``tdx-image-sha256`` value leaves out the launcher-set fields (MRCONFIGID,
MROWNER, MROWNERCONFIG). The fixture quotes are real GCP TDX quotes; the Go
verifier's tests read the same files and vectors
(cmd/cathedral-tdx-verifier/image_identity_test.go).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cathedral.verify.tdx_quote import QUOTE_HEADER_SIZE, parse_tdx_quote

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "cmd" / "cathedral-tdx-verifier" / "testdata" / "gcp-mrowner"
VECTORS = json.loads((FIXTURES / "vectors.json").read_text())["vectors"]

# Body offsets (cathedral/verify/tdx_quote.py _parse_body), into the raw quote.
_FIELDS = {
    "td_attributes": (120, 8),
    "xfam": (128, 8),
    "mr_td": (136, 48),
    "mr_config_id": (184, 48),
    "mr_owner": (232, 48),
    "mr_owner_config": (280, 48),
    "rtmr0": (328, 48),
    "rtmr1": (376, 48),
    "rtmr2": (424, 48),
    "rtmr3": (472, 48),
}


def _quote(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _flip(raw: bytes, field: str) -> bytes:
    offset, _ = _FIELDS[field]
    out = bytearray(raw)
    out[QUOTE_HEADER_SIZE + offset] ^= 0x01
    return bytes(out)


def test_contract_vector_matches_go():
    # Same body as cmd/cathedral-tdx-verifier TestImageMeasurementMatchesPythonContractVector.
    body = b"T" * 8 + b"X" * 8 + b"M" * 48 + b"0" * 48 + b"1" * 48 + b"2" * 48 + b"3" * 48
    want = hashlib.sha256(b"cathedral-tdx-image-v1\0" + body).hexdigest()
    assert want == "5c1e249b50fa545864ca0f4e3f58c7c40114fb4afa7e59ac79714f9c5bb3856c"
    from tests.tdx_quote_fixtures import synthetic_tdx_quote

    parsed = parse_tdx_quote(synthetic_tdx_quote(report_data=bytes(64)))
    assert parsed.image_measurement == "tdx-image-sha256:" + want
    # The v1 contract vector is unchanged.
    assert parsed.measurement == (
        "tdx-measurement-sha256:b3cf84af07e6fb79dce23c46eef78eb627b39989814fcf1b6ea42fd93fea1585"
    )


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["quote"])
def test_fixture_vectors(vector):
    parsed = parse_tdx_quote(_quote(vector["quote"]))
    assert parsed.measurement == vector["measurement"]
    assert parsed.image_measurement == vector["image_measurement"]
    assert parsed.body.mr_owner.hex() == vector["mr_owner"]


@pytest.mark.parametrize(
    "pair", [("same-image-a", "same-image-b"), ("clean-image-a", "clean-image-b")]
)
def test_two_honest_vms_from_one_image_share_v2_but_not_v1(pair):
    a, b = (parse_tdx_quote(_quote(name + ".bin")) for name in pair)
    assert a.body.mr_owner != b.body.mr_owner  # host-set, per VM
    assert a.measurement != b.measurement  # so v1 is per instance
    assert a.image_measurement == b.image_measurement  # and v2 is the image


def test_a_changed_kernel_cmdline_changes_v2():
    same = parse_tdx_quote(_quote("same-image-a.bin"))
    changed = parse_tdx_quote(_quote("cmdline-changed.bin"))
    assert same.body.rtmr1 != changed.body.rtmr1
    assert same.image_measurement != changed.image_measurement


@pytest.mark.parametrize("field", ["mr_config_id", "mr_owner", "mr_owner_config"])
def test_launcher_set_fields_change_v1_only(field):
    raw = _quote("same-image-a.bin")
    base, flipped = parse_tdx_quote(raw), parse_tdx_quote(_flip(raw, field))
    assert flipped.measurement != base.measurement
    assert flipped.image_measurement == base.image_measurement


@pytest.mark.parametrize(
    "field", ["td_attributes", "xfam", "mr_td", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
)
def test_guest_measured_fields_change_v2(field):
    raw = _quote("same-image-a.bin")
    base, flipped = parse_tdx_quote(raw), parse_tdx_quote(_flip(raw, field))
    assert flipped.image_measurement != base.image_measurement
    assert flipped.measurement != base.measurement


def test_v1_and_v2_never_collide():
    parsed = parse_tdx_quote(_quote("same-image-a.bin"))
    assert parsed.image_measurement.startswith("tdx-image-sha256:")
    assert parsed.measurement.startswith("tdx-measurement-sha256:")
    assert parsed.measurement.rpartition(":")[2] != parsed.image_measurement.rpartition(":")[2]
