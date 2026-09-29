"""The owner's signed measurement list (cathedral/capacity/measurement_list.py).

One signed policy-registry release gives TEE box admission its measurement
policy and the validator's #256 mirror file. See docs/MRTD.md, "The TEE box
measurement list".
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.capacity import admission as adm
from cathedral.capacity import measurement_list as ml
from cathedral.policy_registry import (
    PolicyRegistryError,
    PolicyRegistryState,
    canonical_json,
    sign_registry,
)
from cathedral.tee_box.boot import LEASE_EVENT, RTMR3_CONSUMED
from cathedral.verify.tdx_quote import parse_tdx_quote
from tests.test_tee_admission import CONSUMED_QUOTE, FRESH_QUOTE, _admit, _snp, _snp_report, _tdx

SEED = bytes(range(32))
PUBLIC = (
    Ed25519PrivateKey.from_private_bytes(SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
)
KEY_ID = "cathedral-owner-test-1"
TRUSTED = {KEY_ID: PUBLIC}
OTHER_SEED = bytes(range(1, 33))
NOW = datetime(2026, 9, 29, 12, 0, 0, tzinfo=UTC)
VALID_FROM = "2026-09-29T00:00:00Z"
VALID_UNTIL = "2026-10-06T00:00:00Z"

# The fields of tests/tdx_quote_fixtures.py's synthetic quote, so a derived value
# can be compared with a real parsed quote's measurement.
IMAGE: dict[str, str] = {
    "id": "appliance-v1-c3-176",
    "td_attributes": "54" * 8,
    "xfam": "58" * 8,
    "mrtd": "4d" * 48,
    "mrconfigid": "43" * 48,
    "mrowner": "4f" * 48,
    "mrownerconfig": "6f" * 48,
    "rtmr0": "30" * 48,
    "rtmr1": "31" * 48,
    "rtmr2": "32" * 48,
}
OTHER_IMAGE = {**IMAGE, "id": "appliance-v1-c3-88", "rtmr0": "a0" * 48}  # another VM shape
WORKER_MEASUREMENT = "tdx-measurement-sha256:" + "77" * 32  # a non-box CPU worker image
SNP_IMAGE = {"id": "appliance-snp-v1", "measurement": "c3" * 48}


def _reference_measurement(image: dict[str, str], rtmr3: bytes) -> str:
    """cathedral-validator #256 ``reference_measurement``, written out."""

    names = ("td_attributes", "xfam", "mrtd", "mrconfigid", "mrowner", "mrownerconfig")
    fields = [bytes.fromhex(image[name]) for name in names]
    fields += [bytes.fromhex(image[f"rtmr{index}"]) for index in range(3)] + [rtmr3]
    body = b"cathedral-tdx-measurement-v1\0" + b"".join(fields)
    return "tdx-measurement-sha256:" + hashlib.sha256(body).hexdigest()


def _pair(image: dict[str, str]) -> list[str]:
    return sorted(
        [_reference_measurement(image, bytes(48)), _reference_measurement(image, RTMR3_CONSUMED)]
    )


def _profile(
    profile_id: str,
    *,
    kind: str = "cpu_tdx",
    images: list[dict[str, str]] | None = None,
    measurements: list[str] | None = None,
    status: str = "active",
    status_changed_at: str = VALID_FROM,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"description": profile_id}
    if images is not None:
        metadata["tee_box"] = {"schema": ml.TEE_BOX_SCHEMA, "images": images}
        if measurements is None:
            if kind == "cpu_tdx":
                measurements = [value for image in images for value in _pair(image)]
            else:
                measurements = [image["measurement"] for image in images]
    return {
        "id": profile_id,
        "kind": kind,
        "status": status,
        "status_changed_at": status_changed_at,
        "valid_from": VALID_FROM,
        "valid_until": VALID_UNTIL,
        "retire_at": status_changed_at if status in {"retired", "revoked"} else None,
        "measurements": measurements or [WORKER_MEASUREMENT],
        "runtime_measurements": [],
        "allowed_firmware": [],
        "min_tcb": 0,
        "tdx_allowed_tcb_statuses": ["UpToDate"] if kind == "cpu_tdx" else [],
        "tdx_allowed_advisories": [],
        "metadata": metadata,
    }


def _box_profile(**changes) -> dict[str, Any]:
    return _profile("tee-box-tdx-v1", images=[IMAGE], **changes)


def _registry(
    profiles: list[dict[str, Any]] | None = None,
    *,
    release: int = 1,
    generated_at: str = "2026-09-29T11:00:00Z",
    seed: bytes = SEED,
) -> bytes:
    document = {
        "schema": "cathedral_policy_registry_v1",
        "release": release,
        "generated_at": generated_at,
        "valid_from": VALID_FROM,
        "valid_until": VALID_UNTIL,
        "signing_key_id": KEY_ID,
        "receipt_signing_keys": [],
        "profiles": profiles if profiles is not None else [_box_profile()],
        "metadata": {"purpose": "tee box measurement list test"},
    }
    return canonical_json(sign_registry(document, seed))


def _state(tmp_path, name: str = "state.sqlite3") -> PolicyRegistryState:
    return PolicyRegistryState(tmp_path / name, production_mode=True, minimum_release=1)


def _accept(tmp_path, data: bytes | None = None, *, state=None, now=NOW) -> ml.AcceptedRelease:
    return ml.accept_release(
        _registry() if data is None else data, TRUSTED, state or _state(tmp_path), now=now
    )


# -- the derived pair --------------------------------------------------------------------


def test_the_derived_values_are_the_verifier_measurements_of_fresh_and_consumed_quotes():
    fresh, consumed = _accept_images_once()
    assert fresh == parse_tdx_quote(FRESH_QUOTE).measurement
    assert consumed == parse_tdx_quote(CONSUMED_QUOTE).measurement
    assert [fresh, consumed] == [
        _reference_measurement(IMAGE, bytes(48)),
        _reference_measurement(IMAGE, RTMR3_CONSUMED),
    ]


def _accept_images_once() -> tuple[str, str]:
    fields = {name: bytes.fromhex(IMAGE[name]) for name, _ in ml.TDX_IMAGE_FIELDS}
    return ml.tdx_measurement(fields, bytes(48)), ml.tdx_measurement(fields, RTMR3_CONSUMED)


def test_the_consumed_rtmr3_is_one_extend_of_the_lease_event():
    event = hashlib.sha384(LEASE_EVENT).digest()
    assert LEASE_EVENT == b"cathedral tee-box lease granted v1"
    assert hashlib.sha384(bytes(48) + event).digest() == RTMR3_CONSUMED


def test_a_release_carries_each_image_with_both_values(tmp_path):
    release = _accept(tmp_path, _registry([_profile("box", images=[IMAGE, OTHER_IMAGE])]))
    images = ml.eligible_images(release, kind="tdx", at=NOW)
    assert [image.image_id for image in images] == [IMAGE["id"], OTHER_IMAGE["id"]]
    fresh, consumed = _accept_images_once()
    assert (images[0].fresh, images[0].consumed) == (fresh, consumed)
    assert images[0].mrconfigid == IMAGE["mrconfigid"]
    assert images[1].fresh != fresh  # another shape, another value


@pytest.mark.parametrize(
    "measurements",
    [
        lambda pair: pair[:1],  # the consumed value missing
        lambda pair: pair[1:],  # the fresh value missing
        lambda pair: pair + [WORKER_MEASUREMENT],  # an unpaired extra value
        lambda pair: [WORKER_MEASUREMENT, pair[1]],  # a value that is not the image's
    ],
    ids=["no-consumed", "no-fresh", "extra", "mismatched"],
)
def test_a_box_profile_whose_measurements_are_not_its_derived_pair_is_refused(
    tmp_path, measurements
):
    profile = _box_profile(measurements=measurements(_pair(IMAGE)))
    state = _state(tmp_path)
    with pytest.raises(ml.MeasurementListError, match="exactly the images' derived values"):
        _accept(tmp_path, _registry([profile]), state=state)
    assert state.current() is None  # the high-water mark did not move


def _with_image(**changes) -> dict[str, Any]:
    image = {**IMAGE, **changes}
    return _profile("tee-box-tdx-v1", images=[image], measurements=_pair(IMAGE))


@pytest.mark.parametrize(
    ("profile", "message"),
    [
        (_with_image(mrtd="4D" * 48), "mrtd must be 96 lowercase hex"),
        (_with_image(rtmr2="32" * 47), "rtmr2 must be 96 lowercase hex"),
        (_with_image(td_attributes="55" + "54" * 7), "debug bit"),
        (_with_image(id="Bad Id"), "image id is invalid"),
        (_with_image(rtmr3="00" * 48), "must contain exactly"),
        (_profile("box", images=[IMAGE, IMAGE], measurements=_pair(IMAGE)), "ids must be unique"),
        (
            _profile("box", images=[IMAGE, {**IMAGE, "id": "copy"}], measurements=_pair(IMAGE)),
            "same measurement",
        ),
        (_profile("box", images=[]), "1 to 256"),
        (
            _profile("box", kind="gpu_cc", images=[IMAGE], measurements=_pair(IMAGE)),
            "cpu_tdx or cpu_snp",
        ),
        (
            _profile("box", kind="cpu_snp", images=[IMAGE], measurements=["c3" * 48]),
            "must contain exactly",
        ),
        (
            _profile("box", kind="cpu_snp", images=[{**SNP_IMAGE, "measurement": "c3" * 32}]),
            "96 lowercase hex",
        ),
    ],
    ids=[
        "upper-hex",
        "short",
        "debug",
        "bad-id",
        "listed-rtmr3",
        "duplicate-id",
        "same-value",
        "no-images",
        "gpu",
        "tdx-image-in-snp",
        "snp-short",
    ],
)
def test_a_malformed_box_entry_is_refused(tmp_path, profile, message):
    with pytest.raises(ml.MeasurementListError, match=message):
        _accept(tmp_path, _registry([profile]))


@pytest.mark.parametrize(
    "marker",
    [
        {"schema": "cathedral_tee_box_images_v2", "images": [IMAGE]},
        {"schema": ml.TEE_BOX_SCHEMA, "images": [IMAGE], "mode": "enforce"},
        {"images": [IMAGE]},
        "yes",
    ],
    ids=["schema", "extra-key", "no-schema", "not-object"],
)
def test_a_malformed_tee_box_marker_is_refused(tmp_path, marker):
    profile = _box_profile()
    profile["metadata"]["tee_box"] = marker
    with pytest.raises(ml.MeasurementListError, match="tee_box"):
        _accept(tmp_path, _registry([profile]))


# -- the admission policy ----------------------------------------------------------------


def test_a_verified_release_gives_the_admit_policy(tmp_path):
    release = _accept(tmp_path)
    policy = ml.measurement_policy(release, kind="tdx", mode="enforce", at=NOW)
    assert policy.kind == "tdx"
    assert policy.mode == "enforce"
    assert policy.allowed_measurements == frozenset(_pair(IMAGE))
    raw = ml.policy_bytes(release, kind="tdx", mode="enforce", at=NOW)
    assert policy.digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert (release.release, release.digest) == (
        1,
        "sha256:" + hashlib.sha256(_registry()).hexdigest(),
    )


def test_admission_with_the_list_admits_a_fresh_boot_and_a_mid_lease_reattestation(tmp_path):
    policy = ml.measurement_policy(_accept(tmp_path), kind="tdx", mode="enforce", at=NOW)
    fresh = _admit(_tdx(FRESH_QUOTE), policy=policy, require_fresh_boot=True)
    assert fresh.admitted and fresh.measurement_allowed
    assert fresh.policy_digest == policy.digest
    # Mid-lease, the prober's re-attestation carries the consumed value: listed, paid.
    lease = _admit(_tdx(CONSUMED_QUOTE), policy=policy)
    assert lease.admitted and lease.measurement_allowed and lease.evidence is not None
    # Before a new customer the consumed boot is still refused by RTMR3.
    reuse = _admit(_tdx(CONSUMED_QUOTE), policy=policy, require_fresh_boot=True)
    assert reuse.reasons == (adm.BOOT_CONSUMED,)
    # Another image is not on the list.
    other = _admit(_tdx(), policy=policy)  # the fixture's RTMR3 is neither value
    assert other.reasons == (adm.MEASUREMENT_NOT_ALLOWED,)


def test_a_worker_profile_is_not_a_tee_box_image(tmp_path):
    release = _accept(tmp_path, _registry([_box_profile(), _profile("cpu-worker-v1")]))
    policy = ml.measurement_policy(release, kind="tdx", mode="enforce", at=NOW)
    assert WORKER_MEASUREMENT not in policy.allowed_measurements
    everything = ml.allowed_measurements(release, kind="tdx", at=NOW, all_profiles=True)
    assert set(everything) == set(_pair(IMAGE)) | {WORKER_MEASUREMENT}


def test_a_snp_box_image_gives_the_snp_policy(tmp_path):
    profile = _profile("tee-box-snp-v1", kind="cpu_snp", images=[SNP_IMAGE])
    release = _accept(tmp_path, _registry([_box_profile(), profile]))
    policy = ml.measurement_policy(release, kind="sev_snp", mode="enforce", at=NOW)
    assert policy.allowed_measurements == frozenset({SNP_IMAGE["measurement"]})
    (image,) = ml.eligible_images(release, kind="sev_snp", at=NOW)
    assert image.consumed is None and image.mrconfigid is None
    admitted = _admit(_snp(_snp_report(measurement=SNP_IMAGE["measurement"])), policy=policy)
    assert admitted.admitted
    tdx = ml.measurement_policy(release, kind="tdx", mode="enforce", at=NOW)
    assert SNP_IMAGE["measurement"] not in tdx.allowed_measurements


def test_enforce_with_nothing_eligible_is_refused_and_shadow_lists_nothing(tmp_path):
    release = _accept(tmp_path, _registry([_profile("cpu-worker-v1")]))
    with pytest.raises(ml.MeasurementListError, match="at least one measurement"):
        ml.measurement_policy(release, kind="tdx", mode="enforce", at=NOW)
    shadow = ml.measurement_policy(release, kind="tdx", mode="shadow", at=NOW)
    assert shadow.allowed_measurements == frozenset()


def test_an_expired_or_not_yet_valid_profile_contributes_nothing(tmp_path):
    release = _accept(tmp_path)
    late = datetime(2026, 10, 6, 0, 0, 0, tzinfo=UTC)
    assert ml.eligible_images(release, kind="tdx", at=late) == ()
    early = datetime(2026, 9, 28, 23, 59, 59, tzinfo=UTC)
    assert ml.eligible_images(release, kind="tdx", at=early) == ()
    with pytest.raises(ml.MeasurementListError, match="UTC"):
        ml.eligible_images(release, kind="tdx", at=datetime(2026, 9, 29, 12))


def test_only_accept_release_makes_an_accepted_release(tmp_path):
    release = _accept(tmp_path)
    made = ml.AcceptedRelease(snapshot=release.snapshot, images=release.images)
    for copy in (made, dataclasses.replace(release, images=()), release.snapshot):
        with pytest.raises(ml.MeasurementListError, match="from accept_release"):
            ml.measurement_policy(copy, kind="tdx", mode="enforce", at=NOW)  # type: ignore[arg-type]
    with pytest.raises(ml.MeasurementListError, match="durable PolicyRegistryState"):
        ml.accept_release(_registry(), TRUSTED, None, now=NOW)  # type: ignore[arg-type]


# -- revocation ---------------------------------------------------------------------------


def _revoked_at(changed: str = "2026-09-29T11:30:00Z", **changes) -> dict[str, Any]:
    return _box_profile(status="revoked", status_changed_at=changed, **changes)


def test_a_revoked_image_is_excluded(tmp_path):
    state = _state(tmp_path)
    first = _registry([_box_profile(), _profile("box-v2", images=[OTHER_IMAGE])])
    before = _accept(tmp_path, first, state=state)
    assert len(ml.eligible_images(before, kind="tdx", at=NOW)) == 2
    second = _registry(
        [_revoked_at(), _profile("box-v2", images=[OTHER_IMAGE])],
        release=2,
        generated_at="2026-09-29T11:45:00Z",
    )
    after = _accept(tmp_path, second, state=state)
    policy = ml.measurement_policy(after, kind="tdx", mode="enforce", at=NOW)
    assert policy.allowed_measurements == frozenset(_pair(OTHER_IMAGE))
    assert not policy.allowed_measurements & set(_pair(IMAGE))
    result = _admit(_tdx(FRESH_QUOTE), policy=policy, require_fresh_boot=True)
    assert result.reasons == (adm.MEASUREMENT_NOT_ALLOWED,)


def test_revocation_wins_over_another_profile_listing_the_same_image(tmp_path):
    again = _profile("box-again", images=[{**IMAGE, "id": "again"}])
    worker = _profile("cpu-worker-v1", measurements=[_pair(IMAGE)[0]])
    release = _accept(tmp_path, _registry([_revoked_at(), again, worker]))
    assert ml.eligible_images(release, kind="tdx", at=NOW) == ()
    assert ml.allowed_measurements(release, kind="tdx", at=NOW, all_profiles=True) == ()


def test_revoking_one_value_of_an_image_revokes_the_whole_image(tmp_path):
    consumed = _reference_measurement(IMAGE, RTMR3_CONSUMED)
    revoked = _profile(
        "cpu-worker-v1",
        measurements=[consumed],
        status="revoked",
        status_changed_at="2026-09-29T11:30:00Z",
    )
    release = _accept(tmp_path, _registry([_box_profile(), revoked]))
    assert ml.eligible_images(release, kind="tdx", at=NOW) == ()
    assert ml.allowed_measurements(release, kind="tdx", at=NOW, all_profiles=True) == ()


def test_a_retired_profile_contributes_nothing(tmp_path):
    retired = _box_profile(status="retired", status_changed_at="2026-09-29T11:30:00Z")
    release = _accept(tmp_path, _registry([retired, _profile("box-v2", images=[OTHER_IMAGE])]))
    assert [image.profile_id for image in ml.eligible_images(release, kind="tdx", at=NOW)] == [
        "box-v2"
    ]


# -- signature and high water -------------------------------------------------------------


def test_a_lower_release_is_refused_and_the_high_water_holds(tmp_path):
    state = _state(tmp_path)
    _accept(tmp_path, _registry(release=5), state=state)
    with pytest.raises(PolicyRegistryError, match="rollback"):
        _accept(tmp_path, _registry(release=4), state=state)
    assert state.current()["release"] == 5
    # An equal release with other contents is equivocation.
    other = _registry([_profile("box", images=[OTHER_IMAGE])], release=5)
    with pytest.raises(PolicyRegistryError, match="equivocated"):
        _accept(tmp_path, other, state=state)


def test_a_release_below_the_configured_minimum_is_refused(tmp_path):
    state = PolicyRegistryState(tmp_path / "s", production_mode=True, minimum_release=3)
    with pytest.raises(PolicyRegistryError, match="minimum"):
        _accept(tmp_path, _registry(release=2), state=state)


def test_a_bad_signature_is_refused(tmp_path):
    state = _state(tmp_path)
    document = json.loads(_registry())
    document["profiles"][0]["metadata"]["tee_box"]["images"][0]["rtmr1"] = "99" * 48
    with pytest.raises(PolicyRegistryError, match="signature verification failed"):
        _accept(tmp_path, canonical_json(document), state=state)
    with pytest.raises(PolicyRegistryError, match="signature verification failed"):
        _accept(tmp_path, _registry(seed=OTHER_SEED), state=state)
    with pytest.raises(PolicyRegistryError, match="not trusted"):
        ml.accept_release(_registry(), {}, state, now=NOW)
    assert state.current() is None


def test_a_stale_release_is_refused(tmp_path):
    with pytest.raises(PolicyRegistryError, match="too stale"):
        _accept(tmp_path, now=NOW + timedelta(days=2))


# -- the validator mirror -----------------------------------------------------------------

_256_MEASUREMENT = re.compile(r"tdx-measurement-sha256:[0-9a-f]{64}")


def _load_like_256(raw: bytes) -> tuple[str, frozenset[str], str]:
    """cathedral-validator #256's ``load_tdx_measurement_policy`` format checks
    (cathedral_thin/independent_runtime/tdx_measurement.py at 14e2370), vendored:
    this repository cannot import the validator. The owner/mode/size file checks
    of its ``read_owner_policy_file`` are the caller's, covered by the file mode
    test below."""

    def strict(pairs):
        seen: dict[str, Any] = {}
        for key, value in pairs:
            assert key not in seen, "repeats a JSON key"
            seen[key] = value
        return seen

    assert len(raw) <= 128 * 1024
    document = json.loads(raw, object_pairs_hook=strict)
    assert isinstance(document, dict)
    assert set(document) == {"schema", "mode", "allowed_measurements"}
    assert document["schema"] == "cathedral_tdx_measurement_policy_v1"
    assert document["mode"] in ("shadow", "enforce")
    measurements = document["allowed_measurements"]
    assert isinstance(measurements, list)
    assert all(isinstance(item, str) and _256_MEASUREMENT.fullmatch(item) for item in measurements)
    assert measurements == sorted(measurements) and len(set(measurements)) == len(measurements)
    assert document["mode"] != "enforce" or measurements
    return document["mode"], frozenset(measurements), "sha256:" + hashlib.sha256(raw).hexdigest()


def test_the_export_round_trips_through_the_256_format(tmp_path):
    release = _accept(tmp_path, _registry([_profile("box", images=[IMAGE, OTHER_IMAGE])]))
    raw = ml.policy_bytes(release, kind="tdx", mode="shadow", at=NOW)
    mode, allowed, digest = _load_like_256(raw)
    assert mode == "shadow"
    assert allowed == frozenset(_pair(IMAGE) + _pair(OTHER_IMAGE))
    assert adm.parse_policy(raw).digest == digest
    assert ml.policy_bytes(release, kind="tdx", mode="shadow", at=NOW) == raw  # deterministic


def test_the_mirror_source_names_the_release_and_binds_the_policy_file(tmp_path):
    release = _accept(tmp_path, _registry(release=7))
    raw = ml.policy_bytes(release, kind="tdx", mode="enforce", at=NOW)
    source = json.loads(ml.mirror_source(release, raw, kind="tdx", mode="enforce"))
    assert source == {
        "schema": ml.MIRROR_SOURCE_SCHEMA,
        "kind": "tdx",
        "mode": "enforce",
        "policy_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "registry_release": 7,
        "registry_digest": release.digest,
        "registry_signing_key_id": KEY_ID,
        "registry_generated_at": "2026-09-29T11:00:00Z",
        "registry_valid_until": VALID_UNTIL,
    }


def test_the_registry_profile_schema_is_unchanged():
    # The extension lives in signed profile metadata, so a release with TEE box
    # entries still verifies with an unchanged registry verifier.
    profile = deepcopy(_box_profile())
    assert set(profile) == {
        "id",
        "kind",
        "status",
        "status_changed_at",
        "valid_from",
        "valid_until",
        "retire_at",
        "measurements",
        "runtime_measurements",
        "allowed_firmware",
        "min_tcb",
        "tdx_allowed_tcb_statuses",
        "tdx_allowed_advisories",
        "metadata",
    }
