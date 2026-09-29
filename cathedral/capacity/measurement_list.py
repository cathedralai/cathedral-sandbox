"""The owner's signed measurement list, read from the signed policy registry.

Owner decision (2026-09-29, docs/TEE_BOX.md decision 4): the owner publishes
one signed measurement list, and validators, TEE box admission, routing and
the prober all consume it. It replaces each validator's local
cathedral-validator #256 file as the source of truth; during rollout that file
mirrors it (:func:`mirror_source`, ``cathedral policy-registry
export-measurement-policy``).

**The list is the existing signed policy registry** (``cathedral.policy_registry``,
docs/MRTD.md): Ed25519 signed by a pinned owner key, monotonic releases with a
durable high-water mark, and per-profile revocation. Nothing here signs or
verifies anything new. :func:`accept_release` verifies a release with the
trusted keys, validates its TEE box entries, and only then advances the
high-water state, so a stale, rolled-back, equivocated or badly signed release
never yields a policy.

**TEE box images** are marked in a profile's signed ``metadata`` (the registry
schema rejects unknown profile keys, so metadata is the backward-compatible
place: an older verifier still accepts the release). A ``cpu_tdx`` or
``cpu_snp`` profile whose metadata has a ``tee_box`` object is a TEE box
profile::

    "metadata": {"tee_box": {"schema": "cathedral_tee_box_images_v1",
                             "images": [<image>, ...]}}

A TDX image names the quote-body fields the Cathedral measurement covers,
except RTMR3, as lowercase hex (docs/MRTD.md)::

    {"id": "appliance-v3-c3-standard-176", "td_attributes": <16 hex>,
     "xfam": <16 hex>, "mrtd": <96 hex>, "mrconfigid": <96 hex>,
     "mrowner": <96 hex>, "mrownerconfig": <96 hex>,
     "rtmr0": <96 hex>, "rtmr1": <96 hex>, "rtmr2": <96 hex>}

and its two measurements are **derived**: RTMR3 all zero (a fresh boot) and
RTMR3 = ``RTMR3_CONSUMED`` (after the boot's one lease extend,
cathedral/tee_box/boot.py). The owner approves one image and both values
follow; they cannot be listed unpaired or mismatched. The profile's own
``measurements`` list must equal exactly the derived values of its images, so
the registry's other readers (``PolicyRegistrySnapshot.to_policy``, the
verifier's own allowlist) see the same set. A SEV-SNP image is
``{"id", "measurement": <96 hex>}``; SNP has no RTMR, so it has one value.

**Revocation.** Only profiles eligible at the evaluation time contribute
(``PolicyProfile.eligible_at``: active, or retiring before ``retire_at``, and
inside validity). A measurement listed by any ``revoked`` profile is excluded
even when another eligible profile lists it: revocation wins.

Admission (:func:`measurement_policy`) takes only TEE box profiles, so a worker
image approved for other CPU work is never admitted as a TEE box.

**Security controls.** A TEE box ``cpu_tdx`` profile is still a ``cpu_tdx``
profile: ``PolicyRegistrySnapshot.to_policy`` requires every eligible one to
share min_tcb, TCB statuses, advisories and firmware, and a release where it
raises is refused, so a box profile can never break worker admission. Those
controls are applied by the pinned verifier (:func:`verifier_policy`), not by
``admission.admit``, which takes the verifier's verdict and checks only that it
is a complete strict verification.

**MRCONFIGID.** Every TDX image must carry a central-access root binding
(``cathedral.tee_box.measured_root.root_digest_from_mrconfigid``:
SHA-256 of the root key file then 16 zero bytes, not zero), and
:func:`accept_release` can pin the expected root digest.

**Deny all.** An enforcing policy with nothing eligible (every box profile
revoked, say) lists one all-zero measurement (:data:`DENY_ALL`) instead of
failing: #256 refuses an empty enforcing list and stops validating when the
file is missing, while no quote has an all-zero measurement.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Callable, Mapping

from cathedral.capacity.admission import (
    MODES,
    POLICY_SCHEMAS,
    AdmissionError,
    MeasurementPolicy,
    parse_policy,
)
from cathedral.policy_registry import (
    PolicyProfile,
    PolicyRegistryError,
    PolicyRegistrySnapshot,
    PolicyRegistryState,
    verify_registry,
)
from cathedral.common import Policy
from cathedral.tee_box.boot import RTMR3_CONSUMED, RTMR3_FRESH
from cathedral.tee_box.measured_root import MeasuredRootError, root_digest_from_mrconfigid

TEE_BOX_METADATA_KEY = "tee_box"
TEE_BOX_SCHEMA = "cathedral_tee_box_images_v1"
MIRROR_SOURCE_SCHEMA = "cathedral_measurement_list_mirror_v1"
# The registry profile kind for each admission kind.
PROFILE_KINDS = {"tdx": "cpu_tdx", "sev_snp": "cpu_snp"}
MAX_IMAGES_PER_PROFILE = 256
# docs/MRTD.md, and cathedral/verify/tdx_quote.py ParsedTdxQuote.measurement.
TDX_MEASUREMENT_DOMAIN = b"cathedral-tdx-measurement-v1\0"
# The TDX image fields in measurement order, with their byte lengths; RTMR3 follows.
TDX_IMAGE_FIELDS = (
    ("td_attributes", 8),
    ("xfam", 8),
    ("mrtd", 48),
    ("mrconfigid", 48),
    ("mrowner", 48),
    ("mrownerconfig", 48),
    ("rtmr0", 48),
    ("rtmr1", 48),
    ("rtmr2", 48),
)
_TDX_IMAGE_KEYS = frozenset({"id", *(name for name, _ in TDX_IMAGE_FIELDS)})
_SNP_IMAGE_KEYS = frozenset({"id", "measurement"})
_TEE_BOX_KEYS = frozenset({"schema", "images"})
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SNP_MEASUREMENT = re.compile(r"[0-9a-f]{96}")
_TDX_DEBUG_BIT = 0x1  # TD_ATTRIBUTES bit 0, read little-endian as tdx_quote.py does
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
# What an enforcing policy lists when nothing is eligible: a well-formed value
# (#256 and parse_policy load it) that no SHA-256 or SHA-384 output will equal.
DENY_ALL = {"tdx": "tdx-measurement-sha256:" + "0" * 64, "sev_snp": "0" * 96}
SCOPES = ("box", "all")


class MeasurementListError(ValueError):
    """The signed measurement list is unusable: a malformed TEE box entry, or
    no policy can be derived from it."""


def tdx_measurement(fields: Mapping[str, bytes], rtmr3: bytes) -> str:
    """The Cathedral TDX measurement (docs/MRTD.md) of an image's fields with ``rtmr3``.

    SHA-256 over ``cathedral-tdx-measurement-v1\\0`` then TD_ATTRIBUTES, XFAM,
    MRTD, MRCONFIGID, MROWNER, MROWNERCONFIG and RTMR0-3: the value the pinned
    verifier emits and #256's ``reference_measurement`` computes."""

    digest = hashlib.sha256(TDX_MEASUREMENT_DOMAIN)
    for name, length in TDX_IMAGE_FIELDS:
        value = fields[name]
        if len(value) != length:
            raise MeasurementListError(f"{name} must be {length} bytes")
        digest.update(value)
    if len(rtmr3) != 48:
        raise MeasurementListError("rtmr3 must be 48 bytes")
    digest.update(rtmr3)
    return "tdx-measurement-sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class TeeBoxImage:
    """One approved TEE box image (and VM shape) from the signed list."""

    kind: str  # tdx or sev_snp
    profile_id: str
    image_id: str
    fresh: str  # TDX: RTMR3 all zero. SEV-SNP: the image's one measurement.
    consumed: str | None  # TDX: RTMR3 = RTMR3_CONSUMED. SEV-SNP: None.
    mrconfigid: str | None  # TDX: the central-access root binding (docs/TEE_BOX.md section 6)
    root_digest: str | None  # TDX: sha256:<hex> of the root key file MRCONFIGID binds

    @property
    def measurements(self) -> frozenset[str]:
        return frozenset(value for value in (self.fresh, self.consumed) if value is not None)


def _hex_field(image: Mapping[str, object], name: str, length: int, where: str) -> bytes:
    value = image[name]
    if not isinstance(value, str) or re.fullmatch(f"[0-9a-f]{{{2 * length}}}", value) is None:
        raise MeasurementListError(f"{where}: {name} must be {2 * length} lowercase hex")
    return bytes.fromhex(value)


def _profile_images(
    profile: PolicyProfile, expected_root_digest: str | None
) -> tuple[TeeBoxImage, ...] | None:
    """The profile's TEE box images, or None when it is not a TEE box profile.

    Raises :class:`MeasurementListError` when the ``tee_box`` object is
    malformed or the profile's measurements are not exactly its images'
    derived values."""

    marker = profile.metadata.get(TEE_BOX_METADATA_KEY)
    if marker is None:
        return None
    where = f"profile {profile.profile_id}"
    kinds = [kind for kind, name in PROFILE_KINDS.items() if name == profile.kind]
    if not kinds:
        raise MeasurementListError(f"{where}: a TEE box profile must be cpu_tdx or cpu_snp")
    kind = kinds[0]
    if not isinstance(marker, Mapping) or frozenset(marker) != _TEE_BOX_KEYS:
        raise MeasurementListError(f"{where}: tee_box must contain exactly schema and images")
    if marker["schema"] != TEE_BOX_SCHEMA:
        raise MeasurementListError(f"{where}: tee_box schema must be {TEE_BOX_SCHEMA}")
    raw_images = marker["images"]
    # Metadata lists are frozen to tuples by the registry parser.
    if not isinstance(raw_images, tuple) or not 1 <= len(raw_images) <= MAX_IMAGES_PER_PROFILE:
        raise MeasurementListError(
            f"{where}: tee_box images must be a list of 1 to {MAX_IMAGES_PER_PROFILE} entries"
        )
    images: list[TeeBoxImage] = []
    for raw in raw_images:
        expected_keys = _TDX_IMAGE_KEYS if kind == "tdx" else _SNP_IMAGE_KEYS
        if not isinstance(raw, Mapping) or frozenset(raw) != expected_keys:
            raise MeasurementListError(
                f"{where}: each {kind} image must contain exactly {sorted(expected_keys)}"
            )
        image_id = raw["id"]
        if not isinstance(image_id, str) or _ID_RE.fullmatch(image_id) is None:
            raise MeasurementListError(f"{where}: image id is invalid")
        at = f"{where} image {image_id}"
        if kind == "tdx":
            fields = {name: _hex_field(raw, name, length, at) for name, length in TDX_IMAGE_FIELDS}
            if int.from_bytes(fields["td_attributes"], "little") & _TDX_DEBUG_BIT:
                raise MeasurementListError(f"{at}: td_attributes has the debug bit set")
            try:
                root_digest = root_digest_from_mrconfigid(fields["mrconfigid"])
            except MeasuredRootError as exc:
                raise MeasurementListError(f"{at}: {exc}") from exc
            if expected_root_digest is not None and root_digest != expected_root_digest:
                raise MeasurementListError(
                    f"{at}: MRCONFIGID binds {root_digest}, not the pinned central root"
                )
            images.append(
                TeeBoxImage(
                    kind=kind,
                    profile_id=profile.profile_id,
                    image_id=image_id,
                    fresh=tdx_measurement(fields, RTMR3_FRESH),
                    consumed=tdx_measurement(fields, RTMR3_CONSUMED),
                    mrconfigid=fields["mrconfigid"].hex(),
                    root_digest=root_digest,
                )
            )
        else:
            measurement = raw["measurement"]
            if not isinstance(measurement, str) or _SNP_MEASUREMENT.fullmatch(measurement) is None:
                raise MeasurementListError(f"{at}: measurement must be 96 lowercase hex")
            images.append(
                TeeBoxImage(
                    kind=kind,
                    profile_id=profile.profile_id,
                    image_id=image_id,
                    fresh=measurement,
                    consumed=None,
                    mrconfigid=None,
                    root_digest=None,
                )
            )
    ids = [image.image_id for image in images]
    if len(set(ids)) != len(ids):
        raise MeasurementListError(f"{where}: image ids must be unique")
    derived = [value for image in images for value in sorted(image.measurements)]
    if len(set(derived)) != len(derived):
        raise MeasurementListError(f"{where}: two images give the same measurement")
    if set(profile.measurements) != set(derived):
        raise MeasurementListError(
            f"{where}: measurements must be exactly the images' derived values "
            "(for TDX, each image's fresh and consumed measurement)"
        )
    return tuple(images)


@dataclass(frozen=True)
class AcceptedRelease:
    """A registry release verified with the trusted owner keys and accepted by
    the durable high-water state. Only :func:`accept_release` makes one."""

    snapshot: PolicyRegistrySnapshot
    images: tuple[TeeBoxImage, ...]  # every TEE box profile's images, whatever its status
    # Set only by accept_release, as the registry marks a verified snapshot; a
    # constructed or dataclasses.replace()d copy is not accepted.
    _accepted: bool = field(default=False, init=False, repr=False, compare=False)

    @property
    def release(self) -> int:
        return self.snapshot.release

    @property
    def digest(self) -> str:
        return self.snapshot.digest


def accept_release(
    data: bytes | str,
    trusted_keys: Mapping[str, bytes],
    state: PolicyRegistryState,
    *,
    now: datetime | None = None,
    max_age_seconds: int = 86400,
    expected_root_digest: str | None = None,
    before_commit: Callable[[AcceptedRelease], None] | None = None,
) -> AcceptedRelease:
    """Verify one signed release and accept it into the high-water state.

    ``verify_registry`` checks the signature with ``trusted_keys`` (the pinned
    owner keys), the schema, validity and staleness. Every TEE box profile is
    then validated (:func:`_profile_images`; ``expected_root_digest`` pins the
    central root every TDX image's MRCONFIGID must bind), the eligible
    ``cpu_tdx`` profiles must still give a worker policy (``to_policy``), and
    only then does ``state.accept`` advance the durable high-water mark,
    refusing a lower release, an equivocated one, or an invalid profile
    transition. ``before_commit`` runs inside that transaction after every
    check, before the commit: a caller that writes files from the release
    does it there, so the high-water mark never moves past what it wrote, and
    if it raises nothing is recorded. A release this refuses leaves the state
    where it was. Raises ``PolicyRegistryError`` or
    :class:`MeasurementListError`."""

    if not isinstance(state, PolicyRegistryState):
        raise MeasurementListError("state must be the durable PolicyRegistryState")
    if expected_root_digest is not None and (
        not isinstance(expected_root_digest, str)
        or _DIGEST_RE.fullmatch(expected_root_digest) is None
    ):
        raise MeasurementListError("expected_root_digest must be sha256:<64 hex>")
    snapshot = verify_registry(data, trusted_keys, now=now, max_age_seconds=max_age_seconds)
    images: list[TeeBoxImage] = []
    for profile in snapshot.profiles:
        found = _profile_images(profile, expected_root_digest)
        if found is not None:
            images.extend(found)
    when = now or datetime.now(UTC)
    if any(
        profile.kind == "cpu_tdx" and profile.eligible_at(when) for profile in snapshot.profiles
    ):
        # A box profile whose controls differ from the worker profiles' would
        # make to_policy, and so every worker's admission, fail.
        try:
            snapshot.to_policy(at=when)
        except PolicyRegistryError as exc:
            raise MeasurementListError(
                f"the CPU TDX profiles give no worker policy: {exc}"
            ) from exc
    release = AcceptedRelease(snapshot=snapshot, images=tuple(images))
    object.__setattr__(release, "_accepted", True)
    state.accept(
        snapshot,
        before_commit=None if before_commit is None else lambda: before_commit(release),
    )
    return release


def _when(at: datetime | None) -> datetime:
    when = at or datetime.now(UTC)
    if when.tzinfo is None or when.utcoffset() != timedelta(0):
        raise MeasurementListError("the evaluation time must be UTC")
    return when


def verifier_policy(release: AcceptedRelease, *, at: datetime | None = None) -> Policy:
    """The pinned TDX verifier's strict ``Policy`` from the same release: its
    allowlist and the signed TCB status, advisory and firmware controls. The
    prober verifies a box's quote with it before calling ``admission.admit``."""

    _check(release, "tdx")
    return release.snapshot.to_policy(at=_when(at))


def _check(release: object, kind: object, mode: object = "shadow") -> None:
    _check_release(release)
    if kind not in PROFILE_KINDS:
        raise MeasurementListError(f"kind must be one of {sorted(PROFILE_KINDS)}")
    if mode not in MODES:
        raise MeasurementListError("mode must be shadow or enforce")


def _check_release(release: object) -> None:
    if (
        not isinstance(release, AcceptedRelease)
        or release._accepted is not True
        or not release.snapshot.signature_verified
    ):
        raise MeasurementListError("release must come from accept_release")


def eligible_images(
    release: AcceptedRelease, *, kind: str, at: datetime | None = None
) -> tuple[TeeBoxImage, ...]:
    """The TEE box images of ``kind`` that admission, routing and the prober
    accept at ``at`` (default now): from eligible profiles, and none a revoked
    profile lists."""

    _check(release, kind)
    when = _when(at)
    profiles = {profile.profile_id: profile for profile in release.snapshot.profiles}
    revoked = _revoked(release.snapshot)
    return tuple(
        image
        for image in release.images
        if image.kind == kind
        and profiles[image.profile_id].eligible_at(when)
        and not image.measurements & revoked
    )


def _revoked(snapshot: PolicyRegistrySnapshot) -> frozenset[str]:
    return frozenset(
        measurement
        for profile in snapshot.profiles
        if profile.status == "revoked"
        for measurement in profile.measurements
    )


def allowed_measurements(
    release: AcceptedRelease,
    *,
    kind: str,
    scope: str,
    at: datetime | None = None,
) -> tuple[str, ...]:
    """The sorted allowlist of ``kind`` at ``at``.

    ``scope="box"``: only TEE box images (both values of each TDX image).
    ``scope="all"``: also every other eligible profile of the kind, for the
    validator mirror while it still gates non-box miners. There is no default,
    so no caller drops the non-box miners by accident. Revoked measurements are
    excluded either way."""

    if scope not in SCOPES:
        raise MeasurementListError("scope must be box or all")
    images = eligible_images(release, kind=kind, at=at)
    values = {value for image in images for value in image.measurements}
    if scope == "all":
        when = _when(at)
        # TEE box profiles are already counted, image by image, above.
        box_profiles = {image.profile_id for image in release.images}
        values |= {
            measurement
            for profile in release.snapshot.profiles
            if profile.kind == PROFILE_KINDS[kind]
            and profile.profile_id not in box_profiles
            and profile.eligible_at(when)
            for measurement in profile.measurements
        }
        values -= _revoked(release.snapshot)
    return tuple(sorted(values))


def policy_bytes(
    release: AcceptedRelease,
    *,
    kind: str,
    mode: str,
    scope: str,
    at: datetime | None = None,
) -> bytes:
    """The measurement policy file for ``kind`` in #256's exact format.

    ``{"schema", "mode", "allowed_measurements"}`` and nothing else, so #256's
    strict loader reads it (TDX), as does ``admission.parse_policy`` (both
    kinds). The bytes are deterministic, so the policy digest #256 logs and the
    digest :func:`measurement_policy` hands admission are the same for the same
    release, kind, mode, scope and time. An enforcing policy with nothing
    eligible lists :data:`DENY_ALL` instead."""

    _check(release, kind, mode)
    allowed = list(allowed_measurements(release, kind=kind, scope=scope, at=at))
    if mode == "enforce" and not allowed:
        allowed = [DENY_ALL[kind]]
    document = {"schema": POLICY_SCHEMAS[kind], "mode": mode, "allowed_measurements": allowed}
    raw = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")
    try:
        parse_policy(raw)  # never emit a file admission or #256 would refuse
    except AdmissionError as exc:
        raise MeasurementListError(f"no usable {kind} policy: {exc}") from exc
    return raw


def measurement_policy(
    release: AcceptedRelease,
    *,
    kind: str,
    mode: str,
    at: datetime | None = None,
) -> MeasurementPolicy:
    """The ``MeasurementPolicy`` that ``admission.admit`` takes, from TEE box
    profiles only. It lists both values of each TDX image; ``admit(...,
    require_fresh_boot=True)`` is what refuses a consumed boot before a new
    customer, while the consumed value lets a mid-lease re-attestation match."""

    return parse_policy(policy_bytes(release, kind=kind, mode=mode, scope="box", at=at))


def mirror_source(
    release: AcceptedRelease, policy: bytes, *, kind: str, mode: str, scope: str
) -> bytes:
    """The provenance record written next to an exported policy file.

    #256's loader refuses any key beyond schema, mode and allowed_measurements,
    so the list's release and digest cannot go in the policy file itself. This
    record binds them to it by the policy file's SHA-256, which is the digest
    #256 logs and puts in its evidence (``policy_digest``), so a validator's
    reported digest names which signed release it mirrors."""

    _check(release, kind, mode)
    if scope not in SCOPES:
        raise MeasurementListError("scope must be box or all")
    if not isinstance(policy, bytes):
        raise MeasurementListError("policy must be bytes")
    snapshot = release.snapshot
    document = {
        "schema": MIRROR_SOURCE_SCHEMA,
        "kind": kind,
        "mode": mode,
        "scope": scope,
        "policy_digest": "sha256:" + hashlib.sha256(policy).hexdigest(),
        "registry_release": snapshot.release,
        "registry_digest": snapshot.digest,
        "registry_signing_key_id": snapshot.signing_key_id,
        "registry_generated_at": snapshot.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "registry_valid_until": snapshot.valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")


def check_mirror_floor(release: AcceptedRelease, source: bytes | None) -> None:
    """Refuse to mirror a release older than the one an existing source record names.

    The high-water state is the real guard; this one covers a mirror whose
    state file was lost or recreated, which would otherwise take any release
    still inside its validity. ``source`` is the existing
    ``<out>.source.json`` bytes, or None when there is none. A lower release,
    or the same release with another digest, is refused, and so is a record
    that cannot be read: remove it deliberately to start over."""

    _check_release(release)
    if source is None:
        return
    try:
        document = json.loads(source)
        prior_release = document["registry_release"]
        prior_digest = document["registry_digest"]
        if (
            document["schema"] != MIRROR_SOURCE_SCHEMA
            or isinstance(prior_release, bool)
            or not isinstance(prior_release, int)
            or not isinstance(prior_digest, str)
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError) as exc:
        raise MeasurementListError(
            "the existing mirror source record is unreadable; inspect and remove it to start over"
        ) from exc
    if release.release < prior_release:
        raise MeasurementListError(
            f"registry rollback rejected: the mirror already holds release {prior_release}"
        )
    if release.release == prior_release and release.digest != prior_digest:
        raise MeasurementListError(
            f"registry release {prior_release} was equivocated: the mirror holds another digest"
        )


__all__ = [
    "MIRROR_SOURCE_SCHEMA",
    "PROFILE_KINDS",
    "TEE_BOX_METADATA_KEY",
    "TEE_BOX_SCHEMA",
    "DENY_ALL",
    "SCOPES",
    "AcceptedRelease",
    "MeasurementListError",
    "PolicyRegistryError",
    "TeeBoxImage",
    "accept_release",
    "allowed_measurements",
    "check_mirror_floor",
    "eligible_images",
    "measurement_policy",
    "mirror_source",
    "policy_bytes",
    "tdx_measurement",
    "verifier_policy",
]
