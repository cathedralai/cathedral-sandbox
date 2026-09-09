"""Signed miner release record checks.

The property that matters most here is artifact identity: a validator release
record must be structurally incapable of installing as a miner release, even
when it is correctly signed by a key the host happens to trust.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.miner_release import (
    CANONICAL_IMAGE_REPOSITORY,
    MAX_RELEASE_DOCUMENT_BYTES,
    MINER_RELEASE_SCHEMA,
    SN39_SNP_MINER_PRODUCT,
    MinerReleaseError,
    enforce_monotonic_release,
    parse_miner_release,
)
from cathedral.policy_registry import canonical_signed_bytes

KEY_ID = "sn39-miner-release-1"
IMAGE_DIGEST = "0dc8db081dc35a993e8d59936c3ad036b39e68da84751282d9bba4ef16db2255"
LAUNCHER_DIGEST = "a" * 64
RUNTIME_CONTRACT = "snp-signed-validator-fleet-v1"


@pytest.fixture()
def signing_key() -> Ed25519PrivateKey:
    # Deterministic so a failure is reproducible from the test alone.
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.fixture()
def trusted(signing_key: Ed25519PrivateKey) -> dict[str, bytes]:
    from cryptography.hazmat.primitives import serialization

    public = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {KEY_ID: public}


def canary_document() -> dict[str, object]:
    return {
        "schema": MINER_RELEASE_SCHEMA,
        "product": SN39_SNP_MINER_PRODUCT,
        "channel": "canary",
        "sequence": 4,
        "issued_unix": 1_788_900_000,
        "expires_unix": 1_789_504_800,
        "release": {
            "version": "2026.09.09",
            "image": f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{IMAGE_DIGEST}",
            "runtime_contract": RUNTIME_CONTRACT,
            "launcher_sha256": LAUNCHER_DIGEST,
        },
        "signing_key_id": KEY_ID,
    }


def sign(document: dict[str, object], key: Ed25519PrivateKey) -> bytes:
    body = {k: v for k, v in document.items() if k != "signature"}
    signature = key.sign(canonical_signed_bytes(body))
    body["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(body, sort_keys=True).encode("utf-8")


def test_valid_canary_record_parses(signing_key, trusted):
    release = parse_miner_release(sign(canary_document(), signing_key), trusted_keys=trusted)
    assert release.channel == "canary"
    assert release.sequence == 4
    assert release.image_digest == IMAGE_DIGEST
    assert release.runtime_contract == RUNTIME_CONTRACT
    assert release.promoted_canary is None


def test_valid_stable_record_names_its_canary(signing_key, trusted):
    document = canary_document()
    document["channel"] = "stable"
    document["sequence"] = 3
    document["release"]["promoted_canary"] = {"sequence": 4, "signed_sha256": "b" * 64}
    release = parse_miner_release(sign(document, signing_key), trusted_keys=trusted)
    assert release.promoted_canary == (4, "b" * 64)


def test_stable_without_promoted_canary_is_refused(signing_key, trusted):
    """A stable body is a different exact field set, so the omission is caught
    by the field-set check before the promoted-canary shape is ever read."""

    document = canary_document()
    document["channel"] = "stable"
    with pytest.raises(MinerReleaseError, match="body fields are invalid"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


def test_stable_with_malformed_promoted_canary_is_refused(signing_key, trusted):
    document = canary_document()
    document["channel"] = "stable"
    document["release"]["promoted_canary"] = {"sequence": 4}
    with pytest.raises(MinerReleaseError, match="must name the canary"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


def test_canary_carrying_a_promoted_canary_is_refused(signing_key, trusted):
    """Only stable is a promotion. A canary claiming one is malformed."""

    document = canary_document()
    document["release"]["promoted_canary"] = {"sequence": 3, "signed_sha256": "b" * 64}
    with pytest.raises(MinerReleaseError, match="body fields are invalid"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


# --- artifact identity -------------------------------------------------


def test_validator_release_cannot_install_as_a_miner_release(signing_key, trusted):
    """The whole point of the product and schema fields.

    This record is signed by a key the host trusts and is a structurally valid
    validator release. It must still be refused, because it does not name this
    product.
    """

    document = {
        "schema": "cathedral_validator_release_v1",
        "product": "cathedral-validator",
        "channel": "stable",
        "sequence": 3,
        "issued_unix": 1_788_900_000,
        "expires_unix": 1_789_504_800,
        "release": {
            "version": "2026.09.09",
            "image": f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{IMAGE_DIGEST}",
            "runtime_contract": RUNTIME_CONTRACT,
            "launcher_sha256": LAUNCHER_DIGEST,
        },
        "signing_key_id": KEY_ID,
    }
    with pytest.raises(MinerReleaseError, match="schema is unsupported"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


def test_right_schema_wrong_product_is_refused(signing_key, trusted):
    document = canary_document()
    document["product"] = "sn39-tdx-miner"
    with pytest.raises(MinerReleaseError, match="different product"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


def test_expected_product_is_the_callers_choice_not_the_documents(signing_key, trusted):
    document = canary_document()
    document["product"] = "sn39-tdx-miner"
    release = parse_miner_release(
        sign(document, signing_key), trusted_keys=trusted, expected_product="sn39-tdx-miner"
    )
    assert release.product == "sn39-tdx-miner"


# --- signature and key -------------------------------------------------


def test_untrusted_signing_key_is_refused(signing_key):
    with pytest.raises(MinerReleaseError, match="not trusted"):
        parse_miner_release(sign(canary_document(), signing_key), trusted_keys={})


def test_tampered_body_fails_verification(signing_key, trusted):
    raw = sign(canary_document(), signing_key)
    document = json.loads(raw)
    document["release"]["image"] = f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{'c' * 64}"
    with pytest.raises(MinerReleaseError, match="signature verification failed"):
        parse_miner_release(json.dumps(document).encode("utf-8"), trusted_keys=trusted)


def test_signature_is_checked_before_binding(signing_key, trusted):
    """An unsigned document must not reveal which product the host expects."""

    document = canary_document()
    document["product"] = "sn39-tdx-miner"
    document["signature"] = {"algorithm": "ed25519", "value_base64": base64.b64encode(bytes(64)).decode()}
    with pytest.raises(MinerReleaseError, match="signature verification failed"):
        parse_miner_release(json.dumps(document).encode("utf-8"), trusted_keys=trusted)


def test_wrong_signature_length_is_refused(signing_key, trusted):
    document = canary_document()
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(bytes(32)).decode("ascii"),
    }
    with pytest.raises(MinerReleaseError, match="must be 64 bytes"):
        parse_miner_release(json.dumps(document).encode("utf-8"), trusted_keys=trusted)


# --- image pinning -----------------------------------------------------


@pytest.mark.parametrize(
    "image",
    [
        f"{CANONICAL_IMAGE_REPOSITORY}:latest",
        "ghcr.io/attacker/cathedral-sn39-snp-miner@sha256:" + IMAGE_DIGEST,
        f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{IMAGE_DIGEST.upper()}",
        f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{IMAGE_DIGEST[:63]}",
    ],
    ids=["mutable-tag", "wrong-repository", "uppercase-digest", "short-digest"],
)
def test_image_must_be_digest_pinned_to_the_canonical_repository(signing_key, trusted, image):
    document = canary_document()
    document["release"]["image"] = image
    with pytest.raises(MinerReleaseError):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


# --- document hygiene --------------------------------------------------


def test_duplicate_object_keys_are_refused(trusted):
    raw = b'{"schema":"a","schema":"b"}'
    with pytest.raises(MinerReleaseError, match="repeats an object key"):
        parse_miner_release(raw, trusted_keys=trusted)


def test_unknown_top_level_field_is_refused(signing_key, trusted):
    document = canary_document()
    document["extra"] = 1
    with pytest.raises(MinerReleaseError, match="document fields are invalid"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


def test_unknown_release_field_is_refused(signing_key, trusted):
    document = canary_document()
    document["release"]["extra"] = 1
    with pytest.raises(MinerReleaseError, match="body fields are invalid"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


def test_oversized_document_is_refused(trusted):
    with pytest.raises(MinerReleaseError, match="size is out of range"):
        parse_miner_release(b"{" + b" " * MAX_RELEASE_DOCUMENT_BYTES, trusted_keys=trusted)


def test_expiry_must_follow_issue_time(signing_key, trusted):
    document = canary_document()
    document["expires_unix"] = document["issued_unix"]
    with pytest.raises(MinerReleaseError, match="expiry does not follow"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


def test_expiry_is_reported_against_a_supplied_clock(signing_key, trusted):
    release = parse_miner_release(sign(canary_document(), signing_key), trusted_keys=trusted)
    assert not release.is_expired(now_unix=release.expires_unix - 1)
    assert release.is_expired(now_unix=release.expires_unix)


def test_boolean_is_not_accepted_as_a_sequence(signing_key, trusted):
    document = canary_document()
    document["sequence"] = True
    with pytest.raises(MinerReleaseError, match="sequence"):
        parse_miner_release(sign(document, signing_key), trusted_keys=trusted)


# --- monotonicity ------------------------------------------------------


def test_no_previous_floor_accepts_anything(signing_key, trusted):
    release = parse_miner_release(sign(canary_document(), signing_key), trusted_keys=trusted)
    enforce_monotonic_release(None, release)


def test_lower_sequence_is_a_rollback(signing_key, trusted):
    release = parse_miner_release(sign(canary_document(), signing_key), trusted_keys=trusted)
    floor = {"sequence": release.sequence + 1, "signed_sha256": "d" * 64}
    with pytest.raises(MinerReleaseError, match="rolls back"):
        enforce_monotonic_release(floor, release)


def test_same_sequence_different_bytes_is_equivocation(signing_key, trusted):
    release = parse_miner_release(sign(canary_document(), signing_key), trusted_keys=trusted)
    floor = {"sequence": release.sequence, "signed_sha256": "d" * 64}
    with pytest.raises(MinerReleaseError, match="equivocates"):
        enforce_monotonic_release(floor, release)


def test_same_sequence_same_bytes_is_an_accepted_retry(signing_key, trusted):
    release = parse_miner_release(sign(canary_document(), signing_key), trusted_keys=trusted)
    floor = {"sequence": release.sequence, "signed_sha256": release.signed_sha256}
    enforce_monotonic_release(floor, release)


def test_higher_sequence_advances(signing_key, trusted):
    release = parse_miner_release(sign(canary_document(), signing_key), trusted_keys=trusted)
    floor = {"sequence": release.sequence - 1, "signed_sha256": "d" * 64}
    enforce_monotonic_release(floor, release)


def test_signed_digest_covers_exactly_the_signed_bytes(signing_key, trusted):
    document = canary_document()
    raw = sign(document, signing_key)
    release = parse_miner_release(raw, trusted_keys=trusted)
    body = {k: v for k, v in json.loads(raw).items() if k != "signature"}
    assert release.signed_sha256 == hashlib.sha256(canonical_signed_bytes(body)).hexdigest()


def test_reserialising_with_different_whitespace_keeps_the_same_signed_digest(
    signing_key, trusted
):
    """Equivocation detection must not fire on cosmetic reformatting."""

    raw = sign(canary_document(), signing_key)
    compact = parse_miner_release(raw, trusted_keys=trusted)
    spaced = parse_miner_release(
        json.dumps(json.loads(raw), indent=2).encode("utf-8"), trusted_keys=trusted
    )
    assert compact.signed_sha256 == spaced.signed_sha256


# --- product separation ------------------------------------------------


def test_a_record_for_the_other_miner_product_is_refused(signing_key, trusted):
    """The two shipped miners must not be able to install each other.

    The TDX audit miner and the SNP miner have different repositories,
    contracts and pin variables. A host expecting one must refuse a record for
    the other on identity, not on a downstream accident.
    """

    from cathedral.miner_products import SN39_AUDIT_MINER, SN39_SNP_MINER

    document = canary_document()
    document["product"] = SN39_AUDIT_MINER.product
    document["release"]["image"] = f"{SN39_AUDIT_MINER.image_repository}@sha256:{IMAGE_DIGEST}"
    document["release"]["runtime_contract"] = SN39_AUDIT_MINER.runtime_contract
    raw = sign(document, signing_key)

    # An SNP host refuses it.
    with pytest.raises(MinerReleaseError, match="different product"):
        parse_miner_release(
            raw,
            trusted_keys=trusted,
            expected_product=SN39_SNP_MINER.product,
            expected_image_repository=SN39_SNP_MINER.image_repository,
        )

    # A TDX host accepts exactly the same bytes.
    release = parse_miner_release(
        raw,
        trusted_keys=trusted,
        expected_product=SN39_AUDIT_MINER.product,
        expected_image_repository=SN39_AUDIT_MINER.image_repository,
    )
    assert release.runtime_contract == SN39_AUDIT_MINER.runtime_contract


def test_the_right_product_with_the_wrong_repository_is_refused(signing_key, trusted):
    from cathedral.miner_products import SN39_AUDIT_MINER

    document = canary_document()
    document["product"] = SN39_AUDIT_MINER.product
    # Correct product, but the SNP repository.
    with pytest.raises(MinerReleaseError, match="canonical repository"):
        parse_miner_release(
            sign(document, signing_key),
            trusted_keys=trusted,
            expected_product=SN39_AUDIT_MINER.product,
            expected_image_repository=SN39_AUDIT_MINER.image_repository,
        )
