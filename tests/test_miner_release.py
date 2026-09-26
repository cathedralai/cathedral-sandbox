"""Signed miner release record checks.

Kept from #197: strict JSON, signature before binding, product identity, the
monotonic floor and equivocation. Added for review findings F6, F7, F9 and F13:
the 14-day lifetime ceiling, the not-yet-valid refusal, network and netuid
binding, per-channel key roles, and a promoted canary bound to its artifacts.
"""

from __future__ import annotations

import base64
import json

import pytest

from cathedral.miner_release import (
    MAX_RELEASE_LIFETIME_SECONDS,
    NOT_BEFORE_SKEW_SECONDS,
    TRUST_ROOT_SCHEMA,
    MinerReleaseError,
    canonical_json,
    enforce_monotonic_release,
    load_trust_root,
    parse_miner_release,
)
from cathedral.policy_registry import canonical_json as registry_canonical_json
from tests.miner_update_support import (
    CANARY_KEY,
    DAY,
    NETUID,
    NETWORK,
    NOW,
    OTHER_KEY,
    OTHER_NETUID,
    STABLE_KEY,
    public_hex,
    sign_record,
    trusted,
)

REPOSITORY = "ghcr.io/cathedralai/cathedral-test-snp-miner"
IMAGE = f"{REPOSITORY}@sha256:{'2' * 64}"
ARCHIVE = "a" * 64
TREE = "b" * 64


def record(**kwargs) -> bytes:
    kwargs.setdefault("image", IMAGE)
    kwargs.setdefault("archive_sha256", ARCHIVE)
    kwargs.setdefault("tree_sha256", TREE)
    return sign_record(**kwargs)


def parse(raw: bytes, *, channel: str = "stable", now: int = NOW, **expected):
    return parse_miner_release(
        raw,
        trusted_keys=expected.pop("keys", trusted()),
        expected_product=expected.pop("product", "snp-miner"),
        expected_network=expected.pop("network", NETWORK),
        expected_netuid=expected.pop("netuid", NETUID),
        expected_channel=channel,
        now_unix=now,
    )


# --- valid records -------------------------------------------------------------------


def test_a_valid_canary_parses():
    release = parse(record(channel="canary"), channel="canary")
    assert release.channel == "canary"
    assert release.image == IMAGE
    assert release.image_repository == REPOSITORY
    assert release.bundle.tree_sha256 == TREE
    assert release.promoted_canary is None
    assert release.network == NETWORK and release.netuid == NETUID


def test_a_valid_stable_names_the_exact_canary_artifacts():
    release = parse(record())
    assert release.promoted_canary is not None
    assert release.promoted_canary.image == IMAGE
    assert release.promoted_canary.tree_sha256 == TREE


def test_canonical_bytes_match_the_policy_registry():
    """The signer and verifier byte format is unchanged from #197."""

    sample = {"b": [1, "é"], "a": {"z": None, "y": True}}
    assert canonical_json(sample) == registry_canonical_json(sample)


# --- signature and keys ----------------------------------------------------------------


def test_an_untrusted_key_is_refused():
    with pytest.raises(MinerReleaseError, match="not trusted"):
        parse(record(key=OTHER_KEY, key_id="other-1"))


def test_a_canary_key_cannot_sign_stable():
    """Review finding F7: canary and stable are separate roles."""

    with pytest.raises(MinerReleaseError, match="may not sign the stable channel"):
        parse(record(key=CANARY_KEY, key_id="canary-1"))


def test_a_stable_key_cannot_sign_canary():
    with pytest.raises(MinerReleaseError, match="may not sign the canary channel"):
        parse(record(channel="canary", key=STABLE_KEY, key_id="stable-1"), channel="canary")


def test_a_tampered_body_fails_verification():
    document = json.loads(record())
    document["release"]["image"] = f"{REPOSITORY}@sha256:{'9' * 64}"
    with pytest.raises(MinerReleaseError, match="verification failed"):
        parse(json.dumps(document).encode())


def test_the_signature_is_checked_before_binding():
    """An unsigned change to the product reports a signature failure, not a binding one."""

    document = json.loads(record())
    document["product"] = "audit-miner"
    with pytest.raises(MinerReleaseError, match="verification failed"):
        parse(json.dumps(document).encode())


def test_an_unsigned_record_is_refused():
    document = json.loads(record())
    del document["signature"]
    with pytest.raises(MinerReleaseError, match="fields are invalid"):
        parse(json.dumps(document).encode())


@pytest.mark.parametrize(
    "value",
    [
        base64.b64encode(b"x" * 63).decode(),
        base64.b64encode(b"x" * 64).decode().rstrip("="),
        "not base64!",
    ],
)
def test_a_malformed_signature_is_refused(value):
    document = json.loads(record())
    document["signature"]["value_base64"] = value
    with pytest.raises(MinerReleaseError):
        parse(json.dumps(document).encode())


# --- identity (review finding F9) -------------------------------------------------------


def test_a_record_for_another_product_is_refused():
    with pytest.raises(MinerReleaseError, match="different product"):
        parse(record(), product="audit-miner")


def test_a_record_for_another_network_is_refused():
    with pytest.raises(MinerReleaseError, match="different network"):
        parse(record(network="othernet"))


def test_a_record_for_another_netuid_is_refused():
    with pytest.raises(MinerReleaseError, match="different netuid"):
        parse(record(netuid=OTHER_NETUID))


def test_a_record_for_another_channel_is_refused():
    with pytest.raises(MinerReleaseError, match="different channel"):
        parse(record(channel="canary"), channel="stable")


def test_a_validator_release_cannot_install_as_a_miner_release():
    def to_validator(body):
        body["schema"] = "cathedral_validator_release_v1"

    with pytest.raises(MinerReleaseError, match="schema is unsupported"):
        parse(record(mutate=to_validator))


# --- freshness (review finding F6) ------------------------------------------------------


def test_a_lifetime_of_exactly_14_days_is_accepted():
    parse(record(lifetime=MAX_RELEASE_LIFETIME_SECONDS))


def test_a_lifetime_over_14_days_is_refused():
    with pytest.raises(MinerReleaseError, match="exceeds 14 days"):
        parse(record(lifetime=MAX_RELEASE_LIFETIME_SECONDS + 1))


def test_the_review_probe_record_is_refused():
    """Probe A: issued ten years ahead with a 477-year lifetime. It activated before."""

    with pytest.raises(MinerReleaseError):
        parse(record(issued=NOW + 10 * 365 * DAY, lifetime=477 * 365 * DAY))


def test_a_record_not_yet_valid_is_refused():
    with pytest.raises(MinerReleaseError, match="not valid yet"):
        parse(record(issued=NOW + NOT_BEFORE_SKEW_SECONDS + 1))


def test_bounded_clock_skew_is_tolerated():
    parse(record(issued=NOW + NOT_BEFORE_SKEW_SECONDS))


def test_an_expired_record_is_refused():
    with pytest.raises(MinerReleaseError, match="expired"):
        parse(record(issued=NOW - 7 * DAY, lifetime=7 * DAY))


def test_expiry_must_follow_issue_time():
    with pytest.raises(MinerReleaseError, match="does not follow"):
        parse(record(lifetime=0))


# --- body shape ---------------------------------------------------------------------------


def test_a_stable_without_a_promoted_canary_is_refused():
    def drop(body):
        del body["release"]["promoted_canary"]

    with pytest.raises(MinerReleaseError, match="body fields"):
        parse(record(mutate=drop))


def test_a_canary_carrying_a_promoted_canary_is_refused():
    def add(body):
        body["release"]["promoted_canary"] = {
            "sequence": 1,
            "signed_sha256": "5" * 64,
            "image": IMAGE,
            "tree_sha256": TREE,
        }

    with pytest.raises(MinerReleaseError, match="body fields"):
        parse(record(channel="canary", mutate=add), channel="canary")


@pytest.mark.parametrize("field", ["image", "tree_sha256"])
def test_a_stable_must_promote_the_canarys_own_artifacts(field):
    """Review finding F13 (Probe D): the promoted canary was decorative."""

    def change(body):
        value = f"{REPOSITORY}@sha256:{'7' * 64}" if field == "image" else "7" * 64
        body["release"]["promoted_canary"][field] = value

    with pytest.raises(MinerReleaseError, match="exact promoted canary"):
        parse(record(mutate=change))


@pytest.mark.parametrize(
    "image",
    [
        f"ghcr.io/attacker/cathedral-test-snp-miner@sha256:{'2' * 64}",
        f"docker.io/cathedralai/cathedral-test-snp-miner@sha256:{'2' * 64}",
        f"{REPOSITORY}:latest",
        f"{REPOSITORY}@sha256:{'A' * 64}",
        f"{REPOSITORY}@sha256:{'2' * 63}",
    ],
)
def test_the_image_must_be_a_digest_in_a_cathedral_repository(image):
    with pytest.raises(MinerReleaseError):
        parse(record(image=image))


@pytest.mark.parametrize(
    "url",
    ["http://updates.example.test/b.tar.gz", "https://user:pw@updates.example.test/b.tar.gz", "ftp://x"],
)
def test_the_bundle_url_must_be_https_without_credentials(url):
    with pytest.raises(MinerReleaseError):
        parse(record(bundle_url=url))


def test_duplicate_object_keys_are_refused():
    raw = record()
    duplicated = raw.replace(b'"channel": "stable"', b'"channel": "stable", "channel": "stable"', 1)
    with pytest.raises(MinerReleaseError, match="repeats"):
        parse(duplicated)


@pytest.mark.parametrize("where", ["top", "release", "bundle"])
def test_unknown_fields_are_refused(where):
    def add(body):
        target = {"top": body, "release": body["release"], "bundle": body["release"]["bundle"]}[where]
        target["extra"] = 1

    with pytest.raises(MinerReleaseError, match="fields are invalid"):
        parse(record(mutate=add))


def test_an_oversized_document_is_refused():
    with pytest.raises(MinerReleaseError, match="size"):
        parse(b"{" + b" " * 20_000 + b"}")


@pytest.mark.parametrize("field", ["sequence", "state_schema"])
def test_booleans_and_zero_are_not_counts(field):
    def change(body):
        if field == "sequence":
            body["sequence"] = True
        else:
            body["release"]["state_schema"] = 0

    with pytest.raises(MinerReleaseError):
        parse(record(mutate=change))


# --- the floor ------------------------------------------------------------------------------


def test_the_floor_accepts_anything_when_empty():
    enforce_monotonic_release(None, parse(record(sequence=5)))


def test_a_lower_sequence_is_a_rollback():
    release = parse(record(sequence=4))
    with pytest.raises(MinerReleaseError, match="rolls back"):
        enforce_monotonic_release({"sequence": 5, "signed_sha256": "0" * 64}, release)


def test_the_same_sequence_with_different_bytes_is_equivocation():
    release = parse(record(sequence=5))
    with pytest.raises(MinerReleaseError, match="equivocates"):
        enforce_monotonic_release({"sequence": 5, "signed_sha256": "0" * 64}, release)


def test_the_same_record_again_is_an_accepted_retry():
    release = parse(record(sequence=5))
    enforce_monotonic_release({"sequence": 5, "signed_sha256": release.signed_sha256}, release)


def test_a_bootstrap_floor_must_be_exceeded():
    release = parse(record(sequence=5))
    with pytest.raises(MinerReleaseError, match="bootstrap floor"):
        enforce_monotonic_release({"sequence": 5, "signed_sha256": None}, release)
    enforce_monotonic_release({"sequence": 4, "signed_sha256": None}, release)


def test_the_signed_digest_ignores_whitespace():
    raw = record()
    spaced = json.dumps(json.loads(raw), indent=4).encode()
    assert parse(raw).signed_sha256 == parse(spaced).signed_sha256


# --- trust root --------------------------------------------------------------------------------


def _root(keys) -> bytes:
    return json.dumps({"schema": TRUST_ROOT_SCHEMA, "keys": keys}).encode()


@pytest.mark.parametrize(
    "keys",
    [
        {},
        {"k": {"public_key_hex": "zz" * 32, "channels": ["stable"]}},
        {"k": {"public_key_hex": public_hex(STABLE_KEY), "channels": []}},
        {"k": {"public_key_hex": public_hex(STABLE_KEY), "channels": ["stable", "stable"]}},
        {"k": {"public_key_hex": public_hex(STABLE_KEY), "channels": ["beta"]}},
        {"k": {"public_key_hex": public_hex(STABLE_KEY), "channels": ["stable"], "x": 1}},
        {"Bad Id": {"public_key_hex": public_hex(STABLE_KEY), "channels": ["stable"]}},
    ],
)
def test_a_malformed_trust_root_is_refused(keys):
    with pytest.raises(MinerReleaseError):
        load_trust_root(_root(keys))


def test_a_trust_root_reports_fingerprints():
    keys = load_trust_root(_root({"k": {"public_key_hex": public_hex(STABLE_KEY), "channels": ["stable"]}}))
    assert keys["k"].fingerprint.startswith("sha256:")
    assert keys["k"].channels == frozenset({"stable"})
