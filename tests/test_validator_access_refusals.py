"""Refusal branches of the miner's validator-access gate.

``test_validator_access.py`` proves the accepted paths end to end. This file
walks the refusals one field at a time, so each check is shown to refuse on
its own rather than because an earlier check happened to fire:

  1. ``ValidatorRequestAuthorizer``: a valid header from the repository's own
     ``build_validator_request_header`` is decoded, exactly one field is
     changed, and the document is re-signed by the same qualified validator.
     Only the changed field can then be the reason for the refusal. The public
     ``preauthorize`` returns ``None`` without saying why; the private
     ``_preauthorize`` is also called to pin the refusing check by message.
  2. ``preflight_sr25519_verifier``: the real verifier passes, and a verifier
     that accepts a corrupted signature or rejects the known answer is refused.
  3. ``verify_validator_access_snapshot``: every document, trust, signature,
     time, stake and row refusal that was not already covered, plus the
     snapshot provider's file size cap.

The subnet is never pinned: each run draws its own netuid and derives the
mismatching one from it.
"""

from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import sr25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cathedral.common import ChannelBinding, ChannelBindingType
from cathedral.policy_registry import (
    MAX_REGISTRY_BYTES,
    MAX_SQLITE_INTEGER,
    PolicyRegistryError,
    canonical_json,
)
from cathedral.validator_access import (
    MAX_NETUID,
    MAX_REQUEST_FUTURE_SKEW_SECONDS,
    MAX_REQUEST_HEADER_BYTES,
    MAX_REQUEST_LIFETIME_SECONDS,
    MAX_SNAPSHOT_BYTES,
    MAX_STAKE_RAO,
    MAX_UID,
    MAX_VALIDATORS,
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
    VALIDATOR_REQUEST_SCHEMA,
    SignedValidatorSnapshotProvider,
    ValidatorAccessError,
    ReplayRecord,
    StaticValidatorSnapshotProvider,
    ValidatorAccessState,
    ValidatorRefusal,
    ValidatorRequestAuthorizer,
    build_validator_request_header,
    load_sr25519_verifier,
    preflight_sr25519_verifier,
    sign_validator_access_snapshot,
    verify_validator_access_snapshot,
)
from tests.test_validator_access import (
    NETWORK,
    NOW,
    OTHER_VALIDATOR_HOTKEY,
    OTHER_VALIDATOR_PAIR,
    SNAPSHOT_SEED,
    VALIDATOR_HOTKEY,
    VALIDATOR_PAIR,
    WORKER_HOTKEY,
    _binding,
    _hotkey,
    _snapshot_document,
)

NETUID = secrets.randbelow(60_000) + 1
OTHER_NETUID = NETUID + 1
KEY_ID = "cathedral-validator-access"
TRUSTED_KEYS = {
    KEY_ID: ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
}
OTHER_SNAPSHOT_SEED = b"x" * 32
REQUEST_LIFETIME = timedelta(seconds=60)
PROTECTED_PATHS = (
    "/v1/fleet",
    "/v1/evidence",
    "/v1/sat-work",
    "/v1/capabilities",
    "/v1/gpu-evidence",
    "/v1/gpu-work",
    "/v1/gpu-capabilities",
)
REQUEST_FIELDS = (
    "schema",
    "validator_hotkey",
    "worker_hotkey",
    "network",
    "netuid",
    "method",
    "path",
    "body_sha256",
    "channel_binding_type",
    "channel_binding_digest_hex",
    "nonce_hex",
    "issued_at",
    "expires_at",
)
_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# Snapshot builders. The shared ``_snapshot_document`` is reused and only its
# subnet is replaced with this run's random netuid.


def _snapshot_doc(**kwargs: object) -> dict[str, object]:
    document = _snapshot_document(**kwargs)  # type: ignore[arg-type]
    document["netuid"] = NETUID
    return document


def _sign(document: dict[str, object], seed: bytes = SNAPSHOT_SEED) -> bytes:
    return canonical_json(sign_validator_access_snapshot(document, seed))


def _verify(
    encoded: bytes,
    *,
    trusted_keys: dict[str, object] | None = None,
    **overrides: object,
):
    arguments: dict[str, object] = {
        "network": NETWORK,
        "netuid": NETUID,
        "required_minimum_stake_rao": 1_000,
        "now": NOW,
    }
    arguments.update(overrides)
    return verify_validator_access_snapshot(
        encoded,
        TRUSTED_KEYS if trusted_keys is None else trusted_keys,  # type: ignore[arg-type]
        **arguments,  # type: ignore[arg-type]
    )


def _row(hotkey: str, uid: int, stake_rao: int = 2_000) -> dict[str, object]:
    return {"hotkey": hotkey, "uid": uid, "validator_permit": True, "stake_rao": stake_rao}


def _access_snapshot(
    *,
    hotkeys: tuple[str, ...] = (VALIDATOR_HOTKEY,),
    generated_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=9),
):
    document = _snapshot_doc(generated_at=generated_at, expires_at=expires_at)
    document["validators"] = [
        _row(hotkey, 30 + index) for index, hotkey in enumerate(sorted(hotkeys))
    ]
    return _verify(_sign(document), now=generated_at)


# Request builders.


def _authorizer(tmp_path: Path, snapshot_provider: object = None) -> ValidatorRequestAuthorizer:
    return ValidatorRequestAuthorizer(
        snapshot_provider or _access_snapshot(),  # type: ignore[arg-type]
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=_binding(),
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )


def _header(
    *,
    validator_hotkey: str = VALIDATOR_HOTKEY,
    pair=VALIDATOR_PAIR,
    worker_hotkey: str = WORKER_HOTKEY,
    network: str = NETWORK,
    netuid: object = None,
    path: str = "/v1/fleet",
    body: bytes = b"{}",
    binding: ChannelBinding | None = None,
    nonce: bytes = b"n" * 32,
    issued_at: datetime = NOW,
    expires_at: datetime | None = None,
) -> str:
    return build_validator_request_header(
        validator_hotkey=validator_hotkey,
        worker_hotkey=worker_hotkey,
        network=network,
        netuid=NETUID if netuid is None else netuid,  # type: ignore[arg-type]
        method="POST",
        path=path,
        body=body,
        channel_binding=binding or _binding(),
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at or issued_at + REQUEST_LIFETIME,
        signer=lambda message: sr25519.sign(pair, message),
    )


def _decode(header: str) -> dict[str, object]:
    return json.loads(base64.b64decode(header))


def _encode(document: dict[str, object]) -> str:
    return base64.b64encode(canonical_json(document)).decode("ascii")


def _resign(document: dict[str, object], *, pair=VALIDATOR_PAIR) -> str:
    """Re-sign a changed document as the same validator, keeping one change."""

    unsigned = {key: value for key, value in document.items() if key != "signature"}
    signature = sr25519.sign(pair, canonical_json(unsigned))
    unsigned["signature"] = {
        "algorithm": "sr25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return _encode(unsigned)


def _changed(**changes: object) -> str:
    document = _decode(_header())
    document.update(changes)
    return _resign(document)


def _assert_refused(
    authorizer: ValidatorRequestAuthorizer,
    header: object,
    match: str,
    *,
    method: str = "POST",
    path: str = "/v1/fleet",
    now: datetime = NOW,
    error: type[Exception] = ValidatorAccessError,
) -> None:
    assert authorizer.preauthorize(header, method=method, path=path, now=now) is None
    with pytest.raises(error, match=match):
        authorizer._preauthorize(  # noqa: SLF001 - names the refusing check
            header, method=method, path=path, now=now
        )


def _assert_accepted(
    authorizer: ValidatorRequestAuthorizer,
    header: str,
    *,
    path: str = "/v1/fleet",
    body: bytes = b"{}",
    now: datetime = NOW,
) -> None:
    assert (
        authorizer.authorize_caller(header, method="POST", path=path, body=body, now=now)
        == VALIDATOR_HOTKEY
    )


# 1. ValidatorRequestAuthorizer: envelope, identity and target.


def test_resigned_control_header_is_accepted_on_a_random_subnet(tmp_path: Path):
    authorizer = _authorizer(tmp_path)
    original = _decode(_header())
    resigned = _resign(original)

    # An unchanged document re-signed by the test helper is accepted, so each
    # refusal below is caused by its one changed field. sr25519 signing is
    # randomized, so only the signed fields, not the signature, are equal.
    assert original["netuid"] == NETUID
    assert {key: value for key, value in _decode(resigned).items() if key != "signature"} == {
        key: value for key, value in original.items() if key != "signature"
    }
    _assert_accepted(authorizer, resigned)


@pytest.mark.parametrize(
    "header",
    [
        pytest.param(None, id="absent"),
        pytest.param(b"e30=", id="bytes"),
        pytest.param("", id="empty"),
        pytest.param("éAAA", id="non-ascii"),
        pytest.param("A" * (MAX_REQUEST_HEADER_BYTES * 2 + 4), id="over-length"),
        pytest.param("not base64!", id="not-base64"),
        pytest.param("e30", id="missing-padding"),
        pytest.param("e3 0=", id="embedded-space"),
    ],
)
def test_header_that_is_not_bounded_ascii_base64_is_refused(tmp_path: Path, header: object):
    _assert_refused(_authorizer(tmp_path), header, "header is invalid")


def test_decoded_header_over_its_size_cap_is_refused(tmp_path: Path):
    oversized = base64.b64encode(b" " * (MAX_REQUEST_HEADER_BYTES + 1)).decode("ascii")
    assert len(oversized) <= MAX_REQUEST_HEADER_BYTES * 2

    _assert_refused(_authorizer(tmp_path), oversized, "too large")


def _canonical_bytes() -> bytes:
    return canonical_json(_decode(_header()))


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        pytest.param(lambda: b"not json", "not valid UTF-8 JSON", id="text"),
        pytest.param(lambda: b"\xff\xfe", "not valid UTF-8 JSON", id="invalid-utf8"),
        pytest.param(lambda: b"[]", "must be a JSON object", id="array"),
        pytest.param(
            lambda: _canonical_bytes().replace(
                b'{"body_sha256"', b'{"netuid":%d,"body_sha256"' % OTHER_NETUID, 1
            ),
            "duplicate JSON key",
            id="duplicate-netuid",
        ),
        pytest.param(
            lambda: _canonical_bytes().replace(
                b'"netuid":%d,' % NETUID, b'"netuid":%d.0,' % NETUID, 1
            ),
            "floating-point",
            id="float-netuid",
        ),
    ],
)
def test_payload_that_is_not_a_strict_json_object_is_refused(tmp_path: Path, payload, match: str):
    encoded = payload()
    header = base64.b64encode(encoded).decode("ascii")

    _assert_refused(_authorizer(tmp_path), header, match, error=PolicyRegistryError)


def _escaped_network(canonical: bytes) -> bytes:
    plain = json.dumps(NETWORK).encode("ascii")
    escaped = b'"\\u%04x' % ord(NETWORK[0]) + NETWORK[1:].encode("ascii") + b'"'
    return canonical.replace(plain, escaped, 1)


@pytest.mark.parametrize(
    "reencode",
    [
        pytest.param(
            lambda document: json.dumps(document, indent=1, sort_keys=True).encode("ascii"),
            id="pretty-printed",
        ),
        pytest.param(
            lambda document: json.dumps(
                dict(reversed(list(document.items()))), separators=(",", ":")
            ).encode("ascii"),
            id="unsorted-keys",
        ),
        pytest.param(lambda document: _escaped_network(canonical_json(document)), id="escaped"),
        pytest.param(lambda document: canonical_json(document) + b"\n", id="trailing-newline"),
    ],
)
def test_validly_signed_but_non_canonical_encoding_is_refused(tmp_path: Path, reencode):
    document = _decode(_header())
    variant = reencode(document)
    # The variant parses to the same signed document, so its signature still
    # verifies. Only the canonical re-encoding check can refuse it.
    assert variant != canonical_json(document)
    assert json.loads(variant) == document

    _assert_refused(
        _authorizer(tmp_path),
        base64.b64encode(variant).decode("ascii"),
        "must be canonical JSON",
    )


def test_signed_extra_field_is_refused(tmp_path: Path):
    _assert_refused(_authorizer(tmp_path), _changed(comment="harmless"), "fields are invalid")


@pytest.mark.parametrize("field", REQUEST_FIELDS)
def test_signed_document_missing_any_field_is_refused(tmp_path: Path, field: str):
    document = _decode(_header())
    del document[field]

    _assert_refused(_authorizer(tmp_path), _resign(document), "fields are invalid")


def test_unsigned_document_is_refused(tmp_path: Path):
    document = _decode(_header())
    del document["signature"]

    _assert_refused(_authorizer(tmp_path), _encode(document), "fields are invalid")


@pytest.mark.parametrize(
    "schema",
    ["cathedral_validator_request_v2", VALIDATOR_ACCESS_SNAPSHOT_SCHEMA, "", None],
)
def test_other_request_schema_is_refused(tmp_path: Path, schema: object):
    _assert_refused(_authorizer(tmp_path), _changed(schema=schema), "schema is unsupported")


@pytest.mark.parametrize(
    ("method", "path"),
    [
        pytest.param("GET", "/v1/fleet", id="get"),
        pytest.param("post", "/v1/fleet", id="lowercase-post"),
        pytest.param("POST", "/v1/unknown", id="unprotected-path"),
        pytest.param("POST", "/v1/fleet/", id="trailing-slash"),
        pytest.param("POST", "/healthz", id="health"),
    ],
)
def test_request_to_an_unsupported_target_is_refused(tmp_path: Path, method: str, path: str):
    # The header is signed for exactly the presented target, so only the
    # worker's own target allowlist can refuse it.
    header = _changed(method=method, path=path)

    _assert_refused(
        _authorizer(tmp_path),
        header,
        "target is unsupported",
        method=method,
        path=path,
    )


@pytest.mark.parametrize(
    ("header", "presented_path"),
    [
        pytest.param(lambda: _header(path="/v1/fleet"), "/v1/evidence", id="other-path"),
        pytest.param(lambda: _header(path="/v1/gpu-work"), "/v1/sat-work", id="other-work-lane"),
        pytest.param(lambda: _changed(method="PUT"), "/v1/fleet", id="other-method"),
    ],
)
def test_header_signed_for_another_target_is_refused(tmp_path: Path, header, presented_path: str):
    _assert_refused(
        _authorizer(tmp_path),
        header(),
        "target does not match",
        path=presented_path,
    )


@pytest.mark.parametrize("path", PROTECTED_PATHS)
def test_every_protected_target_accepts_its_own_signed_header(tmp_path: Path, path: str):
    _assert_accepted(_authorizer(tmp_path), _header(path=path), path=path)


def test_header_signed_for_another_worker_is_refused(tmp_path: Path):
    header = _header(worker_hotkey=OTHER_VALIDATOR_HOTKEY)

    _assert_refused(_authorizer(tmp_path), header, "worker does not match")


@pytest.mark.parametrize(
    ("network", "netuid"),
    [
        pytest.param("testnet", None, id="other-network"),
        pytest.param(NETWORK.upper(), None, id="network-case"),
        pytest.param(NETWORK, OTHER_NETUID, id="other-netuid"),
        pytest.param("testnet", OTHER_NETUID, id="both"),
    ],
)
def test_header_signed_for_another_subnet_is_refused(tmp_path: Path, network: str, netuid: object):
    # Signed by the qualified validator through the real builder. Everything
    # but the subnet matches, so only the subnet check can refuse it.
    header = _header(network=network, netuid=netuid)

    _assert_refused(_authorizer(tmp_path), header, "subnet does not match")


def test_header_with_a_string_netuid_is_refused_before_the_subnet_check(tmp_path: Path):
    # A string that spells the right netuid never reaches the subnet
    # comparison: the netuid type check refuses it first.
    header = _header(netuid=str(NETUID))

    _assert_refused(_authorizer(tmp_path), header, "request netuid must be an integer")


@pytest.mark.parametrize(
    "digest",
    [
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "sha512:" + "a" * 64,
        "SHA256:" + "a" * 64,
        "a" * 64,
        0,
        None,
    ],
)
def test_malformed_body_digest_is_refused(tmp_path: Path, digest: object):
    _assert_refused(_authorizer(tmp_path), _changed(body_sha256=digest), "body digest is invalid")


def test_header_bound_to_another_channel_type_is_refused(tmp_path: Path):
    other_type = ChannelBinding(ChannelBindingType.APPLICATION_KEY_SHA256, _binding().digest)

    _assert_refused(
        _authorizer(tmp_path),
        _header(binding=other_type),
        "channel type does not match",
    )


@pytest.mark.parametrize(
    "header",
    [
        pytest.param(lambda: _header(binding=_binding(2)), id="other-key"),
        pytest.param(
            lambda: _changed(channel_binding_digest_hex="0x" + _binding().digest.hex()),
            id="same-key-prefixed",
        ),
    ],
)
def test_header_bound_to_another_channel_key_is_refused(tmp_path: Path, header):
    _assert_refused(_authorizer(tmp_path), header(), "channel key does not match")


def _broken_checksum(hotkey: str) -> str:
    return hotkey[:-1] + ("2" if hotkey[-1] != "2" else "3")


@pytest.mark.parametrize(
    "hotkey",
    [
        pytest.param("not-a-hotkey", id="not-ss58"),
        pytest.param(_broken_checksum(VALIDATOR_HOTKEY), id="bad-checksum"),
        pytest.param(7, id="integer"),
    ],
)
def test_malformed_validator_hotkey_is_refused(tmp_path: Path, hotkey: object):
    _assert_refused(_authorizer(tmp_path), _changed(validator_hotkey=hotkey), "hotkey")


@pytest.mark.parametrize(
    "nonce_hex",
    ["AB" * 32, "ab" * 31, "ab" * 33, "zz" * 32, "", 7, None],
)
def test_malformed_nonce_is_refused(tmp_path: Path, nonce_hex: object):
    _assert_refused(_authorizer(tmp_path), _changed(nonce_hex=nonce_hex), "nonce is invalid")


# 1b. ValidatorRequestAuthorizer: time.


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issued_at", "2026-08-29T05:00:00+00:00"),
        ("issued_at", "2026-08-29T05:00:00.000Z"),
        ("issued_at", 1_788_000_000),
        ("expires_at", "2026-08-29T05:01:00z"),
        ("expires_at", "2026-02-30T05:01:00Z"),
    ],
)
def test_non_canonical_request_time_is_refused(tmp_path: Path, field: str, value: object):
    _assert_refused(
        _authorizer(tmp_path),
        _changed(**{field: value}),
        "must be canonical UTC time",
    )


def _utc_text(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.parametrize(
    ("lifetime", "match"),
    [
        pytest.param(timedelta(0), "validity window is invalid", id="zero"),
        pytest.param(timedelta(seconds=-1), "validity window is invalid", id="negative"),
        pytest.param(
            timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS + 1),
            "validity window is too long",
            id="too-long",
        ),
    ],
)
def test_request_validity_window_is_bounded(tmp_path: Path, lifetime: timedelta, match: str):
    header = _changed(expires_at=_utc_text(NOW + lifetime))

    _assert_refused(_authorizer(tmp_path), header, match)


def test_request_at_the_maximum_lifetime_is_accepted(tmp_path: Path):
    header = _header(expires_at=NOW + timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS))

    _assert_accepted(_authorizer(tmp_path), header)


@pytest.mark.parametrize(
    "now",
    [
        pytest.param(NOW.replace(tzinfo=None), id="naive"),
        pytest.param(NOW.astimezone(timezone(timedelta(hours=1))), id="offset"),
    ],
)
def test_verification_time_must_be_utc(tmp_path: Path, now: datetime):
    _assert_refused(_authorizer(tmp_path), _header(), "verification time must be UTC", now=now)


def test_request_issued_beyond_the_future_skew_is_refused(tmp_path: Path):
    authorizer = _authorizer(tmp_path)
    skew = timedelta(seconds=MAX_REQUEST_FUTURE_SKEW_SECONDS)

    _assert_refused(
        authorizer,
        _header(),
        "issued too far in the future",
        now=NOW - skew - timedelta(seconds=1),
    )
    _assert_accepted(authorizer, _header(), now=NOW - skew)


def test_request_is_refused_from_its_expiry_onward(tmp_path: Path):
    authorizer = _authorizer(tmp_path)

    for late in (timedelta(0), timedelta(seconds=1), timedelta(hours=1)):
        _assert_refused(authorizer, _header(), "has expired", now=NOW + REQUEST_LIFETIME + late)
    _assert_accepted(authorizer, _header(), now=NOW + REQUEST_LIFETIME - timedelta(seconds=1))


# 1c. ValidatorRequestAuthorizer: qualification and signature.


def test_validly_signed_validator_absent_from_the_snapshot_is_refused(tmp_path: Path):
    header = _header(validator_hotkey=OTHER_VALIDATOR_HOTKEY, pair=OTHER_VALIDATOR_PAIR)

    _assert_refused(_authorizer(tmp_path), header, "not qualified")


def test_request_outliving_its_snapshot_is_refused(tmp_path: Path):
    snapshot = _access_snapshot(
        generated_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(seconds=30),
    )
    authorizer = _authorizer(tmp_path, snapshot)

    _assert_refused(authorizer, _header(), "not qualified", now=NOW + timedelta(seconds=30))


class _AbsentSnapshotProvider:
    network = NETWORK
    netuid = NETUID

    def load(self, *, now: datetime):
        return None


def test_absent_snapshot_refuses_every_validator(tmp_path: Path):
    _assert_refused(_authorizer(tmp_path, _AbsentSnapshotProvider()), _header(), "not qualified")


def _signature_with_trailing_bits(value: str) -> str:
    # 64 bytes encode to 86 characters plus "=="; the last character carries
    # four unused bits. Setting one leaves the decoded bytes unchanged.
    assert value.endswith("==")
    last = _BASE64_ALPHABET.index(value[-3])
    altered = value[:-3] + _BASE64_ALPHABET[last | 1] + "=="
    assert altered != value
    assert base64.b64decode(altered, validate=True) == base64.b64decode(value)
    return altered


def _signature_value_bytes(length: int) -> str:
    return base64.b64encode(b"\x01" * length).decode("ascii")


@pytest.mark.parametrize(
    ("signature", "match"),
    [
        pytest.param(lambda _: "signature", "signature object is invalid", id="string"),
        pytest.param(lambda _: [], "signature object is invalid", id="list"),
        pytest.param(
            lambda signature: {"algorithm": signature["algorithm"]},
            "signature object is invalid",
            id="missing-value",
        ),
        pytest.param(
            lambda signature: {**signature, "key": VALIDATOR_HOTKEY},
            "signature object is invalid",
            id="extra-key",
        ),
        pytest.param(
            lambda signature: {**signature, "algorithm": "ed25519"},
            "algorithm is unsupported",
            id="ed25519",
        ),
        pytest.param(
            lambda signature: {**signature, "algorithm": "SR25519"},
            "algorithm is unsupported",
            id="uppercase-algorithm",
        ),
        pytest.param(
            lambda signature: {
                **signature,
                "value_base64": _signature_with_trailing_bits(signature["value_base64"]),
            },
            "must be 64 bytes",
            id="non-canonical-trailing-bits",
        ),
        pytest.param(
            lambda signature: {**signature, "value_base64": signature["value_base64"][:-2]},
            "not canonical base64",
            id="missing-padding",
        ),
        pytest.param(
            lambda signature: {
                **signature,
                "value_base64": signature["value_base64"][:40]
                + "\n"
                + signature["value_base64"][40:],
            },
            "not canonical base64",
            id="embedded-newline",
        ),
        pytest.param(
            lambda signature: {**signature, "value_base64": "é" * 88},
            "not canonical base64",
            id="non-ascii",
        ),
        pytest.param(
            lambda signature: {**signature, "value_base64": 64},
            "not canonical base64",
            id="integer",
        ),
        pytest.param(
            lambda signature: {**signature, "value_base64": _signature_value_bytes(63)},
            "must be 64 bytes",
            id="63-bytes",
        ),
        pytest.param(
            lambda signature: {**signature, "value_base64": _signature_value_bytes(65)},
            "must be 64 bytes",
            id="65-bytes",
        ),
    ],
)
def test_malformed_request_signature_object_is_refused(tmp_path: Path, signature, match: str):
    # The signature object is outside the signed bytes, so the rest of the
    # document stays validly signed by the qualified validator.
    document = _decode(_header())
    document["signature"] = signature(document["signature"])

    _assert_refused(_authorizer(tmp_path), _encode(document), match)


def _flip_signature_bit(header: str) -> str:
    document = _decode(header)
    signature = document["signature"]
    assert isinstance(signature, dict)
    raw = bytearray(base64.b64decode(signature["value_base64"]))
    raw[0] ^= 0x01
    signature["value_base64"] = base64.b64encode(bytes(raw)).decode("ascii")
    return _encode(document)


def _changed_after_signing(header: str) -> str:
    document = _decode(header)
    document["nonce_hex"] = "ab" * 32
    return _encode(document)


@pytest.mark.parametrize(
    "header",
    [
        pytest.param(
            lambda: _header(pair=OTHER_VALIDATOR_PAIR),
            id="signed-by-another-key",
        ),
        pytest.param(lambda: _flip_signature_bit(_header()), id="flipped-bit"),
        pytest.param(lambda: _changed_after_signing(_header()), id="field-changed-after-signing"),
    ],
)
def test_signature_that_does_not_verify_under_the_claimed_hotkey_is_refused(tmp_path: Path, header):
    _assert_refused(_authorizer(tmp_path), header(), "signature verification failed")


# 1d. ValidatorRequestAuthorizer: finalize and replay.


def _preauthorized(
    authorizer: ValidatorRequestAuthorizer,
    header: str,
    *,
    path: str = "/v1/fleet",
    now: datetime = NOW,
):
    request = authorizer.preauthorize(header, method="POST", path=path, now=now)
    assert request is not None
    return request


def _assert_finalize_refused(
    authorizer: ValidatorRequestAuthorizer,
    request: object,
    match: str,
    *,
    body: object = b"{}",
    now: datetime = NOW,
) -> None:
    assert authorizer.finalize(request, body=body, now=now) is None  # type: ignore[arg-type]
    with pytest.raises(ValidatorAccessError, match=match):
        authorizer._finalize(request, body=body, now=now)  # type: ignore[arg-type]  # noqa: SLF001


def test_finalize_refuses_a_look_alike_preauthorization(tmp_path: Path):
    authorizer = _authorizer(tmp_path)
    genuine = _preauthorized(authorizer, _header(), now=NOW)
    look_alike = SimpleNamespace(**vars(genuine))

    _assert_finalize_refused(authorizer, look_alike, "preauthorized validator request is invalid")
    assert authorizer.finalize(genuine, body=b"{}", now=NOW) == VALIDATOR_HOTKEY


@pytest.mark.parametrize(
    ("body", "now", "match"),
    [
        pytest.param("{}", NOW, "body must be bytes", id="text-body"),
        pytest.param(bytearray(b"{}"), NOW, "body must be bytes", id="bytearray-body"),
        pytest.param(b"{}", NOW.replace(tzinfo=None), "must be UTC", id="naive-time"),
    ],
)
def test_finalize_refusal_does_not_consume_the_nonce(
    tmp_path: Path, body: object, now: datetime, match: str
):
    authorizer = _authorizer(tmp_path)
    request = _preauthorized(authorizer, _header(), now=NOW)

    _assert_finalize_refused(authorizer, request, match, body=body, now=now)
    assert authorizer.finalize(request, body=b"{}", now=NOW) == VALIDATOR_HOTKEY


def test_request_that_expires_before_finalize_is_refused(tmp_path: Path):
    authorizer = _authorizer(tmp_path)
    request = _preauthorized(
        authorizer, _header(), now=NOW + REQUEST_LIFETIME - timedelta(seconds=1)
    )

    _assert_finalize_refused(authorizer, request, "has expired", now=NOW + REQUEST_LIFETIME)


def test_snapshot_that_lapses_before_finalize_is_refused(tmp_path: Path):
    snapshot = _access_snapshot(
        generated_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(seconds=30),
    )
    authorizer = _authorizer(tmp_path, snapshot)
    request = _preauthorized(authorizer, _header(), now=NOW)

    _assert_finalize_refused(authorizer, request, "not qualified", now=NOW + timedelta(seconds=30))


def test_second_use_of_an_accepted_request_is_refused_at_finalize(tmp_path: Path):
    authorizer = _authorizer(tmp_path)
    header = _header()
    first = _preauthorized(authorizer, header, now=NOW)
    assert authorizer.finalize(first, body=b"{}", now=NOW) == VALIDATOR_HOTKEY

    # Preauthorization is stateless; the durable replay row refuses the reuse.
    _assert_finalize_refused(authorizer, first, "replayed")
    again = _preauthorized(authorizer, header, now=NOW + timedelta(seconds=1))
    _assert_finalize_refused(authorizer, again, "replayed", now=NOW + timedelta(seconds=1))


def test_nonce_is_single_use_across_every_target_of_one_validator(tmp_path: Path):
    authorizer = _authorizer(tmp_path)
    nonce = secrets.token_bytes(32)
    _assert_accepted(authorizer, _header(nonce=nonce))

    # A different, validly signed request passes the stateless envelope checks
    # but cannot reuse the nonce.
    body = b'{"other":true}'
    reused = _preauthorized(
        authorizer, _header(nonce=nonce, path="/v1/evidence", body=body), path="/v1/evidence"
    )
    _assert_finalize_refused(authorizer, reused, "replayed", body=body)
    _assert_accepted(authorizer, _header(nonce=secrets.token_bytes(32)))


def test_nonce_space_is_separate_for_each_validator(tmp_path: Path):
    snapshot = _access_snapshot(hotkeys=(VALIDATOR_HOTKEY, OTHER_VALIDATOR_HOTKEY))
    authorizer = _authorizer(tmp_path, snapshot)
    nonce = secrets.token_bytes(32)

    _assert_accepted(authorizer, _header(nonce=nonce))
    other = _header(validator_hotkey=OTHER_VALIDATOR_HOTKEY, pair=OTHER_VALIDATOR_PAIR, nonce=nonce)
    assert (
        authorizer.authorize_caller(other, method="POST", path="/v1/fleet", body=b"{}", now=NOW)
        == OTHER_VALIDATOR_HOTKEY
    )
    assert not authorizer.authorize(other, method="POST", path="/v1/fleet", body=b"{}", now=NOW)


# 1e. ValidatorRequestAuthorizer: construction.


class _Provider:
    def __init__(self, *, network: object = NETWORK, netuid: object = NETUID) -> None:
        self.network = network
        self.netuid = netuid

    def load(self, *, now: datetime):
        return None


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        pytest.param({"worker_hotkey": "not-a-hotkey"}, "hotkey", id="worker-hotkey"),
        pytest.param(
            {"snapshot_provider": object()}, "snapshot provider is required", id="no-load"
        ),
        pytest.param(
            {"snapshot_provider": _Provider(network=None)},
            "snapshot provider is required",
            id="no-network",
        ),
        pytest.param(
            {"snapshot_provider": _Provider(netuid=True)},
            "snapshot provider is required",
            id="boolean-netuid",
        ),
        pytest.param(
            {"snapshot_provider": _Provider(netuid=str(NETUID))},
            "snapshot provider is required",
            id="string-netuid",
        ),
        pytest.param(
            {"channel_binding": _binding().digest},
            "TLS channel binding",
            id="raw-binding-digest",
        ),
        pytest.param({"state": "validator-access.sqlite"}, "durable replay state", id="state-path"),
    ],
)
def test_authorizer_refuses_unverified_construction(
    tmp_path: Path, overrides: dict[str, object], match: str
):
    arguments: dict[str, object] = {
        "snapshot_provider": _Provider(),
        "worker_hotkey": WORKER_HOTKEY,
        "channel_binding": _binding(),
        "state": ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        "signature_verifier": load_sr25519_verifier(),
    }
    arguments.update(overrides)
    provider = arguments.pop("snapshot_provider")

    with pytest.raises(ValidatorAccessError, match=match):
        ValidatorRequestAuthorizer(provider, **arguments)  # type: ignore[arg-type]


# 2. preflight_sr25519_verifier.


def test_preflight_accepts_the_real_sr25519_verifier():
    assert preflight_sr25519_verifier(load_sr25519_verifier()) is None


_REAL_VERIFIER = load_sr25519_verifier()


@pytest.mark.parametrize(
    "verifier",
    [
        pytest.param(lambda signature, message, public_key: True, id="accepts-everything"),
        pytest.param(lambda signature, message, public_key: False, id="rejects-everything"),
        pytest.param(
            lambda signature, message, public_key: (
                not _REAL_VERIFIER(signature, message, public_key)
            ),
            id="inverted",
        ),
        # Each half is checked by identity, so a verifier that is right in
        # truthiness but returns a non-bool on one side is still refused.
        pytest.param(
            lambda signature, message, public_key: (
                1 if _REAL_VERIFIER(signature, message, public_key) else False
            ),
            id="truthy-integer-accept",
        ),
        pytest.param(
            lambda signature, message, public_key: (
                True if _REAL_VERIFIER(signature, message, public_key) else 0
            ),
            id="falsy-integer-reject",
        ),
    ],
)
def test_preflight_refuses_a_broken_verifier(verifier):
    with pytest.raises(ValidatorAccessError, match="known-answer check"):
        preflight_sr25519_verifier(verifier)


# 3. verify_validator_access_snapshot.


def test_snapshot_on_a_random_subnet_verifies():
    snapshot = _verify(_sign(_snapshot_doc()))

    assert (snapshot.network, snapshot.netuid) == (NETWORK, NETUID)
    assert snapshot.qualifies(VALIDATOR_HOTKEY, at=NOW)


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        pytest.param({"network": ""}, "expected network is invalid", id="empty-network"),
        pytest.param({"network": "Finney"}, "expected network is invalid", id="network-case"),
        pytest.param({"network": 7}, "expected network is invalid", id="network-type"),
        pytest.param({"netuid": -1}, "expected netuid is invalid", id="negative-netuid"),
        pytest.param({"netuid": MAX_NETUID + 1}, "expected netuid is invalid", id="large-netuid"),
        pytest.param({"netuid": True}, "expected netuid is invalid", id="boolean-netuid"),
        pytest.param({"netuid": str(NETUID)}, "expected netuid is invalid", id="string-netuid"),
        pytest.param(
            {"required_minimum_stake_rao": -1},
            "required snapshot minimum stake is invalid",
            id="negative-stake",
        ),
        pytest.param(
            {"required_minimum_stake_rao": MAX_STAKE_RAO + 1},
            "required snapshot minimum stake is invalid",
            id="large-stake",
        ),
        pytest.param(
            {"required_minimum_stake_rao": True},
            "required snapshot minimum stake is invalid",
            id="boolean-stake",
        ),
    ],
)
def test_snapshot_verifier_refuses_an_invalid_worker_policy(
    overrides: dict[str, object], match: str
):
    with pytest.raises(ValidatorAccessError, match=match):
        _verify(_sign(_snapshot_doc()), **overrides)


def _without(field: str) -> dict[str, object]:
    document = _snapshot_doc()
    del document[field]
    return document


@pytest.mark.parametrize(
    ("document", "match"),
    [
        pytest.param(
            lambda: _without("block_hash"), "missing or unknown critical fields", id="no-hash"
        ),
        pytest.param(
            lambda: _without("validators"),
            "missing or unknown critical fields",
            id="no-validators",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "comment": "harmless"},
            "missing or unknown critical fields",
            id="extra-field",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "schema": "cathedral_validator_access_snapshot_v2"},
            "schema is unsupported",
            id="future-schema",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "schema": VALIDATOR_REQUEST_SCHEMA},
            "schema is unsupported",
            id="request-schema",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "network": "testnet"},
            "different network or netuid",
            id="other-network",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "netuid": OTHER_NETUID},
            "different network or netuid",
            id="other-netuid",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "netuid": str(NETUID)},
            "snapshot netuid must be an integer",
            id="string-netuid",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block_is_finalized": False},
            "not finalized",
            id="unfinalized",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block_is_finalized": 1},
            "not finalized",
            id="finalized-as-integer",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block_is_finalized": "true"},
            "not finalized",
            id="finalized-as-string",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block": 0}, "bounded positive integer", id="block-zero"
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block": True},
            "bounded positive integer",
            id="block-boolean",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block": MAX_SQLITE_INTEGER + 1},
            "bounded positive integer",
            id="block-overflow",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block": "8948557"},
            "bounded positive integer",
            id="block-string",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block_hash": "0x" + "A" * 64},
            "block hash is invalid",
            id="hash-uppercase",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block_hash": "a" * 64},
            "block hash is invalid",
            id="hash-no-prefix",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "block_hash": "0x" + "a" * 63},
            "block hash is invalid",
            id="hash-short",
        ),
        pytest.param(
            lambda: {**_snapshot_doc(), "signing_key_id": "Cathedral Validator Access"},
            "signing key id is invalid",
            id="key-id-format",
        ),
    ],
)
def test_signed_snapshot_with_a_bad_header_field_is_refused(document, match: str):
    with pytest.raises(ValidatorAccessError, match=match):
        _verify(_sign(document()))


def test_unsigned_snapshot_is_refused():
    with pytest.raises(ValidatorAccessError, match="missing or unknown critical fields"):
        _verify(canonical_json(_snapshot_doc()))


@pytest.mark.parametrize(
    ("document", "trusted_keys"),
    [
        pytest.param(
            lambda: {**_snapshot_doc(), "signing_key_id": "other-operator-key"},
            TRUSTED_KEYS,
            id="unknown-key-id",
        ),
        pytest.param(_snapshot_doc, {}, id="no-trusted-keys"),
        pytest.param(_snapshot_doc, {KEY_ID: TRUSTED_KEYS[KEY_ID][:31]}, id="short-key"),
        pytest.param(_snapshot_doc, {KEY_ID: TRUSTED_KEYS[KEY_ID].hex()}, id="hex-key"),
    ],
)
def test_snapshot_under_an_untrusted_key_is_refused(document, trusted_keys: dict[str, object]):
    with pytest.raises(ValidatorAccessError, match="signing key is not trusted"):
        _verify(_sign(document()), trusted_keys=trusted_keys)


@pytest.mark.parametrize(
    ("signature", "match"),
    [
        pytest.param(lambda _: "signature", "signature object is invalid", id="string"),
        pytest.param(
            lambda signature: {"algorithm": signature["algorithm"]},
            "signature object is invalid",
            id="missing-value",
        ),
        pytest.param(
            lambda signature: {**signature, "key_id": KEY_ID},
            "signature object is invalid",
            id="extra-key",
        ),
        pytest.param(
            lambda signature: {**signature, "algorithm": "sr25519"},
            "algorithm is unsupported",
            id="sr25519",
        ),
        pytest.param(
            lambda signature: {
                **signature,
                "value_base64": _signature_with_trailing_bits(signature["value_base64"]),
            },
            "must be 64 bytes",
            id="non-canonical-trailing-bits",
        ),
        pytest.param(
            lambda signature: {**signature, "value_base64": "!!"},
            "not canonical base64",
            id="not-base64",
        ),
        pytest.param(
            lambda signature: {**signature, "value_base64": _signature_value_bytes(63)},
            "must be 64 bytes",
            id="63-bytes",
        ),
    ],
)
def test_malformed_snapshot_signature_object_is_refused(signature, match: str):
    signed = sign_validator_access_snapshot(_snapshot_doc(), SNAPSHOT_SEED)
    signed["signature"] = signature(signed["signature"])

    with pytest.raises(ValidatorAccessError, match=match):
        _verify(canonical_json(signed))


def _raised_stake_after_signing() -> bytes:
    signed = sign_validator_access_snapshot(_snapshot_doc(), SNAPSHOT_SEED)
    rows = signed["validators"]
    assert isinstance(rows, list)
    rows[0]["stake_rao"] = 9_000_000
    return canonical_json(signed)


def _moved_block_after_signing() -> bytes:
    signed = sign_validator_access_snapshot(_snapshot_doc(), SNAPSHOT_SEED)
    signed["block"] = 8_948_558
    return canonical_json(signed)


@pytest.mark.parametrize(
    "encoded",
    [
        pytest.param(
            lambda: _sign(_snapshot_doc(), OTHER_SNAPSHOT_SEED), id="another-operator-key"
        ),
        pytest.param(_raised_stake_after_signing, id="stake-raised-after-signing"),
        pytest.param(_moved_block_after_signing, id="block-moved-after-signing"),
    ],
)
def test_snapshot_signature_that_does_not_verify_is_refused(encoded):
    with pytest.raises(ValidatorAccessError, match="signature verification failed"):
        _verify(encoded())


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        pytest.param(
            {"expires_at": _utc_text(NOW)}, "validity window is invalid", id="zero-window"
        ),
        pytest.param(
            {"expires_at": _utc_text(NOW - timedelta(seconds=1))},
            "validity window is invalid",
            id="negative-window",
        ),
        pytest.param(
            {"generated_at": "2026-08-29T05:00:00.000Z"},
            "canonical UTC time",
            id="fractional-generated-at",
        ),
        pytest.param(
            {"expires_at": "2026-02-30T05:10:00Z"},
            "canonical UTC time",
            id="impossible-expires-at",
        ),
    ],
)
def test_snapshot_with_a_bad_validity_window_is_refused(changes: dict[str, object], match: str):
    with pytest.raises(ValidatorAccessError, match=match):
        _verify(_sign({**_snapshot_doc(), **changes}))


@pytest.mark.parametrize(
    ("now", "match"),
    [
        pytest.param(NOW.replace(tzinfo=None), "must be UTC", id="naive"),
        pytest.param(
            NOW - timedelta(seconds=MAX_REQUEST_FUTURE_SKEW_SECONDS + 1),
            "generation time is in the future",
            id="beyond-skew",
        ),
        pytest.param(NOW - timedelta(seconds=1), "outside its validity window", id="not-yet-valid"),
        pytest.param(NOW + timedelta(minutes=10), "outside its validity window", id="at-expiry"),
        pytest.param(NOW + timedelta(days=1), "outside its validity window", id="long-expired"),
    ],
)
def test_snapshot_outside_its_validity_window_is_refused(now: datetime, match: str):
    encoded = _sign(_snapshot_doc(generated_at=NOW, expires_at=NOW + timedelta(minutes=10)))

    with pytest.raises(ValidatorAccessError, match=match):
        _verify(encoded, now=now)


def test_snapshot_older_than_the_worker_maximum_age_is_refused():
    encoded = _sign(_snapshot_doc(generated_at=NOW, expires_at=NOW + timedelta(minutes=10)))

    assert _verify(encoded, now=NOW + timedelta(seconds=60), max_age_seconds=60) is not None
    with pytest.raises(ValidatorAccessError, match="too stale"):
        _verify(encoded, now=NOW + timedelta(seconds=61), max_age_seconds=60)


@pytest.mark.parametrize(
    "minimum",
    [-1, True, MAX_STAKE_RAO + 1, "1000", None],
)
def test_snapshot_with_an_invalid_stake_floor_is_refused(minimum: object):
    document = _snapshot_doc()
    document["minimum_stake_rao"] = minimum

    with pytest.raises(ValidatorAccessError, match="snapshot minimum stake is invalid"):
        _verify(_sign(document))


def _sorted_rows(count: int) -> list[dict[str, object]]:
    hotkeys = sorted(_hotkey(index.to_bytes(32, "big")) for index in range(1, count + 1))
    return [_row(hotkey, uid) for uid, hotkey in enumerate(hotkeys)]


def test_snapshot_at_the_validator_cap_is_accepted():
    document = _snapshot_doc()
    document["validators"] = _sorted_rows(MAX_VALIDATORS)

    assert len(_verify(_sign(document)).validators) == MAX_VALIDATORS


@pytest.mark.parametrize(
    "validators",
    [
        pytest.param(list, id="empty"),
        pytest.param(dict, id="object"),
        pytest.param(lambda: "validators", id="string"),
        pytest.param(lambda: _sorted_rows(MAX_VALIDATORS + 1), id="over-cap"),
    ],
)
def test_snapshot_validator_list_must_be_bounded_and_nonempty(validators):
    document = _snapshot_doc()
    document["validators"] = validators()

    with pytest.raises(ValidatorAccessError, match="bounded nonempty list"):
        _verify(_sign(document))


def _one_row(**changes: object) -> dict[str, object]:
    row = _row(VALIDATOR_HOTKEY, 30)
    row.update(changes)
    return row


def _row_without(field: str) -> dict[str, object]:
    row = _row(VALIDATOR_HOTKEY, 30)
    del row[field]
    return row


@pytest.mark.parametrize(
    ("row", "match"),
    [
        pytest.param(lambda: VALIDATOR_HOTKEY, "validator row is invalid", id="string-row"),
        pytest.param(lambda: _row_without("uid"), "validator row is invalid", id="no-uid"),
        pytest.param(
            lambda: _one_row(coldkey=OTHER_VALIDATOR_HOTKEY),
            "validator row is invalid",
            id="extra-field",
        ),
        pytest.param(lambda: _one_row(hotkey="not-a-hotkey"), "SS58", id="bad-hotkey"),
        pytest.param(lambda: _one_row(uid=-1), "uid is invalid", id="negative-uid"),
        pytest.param(lambda: _one_row(uid=MAX_UID + 1), "uid is invalid", id="large-uid"),
        pytest.param(lambda: _one_row(uid=True), "uid is invalid", id="boolean-uid"),
        pytest.param(lambda: _one_row(uid="30"), "uid is invalid", id="string-uid"),
        pytest.param(lambda: _one_row(stake_rao=-1), "stake is invalid", id="negative-stake"),
        pytest.param(
            lambda: _one_row(stake_rao=MAX_STAKE_RAO + 1), "stake is invalid", id="large-stake"
        ),
        pytest.param(lambda: _one_row(stake_rao=True), "stake is invalid", id="boolean-stake"),
        pytest.param(lambda: _one_row(stake_rao="2000"), "stake is invalid", id="string-stake"),
        pytest.param(
            lambda: _one_row(validator_permit=1), "validator-permit", id="permit-as-integer"
        ),
    ],
)
def test_snapshot_with_a_bad_validator_row_is_refused(row, match: str):
    document = _snapshot_doc()
    document["validators"] = [row()]

    with pytest.raises(ValidatorAccessError, match=match):
        _verify(_sign(document))


def test_snapshot_rows_out_of_hotkey_order_are_refused():
    document = _snapshot_doc()
    document["validators"] = list(reversed(_sorted_rows(2)))

    with pytest.raises(ValidatorAccessError, match="sorted by hotkey"):
        _verify(_sign(document))


def test_snapshot_over_the_registry_size_cap_is_refused():
    encoded = _sign(_snapshot_doc())
    padded = encoded + b" " * (MAX_REGISTRY_BYTES + 1 - len(encoded))

    with pytest.raises(PolicyRegistryError, match="maximum encoded size"):
        _verify(padded)


def _snapshot_provider(tmp_path: Path, encoded: bytes) -> SignedValidatorSnapshotProvider:
    path = tmp_path / "validator-access.json"
    path.write_bytes(encoded)
    path.chmod(0o644)
    return SignedValidatorSnapshotProvider(
        str(path),
        TRUSTED_KEYS,
        network=NETWORK,
        netuid=NETUID,
        minimum_stake_rao=1_000,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
    )


def test_snapshot_file_is_bounded_at_its_size_cap(tmp_path: Path):
    encoded = _sign(_snapshot_doc())
    at_cap = encoded + b" " * (MAX_SNAPSHOT_BYTES - len(encoded))
    over_cap = at_cap + b" "
    assert len(at_cap) == MAX_SNAPSHOT_BYTES

    # Whitespace does not change the signed canonical bytes, so the padded
    # document verifies directly; only the file cap refuses the larger one.
    assert _verify(over_cap).digest == _verify(encoded).digest
    accepted = tmp_path / "at-cap"
    accepted.mkdir(mode=0o700)
    refused = tmp_path / "over-cap"
    refused.mkdir(mode=0o700)
    assert _snapshot_provider(accepted, at_cap).load(now=NOW) is not None
    assert _snapshot_provider(refused, over_cap).load(now=NOW) is None


def test_finalize_result_names_each_refusal_and_its_fault(tmp_path: Path):
    """The worker benches only client faults, so finalize must say which
    refusal it made. finalize itself still answers None for every one."""
    authorizer = _authorizer(tmp_path)

    def refusal(request, *, body=b"{}", now=NOW):
        assert authorizer.finalize(request, body=body, now=now) is None
        return authorizer.finalize_result(request, body=body, now=now)

    request = _preauthorized(authorizer, _header(), now=NOW)
    assert refusal(request, body=b'{"x":1}') is ValidatorRefusal.BODY_MISMATCH
    assert refusal(request, now=NOW + REQUEST_LIFETIME) is ValidatorRefusal.EXPIRED
    assert not authorizer.is_replay(request, now=NOW)
    assert authorizer.finalize_result(request, body=b"{}", now=NOW) == VALIDATOR_HOTKEY
    assert authorizer.is_replay(request, now=NOW)
    assert refusal(request) is ValidatorRefusal.REPLAYED
    for client in (
        ValidatorRefusal.BODY_MISMATCH,
        ValidatorRefusal.EXPIRED,
        ValidatorRefusal.REPLAYED,
        ValidatorRefusal.NOT_QUALIFIED,
    ):
        assert client.client_fault
    for worker_side in (
        ValidatorRefusal.SNAPSHOT_UNAVAILABLE,
        ValidatorRefusal.REPLAY_STATE_UNAVAILABLE,
        ValidatorRefusal.WORKER_ERROR,
    ):
        assert not worker_side.client_fault
    assert refusal(request, body="{}") is ValidatorRefusal.WORKER_ERROR


def test_a_current_snapshot_that_drops_the_validator_is_a_client_fault(tmp_path: Path):
    """A lapsed or missing snapshot is the worker's refusal, but a current one
    that no longer lists the caller is the validator's, so it benches."""
    authorizer = _authorizer(tmp_path)
    request = _preauthorized(authorizer, _header(), now=NOW)
    authorizer.snapshot_provider = StaticValidatorSnapshotProvider(
        _access_snapshot(hotkeys=(OTHER_VALIDATOR_HOTKEY,))
    )
    assert authorizer.finalize(request, body=b"{}", now=NOW) is None
    refusal = authorizer.finalize_result(request, body=b"{}", now=NOW)
    assert refusal is ValidatorRefusal.NOT_QUALIFIED
    assert refusal.client_fault


def test_a_store_expiry_is_refused_as_expired(tmp_path: Path, monkeypatch):
    """record_request compares whole seconds, so it can answer EXPIRED for a
    request finalize's own check still treats as live. That is the request's
    lapse, not the worker's store failing."""
    authorizer = _authorizer(tmp_path)
    request = _preauthorized(authorizer, _header(), now=NOW)
    monkeypatch.setattr(
        authorizer.state, "record_request", lambda *_args, **_kwargs: ReplayRecord.EXPIRED
    )
    assert authorizer.finalize_result(request, body=b"{}", now=NOW) is ValidatorRefusal.EXPIRED


def test_is_replay_consumes_nothing(tmp_path: Path):
    authorizer = _authorizer(tmp_path)
    request = _preauthorized(authorizer, _header(nonce=b"q" * 32), now=NOW)
    for _ in range(3):
        assert not authorizer.is_replay(request, now=NOW)
    assert authorizer.finalize(request, body=b"{}", now=NOW) == VALIDATOR_HOTKEY


def test_a_lapsed_snapshot_or_a_full_store_is_the_workers_refusal(tmp_path: Path):
    snapshot = _access_snapshot(
        generated_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(seconds=30),
    )
    authorizer = _authorizer(tmp_path, snapshot)
    request = _preauthorized(authorizer, _header(), now=NOW)
    assert (
        authorizer.finalize_result(request, body=b"{}", now=NOW + timedelta(seconds=30))
        is ValidatorRefusal.SNAPSHOT_UNAVAILABLE
    )

    full = ValidatorRequestAuthorizer(
        _access_snapshot(),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=_binding(),
        state=ValidatorAccessState(str(tmp_path / "full.sqlite"), max_replay_entries=1),
        signature_verifier=load_sr25519_verifier(),
    )
    first = _preauthorized(full, _header(nonce=b"1" * 32), now=NOW)
    second = _preauthorized(full, _header(nonce=b"2" * 32), now=NOW)
    assert full.finalize(first, body=b"{}", now=NOW) == VALIDATOR_HOTKEY
    assert (
        full.finalize_result(second, body=b"{}", now=NOW)
        is ValidatorRefusal.REPLAY_STATE_UNAVAILABLE
    )
