"""Publisher drift detector (cathedral-compute #141)."""

from __future__ import annotations

import base64
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.evidence import build_signed_index, digest_bytes

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_detect_publisher_drift",
    Path(__file__).resolve().parents[1] / "scripts" / "detect_publisher_drift.py",
)
drift = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(drift)

DEFAULT_MECHANISM_ID = drift.DEFAULT_MECHANISM_ID
DriftError = drift.DriftError
compare_manifest = drift.compare_manifest
load_latest_manifest = drift.load_latest_manifest
main = drift.main

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
INDEX_SEED = bytes(range(96, 128))


def _manifest(**over: object) -> dict:
    document: dict = {
        "generated_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reward_mechanism": {"id": DEFAULT_MECHANISM_ID, "revision": 1},
        "source_revision": "d0e303b" + "0" * 33,
        "verifier": {"digest": "sha256:" + "6" * 64},
    }
    document.update(over)
    return document


def _files_for_manifest(
    manifest: dict, *, signed: bool = False, index_generated_at: datetime = NOW
) -> tuple[str, dict[str, bytes]]:
    body = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
    digest = digest_bytes(body)
    hex_digest = digest.removeprefix("sha256:")
    if signed:
        index = build_signed_index(
            network="finney",
            netuid=39,
            latest_source_epoch=11,
            latest_manifest_digest=digest,
            recent=[],
            signing_key_id="evidence-index-test-1",
            private_key_seed=INDEX_SEED,
            generated_at=index_generated_at.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
        )
    else:
        index = json.dumps({"latest": {"manifest": digest}}).encode()
    files = {
        "https://evidence.test/index.json": index,
        f"https://evidence.test/blobs/sha256/{hex_digest}": body,
    }
    return digest, files


def test_compare_manifest_accepts_a_current_v2_tip() -> None:
    compare_manifest(
        "sha256:" + "ab" * 32,
        _manifest(),
        git_dir=None,
        release=None,
        max_age=timedelta(minutes=180),
        now=NOW,
    )


def test_compare_manifest_fails_a_stale_mechanism() -> None:
    with pytest.raises(DriftError, match="reward_mechanism"):
        compare_manifest(
            "sha256:" + "ab" * 32,
            _manifest(reward_mechanism={"id": "validated_supply_v1", "revision": 1}),
            git_dir=None,
            release=None,
            max_age=timedelta(minutes=180),
            now=NOW,
        )


def test_compare_manifest_fails_when_live_is_ahead_of_the_sealed_release() -> None:
    """A main-only check would pass here. The sealed release is the gate."""
    live = _manifest(source_revision="aaaaaaaa" + "0" * 32)
    release = {
        "source_revision": "bbbbbbbb" + "0" * 32,
        "verifier_digest": live["verifier"]["digest"],
        "reward_mechanism": live["reward_mechanism"],
    }
    with pytest.raises(DriftError, match="sealed release"):
        compare_manifest(
            "sha256:" + "ab" * 32,
            live,
            git_dir=None,
            release=release,
            max_age=timedelta(minutes=180),
            now=NOW,
        )


def test_compare_manifest_fails_a_stale_generated_at() -> None:
    old = (NOW - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(DriftError, match="generated_at"):
        compare_manifest(
            "sha256:" + "ab" * 32,
            _manifest(generated_at=old),
            git_dir=None,
            release=None,
            max_age=timedelta(minutes=180),
            now=NOW,
        )


def test_compare_manifest_fails_a_future_generated_at() -> None:
    future = (NOW + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(DriftError, match="ahead of current UTC"):
        compare_manifest(
            "sha256:" + "ab" * 32,
            _manifest(generated_at=future),
            git_dir=None,
            release=None,
            max_age=timedelta(minutes=180),
            now=NOW,
        )


def test_load_latest_manifest_rejects_an_unhashed_pointer() -> None:
    files = {
        "https://evidence.test/index.json": json.dumps(
            {"latest": {"manifest": "sha256:" + "00" * 32}}
        ).encode(),
        f"https://evidence.test/blobs/sha256/{'00' * 32}": json.dumps(_manifest()).encode(),
    }
    with pytest.raises(DriftError, match="do not hash"):
        load_latest_manifest("https://evidence.test", fetch=lambda url: files[url], netuid=39)


def test_load_latest_manifest_reads_the_public_index_shape() -> None:
    digest, files = _files_for_manifest(_manifest())
    got, manifest = load_latest_manifest(
        "https://evidence.test",
        fetch=lambda url: files[url],
        netuid=39,
    )
    assert got == digest
    assert manifest["reward_mechanism"]["id"] == DEFAULT_MECHANISM_ID


def test_load_latest_manifest_verifies_a_signed_index() -> None:
    digest, files = _files_for_manifest(_manifest(), signed=True)
    public = (
        Ed25519PrivateKey.from_private_bytes(INDEX_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    got, manifest = load_latest_manifest(
        "https://evidence.test",
        fetch=lambda url: files[url],
        index_keys={"evidence-index-test-1": public},
        netuid=39,
        require_signed_index=True,
        now=NOW,
    )
    assert got == digest
    assert manifest["reward_mechanism"]["id"] == DEFAULT_MECHANISM_ID


def test_load_latest_manifest_rejects_unsigned_index_when_required() -> None:
    _digest, files = _files_for_manifest(_manifest(), signed=False)
    with pytest.raises(DriftError, match="requires --index-keys"):
        load_latest_manifest(
            "https://evidence.test",
            fetch=lambda url: files[url],
            netuid=39,
            require_signed_index=True,
        )


def test_main_prints_ok_for_a_matching_surface(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest()
    digest, files = _files_for_manifest(manifest)
    release_path = tmp_path / "release.json"
    release_path.write_text(
        json.dumps(
            {
                "source_revision": manifest["source_revision"],
                "verifier_digest": manifest["verifier"]["digest"],
                "reward_mechanism": manifest["reward_mechanism"],
            }
        )
    )
    assert (
        main(
            [
                "--evidence-url",
                "https://evidence.test",
                "--netuid",
                "39",
                "--release",
                str(release_path),
                "--max-age-minutes",
                "180",
            ],
            fetch=lambda url: files[url],
            now=NOW,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["result"] == "ok"
    assert digest.startswith("sha256:")


def test_main_freshness_reads_the_injected_clock() -> None:
    """A tip fresh by the wall clock is stale under the injected clock, so the
    freshness gate provably reads `now` and the fixed-date fixtures above
    never age out."""
    wall = datetime.now(UTC).replace(microsecond=0)
    _digest, files = _files_for_manifest(
        _manifest(generated_at=wall.strftime("%Y-%m-%dT%H:%M:%SZ"))
    )
    with pytest.raises(DriftError, match="generated_at"):
        main(
            [
                "--evidence-url",
                "https://evidence.test",
                "--netuid",
                "39",
                "--max-age-minutes",
                "180",
            ],
            fetch=lambda url: files[url],
            now=wall + timedelta(hours=4),
        )


def test_main_requires_release_when_asked() -> None:
    with pytest.raises(DriftError, match="requires --release"):
        main(["--require-release", "--evidence-url", "https://evidence.test", "--netuid", "39"])


def test_main_requires_index_keys_when_signed_index_is_required() -> None:
    with pytest.raises(DriftError, match="requires --index-keys"):
        main(
            ["--require-signed-index", "--evidence-url", "https://evidence.test", "--netuid", "39"]
        )


def test_main_requires_the_netuid() -> None:
    # The netuid is deploy config: no default quietly supplies one.
    with pytest.raises(SystemExit) as refused:
        main(["--evidence-url", "https://evidence.test"])
    assert refused.value.code == 2


def test_main_verifies_a_signed_index_against_the_injected_clock(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The signed index is dated after the wall clock but not after the
    injected one, so verify_index accepts it only if main passes `now` on."""
    later = datetime.now(UTC).replace(microsecond=0) + timedelta(days=1)
    manifest = _manifest(generated_at=later.strftime("%Y-%m-%dT%H:%M:%SZ"))
    digest, files = _files_for_manifest(manifest, signed=True, index_generated_at=later)
    public = (
        Ed25519PrivateKey.from_private_bytes(INDEX_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    keys = tmp_path / "evidence-index-keys.json"
    keys.write_text(json.dumps({"evidence-index-test-1": base64.b64encode(public).decode()}))
    argv = [
        "--evidence-url",
        "https://evidence.test",
        "--netuid",
        "39",
        "--index-keys",
        str(keys),
        "--require-signed-index",
    ]
    assert main(argv, fetch=lambda url: files[url], now=later + timedelta(minutes=1)) == 0
    assert json.loads(capsys.readouterr().out)["manifest"] == digest
    with pytest.raises(DriftError, match="in the future"):
        main(argv, fetch=lambda url: files[url], now=later - timedelta(minutes=1))
