"""The offline root tool signs what the worker's central authorizer accepts.

Every artifact the tool writes is checked here through the worker-side path in
cathedral/central_access.py: a delegation from ``delegate`` admits a request the
central key signs, and a list from ``revoke`` withdraws it.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cathedral import central_access as ca
from cathedral.common import ChannelBinding, ChannelBindingType

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_central_access_tool",
    Path(__file__).resolve().parents[1] / "scripts" / "cathedral_central_access.py",
)
tool = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(tool)

NETWORK = "finney"
NETUID = random.SystemRandom().randrange(1, 65_536)
WORKER = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
BINDING = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"t" * 32)
PATH = "/v1/capabilities"
ROOT_ID = "cathedral-root-1"


def _run(capsys, *argv: str) -> dict[str, str]:
    assert tool.main(list(argv)) == 0
    lines = capsys.readouterr().out.splitlines()
    return dict(line.split(" ", 1) if " " in line else (line, "") for line in lines)


def _refused(capsys, message: str, *argv: str) -> None:
    with pytest.raises(SystemExit, match=message):
        tool.main(list(argv))
    capsys.readouterr()


def _seed(path: Path) -> bytes:
    return base64.b64decode(path.read_text().strip())


@pytest.fixture
def root(tmp_path: Path, capsys) -> dict[str, object]:
    seed = tmp_path / "root.seed"
    keys = tmp_path / "root-keys.json"
    printed = _run(
        capsys,
        "keygen",
        "--role",
        "root",
        "--key-id",
        ROOT_ID,
        "--seed-out",
        str(seed),
        "--keys-out",
        str(keys),
    )
    central_seed = tmp_path / "central.seed"
    central = _run(
        capsys,
        "keygen",
        "--role",
        "central",
        "--key-id",
        "central-1",
        "--seed-out",
        str(central_seed),
    )
    return {
        "seed": seed,
        "keys": keys,
        "digest": printed["root_keys_digest"],
        "public": printed["public_key_base64"],
        "central_seed": central_seed,
        "central_public": central["public_key_base64"],
        "ledger": tmp_path / "ledger.jsonl",
    }


def _pinned(root: dict[str, object]) -> list[str]:
    return ["--root-keys", str(root["keys"]), "--root-keys-digest", str(root["digest"])]


def _delegate(capsys, root, out: Path, sequence: int, *extra: str) -> dict[str, str]:
    return _run(
        capsys,
        "delegate",
        "--root-key-file",
        str(root["seed"]),
        "--root-key-id",
        ROOT_ID,
        *_pinned(root),
        "--central-public-key",
        str(root["central_public"]),
        "--route",
        PATH,
        "--network",
        NETWORK,
        "--netuid",
        str(NETUID),
        "--sequence",
        str(sequence),
        "--ledger",
        str(root["ledger"]),
        "--out",
        str(out),
        *extra,
    )


def _authorizer(tmp_path: Path, root) -> ca.CentralAccessAuthorizer:
    keys = ca.load_central_root_keys(str(root["keys"]), pinned_digest=str(root["digest"]))
    return ca.CentralAccessAuthorizer(
        keys,
        worker_hotkey=WORKER,
        network=NETWORK,
        netuid=NETUID,
        channel_binding=BINDING,
        state=ca.open_central_access_state(str(tmp_path / "central-state.sqlite")),
    )


def _request(root, delegation_path: Path, nonce: bytes) -> tuple[str, datetime]:
    now = datetime.now(UTC).replace(microsecond=0)
    header = ca.build_central_request_header(
        delegation=json.loads(delegation_path.read_bytes()),
        central_seed=_seed(Path(root["central_seed"])),
        worker_hotkey=WORKER,
        network=NETWORK,
        netuid=NETUID,
        method="POST",
        path=PATH,
        body=b"{}",
        channel_binding=BINDING,
        nonce=nonce,
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(seconds=60),
    )
    return header, now


def _admit(authorizer, root, delegation_path: Path, nonce: bytes) -> str:
    header, now = _request(root, delegation_path, nonce)
    request = authorizer.preauthorize(header, method="POST", path=PATH, now=now)
    return authorizer.finalize(request, body=b"{}", now=now)


def test_keygen_writes_an_owner_only_seed_and_the_pinned_root_key_file(root, capsys):
    seed_path = Path(root["seed"])
    assert os.stat(seed_path).st_mode & 0o777 == 0o600
    assert os.stat(root["keys"]).st_mode & 0o777 == 0o644
    keys = ca.load_central_root_keys(str(root["keys"]), pinned_digest=str(root["digest"]))
    assert base64.b64encode(keys[ROOT_ID]).decode("ascii") == root["public"]
    assert os.stat(root["central_seed"]).st_mode & 0o777 == 0o600


def test_keygen_never_prints_the_seed_and_never_overwrites(tmp_path, capsys):
    seed = tmp_path / "root.seed"
    keys = tmp_path / "keys.json"
    argv = ["keygen", "--role", "root", "--key-id", ROOT_ID]
    assert tool.main([*argv, "--seed-out", str(seed), "--keys-out", str(keys)]) == 0
    printed = capsys.readouterr().out
    assert seed.read_text().strip() not in printed
    before = seed.read_bytes()
    _refused(
        capsys, "refusing to overwrite", *argv, "--seed-out", str(seed), "--keys-out", str(keys)
    )
    assert seed.read_bytes() == before


def test_keygen_leaves_no_root_seed_when_the_key_file_cannot_be_written(tmp_path, capsys):
    keys = tmp_path / "keys.json"
    keys.write_text("{}")
    seed = tmp_path / "root.seed"
    _refused(
        capsys,
        "refusing to overwrite",
        "keygen",
        "--role",
        "root",
        "--key-id",
        ROOT_ID,
        "--seed-out",
        str(seed),
        "--keys-out",
        str(keys),
    )
    assert not seed.exists()


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--role", "root", "--key-id", ROOT_ID], "needs --keys-out"),
        (["--role", "central", "--key-id", "c", "--keys-out", "k.json"], "no key file"),
        (["--role", "central", "--key-id", "Not-Canonical"], "key id must match"),
    ],
)
def test_keygen_refuses_a_malformed_request(tmp_path, capsys, argv, message):
    _refused(capsys, message, "keygen", *argv, "--seed-out", str(tmp_path / "s"))
    assert not (tmp_path / "s").exists()


def test_a_delegation_from_the_tool_admits_a_central_request(tmp_path, root, capsys):
    out = tmp_path / "delegation.json"
    printed = _delegate(capsys, root, out, 3)

    authorizer = _authorizer(tmp_path, root)
    assert _admit(authorizer, root, out, b"a" * 32).startswith("central:")
    assert printed["routes"] == PATH
    assert printed["subnet"] == f"{NETWORK}/{NETUID}"
    assert os.stat(out).st_mode & 0o777 == 0o644

    ledger = [json.loads(line) for line in Path(root["ledger"]).read_text().splitlines()]
    assert [record["sequence"] for record in ledger] == [3]
    assert ledger[0]["digest"] == printed["delegation_digest"]
    assert os.stat(root["ledger"]).st_mode & 0o777 == 0o600

    verified = _run(
        capsys,
        "verify",
        *_pinned(root),
        "--delegation",
        str(out),
        "--network",
        NETWORK,
        "--netuid",
        str(NETUID),
    )
    assert "CENTRAL_DELEGATION_VALID" in verified
    assert verified["delegation_digest"] == printed["delegation_digest"]


def test_delegate_refuses_a_sequence_that_does_not_increase(tmp_path, root, capsys):
    _delegate(capsys, root, tmp_path / "first.json", 7)
    for sequence in (7, 6):
        out = tmp_path / f"again-{sequence}.json"
        with pytest.raises(SystemExit, match="must exceed 7"):
            _delegate(capsys, root, out, sequence)
        assert not out.exists()
    assert len(Path(root["ledger"]).read_text().splitlines()) == 1
    _delegate(capsys, root, tmp_path / "next.json", 8)


def test_delegate_refuses_a_root_seed_the_pinned_file_does_not_name(tmp_path, root, capsys):
    other = tmp_path / "other.seed"
    other_keys = tmp_path / "other-keys.json"
    _run(
        capsys,
        "keygen",
        "--role",
        "root",
        "--key-id",
        ROOT_ID,
        "--seed-out",
        str(other),
        "--keys-out",
        str(other_keys),
    )
    out = tmp_path / "delegation.json"
    with pytest.raises(SystemExit, match="miners would refuse"):
        _delegate(capsys, {**root, "seed": other}, out, 1)
    assert not out.exists()
    assert not Path(root["ledger"]).exists()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"digest": "sha256:" + "0" * 64}, "digest does not match"),
        ({"central_public": "not-base64"}, "canonical base64"),
        ({"central_public": base64.b64encode(b"k" * 31).decode()}, "32-byte"),
    ],
)
def test_delegate_refuses_bad_pins_and_keys(tmp_path, root, capsys, change, message):
    out = tmp_path / "delegation.json"
    with pytest.raises(SystemExit, match=message):
        _delegate(capsys, {**root, **change}, out, 1)
    assert not out.exists()


_P = 2**255 - 19


@pytest.mark.parametrize(
    ("key", "message"),
    [
        # The identity point, 0x01 then 31 zero bytes, with either sign bit.
        (bytes([1]) + bytes(31), "is a small-order Ed25519 point"),
        (bytes([1]) + bytes(30) + b"\x80", "is a small-order Ed25519 point"),
        # A point of order 8.
        (
            bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
            "is a small-order Ed25519 point",
        ),
        # y = p, the non-canonical form of y = 0 (order 4).
        (_P.to_bytes(32, "little"), "is not a canonical Ed25519 point"),
        # y = 2 is not on the curve.
        ((2).to_bytes(32, "little"), "is not an Ed25519 point"),
    ],
    ids=["identity", "identity-sign-bit", "order-8", "non-canonical", "off-curve"],
)
def test_delegate_refuses_to_sign_for_a_small_order_or_non_canonical_key(
    tmp_path, root, capsys, key, message
):
    # A delegation to a small-order key lets anyone sign central requests.
    out = tmp_path / "delegation.json"
    central_public = base64.b64encode(key).decode("ascii")
    with pytest.raises(SystemExit, match=f"refusing to delegate: --central-public-key {message}"):
        _delegate(capsys, {**root, "central_public": central_public}, out, 1)
    assert not out.exists()
    assert not Path(root["ledger"]).exists()


def test_a_malformed_pinned_key_file_is_refused_without_a_traceback(tmp_path, root, capsys):
    keys = tmp_path / "malformed-keys.json"
    keys.write_bytes(b"[]")
    malformed = {**root, "keys": keys, "digest": "sha256:" + hashlib.sha256(b"[]").hexdigest()}
    with pytest.raises(SystemExit, match="central root keys are unusable"):
        _delegate(capsys, malformed, tmp_path / "delegation.json", 1)

    revocations = tmp_path / "revocations.json"
    revocations.write_bytes(b"{}")
    assert tool.main(["verify", *_pinned(malformed), "--revocations", str(revocations)]) == 1
    assert "CENTRAL_ACCESS_INVALID central root keys are unusable" in capsys.readouterr().out


def test_delegate_refuses_to_delegate_to_a_root_key(tmp_path, root, capsys):
    out = tmp_path / "delegation.json"
    with pytest.raises(SystemExit, match="must not be a root key"):
        _delegate(capsys, {**root, "central_public": root["public"]}, out, 1)
    assert not out.exists()


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--valid-hours", "25"], "--valid-hours must be 1 to 24"),
        (["--valid-hours", "0"], "--valid-hours must be 1 to 24"),
        (["--route", "/v1/sat"], "not a central route"),
    ],
)
def test_delegate_refuses_what_the_worker_would_refuse(tmp_path, root, capsys, extra, message):
    out = tmp_path / "delegation.json"
    with pytest.raises(SystemExit, match=message):
        _delegate(capsys, root, out, 1, *extra)
    assert not out.exists()


def test_delegate_refuses_a_group_readable_seed_or_ledger(tmp_path, root, capsys):
    Path(root["seed"]).chmod(0o640)
    with pytest.raises(SystemExit, match="group or world"):
        _delegate(capsys, root, tmp_path / "a.json", 1)
    Path(root["seed"]).chmod(0o600)

    _delegate(capsys, root, tmp_path / "b.json", 1)
    Path(root["ledger"]).chmod(0o644)
    with pytest.raises(SystemExit, match="group or world"):
        _delegate(capsys, root, tmp_path / "c.json", 2)
    assert not (tmp_path / "c.json").exists()


def test_delegate_refuses_a_ledger_with_a_partial_record(tmp_path, root, capsys):
    _delegate(capsys, root, tmp_path / "a.json", 1)
    with Path(root["ledger"]).open("ab") as handle:
        handle.write(b'{"sequence": 2')
    with pytest.raises(SystemExit, match="partial record"):
        _delegate(capsys, root, tmp_path / "b.json", 3)


def _revoke(capsys, root, out: Path, sequence: int, *extra: str) -> dict[str, str]:
    return _run(
        capsys,
        "revoke",
        "--root-key-file",
        str(root["seed"]),
        "--root-key-id",
        ROOT_ID,
        *_pinned(root),
        "--sequence",
        str(sequence),
        "--out",
        str(out),
        *extra,
    )


def test_revocations_from_the_tool_withdraw_a_delegation(tmp_path, root, capsys):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first_digest = _delegate(capsys, root, first, 1)["delegation_digest"]
    second_digest = _delegate(capsys, root, second, 2)["delegation_digest"]
    authorizer = _authorizer(tmp_path, root)
    _admit(authorizer, root, first, b"a" * 32)

    list_one = tmp_path / "revocations-1.json"
    printed = _revoke(
        capsys,
        root,
        list_one,
        1,
        "--first-list",
        "--ledger",
        str(root["ledger"]),
        "--revoke-sequence",
        "1",
    )
    assert printed["revoked"] == "1"
    authorizer.install_revocations(json.loads(list_one.read_bytes()))
    with pytest.raises(ca.CentralAccessError, match="revoked"):
        _admit(authorizer, root, first, b"b" * 32)
    _admit(authorizer, root, second, b"c" * 32)

    list_two = tmp_path / "revocations-2.json"
    printed = _revoke(
        capsys, root, list_two, 2, "--previous", str(list_one), "--revoke", second_digest
    )
    assert printed["revoked"] == "2"
    document = json.loads(list_two.read_bytes())
    assert document["revoked"] == sorted([first_digest, second_digest])
    authorizer.install_revocations(document)
    with pytest.raises(ca.CentralAccessError, match="revoked"):
        _admit(authorizer, root, second, b"d" * 32)

    verified = _run(capsys, "verify", *_pinned(root), "--revocations", str(list_two))
    assert "CENTRAL_REVOCATIONS_VALID" in verified
    assert verified["revocations_sequence"] == "2"


def test_revoke_refuses_to_drop_or_rewind_the_list_in_force(tmp_path, root, capsys):
    digest = _delegate(capsys, root, tmp_path / "d.json", 1)["delegation_digest"]
    list_one = tmp_path / "revocations-1.json"
    _revoke(capsys, root, list_one, 4, "--first-list", "--revoke", digest)

    out = tmp_path / "revocations-2.json"
    with pytest.raises(SystemExit, match="--previous"):
        _revoke(capsys, root, out, 5, "--revoke", digest)
    for sequence in (4, 3):
        with pytest.raises(SystemExit, match="must exceed 4"):
            _revoke(capsys, root, out, sequence, "--previous", str(list_one))
    with pytest.raises(SystemExit, match="--allow-empty"):
        _revoke(capsys, root, out, 1, "--first-list")
    with pytest.raises(SystemExit, match="not a delegation digest"):
        _revoke(capsys, root, out, 1, "--first-list", "--revoke", "sha256:xyz")
    with pytest.raises(SystemExit, match="no delegation with sequence"):
        _revoke(
            capsys,
            root,
            out,
            5,
            "--previous",
            str(list_one),
            "--ledger",
            str(root["ledger"]),
            "--revoke-sequence",
            "9",
        )
    assert not out.exists()


def test_verify_reports_a_tampered_delegation_as_invalid(tmp_path, root, capsys):
    out = tmp_path / "delegation.json"
    _delegate(capsys, root, out, 1)
    document = json.loads(out.read_bytes())
    document["netuid"] = (NETUID % 65_535) + 1
    tampered = tmp_path / "tampered.json"
    tampered.write_bytes(ca.canonical_json(document))

    assert (
        tool.main(
            [
                "verify",
                *_pinned(root),
                "--delegation",
                str(tampered),
                "--network",
                NETWORK,
                "--netuid",
                str(document["netuid"]),
            ]
        )
        == 1
    )
    assert "CENTRAL_ACCESS_INVALID" in capsys.readouterr().out
