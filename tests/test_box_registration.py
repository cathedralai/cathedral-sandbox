"""Box registration: the miner's signed, sealed record of a Cathedral runtime box."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import sr25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from cathedral import box_registration as reg

# netuid is deploy config: draw one per run, as the other suites do.
NETUID = random.SystemRandom().randrange(1, 65536)
OTHER_NETUID = NETUID % 65535 + 1
NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC)
CERT = "c3" * 32
REVISION = "bd143ad8a18569351ffabf28c84e282f7c55b41b"
RUNTIME_KEY = b"e2b_0123456789abcdef0123456789abcdef"


def _base58(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + (encoded or "1")


def _hotkey(public_key: bytes) -> str:
    payload = b"\x2a" + public_key
    checksum = hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()[:2]
    return _base58(payload + checksum)


def _keypair(seed: bytes):
    pair = sr25519.pair_from_seed(seed)
    return SimpleNamespace(ss58_address=_hotkey(pair[0]), sign=lambda m: sr25519.sign(pair, m))


MINER = _keypair(b"m" * 32)
OTHER = _keypair(b"x" * 32)
PROBER = X25519PrivateKey.generate()


def _host_values(**changes) -> str:
    values = {
        "CATHEDRAL_RUNTIME_GIT_REVISION": REVISION,
        "CATHEDRAL_CAPACITY_VCPU": "16",
        "CATHEDRAL_CAPACITY_MEMORY_GIB": "52",
        "CATHEDRAL_E2B_API_URL": "https://34.1.2.3",
        "CATHEDRAL_E2B_SANDBOX_URL": "https://34.1.2.3:8443",
        "CATHEDRAL_TLS_CERT_SHA256": CERT,
        "CATHEDRAL_TEMPLATES_JSON": json.dumps(
            [
                {
                    "name": "cathedral-standard-1x4",
                    "cpu": 1,
                    "memory_gib": 4,
                    "template_id": "t1",
                    "build_id": "b1",
                }
            ]
        ),
        "CATHEDRAL_TUNNEL_MODE": "direct",
    }
    values.update(changes)
    return "".join(f"{key}={value}\n" for key, value in values.items() if value is not None)


def _registration(**changes):
    args = dict(
        host_values_text=_host_values(),
        runtime_key=RUNTIME_KEY,
        prober_public_key=PROBER.public_key(),
        netuid=NETUID,
        kind="bare_metal",
        keypair=MINER,
        now=NOW,
    )
    args.update(changes)
    return reg.register(**args)


def _verify(signed, **changes):
    args = dict(netuid=NETUID, now=NOW + timedelta(minutes=1))
    args.update(changes)
    return reg.verify_registration(signed, **args)


def test_a_registration_verifies_and_only_the_prober_opens_its_key():
    signed = _registration()
    verified = _verify(signed)
    assert verified.miner_hotkey == MINER.ss58_address
    assert (verified.vcpus, verified.memory_gib, verified.kind) == (16, 52, "bare_metal")
    assert verified.control_url == "https://34.1.2.3"
    assert verified.box_id == reg.box_id_for(CERT, MINER.ss58_address)
    assert reg.open_runtime_key(verified, PROBER) == RUNTIME_KEY
    with pytest.raises(reg.RegistrationError, match="verify the registration"):
        reg.open_runtime_key(signed, PROBER)  # an unverified document is never opened
    with pytest.raises(reg.RegistrationError, match="does not open"):
        reg.open_runtime_key(verified, X25519PrivateKey.generate())
    assert RUNTIME_KEY not in json.dumps(signed).encode()


def test_a_sealed_key_cannot_be_lifted_onto_another_registration():
    first = _registration()
    second = _registration(
        host_values_text=_host_values(
            CATHEDRAL_E2B_API_URL="https://34.9.9.9",
            CATHEDRAL_E2B_SANDBOX_URL="https://34.9.9.9:8443",
        )
    )
    second["sealed_runtime_key"] = first["sealed_runtime_key"]
    body = {k: v for k, v in second.items() if k != "signature"}
    resigned = reg.sign_registration(body, MINER.sign)
    with pytest.raises(reg.RegistrationError, match="does not open"):
        reg.open_runtime_key(_verify(resigned), PROBER)


def test_tampering_or_another_hotkey_is_refused():
    signed = _registration()
    tampered = copy.deepcopy(signed)
    tampered["capacity"]["vcpus"] = 64
    with pytest.raises(reg.RegistrationError, match="does not verify"):
        _verify(tampered)
    stolen = copy.deepcopy(signed)
    stolen["signature"]["value_b64"] = reg.sign_registration(
        {k: v for k, v in signed.items() if k != "signature"}, OTHER.sign
    )["signature"]["value_b64"]
    with pytest.raises(reg.RegistrationError, match="does not verify"):
        _verify(stolen)
    with pytest.raises(reg.RegistrationError, match="another netuid"):
        _verify(signed, netuid=OTHER_NETUID)
    with pytest.raises(reg.RegistrationError, match="not currently valid"):
        _verify(signed, now=NOW + timedelta(days=2))
    with pytest.raises(reg.RegistrationError, match="not a signed object"):
        _verify({k: v for k, v in signed.items() if k != "signature"})


def _body(signed):
    return copy.deepcopy({k: v for k, v in signed.items() if k != "signature"})


def _hand_signed(body, *, algorithm="sr25519", raw=None):
    """Sign a hand-edited body directly, past sign_registration's own checks, so
    that verify_registration is the only thing that can refuse it."""
    raw = MINER.sign(reg.canonical_bytes(body)) if raw is None else raw
    return {
        **body,
        "signature": {"algorithm": algorithm, "value_b64": base64.b64encode(raw).decode()},
    }


def test_the_box_key_is_the_same_under_every_hotkey():
    mine, theirs = _verify(_registration()), _verify(_registration(keypair=OTHER))
    assert mine.box_key == theirs.box_key == reg.box_key_for(CERT)
    assert mine.box_id != theirs.box_id  # box_id stays per hotkey
    assert mine.box_key.startswith("boxkey-") and len(mine.box_key) == len("boxkey-") + 32
    assert reg.box_key_for(CERT) != reg.box_key_for(
        "d4" * 32
    )  # a renewed certificate is a new box_key


def test_a_registration_issued_in_the_future_is_refused():
    body = _body(_registration())
    body["issued_at"] = reg._iso(NOW + reg.ISSUED_AT_SKEW)
    assert _verify(_hand_signed(body), now=NOW).issued_at == NOW + reg.ISSUED_AT_SKEW
    body["issued_at"] = reg._iso(NOW + reg.ISSUED_AT_SKEW + timedelta(seconds=1))
    with pytest.raises(reg.RegistrationError, match="not currently valid"):
        _verify(_hand_signed(body), now=NOW)


@pytest.mark.parametrize("expires_offset", [timedelta(seconds=-1), timedelta(0)])
def test_a_registration_that_expires_before_it_is_issued_is_refused(expires_offset):
    # now sits inside the skew window before issued_at, so the time check alone
    # (now >= expires_at) would accept it.
    body = _body(_registration())
    body["issued_at"] = reg._iso(NOW)
    body["expires_at"] = reg._iso(NOW + expires_offset)
    with pytest.raises(reg.RegistrationError, match="validity must be positive"):
        _verify(_hand_signed(body), now=NOW - timedelta(minutes=2))


def test_a_registration_is_refused_from_the_second_it_expires():
    signed = _registration()
    expires = NOW + timedelta(days=1)
    assert _verify(signed, now=expires - timedelta(seconds=1)).expires_at == expires
    with pytest.raises(reg.RegistrationError, match="not currently valid"):
        _verify(signed, now=expires)


def test_replays_are_ordered_per_ip_and_hotkey_with_a_future_issued_at_clamped():
    owner = _verify(_registration(), now=NOW)
    # Anyone can sign the owner's public host values under their own hotkey,
    # sealing a key they made up, dated to the end of the skew window. It
    # verifies and opens (only the probe fails), but it is ordered in its own
    # scope, so it never outranks or refuses the owner's renewal.
    squatter = _verify(
        _registration(keypair=OTHER, runtime_key=b"f" * 64, now=NOW + reg.ISSUED_AT_SKEW), now=NOW
    )
    assert (squatter.control_url, squatter.box_key) == (owner.control_url, owner.box_key)
    assert reg.open_runtime_key(squatter, PROBER) == b"f" * 64
    owner_scope, owner_order = reg.replay_order(owner, now=NOW)
    squatter_scope, squatter_order = reg.replay_order(squatter, now=NOW)
    assert owner_scope == ("34.1.2.3", MINER.ss58_address)
    assert squatter_scope == ("34.1.2.3", OTHER.ss58_address)
    assert squatter_order == NOW  # clamped from NOW + 5 minutes
    # A renewal after a certificate renewal stays in the owner's scope.
    renewed = _verify(
        _registration(host_values_text=_host_values(CATHEDRAL_TLS_CERT_SHA256="d4" * 32)), now=NOW
    )
    assert reg.replay_order(renewed, now=NOW)[0] == owner_scope
    # The owner's own document dated ahead cannot outrank one signed after it.
    ahead = _verify(_registration(now=NOW + timedelta(minutes=4)), now=NOW)
    later = _verify(_registration(now=NOW + timedelta(minutes=1)), now=NOW + timedelta(minutes=1))
    assert (
        reg.replay_order(ahead, now=NOW)[1]
        < reg.replay_order(later, now=NOW + timedelta(minutes=1))[1]
    )
    # A past issued_at is kept as it is.
    assert owner_order == NOW
    assert reg.replay_order(owner, now=NOW + timedelta(hours=1))[1] == NOW
    with pytest.raises(reg.RegistrationError, match="verify the registration"):
        reg.replay_order(_registration(), now=NOW)


def test_a_proxy_on_a_second_ip_seals_the_same_key_digest():
    direct = _verify(_registration())
    # A TLS proxy on another IP with its own certificate, forwarding to the box.
    proxied = _verify(
        _registration(
            host_values_text=_host_values(
                CATHEDRAL_E2B_API_URL="https://34.9.9.9",
                CATHEDRAL_E2B_SANDBOX_URL="https://34.9.9.9:8443",
                CATHEDRAL_TLS_CERT_SHA256="d4" * 32,
            )
        )
    )
    assert (direct.control_url, direct.box_key) != (proxied.control_url, proxied.box_key)
    digest = reg.opened_key_digest(reg.open_runtime_key(direct, PROBER))
    assert digest == reg.opened_key_digest(reg.open_runtime_key(proxied, PROBER))
    assert digest != reg.opened_key_digest(RUNTIME_KEY + b"x")
    assert len(digest) == 64 and int(digest, 16) >= 0
    assert digest != hashlib.sha256(RUNTIME_KEY).hexdigest()  # domain-separated
    with pytest.raises(reg.RegistrationError, match="must be bytes"):
        reg.opened_key_digest(RUNTIME_KEY.decode())


@pytest.mark.parametrize("form", ["extra key", "json string"])
def test_templates_must_be_signed_in_canonical_form(form):
    body = _body(_registration())
    if form == "extra key":
        body["templates"][0]["gpu"] = 1
    else:
        body["templates"] = json.dumps(body["templates"])
    with pytest.raises(reg.RegistrationError, match="canonical form"):
        _verify(_hand_signed(body))


def test_only_an_sr25519_signature_is_accepted():
    body = _body(_registration())
    assert _verify(_hand_signed(body)).box_id == body["box_id"]
    with pytest.raises(reg.RegistrationError, match="sr25519 object"):
        _verify(_hand_signed(body, algorithm="ed25519"))


def test_a_signature_that_is_not_64_bytes_never_reaches_the_verifier():
    body = _body(_registration())
    good = MINER.sign(reg.canonical_bytes(body))
    seen = []

    def permissive(raw, message, public_key):
        seen.append(raw)
        return True

    for raw in (good + b"\x00", good[:63], b""):
        with pytest.raises(reg.RegistrationError, match="does not verify"):
            _verify(_hand_signed(body, raw=raw), verifier=permissive)
    assert seen == []


def test_only_the_seal_algorithm_is_accepted():
    body = _body(_registration())
    body["sealed_runtime_key"]["algorithm"] = "x25519-hkdf-sha256-aes256gcm"
    with pytest.raises(reg.RegistrationError, match="sealed_runtime_key is malformed"):
        _verify(_hand_signed(body))
    with pytest.raises(reg.RegistrationError, match="sealed_runtime_key is malformed"):
        reg.sign_registration(body, MINER.sign)


def test_the_seal_derivation_binds_both_public_keys():
    shared, aad, ephemeral, recipient = (os.urandom(32) for _ in range(4))
    key = reg._seal_key(shared, aad, ephemeral, recipient)
    assert key != reg._seal_key(shared, aad, os.urandom(32), recipient)
    assert key != reg._seal_key(shared, aad, ephemeral, os.urandom(32))
    # X25519 ignores the top bit of a public key, so a second spelling of the
    # ephemeral key gives the same shared secret. Binding the key bytes in the
    # derivation is what makes the edited registration fail to open.
    body = _body(_registration())
    original = base64.b64decode(body["sealed_runtime_key"]["ephemeral_public_b64"])
    twin = original[:31] + bytes([original[31] ^ 0x80])
    assert PROBER.exchange(X25519PublicKey.from_public_bytes(twin)) == PROBER.exchange(
        X25519PublicKey.from_public_bytes(original)
    )
    body["sealed_runtime_key"]["ephemeral_public_b64"] = base64.b64encode(twin).decode()
    verified = _verify(reg.sign_registration(body, MINER.sign))
    with pytest.raises(reg.RegistrationError, match="does not open"):
        reg.open_runtime_key(verified, PROBER)


def test_the_box_id_is_bound_to_certificate_and_hotkey():
    body = {k: v for k, v in _registration().items() if k != "signature"}
    body["box_id"] = "box-" + "0" * 32
    with pytest.raises(reg.RegistrationError, match="box_id"):
        reg.sign_registration(body, MINER.sign)
    assert reg.box_id_for(CERT, MINER.ss58_address) != reg.box_id_for(CERT, OTHER.ss58_address)
    assert reg.box_id_for(CERT, MINER.ss58_address) != reg.box_id_for("d4" * 32, MINER.ss58_address)


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"CATHEDRAL_TLS_CERT_SHA256": None}, "lack CATHEDRAL_TLS_CERT_SHA256"),
        ({"CATHEDRAL_TLS_CERT_SHA256": "AB" * 32}, "64 lowercase hex"),
        ({"CATHEDRAL_E2B_API_URL": "http://34.1.2.3"}, "public IPv4"),
        ({"CATHEDRAL_E2B_API_URL": "https://34.1.2.3/path"}, "public IPv4"),
        ({"CATHEDRAL_E2B_API_URL": "https://user:pw@34.1.2.3"}, "public IPv4"),
        ({"CATHEDRAL_E2B_API_URL": "HTTPS://34.1.2.3"}, "public IPv4"),
        ({"CATHEDRAL_E2B_API_URL": "https://34.1.2.3:99999"}, "public IPv4"),
        ({"CATHEDRAL_E2B_API_URL": "https://34.1.2.3\t"}, "control character"),
        ({"CATHEDRAL_E2B_API_URL": "https://box.example.com"}, "public IPv4"),
        (
            {
                "CATHEDRAL_E2B_API_URL": "https://127.0.0.1",
                "CATHEDRAL_E2B_SANDBOX_URL": "https://127.0.0.1:8443",
            },
            "public IPv4 address",
        ),
        (
            {
                "CATHEDRAL_E2B_API_URL": "https://169.254.169.254",
                "CATHEDRAL_E2B_SANDBOX_URL": "https://169.254.169.254:8443",
            },
            "public IPv4 address",
        ),
        (
            {
                "CATHEDRAL_E2B_API_URL": "https://10.0.0.5",
                "CATHEDRAL_E2B_SANDBOX_URL": "https://10.0.0.5:8443",
            },
            "public IPv4 address",
        ),
        *(
            (
                {
                    "CATHEDRAL_E2B_API_URL": f"https://{address}",
                    "CATHEDRAL_E2B_SANDBOX_URL": f"https://{address}:8443",
                },
                "public IPv4 address",
            )
            for address in ("239.1.1.1", "224.0.1.1", "192.88.99.1", "240.0.0.1")
        ),
        ({"CATHEDRAL_E2B_SANDBOX_URL": "https://34.9.9.9:8443"}, "same IPv4"),
        ({"CATHEDRAL_E2B_SANDBOX_URL": "https://34.1.2.3:9443"}, "same IPv4"),
        ({"CATHEDRAL_CAPACITY_VCPU": "0"}, "positive integer"),
        ({"CATHEDRAL_CAPACITY_VCPU": "016"}, "positive integer"),
        ({"CATHEDRAL_CAPACITY_VCPU": "\u00b2"}, "positive integer"),  # "²".isdigit()
        ({"CATHEDRAL_CAPACITY_MEMORY_GIB": "\u0664"}, "positive integer"),  # Arabic-Indic 4
        ({"CATHEDRAL_TEMPLATES_JSON": "[]"}, "1 to 32"),
        (
            {"CATHEDRAL_TEMPLATES_JSON": json.dumps([{"name": "big", "cpu": 64, "memory_gib": 4}])},
            "larger than the box",
        ),
        ({"CATHEDRAL_RUNTIME_GIT_REVISION": "main"}, "40-hex"),
    ],
)
def test_bad_host_values_are_refused(changes, message):
    with pytest.raises(reg.RegistrationError, match=message):
        _registration(host_values_text=_host_values(**changes))


def test_host_values_are_read_literally_never_sourced():
    assert reg.parse_host_values("# comment\n\nCATHEDRAL_A=1\nCATHEDRAL_B=$(reboot)\n") == {
        "CATHEDRAL_A": "1",
        "CATHEDRAL_B": "$(reboot)",
    }
    for text in (
        "CATHEDRAL_A=1\nCATHEDRAL_A=2\n",
        "export CATHEDRAL_A=1\n",
        "lowercase=1\n",
        "CATHEDRAL_A\n",
        "CATHEDRAL_A=1\r\n",
        "CATHEDRAL_A=1\x0bCATHEDRAL_A=2\n",
    ):
        with pytest.raises(reg.RegistrationError):
            reg.parse_host_values(text)
    with pytest.raises(reg.RegistrationError, match="too large"):
        reg.parse_host_values("CATHEDRAL_A=" + "x" * reg.MAX_HOST_VALUES_BYTES)


def test_validity_is_bounded_and_the_kind_is_checked():
    with pytest.raises(reg.RegistrationError, match="7 days"):
        _registration(valid_for=timedelta(days=8))
    with pytest.raises(reg.RegistrationError, match="tee or bare_metal"):
        _registration(kind="gpu")
    assert _verify(_registration(kind="tee")).kind == "tee"


def test_the_runtime_key_size_is_bounded():
    for key in (b"", b"k" * 1025):
        with pytest.raises(reg.RegistrationError, match="1 to 1024"):
            _registration(runtime_key=key)


def test_the_command_writes_a_verifiable_registration(tmp_path, capsys):
    host_values = tmp_path / "host-values.env"
    host_values.write_text(_host_values())
    key_file = tmp_path / "runtime.key"
    key_file.write_bytes(RUNTIME_KEY + b"\n")
    key_file.chmod(0o600)
    host_values.chmod(0o644)  # host values are not secret: no warning
    prober_hex = (
        PROBER.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    argv = [
        "--host-values",
        str(host_values),
        "--runtime-key-file",
        str(key_file),
        "--prober-key",
        prober_hex,
        "--netuid",
        str(NETUID),
        "--kind",
        "bare_metal",
        "--wallet-name",
        "miner",
        "--hotkey-name",
        "default",
    ]
    code = reg.main(argv, keypair_factory=lambda *_args: MINER)
    assert code == 0
    captured = capsys.readouterr()
    assert "warning" not in captured.err
    signed = json.loads(captured.out)
    verified = reg.verify_registration(signed, netuid=NETUID, now=datetime.now(UTC))
    assert reg.open_runtime_key(verified, PROBER) == RUNTIME_KEY  # trailing newline stripped
    bad_argv = ["zz" if arg == prober_hex else arg for arg in argv]
    bad = reg.main(bad_argv, keypair_factory=lambda *_args: MINER)
    assert bad == 2 and "refused" in capsys.readouterr().err
    # A key file the group or others can read still works, with a warning.
    for mode in (0o640, 0o604):
        key_file.chmod(mode)
        assert reg.main(argv, keypair_factory=lambda *_args: MINER) == 0
        captured = capsys.readouterr()
        assert f"runtime key file {key_file} is readable by group or others" in captured.err
        assert "host values" not in captured.err
        verified = reg.verify_registration(
            json.loads(captured.out), netuid=NETUID, now=datetime.now(UTC)
        )
        assert reg.open_runtime_key(verified, PROBER) == RUNTIME_KEY


def test_real_installer_output_registers_and_tunnel_mode_is_refused():
    # The shape install-runtime-host.sh writes in --direct-ip mode, empty values included.
    real = _host_values(
        CATHEDRAL_OPERATOR_GIT_REVISION=REVISION,
        CATHEDRAL_HOST_DEADLINE_AT="",
        CATHEDRAL_TUNNEL_ID="",
        CATHEDRAL_PUBLIC_IP="34.1.2.3",
        CATHEDRAL_TLS_CERT_B64="MIIB" + "A" * 400,
    )
    assert _verify(_registration(host_values_text=real)).cert_sha256 == CERT
    tunnel = _host_values(
        CATHEDRAL_TUNNEL_MODE="named",
        CATHEDRAL_E2B_API_URL="https://control.example.com",
        CATHEDRAL_E2B_SANDBOX_URL="https://guest.example.com",
        CATHEDRAL_TLS_CERT_SHA256="",
    )
    with pytest.raises(reg.RegistrationError):
        _registration(host_values_text=tunnel)


def test_a_sealed_key_cannot_be_lifted_onto_another_hotkeys_registration():
    theirs = _registration()
    mine = _registration(keypair=OTHER)
    mine["sealed_runtime_key"] = theirs["sealed_runtime_key"]
    body = {k: v for k, v in mine.items() if k != "signature"}
    with pytest.raises(reg.RegistrationError, match="does not open"):
        reg.open_runtime_key(_verify(reg.sign_registration(body, OTHER.sign)), PROBER)


def test_template_ids_are_plain_ascii():
    bad = json.dumps([{"name": "t", "cpu": 1, "memory_gib": 4, "template_id": "caf\u00e9"}])
    with pytest.raises(reg.RegistrationError, match="template_id"):
        _registration(host_values_text=_host_values(CATHEDRAL_TEMPLATES_JSON=bad))


def _signed_directly(body):
    # Signed by the hotkey itself, past sign_registration's own checks, as a hostile
    # or buggy client could.
    return {
        **body,
        "signature": {
            "algorithm": "sr25519",
            "value_b64": base64.b64encode(MINER.sign(reg.canonical_bytes(body))).decode(),
        },
    }


@pytest.mark.parametrize(
    "issued_at, expires_at",
    [
        ("2026-02-30T00:00:00Z", "2026-03-01T00:00:00Z"),  # no such day
        ("0000-01-01T00:00:00Z", "0000-01-01T01:00:00Z"),  # no year 0
        ("9999-12-31T00:00:00Z", "9999-12-31T01:00:00Z"),  # adding the window overflows
        ("0001-01-01T00:00:00Z", "0001-01-01T01:00:00Z"),  # subtracting the skew overflows
    ],
)
def test_unsigned_dates_never_escape_as_other_errors(issued_at, expires_at):
    body = {k: v for k, v in _registration().items() if k != "signature"}
    body.update(issued_at=issued_at, expires_at=expires_at)
    with pytest.raises(reg.RegistrationError):
        _verify(_signed_directly(body))


def test_deeply_nested_templates_are_a_registration_error(tmp_path, capsys):
    # A signed document's templates field, and a host value under the 64 KiB file cap.
    with pytest.raises(reg.RegistrationError, match="not JSON"):
        reg._templates("[" * 200_000)
    with pytest.raises(reg.RegistrationError, match="not JSON"):
        _registration(host_values_text=_host_values(CATHEDRAL_TEMPLATES_JSON="[" * 60_000))
    # And through the command: a refusal, not a traceback.
    host_values = tmp_path / "host-values.env"
    host_values.write_text(_host_values(CATHEDRAL_TEMPLATES_JSON="[" * 60_000))
    key_file = tmp_path / "runtime.key"
    key_file.write_bytes(RUNTIME_KEY)
    key_file.chmod(0o600)
    prober_hex = (
        PROBER.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    code = reg.main(
        [
            "--host-values",
            str(host_values),
            "--runtime-key-file",
            str(key_file),
            "--prober-key",
            prober_hex,
            "--netuid",
            str(NETUID),
            "--kind",
            "bare_metal",
            "--wallet-name",
            "miner",
            "--hotkey-name",
            "default",
        ],
        keypair_factory=lambda *_args: MINER,
    )
    assert code == 2 and "not JSON" in capsys.readouterr().err
