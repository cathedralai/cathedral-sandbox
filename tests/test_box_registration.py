"""Box registration: the miner's signed, sealed record of a Cathedral runtime box."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import sr25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from cathedral import box_registration as reg

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
        netuid=94,
        kind="bare_metal",
        keypair=MINER,
        now=NOW,
    )
    args.update(changes)
    return reg.register(**args)


def _verify(signed, **changes):
    args = dict(netuid=94, now=NOW + timedelta(minutes=1))
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
        _verify(signed, netuid=39)
    with pytest.raises(reg.RegistrationError, match="not currently valid"):
        _verify(signed, now=NOW + timedelta(days=2))
    with pytest.raises(reg.RegistrationError, match="not a signed object"):
        _verify({k: v for k, v in signed.items() if k != "signature"})


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
        ({"CATHEDRAL_E2B_SANDBOX_URL": "https://34.9.9.9:8443"}, "same IPv4"),
        ({"CATHEDRAL_E2B_SANDBOX_URL": "https://34.1.2.3:9443"}, "same IPv4"),
        ({"CATHEDRAL_CAPACITY_VCPU": "0"}, "positive integer"),
        ({"CATHEDRAL_CAPACITY_VCPU": "016"}, "positive integer"),
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
            "94",
            "--kind",
            "bare_metal",
            "--wallet-name",
            "miner",
            "--hotkey-name",
            "default",
        ],
        keypair_factory=lambda *_args: MINER,
    )
    assert code == 0
    signed = json.loads(capsys.readouterr().out)
    verified = reg.verify_registration(signed, netuid=94, now=datetime.now(UTC))
    assert reg.open_runtime_key(verified, PROBER) == RUNTIME_KEY  # trailing newline stripped
    bad = reg.main(
        [
            "--host-values",
            str(host_values),
            "--runtime-key-file",
            str(key_file),
            "--prober-key",
            "zz",
            "--netuid",
            "94",
            "--kind",
            "bare_metal",
            "--wallet-name",
            "miner",
            "--hotkey-name",
            "default",
        ],
        keypair_factory=lambda *_args: MINER,
    )
    assert bad == 2 and "refused" in capsys.readouterr().err


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
