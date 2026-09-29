"""The TEE box's central root: a fixed image path, bound to MRCONFIGID."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cathedral.policy_registry import canonical_json
from cathedral.tee_box import measured_root

ROOT_SEED = b"r" * 32
OTHER_ROOT_SEED = b"o" * 32


def _public(seed: bytes) -> bytes:
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


ROOT_KEYS = {"cathedral-root-1": _public(ROOT_SEED)}


def _root_file(seed: bytes = ROOT_SEED) -> bytes:
    return canonical_json({"cathedral-root-1": base64.b64encode(_public(seed)).decode("ascii")})


@pytest.fixture
def image_root(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "central-root-keys.json"
    path.write_bytes(_root_file())
    monkeypatch.setattr(measured_root, "CENTRAL_ROOT_KEYS_PATH", str(path))
    return path


def test_the_root_path_is_fixed_inside_the_image():
    assert measured_root.CENTRAL_ROOT_KEYS_PATH == "/usr/share/cathedral/central-root-keys.json"
    assert measured_root.TDX_GUEST_DEVICE == "/dev/tdx_guest"


def test_matching_mrconfigid_loads_the_root(image_root: Path):
    binding = measured_root.mrconfigid_for_root_keys(image_root.read_bytes())
    assert binding[:32] == hashlib.sha256(image_root.read_bytes()).digest()
    assert binding[32:] == bytes(16)
    keys, digest = measured_root.load_measured_root_keys("tdx", read_binding=lambda: binding)
    assert keys == ROOT_KEYS
    assert digest == "sha256:" + hashlib.sha256(image_root.read_bytes()).hexdigest()


def test_a_root_file_changed_after_launch_refuses(image_root: Path):
    binding = measured_root.mrconfigid_for_root_keys(image_root.read_bytes())
    image_root.write_bytes(_root_file(OTHER_ROOT_SEED))
    with pytest.raises(measured_root.MeasuredRootError, match="does not match MRCONFIGID"):
        measured_root.load_measured_root_keys("tdx", read_binding=lambda: binding)


def test_snp_and_unknown_tees_refuse(image_root: Path):
    with pytest.raises(measured_root.MeasuredRootError, match="HOST_DATA"):
        measured_root.load_measured_root_keys("snp")
    binding = measured_root.mrconfigid_for_root_keys(image_root.read_bytes())
    # Even a reader that returns a matching value is not an SNP binding.
    with pytest.raises(measured_root.MeasuredRootError, match="no measured root binding"):
        measured_root.load_measured_root_keys("snp", read_binding=lambda: binding)
    with pytest.raises(measured_root.MeasuredRootError, match="no measured root binding"):
        measured_root.load_measured_root_keys("gpu")


class _FakeTdxGuest:
    """Stands in for the TDX guest driver's TDX_CMD_GET_REPORT0 ioctl."""

    def __init__(self, mrconfigid: bytes) -> None:
        self.mrconfigid = mrconfigid
        self.report_type = measured_root.TDX_REPORT_TYPE_TDX
        self.echo = True
        self.fail = False
        self.requests: list[int] = []

    def ioctl(self, _fd, request, buffer, mutate):
        assert mutate is True and len(buffer) == 64 + 1024
        self.requests.append(request)
        if self.fail:
            raise OSError("EIO")
        report_data = bytes(buffer[:64])
        report = bytearray(1024)
        report[0] = self.report_type
        report[128:192] = report_data if self.echo else bytes(64)
        report[576:624] = self.mrconfigid
        buffer[64:] = report


@pytest.fixture
def tdx_guest(tmp_path: Path, monkeypatch):
    device = tmp_path / "tdx_guest"
    device.write_bytes(b"")
    guest = _FakeTdxGuest(measured_root.mrconfigid_for_root_keys(_root_file()))
    monkeypatch.setattr(measured_root.fcntl, "ioctl", guest.ioctl)
    guest.device = str(device)
    return guest


def test_the_td_report_reader_returns_mrconfigid(tdx_guest):
    assert measured_root.read_tdx_mrconfigid(tdx_guest.device) == tdx_guest.mrconfigid
    # _IOWR('T', 1, struct tdx_report_req) from linux/include/uapi/linux/tdx-guest.h.
    assert tdx_guest.requests == [0xC4405401]


def test_the_default_tdx_reader_is_the_td_report(image_root: Path, tdx_guest, monkeypatch):
    assert measured_root.default_binding_reader("tdx") is measured_root.read_tdx_mrconfigid
    # With no injected reader, a TDX box reads its TD report.
    real = measured_root.read_tdx_mrconfigid
    monkeypatch.setattr(measured_root, "read_tdx_mrconfigid", lambda: real(tdx_guest.device))
    keys, _digest = measured_root.load_measured_root_keys("tdx")
    assert keys == ROOT_KEYS and tdx_guest.requests == [0xC4405401]


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ("report_type", "not a TDX report"),
        ("echo", "requested REPORTDATA"),
        ("fail", "refused a TD report"),
    ],
)
def test_a_bad_td_report_refuses(tdx_guest, change, match):
    if change == "report_type":
        tdx_guest.report_type = 0x00
    elif change == "echo":
        tdx_guest.echo = False
    else:
        tdx_guest.fail = True
    with pytest.raises(measured_root.MeasuredRootError, match=match):
        measured_root.read_tdx_mrconfigid(tdx_guest.device)


def test_a_missing_td_report_device_refuses(tmp_path: Path):
    with pytest.raises(measured_root.MeasuredRootError, match="unavailable"):
        measured_root.read_tdx_mrconfigid(str(tmp_path / "absent"))


@pytest.mark.parametrize(
    ("binding", "match"),
    [
        (bytes(48), "zero"),
        (b"\x01" * 32 + b"\x00" * 15 + b"\x01", "16 zero bytes"),
        (b"\x01" * 47, "48 bytes"),
        ("01" * 48, "48 bytes"),
    ],
)
def test_malformed_mrconfigid_refuses(binding, match):
    with pytest.raises(measured_root.MeasuredRootError, match=match):
        measured_root.root_digest_from_mrconfigid(binding)
