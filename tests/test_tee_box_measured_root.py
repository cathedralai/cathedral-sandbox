"""The TEE box's central root: a fixed image path, bound to MRCONFIGID."""

from __future__ import annotations

import base64
import hashlib
import subprocess
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


@pytest.mark.parametrize(
    ("contents", "match"),
    [
        (b"[]", "central root keys are unusable"),
        (
            canonical_json(
                {"cathedral-root-1": base64.b64encode(bytes([1]) + bytes(31)).decode("ascii")}
            ),
            "is a small-order Ed25519 point",
        ),
    ],
    ids=["malformed", "identity-key"],
)
def test_a_measured_but_unusable_root_file_refuses_cleanly(image_root: Path, contents, match):
    image_root.write_bytes(contents)
    binding = measured_root.mrconfigid_for_root_keys(contents)
    with pytest.raises(measured_root.MeasuredRootError, match=match):
        measured_root.load_measured_root_keys("tdx", read_binding=lambda: binding)


def test_matching_host_data_loads_the_root(image_root: Path):
    binding = measured_root.host_data_for_root_keys(image_root.read_bytes())
    assert binding == hashlib.sha256(image_root.read_bytes()).digest()
    keys, digest = measured_root.load_measured_root_keys("snp", read_binding=lambda: binding)
    assert keys == ROOT_KEYS
    assert digest == "sha256:" + hashlib.sha256(image_root.read_bytes()).hexdigest()


def test_a_root_file_changed_after_snp_launch_refuses(image_root: Path):
    binding = measured_root.host_data_for_root_keys(image_root.read_bytes())
    image_root.write_bytes(_root_file(OTHER_ROOT_SEED))
    with pytest.raises(measured_root.MeasuredRootError, match="does not match HOST_DATA"):
        measured_root.load_measured_root_keys("snp", read_binding=lambda: binding)


def test_snp_without_a_guest_device_refuses(image_root: Path):
    with pytest.raises(measured_root.MeasuredRootError, match="HOST_DATA"):
        measured_root.load_measured_root_keys("snp")


def test_an_mrconfigid_shaped_binding_is_not_host_data(image_root: Path):
    binding = measured_root.mrconfigid_for_root_keys(image_root.read_bytes())
    with pytest.raises(measured_root.MeasuredRootError, match="HOST_DATA must be 32 bytes"):
        measured_root.load_measured_root_keys("snp", read_binding=lambda: binding)


def test_unknown_tees_refuse(image_root: Path):
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


@pytest.mark.parametrize(
    ("binding", "match"),
    [
        (bytes(32), "zero"),
        (b"\x01" * 31, "32 bytes"),
        (b"\x01" * 48, "32 bytes"),
        ("01" * 32, "32 bytes"),
    ],
)
def test_malformed_host_data_refuses(binding, match):
    with pytest.raises(measured_root.MeasuredRootError, match=match):
        measured_root.root_digest_from_host_data(binding)


class _FakeSnpGuest:
    """Stands in for ``snpguest report`` writing an 1184-byte attestation report."""

    def __init__(self, host_data: bytes) -> None:
        self.host_data = host_data
        self.echo = True
        self.fail = False
        self.timeout = False
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        assert argv[1] == "report" and argv[4:6] == ["--vmpl", "0"]
        if self.timeout:
            raise subprocess.TimeoutExpired(argv[0], kwargs["timeout"])
        if self.fail:
            raise subprocess.CalledProcessError(1, argv, stderr="report failed")
        request = Path(argv[3]).read_bytes()
        report = bytearray(measured_root.SNP_REPORT_SIZE)
        report_data = request if self.echo else bytes(64)
        report[
            measured_root.SNP_REPORT_DATA_OFFSET : measured_root.SNP_REPORT_DATA_OFFSET
            + measured_root.SNP_REPORT_DATA_SIZE
        ] = report_data
        report[
            measured_root.HOST_DATA_OFFSET : measured_root.HOST_DATA_OFFSET
            + measured_root.HOST_DATA_SIZE
        ] = self.host_data
        Path(argv[2]).write_bytes(report)
        return subprocess.CompletedProcess(argv, 0, "", "")


@pytest.fixture
def snp_guest(tmp_path: Path, monkeypatch):
    device = tmp_path / "sev-guest"
    device.write_bytes(b"")
    binary = tmp_path / "snpguest"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    guest = _FakeSnpGuest(measured_root.host_data_for_root_keys(_root_file()))
    monkeypatch.setattr(measured_root.subprocess, "run", guest)
    guest.device = str(device)
    guest.binary = str(binary)
    return guest


def test_the_snp_report_reader_returns_host_data(snp_guest):
    assert (
        measured_root.read_snp_host_data(snp_guest.device, snpguest=snp_guest.binary)
        == snp_guest.host_data
    )
    assert snp_guest.calls[0][0] == snp_guest.binary
    assert snp_guest.calls[0][4:6] == ["--vmpl", "0"]


def test_the_default_snp_reader_is_the_report(image_root: Path, snp_guest, monkeypatch):
    assert measured_root.default_binding_reader("snp") is measured_root.read_snp_host_data
    real = measured_root.read_snp_host_data
    monkeypatch.setattr(
        measured_root,
        "read_snp_host_data",
        lambda: real(snp_guest.device, snpguest=snp_guest.binary),
    )
    keys, _digest = measured_root.load_measured_root_keys("snp")
    assert keys == ROOT_KEYS and snp_guest.calls


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ("echo", "requested REPORT_DATA"),
        ("fail", "refused an SNP report"),
        ("timeout", "timed out"),
    ],
)
def test_a_bad_snp_report_refuses(snp_guest, change, match):
    if change == "echo":
        snp_guest.echo = False
    elif change == "fail":
        snp_guest.fail = True
    else:
        snp_guest.timeout = True
    with pytest.raises(measured_root.MeasuredRootError, match=match):
        measured_root.read_snp_host_data(snp_guest.device, snpguest=snp_guest.binary)


def test_a_missing_sev_guest_device_refuses(tmp_path: Path):
    with pytest.raises(measured_root.MeasuredRootError, match="unavailable"):
        measured_root.read_snp_host_data(str(tmp_path / "absent"))
