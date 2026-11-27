"""Custom guest intake validator (spec-r9 4.4, 5.5; test plan 14.1 "Intake").

A synthetic bzImage (PE stub, boot header, gzip payload carrying IKCONFIG), a fake
veritysetup on PATH, and the validator run as the host runs it (python3 -I)."""
from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
STAGE = REPO / "ops" / "custom-guest" / "custom_guest_stage.py"
spec = importlib.util.spec_from_file_location("custom_guest_stage", STAGE)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

OWNER = bytes(range(32))
OWNER_URL = base64.urlsafe_b64encode(OWNER).rstrip(b"=").decode()
VERITY = "cd" * 32
ROOT_BYTES = 3 * 4096
GOOD_CMDLINE = (f"console=ttyS0 cathedral.owner={OWNER_URL} cathedral.root_verity={VERITY} "
                f"cathedral.root_data_bytes=8192 systemd.import_credentials=no")
INITRD = b"reference initrd 1"
GOOD_CONFIG = {**{n: "y" for n in stage.REQUIRED_Y}, "IKCONFIG": "y", "SQUASHFS": "y", "INITRAMFS_SOURCE": '""'}


def config_text(cfg: dict) -> bytes:
    return "".join(f"CONFIG_{k}={v}\n" for k, v in cfg.items()).encode()


def bzimage(cfg: dict | None = None, protocol: int = 0x020F, xlf: int = 1, cmdline_size: int = 2047,
            pe: bool = True, ikconfig: bool = True) -> bytes:
    vmlinux = b"\0" * 64 + ((b"IKCFG_ST" + gzip.compress(config_text(cfg or GOOD_CONFIG)) + b"IKCFG_ED")
                            if ikconfig else b"no config here") + b"\0" * 64
    payload = gzip.compress(vmlinux)
    setup_sects = 4
    head = bytearray((setup_sects + 1) * 512)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    if pe:
        head[0x80:0x84] = b"PE\0\0"
    head[0x1F1] = setup_sects
    head[0x202:0x206] = b"HdrS"
    head[0x206:0x208] = protocol.to_bytes(2, "little")
    head[0x236:0x238] = xlf.to_bytes(2, "little")
    head[0x238:0x23C] = cmdline_size.to_bytes(4, "little")
    head[0x248:0x24C] = (0).to_bytes(4, "little")
    head[0x24C:0x250] = len(payload).to_bytes(4, "little")
    return bytes(head) + payload


def make_inbox(tmp: Path, kernel: bytes | None = None, cmdline: str = GOOD_CMDLINE, initrd: bytes = INITRD,
               request_changes: dict | None = None, published: str | None = None) -> tuple[Path, Path]:
    inbox, staging = tmp / "inbox", tmp / "staging"
    inbox.mkdir()
    staging.mkdir()
    kernel = bzimage() if kernel is None else kernel
    root = os.urandom(ROOT_BYTES)
    (inbox / "vmlinuz").write_bytes(kernel)
    (inbox / "initrd").write_bytes(initrd)
    (inbox / "root.raw").write_bytes(root)
    req = {"schema": stage.REQUEST_SCHEMA,
           "kernel": {"sha256": hashlib.sha256(kernel).hexdigest(), "bytes": len(kernel)},
           "initrd": {"reference": "1", "sha256": hashlib.sha256(INITRD).hexdigest()},
           "root_disk": {"sha256": hashlib.sha256(root).hexdigest(), "bytes": ROOT_BYTES},
           "cmdline": cmdline, "data_disk_gib": 0, "vcpus": 4, "mem_gib": 24, "cpu_model": "EPYC-Genoa-v1",
           "owner_ed25519_b64": base64.b64encode(OWNER).decode(), "ssh_public_key": "ssh-ed25519 AAAA",
           "launch_nonce_hex": "00" * 32, "ports": [{"public": 20022, "guest": 22}, {"public": 20443, "guest": 443}]}
    req.update(request_changes or {})
    (inbox / "request.json").write_text(json.dumps(req))
    (inbox / "inputs.json").write_text(json.dumps(
        {"reference_initrds": {"1": published or hashlib.sha256(INITRD).hexdigest()}}))
    return inbox, staging


@pytest.fixture
def fake_verity(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "verity.log"
    (bin_dir / "veritysetup").write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit "${{FAKE_VERITY_RC:-0}}"\n')
    (bin_dir / "veritysetup").chmod(0o755)
    return bin_dir, log


def run(inbox: Path, staging: Path, bin_dir: Path, verity_rc: int = 0) -> tuple[int, dict]:
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", FAKE_VERITY_RC=str(verity_rc))
    p = subprocess.run([sys.executable, "-I", str(STAGE), "--inbox", str(inbox), "--staging", str(staging)],
                       capture_output=True, text=True, env=env, timeout=60)
    report = json.loads((staging / "report.json").read_text())
    assert json.loads(p.stdout) == report
    return p.returncode, report


def test_good_image_is_staged_with_the_exact_cmdline(tmp_path, fake_verity):
    bin_dir, log = fake_verity
    inbox, staging = make_inbox(tmp_path)
    rc, report = run(inbox, staging, bin_dir)
    assert rc == 0 and report["ok"], report
    assert (staging / "cmdline").read_bytes() == GOOD_CMDLINE.encode()
    assert report["kernel"] == {"protocol": "2.15", "cmdline_size": 2047}
    assert report["files"]["root.raw"]["bytes"] == ROOT_BYTES
    args = log.read_text().split()
    assert args[0] == "verify" and args[3] == VERITY
    assert "--hash-offset=8192" in args and "--data-blocks=2" in args and "--data-block-size=4096" in args


@pytest.mark.parametrize("token", ["rdinit=/bin/sh", "init=/bin/sh", "root=/dev/vda", "ro", "rw", "noinitrd",
                                  "initrd=x", "systemd.unit=rescue.target", "systemd.import_credentials=yes",
                                  "ds=nocloud", "loglevel=8", "panic=3601", "console=tty0", "cathedral.extra=1"])
def test_cmdline_tokens_off_the_allowlist(token):
    with pytest.raises(stage.Refused) as e:
        stage.check_cmdline(f"{GOOD_CMDLINE} {token}", OWNER, ROOT_BYTES)
    assert e.value.code == "custom_guest_cmdline_invalid"


def test_cmdline_optional_tokens_pass():
    line = f"{GOOD_CMDLINE} quiet loglevel=3 panic=-1 cathedral.note=build-7"
    assert stage.check_cmdline(line, OWNER, ROOT_BYTES)["root_data_bytes"] == 8192


@pytest.mark.parametrize("line,why", [
    (GOOD_CMDLINE.replace(" systemd.import_credentials=no", ""), "credentials token required"),
    (GOOD_CMDLINE.replace(OWNER_URL, base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()), "owner mismatch"),
    (GOOD_CMDLINE.replace("=8192", "=8000"), "not a multiple of 4096"),
    (GOOD_CMDLINE.replace("=8192", f"={ROOT_BYTES}"), "not below the root size"),
    (GOOD_CMDLINE.replace(VERITY, VERITY.upper()), "upper hex"),
    (GOOD_CMDLINE.replace(" ", "  ", 1), "double space"),
    (" " + GOOD_CMDLINE, "leading space"),
    (GOOD_CMDLINE + " quiet quiet", "duplicate token"),
    (GOOD_CMDLINE + " cathedral.note=é", "non-ascii byte"),
    (GOOD_CMDLINE + "\tquiet", "control byte"),
    (GOOD_CMDLINE + " cathedral.note=" + "x" * (2034 - len(GOOD_CMDLINE) - 16), "2034 bytes"),
])
def test_cmdline_shape_refusals(line, why):
    with pytest.raises(stage.Refused):
        stage.check_cmdline(line, OWNER, ROOT_BYTES)


def test_cmdline_at_the_length_limit_passes():
    line = GOOD_CMDLINE + " cathedral.note=" + "x" * (2033 - len(GOOD_CMDLINE) - 16)
    assert len(line) == 2033
    stage.check_cmdline(line, OWNER, ROOT_BYTES)


@pytest.mark.parametrize("kernel,code", [
    (bzimage(cfg={**GOOD_CONFIG, "CMDLINE_BOOL": "y"}), "custom_guest_kernel_config_refused"),
    (bzimage(cfg={**GOOD_CONFIG, "BOOT_CONFIG_EMBED": "y"}), "custom_guest_kernel_config_refused"),
    (bzimage(cfg={**GOOD_CONFIG, "INITRAMFS_SOURCE": '"/x.cpio"'}), "custom_guest_kernel_config_refused"),
    (bzimage(cfg={k: v for k, v in GOOD_CONFIG.items() if k != "DM_VERITY"}), "custom_guest_kernel_config_refused"),
    (bzimage(cfg={**GOOD_CONFIG, "DM_VERITY": "m"}), "custom_guest_kernel_config_refused"),
    (bzimage(cfg={**{k: v for k, v in GOOD_CONFIG.items() if k != "SQUASHFS"}}), "custom_guest_kernel_config_refused"),
    (bzimage(ikconfig=False), "custom_guest_kernel_config_refused"),
    (bzimage(protocol=0x020B), "custom_guest_not_snp_bootable"),
    (bzimage(xlf=0), "custom_guest_not_snp_bootable"),
    (bzimage(cmdline_size=1024), "custom_guest_not_snp_bootable"),
    (bzimage(pe=False), "custom_guest_not_snp_bootable"),
    (b"\x7fELF" + b"\0" * 1024, "custom_guest_not_snp_bootable"),
])
def test_kernel_refusals(tmp_path, fake_verity, kernel, code):
    inbox, staging = make_inbox(tmp_path, kernel=kernel)
    rc, report = run(inbox, staging, fake_verity[0])
    assert rc == 1 and report["error_code"] == code, report
    assert not (staging / "cmdline").exists()


def test_a_2033_byte_cmdline_fits_a_stock_kernel(tmp_path, fake_verity):
    """A stock x86 kernel keeps 2047 bytes (cmdline_size = COMMAND_LINE_SIZE - 1): 14 + 2033 fits."""
    line = GOOD_CMDLINE + " cathedral.note=" + "x" * (2033 - len(GOOD_CMDLINE) - 16)
    inbox, staging = make_inbox(tmp_path, kernel=bzimage(cmdline_size=2047), cmdline=line)
    rc, report = run(inbox, staging, fake_verity[0])
    assert rc == 0 and report["ok"], report
    assert (staging / "cmdline").read_bytes() == line.encode()


def test_a_kernel_that_keeps_less_than_2047_is_refused(tmp_path, fake_verity):
    inbox, staging = make_inbox(tmp_path, kernel=bzimage(cmdline_size=2046))
    rc, report = run(inbox, staging, fake_verity[0])
    assert rc == 1 and report["error_code"] == "custom_guest_not_snp_bootable"


@pytest.mark.parametrize("case,code", [
    ("initrd_not_published", "custom_guest_not_reference_initrd"),
    ("initrd_bytes_differ", "custom_guest_not_reference_initrd"),
    ("kernel_digest", "custom_guest_digest_mismatch"),
    ("root_size", "custom_guest_size_mismatch"),
    ("verity_fails", "custom_guest_root_not_verity"),
    ("hotel_field", "custom_guest_request_invalid"),
    ("ssh_not_first", "custom_guest_ssh_port_required"),
    ("public_port_range", "custom_guest_port_invalid"),
    ("vcpus", "custom_guest_resources_exceeded"),
    ("cpu_model", "custom_guest_cpu_model_unsupported"),
])
def test_request_and_file_refusals(tmp_path, fake_verity, case, code):
    changes, kwargs, verity_rc = {}, {}, 0
    if case == "initrd_not_published":
        kwargs["published"] = "ee" * 32
    elif case == "initrd_bytes_differ":
        kwargs["initrd"] = b"not the reference"
    elif case == "kernel_digest":
        changes["kernel"] = {"sha256": "aa" * 32, "bytes": len(bzimage())}
    elif case == "root_size":
        changes["root_disk"] = None
    elif case == "verity_fails":
        verity_rc = 1
    elif case == "hotel_field":
        changes["hotel"] = "chi-ur-2"
    elif case == "ssh_not_first":
        changes["ports"] = [{"public": 20443, "guest": 443}, {"public": 20022, "guest": 22}]
    elif case == "public_port_range":
        changes["ports"] = [{"public": 2222, "guest": 22}]
    elif case == "vcpus":
        changes["vcpus"] = 57
    elif case == "cpu_model":
        changes["cpu_model"] = "host"
    inbox, staging = make_inbox(tmp_path, request_changes=changes, **kwargs)
    if case == "root_size":
        req = json.loads((inbox / "request.json").read_text())
        root = (inbox / "root.raw").read_bytes()
        req["root_disk"] = {"sha256": hashlib.sha256(root).hexdigest(), "bytes": ROOT_BYTES + 4096}
        (inbox / "request.json").write_text(json.dumps(req))
    rc, report = run(inbox, staging, fake_verity[0], verity_rc)
    assert rc == 1 and report["error_code"] == code, report


def test_a_linked_input_is_refused(tmp_path, fake_verity):
    inbox, staging = make_inbox(tmp_path)
    real = tmp_path / "elsewhere"
    os.replace(inbox / "root.raw", real)
    os.symlink(real, inbox / "root.raw")
    rc, report = run(inbox, staging, fake_verity[0])
    assert rc == 1 and not report["ok"]
