"""Sealed data volume (docs/SEALED_DATA_VOLUME.md): checks that need no SNP host.

- sealed_data_key.py against a fake /dev/sev-guest ioctl: the request it sends,
  the key it takes from the answer, HKDF, HOST_DATA in the key, stdout only;
- sealed-data.sh against fake cryptsetup, mkfs.xfs, mount and key tool: it
  formats a blank disk once, reopens it, and never formats a volume it cannot
  open;
- room-data.sh binds ROOM_WORKSPACES_SOURCE only when it is on its own volume;
- build-guest.sh, launch-guest.sh and install-sealed.sh wiring.

The real thing ran on an SNP host (c48); the proof is in the pull request.
"""
from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from test_room_kit_installer_behaviour import BASH, FakeHost, _sealed_step5, host  # noqa: F401  (host is a fixture)

ROOT = Path(__file__).resolve().parents[1]
SEALED = ROOT / "room-kit" / "sealed"


def _load_key_tool():
    spec = importlib.util.spec_from_file_location("sealed_data_key", SEALED / "sealed_data_key.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


kt = _load_key_tool()
CHIP_KEY = bytes(range(0x40, 0x60))
HOST_DATA = bytes.fromhex("11" * 32)


# ---------------------------------------------------------------- sealed_data_key.py

def test_ioctl_number_and_struct_layout_match_linux_sev_guest_h() -> None:
    # _IOWR('S', 0x1, struct snp_guest_request_ioctl), 32 bytes each.
    assert kt.SNP_GET_DERIVED_KEY == 0xC0205301
    assert ctypes.sizeof(kt._GuestRequest) == 32
    assert ctypes.sizeof(kt._DerivedKeyRequest) == 32
    assert kt._GuestRequest.req_data.offset == 8 and kt._GuestRequest.exitinfo2.offset == 24
    assert kt._DerivedKeyRequest.guest_field_select.offset == 8 and kt._DerivedKeyRequest.tcb_version.offset == 24


def test_field_select_is_policy_and_measurement_only() -> None:
    assert kt.FIELD_SELECT == 0x9
    # IDs come from a host-signed ID block; TCB would lose the volume at a firmware update.
    for bit in (kt.FIELD_IMAGE_ID, kt.FIELD_FAMILY_ID, kt.FIELD_GUEST_SVN, kt.FIELD_TCB_VERSION):
        assert not kt.FIELD_SELECT & bit


def _fake_ioctl(seen: list, status: int = 0, key: bytes = CHIP_KEY, fail: OSError | None = None, exitinfo2: int = 0):
    def ioctl(fd, op, guest, mutate):
        assert mutate is True
        seen.append({"op": op, "msg_version": guest.msg_version,
                     "req": ctypes.string_at(guest.req_data, ctypes.sizeof(kt._DerivedKeyRequest))})
        if fail is not None:
            guest.exitinfo2 = exitinfo2
            raise fail
        resp = status.to_bytes(4, "little") + bytes(28) + key
        ctypes.memmove(guest.resp_data, resp, len(resp))
        return 0
    return ioctl


def test_derived_key_sends_vcek_root_policy_and_measurement_at_vmpl0(tmp_path: Path) -> None:
    dev = tmp_path / "sev-guest"
    dev.write_bytes(b"")
    seen: list = []
    key = kt.derived_key(str(dev), _fake_ioctl(seen))
    assert key == CHIP_KEY
    req = kt._DerivedKeyRequest.from_buffer_copy(seen[0]["req"])
    assert seen[0]["op"] == kt.SNP_GET_DERIVED_KEY and seen[0]["msg_version"] == 1
    assert (req.root_key_select, req.guest_field_select, req.vmpl, req.guest_svn, req.tcb_version) == (0, 0x9, 0, 0, 0)


def test_derived_key_refuses_a_firmware_error_a_failed_ioctl_and_a_zero_key(tmp_path: Path) -> None:
    dev = tmp_path / "sev-guest"
    dev.write_bytes(b"")
    with pytest.raises(kt.SealedKeyError, match="status 0x16"):
        kt.derived_key(str(dev), _fake_ioctl([], status=0x16))
    with pytest.raises(kt.SealedKeyError, match="firmware error 0x7"):
        kt.derived_key(str(dev), _fake_ioctl([], fail=OSError(5, "Input/output error"), exitinfo2=0x7))
    with pytest.raises(kt.SealedKeyError, match="all-zero"):
        kt.derived_key(str(dev), _fake_ioctl([], key=bytes(32)))
    with pytest.raises(kt.SealedKeyError, match="cannot open"):
        kt.derived_key(str(tmp_path / "missing"), _fake_ioctl([]))


def test_hkdf_matches_rfc5869_case_1() -> None:
    okm = kt.hkdf(bytes([0x0B] * 22), bytes(range(0x0D)), bytes(range(0xF0, 0xFA)), 42)
    assert okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"


def test_volume_key_depends_on_host_data_and_key_id_is_not_the_key() -> None:
    a = kt.volume_key(CHIP_KEY, 0x9, HOST_DATA)
    b = kt.volume_key(CHIP_KEY, 0x9, bytes(32))
    assert len(a) == 32 and a != b and a != CHIP_KEY
    assert kt.volume_key(CHIP_KEY, 0x9, HOST_DATA) == a, "the same inputs make the same key at the next boot"
    assert kt.volume_key(bytes(32), 0x9, HOST_DATA) != a
    kid = kt.key_id(CHIP_KEY, 0x9, HOST_DATA)
    assert len(kid) == 16 and kid not in a.hex() and kid not in CHIP_KEY.hex()
    assert kt.key_id(CHIP_KEY, 0x9, bytes(32)) != kid


def _report() -> bytes:
    r = bytearray(kt.REPORT_BYTES)
    r[kt.REPORT_POLICY] = (0x30000).to_bytes(8, "little")
    r[kt.REPORT_MEASUREMENT] = bytes.fromhex("ab" * 48)
    r[kt.REPORT_HOST_DATA] = HOST_DATA
    return bytes(r)


def test_main_prints_the_key_on_stdout_only_and_info_never_holds_it(monkeypatch, capsysbinary) -> None:
    monkeypatch.setattr(kt, "tsm_report", lambda root=None: _report())
    monkeypatch.setattr(kt, "derived_key", lambda path, ioctl, field_select: CHIP_KEY)
    want = kt.volume_key(CHIP_KEY, 0x9, HOST_DATA)
    assert kt.main(["x", "key"]) == 0
    out = capsysbinary.readouterr()
    assert out.out == want and out.err == b""
    assert kt.main(["x", "info"]) == 0
    out = capsysbinary.readouterr()
    info = json.loads(out.out)
    assert info["guest_field_select"] == 9 and info["root_key"] == "vcek" and info["policy"] == "0x30000"
    assert info["measurement"] == "ab" * 48 and info["host_data"] == "11" * 32
    assert info["key_id"] == kt.key_id(CHIP_KEY, 0x9, HOST_DATA)
    assert want.hex() not in out.out.decode() and CHIP_KEY.hex() not in out.out.decode()


def test_main_without_a_secure_processor_fails_and_prints_no_key(monkeypatch, capsysbinary) -> None:
    def no_report(root=None):
        raise kt.SealedKeyError("cannot make a report entry")
    monkeypatch.setattr(kt, "tsm_report", no_report)
    assert kt.main(["x", "key"]) == 1
    out = capsysbinary.readouterr()
    assert out.out == b"" and b"cannot make a report entry" in out.err


def test_tsm_report_reads_the_outblob_and_removes_its_entry(tmp_path: Path, monkeypatch) -> None:
    # configfs makes outblob when inblob is written; a plain directory needs help.
    real_open = open

    def fake_open(path, mode="r", *a, **kw):
        if str(path).endswith("/inblob"):
            Path(path).with_name("outblob").write_bytes(_report())
        return real_open(path, mode, *a, **kw)

    monkeypatch.setattr("builtins.open", fake_open)
    real_rmdir = os.rmdir

    def rmdir(path):  # configfs removes its attribute files with the entry
        for f in Path(path).iterdir():
            f.unlink()
        real_rmdir(path)

    monkeypatch.setattr(kt.os, "rmdir", rmdir)
    assert kt.tsm_report(root=str(tmp_path)) == _report()
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------- sealed-data.sh

KEY_A = "a1" * 32
KEY_B = "b2" * 32

FAKE_CRYPTSETUP = r"""#!@BASH@
# Fake cryptsetup: one LUKS2 volume in a regular file, one key slot, a token in the state dir.
printf 'cryptsetup %s\n' "$*" >> "$FAKE_LOG"
args=("$@"); keyfile=""; dev=""
for ((i = 0; i < ${#args[@]}; i++)); do [ "${args[$i]}" = --key-file ] && keyfile=${args[$((i + 1))]}; done
case "$1" in
  isLuks) [ -e "$FAKE_STATE/isluks-broken" ] && exit 1
          [ "$(head -c 6 "$2" | od -An -tx1 | tr -d ' \n')" = 4c554b53babe ] ;;
  luksFormat) dev=${args[-1]}
              [ "$(wc -c < "$keyfile" | tr -d ' ')" = 32 ] || exit 3
              printf 'LUKS\xba\xbe' | dd of="$dev" conv=notrunc 2>/dev/null
              od -An -tx1 "$keyfile" | tr -d ' \n' > "$FAKE_STATE/slot0" ;;
  open) dev=${args[-2]}
        [ "$(od -An -tx1 "$keyfile" | tr -d ' \n')" = "$(cat "$FAKE_STATE/slot0" 2>/dev/null)" ] || exit 2
        touch "$FAKE_STATE/opened" ;;
  token) case "$2" in
           export) cat "$FAKE_STATE/token" 2>/dev/null || exit 1 ;;
           import) cat > "$FAKE_STATE/token" ;;
         esac ;;
  *) exit 9 ;;
esac
"""

FAKE_KEYTOOL = r"""#!@BASH@
# Fake sealed_data_key.py: FAKE_KEY is the key in hex, FAKE_KEY_FAILS makes it fail.
[ -n "${FAKE_KEY_FAILS:-}" ] && { echo "sealed_data_key: cannot open /dev/sev-guest" >&2; exit 1; }
case "$1" in
  info) printf '{"key_id": "id-%s", "measurement": "%s"}\n' "${FAKE_KEY:0:8}" "${FAKE_MEASUREMENT:-ab}" ;;
  key) python3 -c 'import os, sys; sys.stdout.buffer.write(bytes.fromhex(os.environ["FAKE_KEY"]))' ;;
esac
"""

FAKE_SIMPLE = {
    "mkfs.xfs": 'printf "mkfs.xfs %s\\n" "$*" >> "$FAKE_LOG"',
    "mount": 'printf "mount %s\\n" "$*" >> "$FAKE_LOG"; [ -z "${FAKE_MOUNT_FAILS:-}" ] || exit 32; touch "$FAKE_STATE/mounted"',
    "mountpoint": '[ -e "$FAKE_STATE/mounted" ]',
    "df": 'echo " Size"; echo " 4211081216"',
}


@pytest.fixture
def disk(tmp_path: Path):
    if BASH is None:
        pytest.skip("needs bash 4+")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, body in {"cryptsetup": FAKE_CRYPTSETUP, "keytool": FAKE_KEYTOOL}.items():
        (bin_ / name).write_text(body.replace("@BASH@", BASH))
        (bin_ / name).chmod(0o755)
    for name, body in FAKE_SIMPLE.items():
        (bin_ / name).write_text(f"#!{BASH}\n{body}\n")
        (bin_ / name).chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    run = tmp_path / "run"
    run.mkdir()
    dev = tmp_path / "data.raw"
    dev.write_bytes(bytes(1 << 16))
    script = tmp_path / "sealed-data.sh"
    text = (SEALED / "sealed-data.sh").read_text()
    script.write_text(f"#!{BASH}\n" + text[len("#!/bin/bash\n"):])
    script.chmod(0o755)

    class Disk:
        def __init__(self) -> None:
            self.dev, self.state, self.run_dir, self.mnt = dev, state, run, tmp_path / "srv" / "sealed-data"
            self.log = state / "calls.log"

        def boot(self, key: str = KEY_A, **env: str) -> tuple[subprocess.CompletedProcess, dict]:
            (state / "mounted").unlink(missing_ok=True)  # a new boot: nothing mounted
            (state / "opened").unlink(missing_ok=True)
            self.log.write_text("")
            proc = subprocess.run([str(script)], capture_output=True, text=True, timeout=60, env={
                "PATH": f"{bin_}:/usr/bin:/bin:/usr/sbin:/sbin", "FAKE_LOG": str(self.log), "FAKE_STATE": str(state),
                "FAKE_KEY": key, "SEALED_DATA_DEV": str(dev), "SEALED_DATA_MNT": str(self.mnt),
                "SEALED_DATA_STATUS": str(run / "sealed-data.status"), "SEALED_DATA_KEYTOOL": str(bin_ / "keytool"),
                "SEALED_DATA_RUNDIR": str(run), "SEALED_DATA_FAKE_DISK": "1", **env})
            status = json.loads((run / "sealed-data.status").read_text()) if (run / "sealed-data.status").exists() else {}
            return proc, status

        def calls(self, prefix: str = "") -> list[str]:
            return [c for c in self.log.read_text().splitlines() if c.startswith(prefix)]

    return Disk()


def test_a_blank_disk_gets_one_luks2_volume_with_xfs_mounted_safely(disk) -> None:
    proc, status = disk.boot()
    assert proc.returncode == 0, proc.stderr
    assert status["state"] == "new" and status["persistent"] is True and status["key_id"] == "id-" + KEY_A[:8]
    fmt = disk.calls("cryptsetup luksFormat")
    assert len(fmt) == 1
    for opt in ("--type luks2", "--cipher aes-xts-plain64", "--key-size 512", "--sector-size 4096",
                "--pbkdf pbkdf2", "--keyfile-size 32"):
        assert opt in fmt[0]
    assert disk.calls("mkfs.xfs") == ["mkfs.xfs -f -q /dev/mapper/sealed-data"]
    assert disk.calls("mount") == [f"mount -t xfs -o nosuid,nodev,noexec,noatime /dev/mapper/sealed-data {disk.mnt}"]
    assert json.loads((disk.state / "token").read_text())["fs"] == "xfs"
    assert (disk.mnt / "workspaces").is_dir() and (disk.mnt / "hotel").is_dir()
    assert oct((disk.mnt / "workspaces").stat().st_mode & 0o777) == "0o700"


def test_the_key_never_reaches_argv_or_output_and_its_file_is_removed(disk) -> None:
    proc, _ = disk.boot()
    assert proc.returncode == 0, proc.stderr
    for text in (disk.log.read_text(), proc.stdout, proc.stderr, (disk.run_dir / "sealed-data.status").read_text()):
        assert KEY_A not in text
    assert not list(disk.run_dir.glob("sealed-data.key.*"))


def test_the_next_boot_of_the_same_build_reopens_without_formatting(disk) -> None:
    disk.boot()
    proc, status = disk.boot()
    assert proc.returncode == 0, proc.stderr
    assert status["state"] == "open" and status["persistent"] is True
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("mkfs.xfs")
    assert disk.calls("cryptsetup open") and disk.calls("mount -t xfs")


def test_another_build_cannot_open_the_volume_and_leaves_it_untouched(disk) -> None:
    disk.boot(KEY_A)
    before = disk.dev.read_bytes(), (disk.state / "token").read_text()
    proc, status = disk.boot(KEY_B)
    assert proc.returncode == 0, "a locked volume must not stop the hotel"
    assert status["state"] == "locked" and status["persistent"] is False
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("mkfs.xfs") and not disk.calls("mount")
    assert (disk.dev.read_bytes(), (disk.state / "token").read_text()) == before
    proc, status = disk.boot(KEY_A)
    assert status["state"] == "open", "the build that made it still opens it"


def test_no_data_disk_and_no_key_fall_back_without_formatting(disk) -> None:
    disk.dev.unlink()
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "absent" and status["persistent"] is False
    disk.dev.write_bytes(bytes(1 << 16))
    proc, status = disk.boot(FAKE_KEY_FAILS="1")
    assert proc.returncode == 0 and status["state"] == "nokey"
    assert "cannot open /dev/sev-guest" in status["detail"]
    assert not disk.calls("cryptsetup") and not disk.calls("mkfs.xfs")


def test_a_first_boot_that_stopped_before_mkfs_formats_the_file_system_once(disk) -> None:
    disk.boot()
    (disk.state / "token").unlink()  # luksFormat done, mkfs and the token not
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "new"
    assert not disk.calls("cryptsetup luksFormat") and len(disk.calls("mkfs.xfs")) == 1
    proc, status = disk.boot()
    assert status["state"] == "open" and not disk.calls("mkfs.xfs")


def test_a_luks_header_cryptsetup_cannot_read_is_never_formatted(disk) -> None:
    disk.boot()
    (disk.state / "isluks-broken").touch()
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "broken"
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("mkfs.xfs")


def test_a_volume_whose_file_system_does_not_mount_is_reported_broken(disk) -> None:
    disk.boot()
    proc, status = disk.boot(FAKE_MOUNT_FAILS="1")
    assert proc.returncode == 0 and status["state"] == "broken" and status["persistent"] is False
    assert not disk.calls("mkfs.xfs")


def test_the_disk_check_accepts_a_regular_file_only_in_tests() -> None:
    text = (SEALED / "sealed-data.sh").read_text()
    assert '[ -b "$1" ] || { [ "${SEALED_DATA_FAKE_DISK:-0}" = 1 ] && [ -f "$1" ]; }' in text


# ---------------------------------------------------------------- room-data.sh

def _room_data(tmp_path: Path, source: str, findmnt_target: str) -> tuple[subprocess.CompletedProcess, list[str]]:
    if BASH is None:
        pytest.skip("needs bash 4+")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    log = tmp_path / "calls.log"
    fakes = {
        "mount": f'echo "mount $*" >> {log}',
        "mountpoint": f'echo "mountpoint $*" >> {log}; exit 1',
        "findmnt": f'echo "{findmnt_target}"',
        "losetup": "echo /dev/loop9",
    }
    for name, body in fakes.items():
        (bin_ / name).write_text(f"#!{BASH}\n{body}\n")
        (bin_ / name).chmod(0o755)
    env_file = tmp_path / "room.env"
    data = tmp_path / "srv" / "room-sealed"
    env_file.write_text(f'ROOM_DATA_DIR="{data}"\nROOM_DATA_DEVICE="/dev/mapper/sealed-scratch"\n'
                        f'ROOM_WORKSPACES="1"\nROOM_WORKSPACES_SOURCE="{source}"\n')
    proc = subprocess.run([BASH, str(ROOT / "room-kit" / "lib" / "room-data.sh"), "up", str(env_file)],
                          capture_output=True, text=True, timeout=30, env={"PATH": f"{bin_}:/usr/bin:/bin:/usr/sbin:/sbin"})
    return proc, log.read_text().splitlines()


def test_room_data_binds_the_workspaces_source_on_its_own_volume(tmp_path: Path) -> None:
    src = tmp_path / "srv" / "sealed-data" / "workspaces"
    src.mkdir(parents=True)
    proc, calls = _room_data(tmp_path, str(src), str(src.parent))
    assert proc.returncode == 0, proc.stderr
    ws = tmp_path / "srv" / "room-sealed" / "workspaces"
    assert f"mount --bind {src} {ws}" in calls
    assert f"mount -o remount,bind,nosuid,nodev,noexec {ws}" in calls


@pytest.mark.parametrize("on_root", [True, False])
def test_room_data_keeps_workspaces_on_the_data_volume_without_a_usable_source(tmp_path: Path, on_root: bool) -> None:
    src = tmp_path / "srv" / "sealed-data" / "workspaces"
    if on_root:
        src.mkdir(parents=True)  # exists, but on the guest's root file system (memory)
    proc, calls = _room_data(tmp_path, str(src), "/")
    assert proc.returncode == 0, proc.stderr
    ws = tmp_path / "srv" / "room-sealed" / "workspaces"
    assert f"mount --bind {ws} {ws}" in calls and f"mount --bind {src} {ws}" not in calls
    assert "is not on a volume of its own" in proc.stderr
    assert f"mount -o remount,bind,nosuid,nodev,noexec {ws}" in calls


# ---------------------------------------------------------------- build, launch, install wiring

def _build_env(tmp_path: Path, **values: str) -> Path:
    env = tmp_path / "sealed.env"
    base = {"SEALED_NAME": "t", "SEALED_DIR": str(tmp_path / "sealed"), "SEALED_MINER": "0"}
    base.update(values)
    env.write_text("".join(f'{k}="{v}"\n' for k, v in base.items()))
    return env


@pytest.mark.parametrize("values, message", [
    ({"SEALED_DATA_GIB": "8", "SEALED_ROOM_WORKSPACES": "0"}, "needs SEALED_ROOM_WORKSPACES=1"),
    ({"SEALED_DATA_GIB": "8G", "SEALED_ROOM_WORKSPACES": "1"}, "whole number of GiB"),
    ({"SEALED_DATA_GIB": "-1", "SEALED_ROOM_WORKSPACES": "1"}, "whole number of GiB"),
])
def test_build_refuses_a_bad_data_volume_setting_before_the_long_build(tmp_path: Path, values, message) -> None:
    if BASH is None:
        pytest.skip("needs bash 4+")
    proc = subprocess.run([BASH, str(SEALED / "build-guest.sh"), str(_build_env(tmp_path, **values))],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 1 and message in proc.stderr
    assert not (tmp_path / "sealed").exists(), "nothing is made before the check"


def test_build_puts_both_tools_in_the_measured_initrd_and_the_switch_in_room_env() -> None:
    text = (SEALED / "build-guest.sh").read_text()
    assert 'install -m 0755 "$KIT/sealed/sealed-data.sh" "$R/usr/local/sbin/sealed-data.sh"' in text
    assert 'install -m 0755 "$KIT/sealed/sealed_data_key.py" "$R/usr/local/sbin/sealed_data_key.py"' in text
    room_env = text[text.index('cat > "$R/opt/room-kit/room.env" <<EOF'):text.index("ROOM_HOTEL_NAME=$SEALED_NAME")]
    assert "ROOM_WORKSPACES_SOURCE=$DATA_WS\n" in room_env
    assert text.index("DATA_WS=/srv/sealed-data/workspaces") < text.index("mmdebstrap")
    for pkg in ("cryptsetup-bin", "xfsprogs", "dmsetup", "python3"):
        assert pkg in text[text.index("PKGS="):text.index("BASE_ID=")]
    assert "sev-guest" in text and "tsm_report" in text and "dm-crypt" in text


def test_guest_boot_opens_the_volume_only_when_the_measured_env_asks() -> None:
    text = (SEALED / "guest-boot.sh").read_text()
    assert "if grep -q '^ROOM_WORKSPACES_SOURCE=/' /opt/room-kit/room.env; then\n  /usr/local/sbin/sealed-data.sh" in text
    call = text.index("  /usr/local/sbin/sealed-data.sh\n")
    assert call < text.index("/opt/room-kit/install.sh /opt/room-kit/room.env")
    # The scratch stays per boot: it is opened with /dev/urandom before the data volume.
    assert text.index("--key-file /dev/urandom") < call


def _miner_key_step(tmp_path: Path, volume_open: bool) -> tuple[subprocess.CompletedProcess, Path, Path]:
    """guest-boot.sh step 2 for a miner hotel, against a temporary root and a fake mountpoint."""
    text = (SEALED / "guest-boot.sh").read_text()
    step = text[text.index("KEY=/sys/firmware/qemu_fw_cfg"):text.index('log "installing the room kit"')]
    root = tmp_path / "guest"
    data = root / "srv" / "sealed-data"
    (data / "hotel").mkdir(parents=True, exist_ok=True)
    (root / "room.env").write_text("ROOM_MINER=1\n")
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    (bin_ / "mountpoint").write_text(f"#!{BASH}\n" + ("exit 0\n" if volume_open else "exit 1\n"))
    (bin_ / "mountpoint").chmod(0o755)
    step = (step.replace("/sys/firmware/qemu_fw_cfg/by_name/opt/cathedral/room-api-key/raw", str(root / "fw-none"))
            .replace("DATA=/srv/sealed-data", f"DATA={data}")
            .replace("/opt/room-kit/room.env", str(root / "room.env"))
            .replace("/run/room-api-key", str(root / "room-api-key")))
    script = root / "step.sh"
    script.write_text('set -euo pipefail\nlog() { echo "[sealed-hotel] $*"; }\n' + step)
    proc = subprocess.run([BASH, str(script)], capture_output=True, text=True, timeout=60,
                          env={"PATH": f"{bin_}:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
    return proc, root / "room-api-key", data / "hotel" / "internal-api-key"


def test_miner_internal_key_is_kept_on_the_open_volume_so_workspace_owners_survive(tmp_path: Path) -> None:
    if BASH is None:
        pytest.skip("needs bash 4+")
    proc, key, kept = _miner_key_step(tmp_path, volume_open=True)
    assert proc.returncode == 0, proc.stderr
    first = key.read_text()
    assert len(first) == 43 and kept.read_text() == first and oct(kept.stat().st_mode & 0o777) == "0o600"
    proc, key, kept = _miner_key_step(tmp_path, volume_open=True)  # the next boot of the same build
    assert proc.returncode == 0 and key.read_text() == first
    proc, key, _ = _miner_key_step(tmp_path, volume_open=False)  # no volume: a new key per boot, as before
    assert proc.returncode == 0 and len(key.read_text()) == 43 and key.read_text() != first


def test_launch_attaches_the_data_disk_only_when_asked() -> None:
    text = (SEALED / "launch-guest.sh").read_text()
    block = text[text.index("DATA_DRIVE=()"):text.index("exec /usr/bin/qemu-system-x86_64")]
    assert 'if [ "${SEALED_DATA_GIB:-0}" != 0 ]; then' in block
    assert '[ -f "$SEALED_DIR/data.raw" ] || truncate -s "${SEALED_DATA_GIB}G" "$SEALED_DIR/data.raw"' in block
    assert "serial=sealed-data" in block and "cache=none" in block
    assert '${DATA_DRIVE[@]+"${DATA_DRIVE[@]}"}' in text[text.index("exec /usr/bin/qemu-system-x86_64"):]


# ---------------------------------------------------------------- install-sealed.sh roll guard

def _step5_with_data(host: FakeHost, booted: str | None, **env: str):
    """Step 5 with a data volume made by the booted build (measurement *booted*)."""
    sealed = host.tmp / "sealed"
    # _sealed_step5 makes the sealed dir afresh; plant the volume just before it runs the slice.
    orig_run = host.run

    def run(script, *args, env=None):
        (sealed / "data.raw").write_bytes(b"ciphertext")
        if booted is not None:
            old = sealed / "images" / "20260101T000000Z"
            (old / "expected-measurement").write_text(booted + "\n")
            (sealed / "run" / "booted-image").symlink_to(old)
        return orig_run(script, *args, env=env)

    host.run = run
    try:
        return _sealed_step5(host, "ab" * 48, sealed={"SEALED_DATA_GIB": "4"}, **env)
    finally:
        host.run = orig_run


def test_a_new_build_with_a_data_volume_stops_until_the_operator_chooses(host: FakeHost) -> None:
    proc, _ = _step5_with_data(host, "cd" * 48)
    assert proc.returncode == 1
    assert "cannot open the data volume of the booted build" in proc.stderr and "SEALED_DATA_ON_NEW_BUILD=reset" in proc.stderr
    assert not host.calls("systemctl restart")
    assert (host.tmp / "sealed" / "data.raw").read_bytes() == b"ciphertext"


def test_reset_keeps_the_old_volume_aside_and_keep_leaves_it(host: FakeHost) -> None:
    proc, _ = _step5_with_data(host, "cd" * 48, SEALED_DATA_ON_NEW_BUILD="reset")
    assert proc.returncode == 0, proc.stderr[-3000:]
    sealed = host.tmp / "sealed"
    assert (sealed / "data.raw.prev").read_bytes() == b"ciphertext" and not (sealed / "data.raw").exists()
    proc, _ = _step5_with_data(host, "cd" * 48, SEALED_DATA_ON_NEW_BUILD="keep")
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert (sealed / "data.raw").read_bytes() == b"ciphertext" and not (sealed / "data.raw.prev").exists()


def test_the_same_build_restarts_with_its_volume_and_no_choice(host: FakeHost) -> None:
    proc, _ = _step5_with_data(host, "ab" * 48)
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert (host.tmp / "sealed" / "data.raw").read_bytes() == b"ciphertext"


def test_a_reset_build_that_fails_its_measurement_gets_the_old_volume_back(host: FakeHost) -> None:
    sealed = host.tmp / "sealed"
    orig_run = host.run

    def run(script, *args, env=None):
        (sealed / "data.raw").write_bytes(b"ciphertext")
        old = sealed / "images" / "20260101T000000Z"
        (old / "expected-measurement").write_text("cd" * 48 + "\n")
        (sealed / "run" / "booted-image").symlink_to(old)
        return orig_run(script, *args, env=env)

    host.run = run
    try:
        proc, images = _sealed_step5(host, "ee" * 48, sealed={"SEALED_DATA_GIB": "4"}, SEALED_DATA_ON_NEW_BUILD="reset")
    finally:
        host.run = orig_run
    assert proc.returncode == 1 and "MEASUREMENT DIFFERS" in proc.stdout
    assert (sealed / "data.raw").read_bytes() == b"ciphertext" and not (sealed / "data.raw.prev").exists()


# ---------------------------------------------------------------- health

def test_health_reports_where_workspaces_live(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ROOM_DOCKER_SOCK", "/nonexistent.sock")
    sys.path.insert(0, str(ROOT / "room-kit"))
    try:
        import room_health
    finally:
        sys.path.pop(0)
    status = tmp_path / "sealed-data.status"
    env = {"ROOM_WORKSPACES": "1", "ROOM_WORKSPACES_SOURCE": "/srv/sealed-data/workspaces"}
    assert room_health.workspaces_storage({"ROOM_WORKSPACES": "1"}, status) is None
    assert room_health.workspaces_storage({**env, "ROOM_WORKSPACES": "0"}, status) is None
    assert room_health.workspaces_storage(env, status)["state"] == "unknown"
    status.write_text(json.dumps({"state": "locked", "persistent": False, "key_id": "k", "detail": "d", "x": 1}))
    assert room_health.workspaces_storage(env, status) == {"state": "locked", "persistent": False, "key_id": "k", "detail": "d"}
