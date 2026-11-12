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
import shutil
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

# The fake cryptsetup models a LUKS2 volume: key slot 0, a header JSON the test
# can edit (as a host editing the on-disk header would), tokens, and the active
# device-mapper cipher that open would build from the header. It is enough to
# exercise verify_header's control flow. It does NOT prove the kernel enforces
# the cipher: only a real cryptsetup and dm-crypt do (see the c48 note in the PR).
FAKE_CRYPTSETUP = r"""#!@BASH@
printf 'cryptsetup %s\n' "$*" >> "$FAKE_LOG"
args=("$@"); keyfile=""
for ((i = 0; i < ${#args[@]}; i++)); do [ "${args[$i]}" = --key-file ] && keyfile=${args[$((i + 1))]}; done
H=$FAKE_STATE/header.json
case "$1" in
  --version) echo "cryptsetup ${FAKE_CRYPTSETUP_VERSION:-2.8.1} flags: UDEV BLKID" ;;
  isLuks) [ -e "$FAKE_STATE/isluks-broken" ] && exit 1
          [ "$(head -c 6 "${args[-1]}" | od -An -tx1 | tr -d ' \n')" = 4c554b53babe ] ;;
  luksFormat)
    dev=${args[-1]}
    [ "$(wc -c < "$keyfile" | tr -d ' ')" = 32 ] || exit 3
    # A LUKS2 layout as luksFormat writes it: primary signature at 0, its JSON area at 4 KiB,
    # the secondary signature at 16 KiB, and key slot bytes at 32 KiB.
    python3 -c 'import os,sys
with open(sys.argv[1], "r+b") as f:
    f.seek(0); f.write(b"LUKS\xba\xbe\x00\x02")
    f.seek(4096); f.write(b"{\"keyslots\":{\"0\":{}},\"segments\":{\"0\":{}}}")
    f.seek(16384); f.write(b"SKUL\xba\xbe\x00\x02")
    f.seek(32768); f.write(os.urandom(4096))' "$dev"
    od -An -tx1 "$keyfile" | tr -d ' \n' > "$FAKE_STATE/slot0"
    python3 -c 'import json,sys; json.dump({
      "keyslots":{"0":{"type":"luks2","key_size":64,"area":{"encryption":"aes-xts-plain64"},"kdf":{"type":"pbkdf2","hash":"sha256"}}},
      "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","encryption":"aes-xts-plain64","sector_size":4096}},
      "tokens":{}}, open(sys.argv[1],"w"))' "$H" ;;
  open)
    [ "$(od -An -tx1 "$keyfile" | tr -d ' \n')" = "$(cat "$FAKE_STATE/slot0" 2>/dev/null)" ] || exit 2
    # Build the active mapping from the (host-controlled) header segment.
    python3 -c 'import json,sys; s=json.load(open(sys.argv[1]))["segments"]["0"]
open(sys.argv[2]+"-cipher","w").write(s.get("encryption",""))
open(sys.argv[2]+"-sector","w").write(str(s.get("sector_size","")))' "$H" "$FAKE_STATE/map"
    touch "$SEALED_DATA_MAP" ;;
  close) rm -f "$SEALED_DATA_MAP" "$FAKE_STATE/map-cipher" "$FAKE_STATE/map-sector" ;;
  luksDump) [ "$2" = --dump-json-metadata ] && cat "$H" ;;
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
  info) printf '{"key_id": "id-%s", "measurement": "%s", "policy": "%s", "host_data": "%s"}\n' \
          "${FAKE_KEY:0:8}" "${FAKE_MEASUREMENT:-ab}" "${FAKE_POLICY:-0x30000}" "${FAKE_HOST_DATA:-1133}" ;;
  key) python3 -c 'import os, sys; sys.stdout.buffer.write(bytes.fromhex(os.environ["FAKE_KEY"]))' ;;
esac
"""

FAKE_SIMPLE = {
    "mkfs.xfs": 'printf "mkfs.xfs %s\\n" "$*" >> "$FAKE_LOG"; [ ! -e "$FAKE_STATE/mkfs-fails" ]',
    "mount": 'printf "mount %s\\n" "$*" >> "$FAKE_LOG"; [ -z "${FAKE_MOUNT_FAILS:-}" ] || exit 32; touch "$FAKE_STATE/mounted"',
    "mountpoint": '[ -e "$FAKE_STATE/mounted" ]',
    "df": 'echo " Size"; echo " 4211081216"',
    # The active device-mapper table: cipher from the header the open built.
    "dmsetup": 'printf "dmsetup %s\\n" "$*" >> "$FAKE_LOG"; [ "$1" = table ] || exit 0; '
               'c=$(cat "$FAKE_STATE/map-cipher" 2>/dev/null); s=$(cat "$FAKE_STATE/map-sector" 2>/dev/null); '
               '[ -n "$c" ] || exit 1; echo "0 8216576 crypt $c 0000 0 7:0 32768 1 sector_size:$s"',
    # blkid -p -u filesystem <map>: a file system is present only when planted.
    "blkid": '[ -e "$FAKE_STATE/planted-fs" ] && { echo "TYPE=ext4"; exit 0; }; exit 2',
    "sync": 'printf "sync %s\\n" "$*" >> "$FAKE_LOG"',
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
    mapfile = tmp_path / "mapper-sealed-data"
    script = tmp_path / "sealed-data.sh"
    text = (SEALED / "sealed-data.sh").read_text()
    script.write_text(f"#!{BASH}\n" + text[len("#!/bin/bash\n"):])
    script.chmod(0o755)

    class Disk:
        def __init__(self) -> None:
            self.dev, self.state, self.run_dir, self.mnt = dev, state, run, tmp_path / "srv" / "sealed-data"
            self.map = mapfile
            self.log = state / "calls.log"

        def header(self) -> dict:
            return json.loads((state / "header.json").read_text())

        def write_header(self, h: dict) -> None:
            (state / "header.json").write_text(json.dumps(h))

        def boot(self, key: str = KEY_A, **env: str) -> tuple[subprocess.CompletedProcess, dict]:
            for f in ("mounted", "map-cipher", "map-sector"):  # a new boot: fresh mapping
                (state / f).unlink(missing_ok=True)
            mapfile.unlink(missing_ok=True)
            self.log.write_text("")
            proc = subprocess.run([str(script)], capture_output=True, text=True, timeout=60, env={
                "PATH": f"{bin_}:/usr/bin:/bin:/usr/sbin:/sbin", "FAKE_LOG": str(self.log), "FAKE_STATE": str(state),
                "FAKE_KEY": key, "SEALED_DATA_DEV": str(dev), "SEALED_DATA_MNT": str(self.mnt),
                "SEALED_DATA_MAP": str(mapfile),
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
    assert disk.calls("mkfs.xfs") == [f"mkfs.xfs -f -q {disk.map}"]
    assert disk.calls("mount") == [f"mount -t xfs -o nosuid,nodev,noexec,noatime {disk.map} {disk.mnt}"]
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
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("cryptsetup open") and not disk.calls("mkfs.xfs")


def test_a_second_boot_with_no_token_is_broken_and_never_formats(disk) -> None:
    # A first boot that stopped between luksFormat and the token import no longer repairs itself: only
    # the boot that proved the disk blank may run mkfs. A person removes data.raw (see the recovery step).
    disk.boot()
    (disk.state / "token").unlink()  # luksFormat done, mkfs and the token not
    before = disk.dev.read_bytes()
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "broken" and status["persistent"] is False
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("mkfs.xfs") and not disk.calls("mount")
    assert disk.calls("cryptsetup close")
    assert disk.dev.read_bytes() == before


def test_an_existing_volume_with_no_token_and_no_blkid_hit_is_never_formatted(disk) -> None:
    # AB#598 reviewer regression: a lost token plus a damaged xfs signature (blkid sees nothing).
    disk.boot()
    (disk.state / "token").unlink()
    assert not (disk.state / "planted-fs").exists()  # the fake blkid fails: "no file system here"
    before = disk.dev.read_bytes()
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "broken"
    assert not disk.calls("mkfs.xfs") and not disk.calls("mount") and not disk.calls("cryptsetup token import")
    assert disk.dev.read_bytes() == before


@pytest.mark.parametrize("token", [
    {"type": "other-type", "fs": "xfs"},
    {"type": "cathedral-sealed-data", "fs": "ext4"},
    {"type": "cathedral-sealed-data"},
], ids=["wrong-type", "fs-not-xfs", "no-fs-field"])
def test_an_existing_volume_whose_token_is_not_the_xfs_token_is_never_formatted(disk, token) -> None:
    disk.boot()
    (disk.state / "token").write_text(json.dumps(token))
    before = disk.dev.read_bytes()
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "broken"
    assert not disk.calls("mkfs.xfs") and not disk.calls("mount")
    assert disk.dev.read_bytes() == before


def test_a_first_boot_whose_mkfs_failed_does_not_format_on_the_next_boot(disk) -> None:
    (disk.state / "mkfs-fails").touch()
    proc, status = disk.boot()
    assert status["state"] == "error" and len(disk.calls("mkfs.xfs")) == 1
    (disk.state / "mkfs-fails").unlink()
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "broken"
    assert not disk.calls("mkfs.xfs") and not disk.calls("mount")


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


def test_a_failing_step_reports_error_and_still_removes_the_key(disk) -> None:
    (disk.state / "mkfs-fails").touch()
    proc, status = disk.boot()
    assert proc.returncode != 0, "the boot script logs it and goes on without the volume"
    assert status["state"] == "error" and status["persistent"] is False
    assert not list(disk.run_dir.glob("sealed-data.key.*"))


def test_damaged_dual_luks2_signatures_are_never_formatted(disk) -> None:
    # SpockChaser's HOLD on #413: both 6-byte LUKS2 signatures (offset 0 and 16 KiB) zeroed,
    # the rest of the header and the key slots intact. A backup restore could still use them.
    disk.boot()
    with open(disk.dev, "r+b") as f:
        f.seek(0)
        f.write(bytes(6))
        f.seek(16384)
        f.write(bytes(6))
    before = disk.dev.read_bytes()
    proc, status = disk.boot()
    assert proc.returncode == 0, "a disk it will not format must not stop the hotel"
    assert status["state"] == "broken" and status["persistent"] is False
    assert "holds data that is not a LUKS2 volume" in status["detail"]
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("mkfs.xfs") and not disk.calls("mount")
    assert disk.dev.read_bytes() == before, "left byte for byte untouched"


def test_a_random_non_luks_disk_is_never_formatted(disk) -> None:
    disk.dev.write_bytes(b"NOTLUKS" + os.urandom((1 << 16) - 7))
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "broken"
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("mkfs.xfs")


def test_one_nonzero_byte_anywhere_in_the_first_16_mib_blocks_the_format(disk) -> None:
    # The header areas and the key slots: the first 16 MiB.
    with open(disk.dev, "wb") as f:
        f.truncate(32 << 20)               # sparse, reads as zero
        f.seek((16 << 20) - 1)
        f.write(b"\x01")                   # the last byte of the 16 MiB window
    proc, status = disk.boot()
    assert status["state"] == "broken" and not disk.calls("cryptsetup luksFormat")


def test_a_zeroed_header_over_a_payload_is_never_formatted(disk) -> None:
    # SpockChaser's second HOLD on #413: the first 16 MiB zeroed, the encrypted payload still there.
    # A header backup could restore it, so a format here would destroy recoverable data.
    with open(disk.dev, "wb") as f:
        f.truncate(32 << 20)
        f.seek(16 << 20)
        f.write(b"\x01")                   # the first byte past the header window
    before = disk.dev.read_bytes()
    proc, status = disk.boot()
    assert proc.returncode == 0, proc.stderr
    assert status["state"] == "broken" and "holds data that is not a LUKS2 volume" in status["detail"]
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("mkfs.xfs") and not disk.calls("mount")
    assert disk.dev.read_bytes() == before, "left byte for byte untouched"


def test_a_nonzero_last_byte_of_the_disk_blocks_the_format(disk) -> None:
    with open(disk.dev, "wb") as f:
        f.seek((32 << 20) + 4)             # 32 MiB + 5 bytes: the last chunk is 5 bytes long
        f.write(b"\x01")                   # the very last byte of the disk
    proc, status = disk.boot()
    assert status["state"] == "broken" and not disk.calls("cryptsetup luksFormat")


def test_a_fresh_all_zero_disk_still_formats(disk) -> None:
    with open(disk.dev, "wb") as f:
        f.truncate(32 << 20)               # a fresh sparse data.raw, as launch-guest.sh makes it
    proc, status = disk.boot()
    assert proc.returncode == 0, proc.stderr
    assert status["state"] == "new" and len(disk.calls("cryptsetup luksFormat")) == 1
    assert "the data disk is blank (read in" in proc.stdout


def test_an_empty_disk_is_not_proven_blank(disk) -> None:
    disk.dev.write_bytes(b"")
    proc, status = disk.boot()
    assert proc.returncode == 0, proc.stderr
    assert status["state"] == "broken" and "could not be read to its end" in status["detail"]
    assert not disk.calls("cryptsetup luksFormat")


def _virgin_program() -> str:
    """The Python that virgin_disk() runs, cut from sealed-data.sh, so the read loop can be driven directly."""
    text = (SEALED / "sealed-data.sh").read_text()
    body = text[text.index("virgin_disk() {"):]
    start = body.index("python3 -c '") + len("python3 -c '")
    return body[start:body.index("' \"$DEV\"", start)]


@pytest.mark.parametrize("fault, why", [
    ("return _real(fd, n) if calls[0] == 1 else b''", "short read: the device ends before its size"),
    ("raise OSError(5, 'Input/output error')", "an I/O error part way"),
])
def test_the_virgin_check_fails_closed_when_the_disk_cannot_be_read_whole(tmp_path: Path, fault: str, why: str) -> None:
    dev = tmp_path / "data.raw"
    with open(dev, "wb") as f:
        f.truncate(24 << 20)               # all zero, three 8 MiB chunks
    prelude = ("import os\n_real = os.read\ncalls = [0]\n"
               "def _read(fd, n):\n    calls[0] += 1\n"
               f"    if calls[0] == 1:\n        return _real(fd, n)\n    {fault}\n"
               "os.read = _read\n")
    proc = subprocess.run([sys.executable, "-c", prelude + _virgin_program(), str(dev)], capture_output=True, text=True)
    assert proc.returncode == 2, (why, proc.stderr)


@pytest.mark.parametrize("payload, code", [(None, 0), ((24 << 20) - 1, 1), (8 << 20, 1)])
def test_the_virgin_check_reads_every_chunk(tmp_path: Path, payload, code: int) -> None:
    dev = tmp_path / "data.raw"
    with open(dev, "wb") as f:
        f.truncate(24 << 20)
        if payload is not None:
            f.seek(payload)
            f.write(b"\x01")
    proc = subprocess.run([sys.executable, "-c", _virgin_program(), str(dev)], capture_output=True, text=True)
    assert proc.returncode == code, proc.stderr


def test_the_disk_check_accepts_a_regular_file_only_in_tests() -> None:
    text = (SEALED / "sealed-data.sh").read_text()
    assert '[ -b "$1" ] || { [ "${SEALED_DATA_FAKE_DISK:-0}" = 1 ] && [ -f "$1" ]; }' in text


# ---------------------------------------------------------------- sealed-data.sh header checks (Finding 1)
#
# The fake cryptsetup proves the script's control flow: it reads the device-mapper
# table and the LUKS2 header JSON after open, and refuses (closes, does not mkfs or
# mount) on any mismatch. It does NOT prove the kernel enforces the cipher; only a
# real cryptsetup and dm-crypt do. The c48 note in the PR covers the real check.

def test_the_token_records_the_full_launch_identity(disk) -> None:
    proc, _ = disk.boot(FAKE_MEASUREMENT="aa", FAKE_POLICY="0x30000", FAKE_HOST_DATA="dead")
    assert proc.returncode == 0, proc.stderr
    slot = json.loads((disk.state / "token").read_text())["slots"]["0"]
    assert slot["measurement"] == "aa" and slot["policy"] == "0x30000" and slot["host_data"] == "dead"
    import hashlib
    assert slot["launch_id"] == hashlib.sha256(b"aa:0x30000:dead").hexdigest()


def test_a_cryptsetup_older_than_2_8_1_opens_nothing(disk) -> None:
    proc, status = disk.boot(FAKE_CRYPTSETUP_VERSION="2.7.5")
    assert proc.returncode == 0 and status["state"] == "error"
    assert "2.7.5" in status["detail"] and "2.8.1" in status["detail"]
    assert not disk.calls("cryptsetup luksFormat") and not disk.calls("cryptsetup open") and not disk.calls("mkfs.xfs")
    # 2.8.1 exactly is accepted.
    proc, status = disk.boot(FAKE_CRYPTSETUP_VERSION="2.8.1")
    assert status["state"] == "new"


def test_a_header_edited_to_a_null_cipher_segment_is_refused(disk) -> None:
    disk.boot()  # makes the volume
    h = disk.header()
    h["segments"]["0"]["encryption"] = "cipher_null-ecb"  # a host edits the on-disk header
    disk.write_header(h)
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "tampered"
    assert not disk.calls("mkfs.xfs") and not disk.calls("mount")
    assert "cryptsetup close sealed-data" in disk.calls("cryptsetup close") or disk.calls("cryptsetup close")


def test_a_key_slot_with_a_null_cipher_area_is_refused(disk) -> None:
    disk.boot()
    h = disk.header()
    h["keyslots"]["0"]["area"]["encryption"] = "cipher_null-ecb"
    disk.write_header(h)
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "tampered"
    assert not disk.calls("mkfs.xfs")


def test_an_extra_segment_in_the_header_is_refused(disk) -> None:
    disk.boot()
    h = disk.header()
    h["segments"]["1"] = dict(h["segments"]["0"])
    disk.write_header(h)
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "tampered"


def test_a_wrong_sector_size_is_refused(disk) -> None:
    disk.boot()
    h = disk.header()
    h["segments"]["0"]["sector_size"] = 512
    disk.write_header(h)
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "tampered"
    assert not disk.calls("mkfs.xfs")


def test_a_volume_with_a_file_system_but_no_token_is_not_formatted(disk) -> None:
    disk.boot()
    (disk.state / "token").unlink()      # the token is gone
    (disk.state / "planted-fs").touch()  # but a file system is present
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "broken"
    assert not disk.calls("mkfs.xfs")


def test_the_verified_fresh_volume_is_formatted_and_mounted(disk) -> None:
    # The header checks and the blkid guard must not block the normal first boot.
    proc, status = disk.boot()
    assert proc.returncode == 0 and status["state"] == "new"
    assert disk.calls("dmsetup table") and disk.calls("cryptsetup luksDump")
    assert len(disk.calls("mkfs.xfs")) == 1 and disk.calls("mount -t xfs")


def test_the_by_id_device_wait_is_30_seconds() -> None:
    assert "for _ in $(seq 30); do is_disk" in (SEALED / "sealed-data.sh").read_text()


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
    assert "if grep -q '^ROOM_WORKSPACES_SOURCE=/' /opt/room-kit/room.env; then\n" in text
    call = text.index("  /usr/local/sbin/sealed-data.sh || log ")
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


# ---------------------------------------------------------------- install-sealed.sh roll guard (Findings 2 and 3)
#
# Ownership is decided from the launch identity in the volume's own LUKS token
# (measurement, policy, HOST_DATA), the choice comes from a one-time file, a
# reset keeps exactly one data.raw.prev, and an EXIT trap restores it on every
# failure path (not only a measurement mismatch).

MANIFEST = b"MANIFEST-BYTES"
OWNER = b"OWNER-CIPHERTEXT"


def _owner_launch_id(expected: str = "ab" * 48, manifest: bytes = MANIFEST) -> str:
    import hashlib
    hd_hex = hashlib.sha256(manifest).hexdigest()
    return hashlib.sha256(f"{expected}:0x30000:{hd_hex}".encode()).hexdigest()


def _roll(host: FakeHost, *, token_launch_id: str | None, choice: str | None = None,
          measurement: str = "ab" * 48, expected: str = "ab" * 48, prev: bytes | None = None,
          host_cryptsetup: bool = True, **env: str):
    """Run step 5 with a data volume whose token records *token_launch_id*.

    Plants what section 4 and the guest would have left: the installed
    launch-guest.sh and sealed.env, the build's manifest.json, the owner's
    data.raw and its token, an optional earlier data.raw.prev, and an optional
    one-time data-on-new-build file.
    """
    sealed = host.tmp / "sealed"
    orig_run = host.run
    # Fake cryptsetup for the host side: token export reads <dev>.token.
    if host_cryptsetup:
        (host.bin / "cryptsetup").write_text(
            f"#!{BASH}\n" + 'if [ "$1 $2" = "token export" ]; then d=${*: -1}; cat "$d.token" 2>/dev/null || exit 1; fi\n')
        (host.bin / "cryptsetup").chmod(0o755)

    def run(script, *args, env=None):
        (sealed / "launch-guest.sh").write_text((host.kit / "sealed" / "launch-guest.sh").read_text())
        (sealed / "launch-guest.sh").chmod(0o755)
        (sealed / "sealed.env").write_text((host.tmp / "sealed.env").read_text())
        (sealed / "images" / "20260102T000000Z" / "manifest.json").write_bytes(MANIFEST)
        (sealed / "data.raw").write_bytes(OWNER)
        if token_launch_id is not None:
            (sealed / "data.raw.token").write_text(json.dumps(
                {"type": "cathedral-sealed-data", "slots": {"0": {"launch_id": token_launch_id}}}))
        if prev is not None:
            (sealed / "data.raw.prev").write_bytes(prev)
        if choice is not None:
            (sealed / "data-on-new-build").write_text(choice + "\n")
        return orig_run(script, *args, env=env)

    host.run = run
    try:
        return _sealed_step5(host, measurement, expected=expected, sealed={"SEALED_DATA_GIB": "4"}, **env)
    finally:
        host.run = orig_run


def test_a_new_launch_identity_stops_until_the_operator_writes_a_choice(host: FakeHost) -> None:
    proc, _ = _roll(host, token_launch_id="feed" * 16)
    assert proc.returncode == 1
    assert "cannot open the data volume its current owner made" in proc.stderr
    assert "data-on-new-build" in proc.stderr and "reset" in proc.stderr and "keep" in proc.stderr
    assert not host.calls("systemctl restart")
    assert (host.tmp / "sealed" / "data.raw").read_bytes() == OWNER


def test_a_host_without_cryptsetup_stops_before_any_choice_and_names_the_cause(host: FakeHost) -> None:
    # Bugbot, 8 Nov: with no host cryptsetup the owner id read as empty, so a same-build reinstall was told
    # the new build cannot open the volume and offered reset, which sets a readable customer volume aside.
    if shutil.which("cryptsetup", path="/usr/bin:/bin:/usr/sbin:/sbin"):
        pytest.skip("a system cryptsetup is on the fixed test PATH")
    for choice in (None, "reset"):
        proc, _ = _roll(host, token_launch_id="feed" * 16, choice=choice, host_cryptsetup=False)
        assert proc.returncode == 1
        assert "cryptsetup is not installed on this host" in proc.stderr and "cryptsetup-bin" in proc.stderr
        assert "cannot open the data volume its current owner made" not in proc.stderr
        assert not host.calls("systemctl restart")
        sealed = host.tmp / "sealed"
        assert (sealed / "data.raw").read_bytes() == OWNER and not (sealed / "data.raw.prev").exists()


def test_the_same_launch_identity_restarts_with_no_choice(host: FakeHost) -> None:
    proc, _ = _roll(host, token_launch_id=_owner_launch_id())
    assert proc.returncode == 0, proc.stderr[-3000:]
    sealed = host.tmp / "sealed"
    assert (sealed / "data.raw").read_bytes() == OWNER and not (sealed / "data.raw.prev").exists()
    assert "systemctl restart room-sealed-sealed-1.service" in host.calls("systemctl")


def test_reset_sets_the_owner_volume_aside_and_consumes_the_choice_file(host: FakeHost) -> None:
    proc, _ = _roll(host, token_launch_id="feed" * 16, choice="reset")
    assert proc.returncode == 0, proc.stderr[-3000:]
    sealed = host.tmp / "sealed"
    assert (sealed / "data.raw.prev").read_bytes() == OWNER and not (sealed / "data.raw").exists()
    assert not (sealed / "data-on-new-build").exists(), "the one-time choice is consumed"


def test_keep_leaves_the_volume_and_consumes_the_choice_file(host: FakeHost) -> None:
    proc, _ = _roll(host, token_launch_id="feed" * 16, choice="keep")
    assert proc.returncode == 0, proc.stderr[-3000:]
    sealed = host.tmp / "sealed"
    assert (sealed / "data.raw").read_bytes() == OWNER and not (sealed / "data.raw.prev").exists()
    assert not (sealed / "data-on-new-build").exists()


def test_reset_refuses_to_overwrite_an_existing_prev_without_the_flag(host: FakeHost) -> None:
    proc, _ = _roll(host, token_launch_id="feed" * 16, choice="reset", prev=b"EARLIER-PREV")
    assert proc.returncode == 1
    assert "data.raw.prev already exists" in proc.stderr and "SEALED_DATA_OVERWRITE_PREV=1" in proc.stderr
    sealed = host.tmp / "sealed"
    assert (sealed / "data.raw").read_bytes() == OWNER and (sealed / "data.raw.prev").read_bytes() == b"EARLIER-PREV"
    # With the explicit flag it overwrites.
    proc, _ = _roll(host, token_launch_id="feed" * 16, choice="reset", prev=b"EARLIER-PREV", SEALED_DATA_OVERWRITE_PREV="1")
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert (host.tmp / "sealed" / "data.raw.prev").read_bytes() == OWNER


def test_a_reset_roll_that_fails_its_measurement_restores_the_owner_volume(host: FakeHost) -> None:
    proc, _ = _roll(host, token_launch_id="feed" * 16, choice="reset", measurement="ee" * 48)
    assert proc.returncode == 1 and "MEASUREMENT DIFFERS" in proc.stdout
    sealed = host.tmp / "sealed"
    assert (sealed / "data.raw").read_bytes() == OWNER and not (sealed / "data.raw.prev").exists()


def test_a_reset_roll_whose_guest_never_answers_also_restores_the_owner_volume(host: FakeHost) -> None:
    # An early exit (guest stopped) before the measurement check: the trap, not
    # the old manual restore, must put the owner's volume back.
    proc, _ = _roll(host, token_launch_id="feed" * 16, choice="reset",
                    FAKE_ATT_FAILS="999", FAKE_RESTART_KILLS="room-sealed-sealed-1.service")
    assert proc.returncode == 1 and "guest stopped" in proc.stderr
    sealed = host.tmp / "sealed"
    assert (sealed / "data.raw").read_bytes() == OWNER and not (sealed / "data.raw.prev").exists()


def test_the_roll_guard_reads_the_token_not_the_booted_image() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    body = text[text.index("data_volume_new_build()"):text.index("refuse_sealed_restart_with_rooms\ndata_volume_new_build")]
    assert "data_volume_owner_id" in body and "booted-image" not in body
    assert 'cryptsetup token export --token-id 0 "$SEALED_DIR/data.raw"' in text


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


# ---------------------------------------------------------------- build-time cryptsetup gate (Finding 1)

def test_build_requires_cryptsetup_2_8_1_when_the_data_volume_is_on() -> None:
    text = (SEALED / "build-guest.sh").read_text()
    assert 'if [ "$DATA_GIB" != 0 ]; then' in text
    assert 'chroot "$R" cryptsetup --version' in text and "(2,8,1)" in text
    assert text.index('CRYPTVER=$(chroot "$R" cryptsetup --version') < text.index("# ---------------------------------------------------------------- 2. kernel out")


# ---------------------------------------------------------------- workspace create answer (Finding 4)

from cathedral.sandbox_workspaces import LocalCopier, WorkspaceStore, workspace_persistence  # noqa: E402


def test_workspace_persistence_reads_the_sealed_data_status(tmp_path: Path) -> None:
    status = tmp_path / "sealed-data.status"
    assert workspace_persistence({}, status) is None, "no sealed data volume: the API claims nothing"
    env = {"ROOM_WORKSPACES_SOURCE": "/srv/sealed-data/workspaces"}
    assert workspace_persistence(env, status) is False, "a data-volume build with no status: not persistent"
    status.write_text(json.dumps({"persistent": True, "state": "open"}))
    assert workspace_persistence(env, status) is True
    status.write_text(json.dumps({"persistent": False, "state": "locked"}))
    assert workspace_persistence(env, status) is False


def test_workspace_create_answer_shows_persistent_only_when_known(tmp_path: Path) -> None:
    def store(name: str, persistent: bool | None) -> WorkspaceStore:
        root = tmp_path / name
        root.mkdir()
        return WorkspaceStore(root, LocalCopier(), check_mount=False, persistent=persistent)

    assert store("a", False).create("owner", "w")["persistent"] is False
    assert store("b", True).create("owner", "w")["persistent"] is True
    assert "persistent" not in store("c", None).create("owner", "w"), "unsealed/unknown: no claim"


# ---------------------------------------------------------------- miner key durability (Finding 5)

def test_the_miner_internal_key_is_synced_before_and_after_the_rename() -> None:
    text = (SEALED / "guest-boot.sh").read_text()
    block = text[text.index("internal-api-key.tmp"):text.index('cat "$DATA/hotel/internal-api-key" > /run/room-api-key')]
    assert 'sync "$DATA/hotel/internal-api-key.tmp"' in block
    assert block.index('sync "$DATA/hotel/internal-api-key.tmp"') < block.index('mv "$DATA/hotel/internal-api-key.tmp"')
    assert 'sync "$DATA/hotel"' in block
    assert block.index('mv "$DATA/hotel/internal-api-key.tmp"') < block.index('sync "$DATA/hotel"')


def test_the_installer_adds_cryptsetup_to_the_host_packages_when_a_data_volume_is_on() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    assert '[ "${SEALED_DATA_GIB:-0}" = 0 ] || command -v cryptsetup' in text and "need+=(cryptsetup-bin)" in text
    assert text.index("need+=(cryptsetup-bin)") < text.index('apt-get install -y -q')
