"""Archive rejection tests: no guest boot or SNP hardware claim."""
import hashlib
import json
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path

import pytest
import zstandard

KIT = Path(__file__).resolve().parents[1] / "room-kit"
sys.path.insert(0, str(KIT))
import custom_guest_initrd as archive


def elf(extra_type=None, dynamic_tag=0):
    count = 1 + (extra_type is not None)
    payload_offset = 64 + count * 56
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                         2, 62, 1, 0x400000 + payload_offset, 64, 0, 0, 64, 56, count, 0, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0, payload_offset + 16,
                     payload_offset + 16, 4096)
    if extra_type is not None:
        ph += struct.pack("<IIQQQQQQ", extra_type, 4, payload_offset, 0, 0, 16, 16, 8)
    return header + ph + struct.pack("<qQ", dynamic_tag, 0)


def inputs():
    files = {"init": elf(), "usr/lib/cathedral/probe": elf()}
    return files, {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}


def raw_records(rows):
    return b"".join(archive.entry(n, m, d, i) for i, (n, m, d) in enumerate(rows, 1)) + archive.entry("TRAILER!!!", 0, b"", 0)


def records():
    return [("init", stat.S_IFREG | 0o755, elf()), ("usr", stat.S_IFDIR | 0o755, b""),
            ("usr/lib", stat.S_IFDIR | 0o755, b""),
            ("usr/lib/cathedral", stat.S_IFDIR | 0o755, b""),
            ("usr/lib/cathedral/probe", stat.S_IFREG | 0o755, elf())]


def test_deterministic_roundtrip_and_standard_cpio_reader():
    files, closure = inputs()
    raw = archive.build_raw(files, closure)
    assert archive.build_raw(dict(reversed(list(files.items()))), closure) == raw
    packed = archive.pack(raw, closure)
    assert archive.pack(raw, closure) == packed
    assert archive.unpack(packed, closure) == raw
    assert archive.verify_raw(raw, closure) == closure
    if shutil.which("cpio"):
        result = subprocess.run(["cpio", "-it", "--quiet"], input=raw, capture_output=True, check=True)
        assert result.stdout.decode().splitlines() == [r[0] for r in records()]


@pytest.mark.parametrize("change", ["duplicate", "absolute", "dotdot", "dot", "symlink", "device",
                                    "fifo", "unlisted", "missing", "setuid", "nonexec_init", "parent_file"])
def test_archive_rejects_unsafe_layout(change):
    _, closure = inputs()
    rows = records()
    n, m, d = rows[0]
    if change == "duplicate":
        rows.insert(1, rows[0])
    elif change in ("absolute", "dotdot", "dot"):
        rows[0] = ({"absolute": "/init", "dotdot": "../init", "dot": "./init"}[change], m, d)
    elif change in ("symlink", "device", "fifo"):
        rows[0] = (n, {"symlink": stat.S_IFLNK, "device": stat.S_IFCHR, "fifo": stat.S_IFIFO}[change] | 0o755, d)
    elif change == "unlisted":
        rows.append(("shell", m, d))
    elif change == "missing":
        rows.pop()
    elif change == "setuid":
        rows[0] = (n, m | 0o4000, d)
    elif change == "nonexec_init":
        rows[0] = (n, stat.S_IFREG | 0o644, d)
    else:
        rows[1] = ("usr", stat.S_IFREG | 0o755, d)
    with pytest.raises(ValueError):
        archive.verify_raw(raw_records(rows), closure)


@pytest.mark.parametrize("field,value", [(0, 0), (2, 1), (3, 1), (4, 2), (5, 1), (7, 1), (8, 1), (9, 1), (10, 1), (12, 1)])
def test_archive_rejects_noncanonical_metadata(field, value):
    files, closure = inputs()
    raw = bytearray(archive.build_raw(files, closure))
    raw[6 + 8 * field:14 + 8 * field] = f"{value:08x}".encode()
    with pytest.raises(ValueError):
        archive.verify_raw(bytes(raw), closure)


@pytest.mark.parametrize("tail", [b"\0", b"junk", archive.entry("TRAILER!!!", 0, b"", 0)])
def test_no_bytes_or_second_archive_after_trailer(tail):
    files, closure = inputs()
    with pytest.raises(ValueError, match="data after trailer"):
        archive.verify_raw(archive.build_raw(files, closure) + tail, closure)


def test_every_truncation_rejected():
    files, closure = inputs()
    raw = archive.build_raw(files, closure)
    for length in range(len(raw)):
        with pytest.raises(ValueError):
            archive.verify_raw(raw[:length], closure)


@pytest.mark.parametrize("kind", ["hash", "interp", "needed", "arch", "class", "entry", "ph_bounds", "unterminated"])
def test_elf_and_pinned_digest_refuse(kind):
    files, closure = inputs()
    data = bytearray(elf())
    if kind == "interp":
        data = elf(3)
    elif kind == "needed":
        data = elf(2, 1)
    elif kind == "unterminated":
        data = elf(2, 2)
    elif kind == "arch":
        struct.pack_into("<H", data, 18, 183)
    elif kind == "class":
        data[4] = 1
    elif kind == "entry":
        struct.pack_into("<Q", data, 24, 0)
    elif kind == "ph_bounds":
        struct.pack_into("<Q", data, 32, 2**64 - 1)
    else:
        data[-1] ^= 1
    files["init"] = bytes(data)
    if kind != "hash":
        closure["init"] = hashlib.sha256(data).hexdigest()
    with pytest.raises(ValueError):
        archive.build_raw(files, closure)
    rows = records()
    rows[0] = ("init", stat.S_IFREG | 0o755, bytes(data))
    with pytest.raises(ValueError):
        archive.verify_raw(raw_records(rows), closure)


@pytest.mark.parametrize("kind", ["second_frame", "trailing", "unknown_size", "oversized", "no_checksum", "truncated"])
def test_zstd_strict_single_bounded_frame(kind, monkeypatch):
    files, closure = inputs()
    raw = archive.build_raw(files, closure)
    packed = archive.pack(raw, closure)
    if kind == "second_frame":
        packed += packed
    elif kind == "trailing":
        packed += b"\0"
    elif kind == "unknown_size":
        packed = zstandard.ZstdCompressor(write_content_size=False, write_checksum=True).compress(raw)
    elif kind == "no_checksum":
        packed = zstandard.ZstdCompressor(write_checksum=False).compress(raw)
    elif kind == "truncated":
        packed = packed[:-1]
    else:
        monkeypatch.setattr(archive, "MAX_BYTES", len(raw) - 1)
    with pytest.raises((ValueError, zstandard.ZstdError)):
        archive.unpack(packed, closure)


def test_real_static_binary_and_dynamic_binary(tmp_path):
    if not shutil.which("cc"):
        pytest.skip("C compiler unavailable")
    source = tmp_path / "main.c"
    source.write_text("int main(void) { return 0; }\n")
    binary = tmp_path / "init"
    result = subprocess.run(["cc", "-static", "-o", str(binary), str(source)], capture_output=True, check=False)
    if result.returncode:
        pytest.skip("static libc toolchain unavailable")
    archive.static_elf(binary.read_bytes())
    subprocess.run([str(binary)], check=True)
    subprocess.run(["cc", "-o", str(binary), str(source)], check=True)
    with pytest.raises(ValueError, match="PT_INTERP"):
        archive.static_elf(binary.read_bytes())


def test_cli_reproducible_normalized_metadata_and_no_overwrite(tmp_path):
    files, closure = inputs()
    root = tmp_path / "root"
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
    pinned = tmp_path / "closure.json"
    pinned.write_text(json.dumps(closure))
    command = [sys.executable, str(KIT / "custom_guest_initrd.py")]
    outputs = []
    for number in range(2):
        output = tmp_path / f"{number}.zst"
        built = subprocess.run(command + ["build", "--root", str(root), "--closure", str(pinned),
                                           "--archive", str(output)], capture_output=True, check=True)
        checked = subprocess.run(command + ["check", "--closure", str(pinned), "--archive", str(output)],
                                 capture_output=True, check=True)
        assert built.stdout == checked.stdout
        assert json.loads(checked.stdout)["boot_verified"] is False
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1]
    failed = subprocess.run(command + ["build", "--root", str(root), "--closure", str(pinned),
                                       "--archive", str(output)], capture_output=True, check=False)
    assert failed.returncode != 0
    assert output.read_bytes() == outputs[0]
    (root / "extra").symlink_to(root / "init")
    failed = subprocess.run(command + ["build", "--root", str(root), "--closure", str(pinned),
                                       "--archive", str(tmp_path / "bad.zst")], capture_output=True, check=False)
    assert failed.returncode != 0
    assert not (tmp_path / "bad.zst").exists()


def test_duplicate_closure_json_rejected(tmp_path):
    path = tmp_path / "closure.json"
    path.write_text('{"init":"' + "00" * 32 + '","init":"' + "11" * 32 + '"}')
    with pytest.raises(ValueError, match="duplicate"):
        archive.load_closure(path)
