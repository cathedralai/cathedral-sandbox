#!/usr/bin/env python3
"""Build/check the reference initrd. Never extract or execute input files.

This validates the measured archive and executable closure, not boot semantics.
The closure is an independently reviewed input, never inferred from the archive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import struct
from pathlib import Path

MAX_BYTES = 256 * 1024 * 1024
MAX_FILES = 128
ZSTD_VERSION = (1, 5, 7)
PY_ZSTD_VERSION = "0.25.0"


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def region(data: bytes, offset: int, size: int) -> bytes:
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset, "truncated input")
    return data[offset:offset + size]


def static_elf(data: bytes) -> None:
    """Require a bounded ELF64 little-endian x86 executable without a loader/dependencies."""
    header = struct.unpack("<16sHHIQQQIHHHHHH", region(data, 0, 64))
    ident, kind, machine, version, entry, phoff, _, _, ehsize, phsize, phnum, *_ = header
    require(ident[:7] == b"\x7fELF\x02\x01\x01" and kind in (2, 3)
            and machine == 62 and version == 1 and ehsize == 64, "not x86_64 ELF executable")
    require(phoff >= 64 and phsize == 56 and 0 < phnum <= 256, "invalid ELF program headers")
    region(data, phoff, phsize * phnum)
    executable_entry = False
    for i in range(phnum):
        ptype, flags, offset, vaddr, _, filesz, memsz, _ = struct.unpack(
            "<IIQQQQQQ", region(data, phoff + i * phsize, phsize))
        segment = region(data, offset, filesz)
        require(ptype != 3, "PT_INTERP forbidden")
        if ptype == 1:
            require(filesz <= memsz, "invalid ELF load segment")
            executable_entry |= bool(flags & 1 and vaddr <= entry < vaddr + filesz)
        if ptype == 2:
            require(filesz > 0 and filesz % 16 == 0, "invalid ELF dynamic segment")
            terminated = False
            for pos in range(0, filesz, 16):
                tag, _ = struct.unpack("<qQ", segment[pos:pos + 16])
                require(tag != 1, "DT_NEEDED forbidden")
                if tag == 0:
                    terminated = True
                    break
            require(terminated, "unterminated ELF dynamic segment")
    require(executable_entry, "ELF entry is not file-backed executable code")


def valid_path(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*", name)) and all(
        part not in (".", "..") for part in name.split("/"))


def closure_check(closure: dict) -> None:
    require(isinstance(closure, dict) and 0 < len(closure) <= MAX_FILES, "invalid closure")
    require("init" in closure, "closure missing init")
    for name, digest in closure.items():
        require(isinstance(name, str) and valid_path(name) and (
            name == "init" or re.fullmatch(r"usr/lib/cathedral/[A-Za-z0-9_.+-]+", name)),
            "closure executable outside permitted paths")
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                "invalid closure digest")


def parents(names: set[str]) -> set[str]:
    return {"/".join(parts[:i]) for name in names for parts in [name.split("/")]
            for i in range(1, len(parts))}


def entry(name: str, mode: int, data: bytes, ino: int) -> bytes:
    # newc: ino,mode,uid,gid,nlink,mtime,size,devmajor,devminor,rdevmajor,rdevminor,namesize,check.
    encoded = name.encode("ascii") + b"\0"
    fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
    result = b"070701" + b"".join(f"{v:08x}".encode() for v in fields) + encoded
    result += b"\0" * (-len(result) % 4)
    result += data
    return result + b"\0" * (-len(result) % 4)


def build_raw(files: dict[str, bytes], closure: dict[str, str]) -> bytes:
    closure_check(closure)
    require(set(files) == set(closure), "archive files differ from pinned closure")
    dirs = parents(set(files))
    require(not dirs.intersection(files), "file is also a parent directory")
    require(sum(map(len, files.values())) <= MAX_BYTES, "initrd exceeds size limit")
    chunks = []
    for ino, name in enumerate(sorted(set(files) | dirs), 1):
        if name in dirs:
            chunks.append(entry(name, stat.S_IFDIR | 0o755, b"", ino))
        else:
            require(hashlib.sha256(files[name]).hexdigest() == closure[name], "closure hash mismatch")
            static_elf(files[name])
            chunks.append(entry(name, stat.S_IFREG | 0o755, files[name], ino))
    chunks.append(entry("TRAILER!!!", 0, b"", 0))
    raw = b"".join(chunks)
    verify_raw(raw, closure)
    return raw


def verify_raw(raw: bytes, closure: dict[str, str]) -> dict[str, str]:
    closure_check(closure)
    require(len(raw) <= MAX_BYTES, "initrd exceeds size limit")
    offset = 0
    seen: set[str] = set()
    files = {}
    expected_dirs = parents(set(closure))
    inodes = set()
    while True:
        header = region(raw, offset, 110)
        require(header[:6] == b"070701" and re.fullmatch(b"[0-9a-fA-F]{104}", header[6:])
                is not None, "not a newc header")
        values = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        ino, mode, uid, gid, nlink, mtime, size, devmaj, devmin, rmaj, rmin, namesize, check = values
        require(1 < namesize <= 256, "invalid archive name size")
        start = offset + 110
        name_raw = region(raw, start, namesize)
        require(name_raw[-1:] == b"\0" and b"\0" not in name_raw[:-1], "invalid archive name")
        try:
            name = name_raw[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII archive name") from exc
        after_name = (start + namesize + 3) & ~3
        require(not any(region(raw, start + namesize, after_name - start - namesize)),
                "nonzero name padding")
        data = region(raw, after_name, size)
        offset = (after_name + size + 3) & ~3
        require(not any(region(raw, after_name + size, offset - after_name - size)),
                "nonzero data padding")
        require((uid, gid, nlink, mtime, devmaj, devmin, rmaj, rmin, check)
                == (0, 0, 1, 0, 0, 0, 0, 0, 0), "noncanonical ownership/link/metadata")
        if name == "TRAILER!!!":
            require(mode == 0 and size == 0 and ino == 0, "invalid trailer")
            require(offset == len(raw), "data after trailer")
            break
        require(valid_path(name) and name not in seen, "duplicate or unsafe archive path")
        require(ino > 0 and ino not in inodes, "duplicate archive inode")
        inodes.add(ino)
        require(len(seen) < MAX_FILES + 3, "too many archive entries")
        require(parents({name}).issubset(seen), "parent directory must precede file")
        seen.add(name)
        if mode == stat.S_IFDIR | 0o755:
            require(name in expected_dirs and size == 0, "unexpected directory")
        else:
            require(mode == stat.S_IFREG | 0o755 and name in closure,
                    "unlisted executable, special file or invalid mode")
            require(hashlib.sha256(data).hexdigest() == closure[name], "closure hash mismatch")
            static_elf(data)
            files[name] = closure[name]
    require(seen == set(closure) | expected_dirs, "incomplete executable closure")
    return files


def zstd_module():
    import zstandard
    require(zstandard.__version__ == PY_ZSTD_VERSION and zstandard.ZSTD_VERSION == ZSTD_VERSION,
            "reference builder needs python-zstandard 0.25.0 / libzstd 1.5.7")
    return zstandard


def pack(raw: bytes, closure: dict[str, str]) -> bytes:
    verify_raw(raw, closure)
    zstd = zstd_module()
    return zstd.ZstdCompressor(level=19, threads=0, write_checksum=True,
                              write_content_size=True, write_dict_id=False).compress(raw)


def unpack(packed: bytes, closure: dict[str, str]) -> bytes:
    require(len(packed) <= MAX_BYTES, "compressed initrd exceeds size limit")
    zstd = zstd_module()
    require(packed[:4] == b"\x28\xb5\x2f\xfd", "not a standard zstd frame")
    info = zstd.get_frame_parameters(packed)
    # Check BEFORE decompression: a frame's declared size otherwise overrides max_output_size.
    require(0 < info.content_size <= MAX_BYTES and info.window_size <= MAX_BYTES
            and info.dict_id == 0 and info.has_checksum, "invalid or oversized zstd frame")
    raw = zstd.ZstdDecompressor(max_window_size=MAX_BYTES // 1024).decompress(
        packed, max_output_size=MAX_BYTES, allow_extra_data=False)
    verify_raw(raw, closure)
    return raw


def read_bounded(path: Path, limit: int = MAX_BYTES) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "file exceeds size limit")
    return data


def load_closure(path: Path) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate closure key")
            result[key] = value
        return result
    result = json.loads(read_bounded(path, 32768), object_pairs_hook=unique)
    closure_check(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "check"))
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--root", type=Path, help="staging tree for build")
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    closure = load_closure(args.closure)
    if args.action == "build":
        require(args.root is not None and args.root.is_dir() and not args.root.is_symlink(),
                "build requires a real staging directory")
        allowed = set(closure) | parents(set(closure))
        files = {}
        # Never follow symlinks or package special files. The staging tree must be quiescent.
        for path in args.root.rglob("*"):
            name = path.relative_to(args.root).as_posix()
            mode = path.lstat().st_mode
            require(name in allowed and not path.is_symlink(), "unexpected staging entry")
            if name in closure:
                require(stat.S_ISREG(mode), "staging executable is not a regular file")
                files[name] = read_bounded(path)
                require(sum(map(len, files.values())) <= MAX_BYTES, "staging tree exceeds size limit")
            else:
                require(stat.S_ISDIR(mode), "staging parent is not a directory")
        packed = pack(build_raw(files, closure), closure)
        with args.archive.open("xb") as out:
            out.write(packed)
    else:
        packed = read_bounded(args.archive)
        unpack(packed, closure)
    print(json.dumps({"sha256": hashlib.sha256(packed).hexdigest(), "bytes": len(packed),
                      "closure": closure, "status": "archive_verified",
                      "boot_verified": False}, sort_keys=True))


if __name__ == "__main__":
    main()
