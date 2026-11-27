#!/usr/bin/env python3
"""Build and check the sealed VM initrd (AB#999, VM runtime spec r3 section 5: "a second published
initrd from the same source, adding cryptsetup, e2fsprogs, the kernel module tree and the VM steps
of 7.2. The mode is fixed per artifact, never chosen by cmdline").

It is the VM sibling of room-kit/custom_guest_initrd.py and reuses its archive primitives
(static_elf, newc entries, the zstd frame rules) read-only. Differences:

- the executables are the Go mains (cmd/cathedral-vm-init as /init, cathedral-vm-attest and
  cathedral-vm) built here, twice, and four static C tools built by scripts/build_vm_initrd_tools.py;
- the archive also carries the kernel's module tree under usr/lib/modules/<release>/, each file
  pinned by sha256 in the closure (a module is not a static ELF, so only the digest applies);
- two generated files for the init: usr/lib/cathedral/vm-closure.json (the pinned digests) and
  usr/lib/cathedral/vm-modules.list (the boot modules in load order, dependencies first).

The closure is an independently reviewed input, never inferred from the archive. A closure with a
null digest is `unpinned`: `pin` prints the digests of a build for review, and `build` and `check`
refuse it. Nothing here extracts or executes an input file.

  build-vm-initrd.py pin   --closure C --module-dir GO_MODULE --tools DIR --modules DIR
  build-vm-initrd.py build --closure C --module-dir GO_MODULE --tools DIR --modules DIR --archive OUT
  build-vm-initrd.py check --closure C --archive A
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT))
import custom_guest_initrd as base  # noqa: E402

SCHEMA = "cathedral.vm.initrd-closure/v1"
MANIFEST_SCHEMA = "cathedral.vm.initrd-manifest/v1"
MAX_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 40000
MAX_CLOSURE_BYTES = 8 * 1024 * 1024
RELEASE_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[a-z0-9]+")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
MODULE_SUFFIX_RE = re.compile(r"\.ko(\.zst|\.xz|\.gz)?$")
CLOSURE_PATH = "usr/lib/cathedral/vm-closure.json"
MODULES_LIST_PATH = "usr/lib/cathedral/vm-modules.list"
# A binary built with `-tags vmcuttest` (the disk package's cut hook) carries the tag in its Go
# build info. No executable in a published initrd may contain it.
CUT_HOOK_MARKER = b"vmcuttest"
EXEC_MODE = stat.S_IFREG | 0o755
FILE_MODE = stat.S_IFREG | 0o644
DIR_MODE = stat.S_IFDIR | 0o755


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---- closure --------------------------------------------------------------------------------

def _unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate closure key")
        out[key] = value
    return out


def load_closure(path: Path) -> dict:
    return parse_closure(base.read_bounded(path, MAX_CLOSURE_BYTES))


def parse_closure(raw: bytes) -> dict:
    closure = json.loads(raw, object_pairs_hook=_unique)
    check_closure_shape(closure)
    return closure


def check_closure_shape(closure: dict) -> None:
    require(isinstance(closure, dict) and closure.get("schema") == SCHEMA, "not a VM initrd closure")
    require(set(closure) == {"schema", "status", "kernel_release", "boot_modules", "go_mains", "static_tools",
                             "executables", "modules"}, "closure members differ from the schema")
    require(closure["status"] in ("unpinned", "pinned"), "closure status")
    release = closure["kernel_release"]
    require(isinstance(release, str) and (release == "" and closure["status"] == "unpinned"
                                          or RELEASE_RE.fullmatch(release) is not None), "kernel_release")
    for key in ("boot_modules", "static_tools"):
        require(isinstance(closure[key], list) and len(set(closure[key])) == len(closure[key]), key)
    require(all(isinstance(n, str) and re.fullmatch(r"[A-Za-z0-9_.+-]+", n) for n in closure["boot_modules"]),
            "boot module names")
    require(isinstance(closure["go_mains"], dict) and "init" in closure["go_mains"], "go_mains needs init")
    for name, package in closure["go_mains"].items():
        require(isinstance(package, str) and re.fullmatch(r"\./(cmd|testdata)/[A-Za-z0-9/-]+", package), "go main package")
        require(name == "init" or re.fullmatch(r"usr/lib/cathedral/[A-Za-z0-9_.+-]+", name), "go main path")
    exes = closure["executables"]
    require(isinstance(exes, dict) and 0 < len(exes) <= 64 and "init" in exes, "executables")
    require(set(exes) == set(closure["go_mains"]) | set(closure["static_tools"]), "executables are the mains and tools")
    for name in exes:
        require(base.valid_path(name) and (name == "init" or re.fullmatch(r"usr/lib/cathedral/[A-Za-z0-9_.+-]+", name)),
                "executable path")
    mods = closure["modules"]
    require(isinstance(mods, dict) and len(mods) <= MAX_ENTRIES, "modules")
    prefix = f"usr/lib/modules/{release}/"
    for name in mods:
        require(isinstance(name, str) and base.valid_path(name) and name.startswith(prefix), "module path")
    if closure["status"] == "pinned":
        require(release != "" and (prefix + "modules.dep") in mods, "a pinned closure lists modules.dep")


def require_pinned(closure: dict) -> None:
    require(closure["status"] == "pinned", "the closure is unpinned: run `pin` and review its digests first")
    for table in (closure["executables"], closure["modules"]):
        for name, digest in table.items():
            require(isinstance(digest, str) and HEX64_RE.fullmatch(digest) is not None, f"unpinned digest: {name}")


def all_paths(closure: dict) -> set[str]:
    return set(closure["executables"]) | set(closure["modules"]) | {CLOSURE_PATH, MODULES_LIST_PATH}


# ---- generated files ------------------------------------------------------------------------

def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def parse_dep(text: str) -> dict[str, list[str]]:
    out = {}
    for line in text.splitlines():
        if not line:
            continue
        name, _, deps = line.partition(":")
        require(name not in out, "duplicate modules.dep entry")
        out[name] = deps.split()
    return out


def module_key(path: str) -> str:
    return MODULE_SUFFIX_RE.sub("", path.rsplit("/", 1)[-1]).replace("-", "_")


def load_order(closure: dict, dep_text: str, builtin_text: str) -> list[str]:
    """The boot modules' files in load order, each after its dependencies. A module the kernel has
    built in (modules.builtin) needs no file. A name in neither is a refusal."""
    dep = parse_dep(dep_text)
    by_name = {}
    for path in dep:
        by_name.setdefault(module_key(path), path)
    builtin = {module_key(line) for line in builtin_text.splitlines() if line}
    order: list[str] = []
    seen: set[str] = set()

    def visit(path: str, stack: tuple = ()) -> None:
        require(path not in stack, "modules.dep has a cycle")
        require(path in dep, f"modules.dep has no entry for {path}")
        if path in seen:
            return
        for d in dep[path]:
            visit(d, stack + (path,))
        seen.add(path)
        order.append(path)

    for name in closure["boot_modules"]:
        key = name.replace("-", "_")
        if key in by_name:
            visit(by_name[key])
        else:
            require(key in builtin, f"boot module {name} is neither a module file nor built in")
    return order


def generated_files(closure: dict, modules_dep: bytes, modules_builtin: bytes) -> dict[str, bytes]:
    prefix = f"usr/lib/modules/{closure['kernel_release']}/"
    order = load_order(closure, modules_dep.decode("ascii"), modules_builtin.decode("ascii"))
    for rel in order:
        require(prefix + rel in closure["modules"], f"boot module file {rel} is not in the closure")
    listing = "".join(f"{prefix}{rel}\n" for rel in order).encode("ascii")
    manifest = canonical({"schema": MANIFEST_SCHEMA, "kernel_release": closure["kernel_release"],
                          "executables": closure["executables"], "boot_modules": closure["boot_modules"]})
    return {CLOSURE_PATH: manifest, MODULES_LIST_PATH: listing}


# ---- archive --------------------------------------------------------------------------------

def tree_parents(names: set[str]) -> set[str]:
    return base.parents(names)


def build_raw(files: dict[str, bytes], closure: dict) -> bytes:
    check_closure_shape(closure)
    require_pinned(closure)
    release = closure["kernel_release"]
    prefix = f"usr/lib/modules/{release}/"
    expected_inputs = set(closure["executables"]) | set(closure["modules"])
    require(set(files) == expected_inputs, "input files differ from the pinned closure")
    gen = generated_files(closure, files[prefix + "modules.dep"], files.get(prefix + "modules.builtin", b""))
    everything = {**files, **gen}
    dirs = tree_parents(set(everything))
    require(not dirs.intersection(everything), "a file is also a parent directory")
    require(sum(map(len, everything.values())) <= MAX_BYTES, "initrd exceeds the size limit")
    chunks = []
    for ino, name in enumerate(sorted(set(everything) | dirs), 1):
        if name in dirs:
            chunks.append(base.entry(name, DIR_MODE, b"", ino))
        elif name in closure["executables"]:
            data = everything[name]
            require(sha256_hex(data) == closure["executables"][name], f"closure hash mismatch: {name}")
            base.static_elf(data)
            require(CUT_HOOK_MARKER not in data, f"{name} was built with the vmcuttest hook")
            chunks.append(base.entry(name, EXEC_MODE, data, ino))
        else:
            data = everything[name]
            if name in closure["modules"]:
                require(sha256_hex(data) == closure["modules"][name], f"closure hash mismatch: {name}")
            chunks.append(base.entry(name, FILE_MODE, data, ino))
    chunks.append(base.entry("TRAILER!!!", 0, b"", 0))
    raw = b"".join(chunks)
    verify_raw(raw, closure)
    return raw


def verify_raw(raw: bytes, closure: dict) -> dict[str, str]:
    check_closure_shape(closure)
    require_pinned(closure)
    require(len(raw) <= MAX_BYTES, "initrd exceeds the size limit")
    expected = all_paths(closure)
    expected_dirs = tree_parents(expected)
    offset, seen, files, inodes = 0, set(), {}, set()
    while True:
        header = base.region(raw, offset, 110)
        require(header[:6] == b"070701" and re.fullmatch(b"[0-9a-fA-F]{104}", header[6:]) is not None,
                "not a newc header")
        values = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        ino, mode, uid, gid, nlink, mtime, size, devmaj, devmin, rmaj, rmin, namesize, check = values
        require(1 < namesize <= 512, "invalid archive name size")
        start = offset + 110
        name_raw = base.region(raw, start, namesize)
        require(name_raw[-1:] == b"\0" and b"\0" not in name_raw[:-1], "invalid archive name")
        try:
            name = name_raw[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII archive name") from exc
        after_name = (start + namesize + 3) & ~3
        require(not any(base.region(raw, start + namesize, after_name - start - namesize)), "nonzero name padding")
        data = base.region(raw, after_name, size)
        offset = (after_name + size + 3) & ~3
        require(not any(base.region(raw, after_name + size, offset - after_name - size)), "nonzero data padding")
        require((uid, gid, nlink, mtime, devmaj, devmin, rmaj, rmin, check) == (0, 0, 1, 0, 0, 0, 0, 0, 0),
                "noncanonical ownership/link/metadata")
        if name == "TRAILER!!!":
            require(mode == 0 and size == 0 and ino == 0, "invalid trailer")
            require(offset == len(raw), "data after trailer")
            break
        require(base.valid_path(name) and name not in seen, "duplicate or unsafe archive path")
        require(ino > 0 and ino not in inodes, "duplicate archive inode")
        inodes.add(ino)
        require(len(seen) < MAX_ENTRIES + 64, "too many archive entries")
        require(base.parents({name}).issubset(seen), "parent directory must precede file")
        seen.add(name)
        if mode == DIR_MODE:
            require(name in expected_dirs and size == 0, "unexpected directory")
        elif name in closure["executables"]:
            require(mode == EXEC_MODE, "executable mode")
            require(sha256_hex(data) == closure["executables"][name], f"closure hash mismatch: {name}")
            base.static_elf(data)
            require(CUT_HOOK_MARKER not in data, f"{name} was built with the vmcuttest hook")
            files[name] = data
        elif name in expected:
            require(mode == FILE_MODE, "file mode")
            if name in closure["modules"]:
                require(sha256_hex(data) == closure["modules"][name], f"closure hash mismatch: {name}")
            files[name] = data
        else:
            raise ValueError("unlisted file, special file or invalid mode")
    require(seen == expected | expected_dirs, "incomplete closure: a listed file is missing")
    prefix = f"usr/lib/modules/{closure['kernel_release']}/"
    gen = generated_files(closure, files[prefix + "modules.dep"], files.get(prefix + "modules.builtin", b""))
    for name, data in gen.items():
        require(files[name] == data, f"{name} differs from what the closure derives")
    return {name: sha256_hex(data) for name, data in files.items()}


def pack(raw: bytes, closure: dict) -> bytes:
    verify_raw(raw, closure)
    zstd = base.zstd_module()
    return zstd.ZstdCompressor(level=19, threads=0, write_checksum=True, write_content_size=True,
                              write_dict_id=False).compress(raw)


def unpack(packed: bytes, closure: dict) -> bytes:
    require(len(packed) <= MAX_BYTES, "compressed initrd exceeds the size limit")
    zstd = base.zstd_module()
    require(packed[:4] == b"\x28\xb5\x2f\xfd", "not a standard zstd frame")
    info = zstd.get_frame_parameters(packed)
    require(0 < info.content_size <= MAX_BYTES and info.window_size <= MAX_BYTES and info.dict_id == 0
            and info.has_checksum, "invalid or oversized zstd frame")
    raw = zstd.ZstdDecompressor(max_window_size=MAX_BYTES // 1024).decompress(
        packed, max_output_size=MAX_BYTES, allow_extra_data=False)
    verify_raw(raw, closure)
    return raw


# ---- inputs ---------------------------------------------------------------------------------

def go_env() -> dict:
    """A clean environment: no caller GOFLAGS, tags, compiler or linker overrides."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GO", "CGO_", "CC", "CXX")) and k not in ("CFLAGS", "LDFLAGS", "CPPFLAGS")}
    for key in ("GOCACHE", "GOMODCACHE", "GOPATH", "GOROOT"):
        if key in os.environ:
            env[key] = os.environ[key]
    env.update({"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "-mod=readonly",
                "GOTOOLCHAIN": "local", "LC_ALL": "C", "TZ": "UTC"})
    return env


def go_build(module_dir: Path, package: str, out: Path) -> bytes:
    # No -tags: the vmcuttest hook is compiled in only by an explicit tag, so none here. -trimpath and
    # an empty buildid keep the bytes independent of the build directory.
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-tags=", "-ldflags=-s -w -buildid=",
                    "-o", str(out), package], cwd=module_dir, env=go_env(), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return out.read_bytes()


def build_go_mains(closure: dict, module_dir: Path) -> dict[str, bytes]:
    """Each main is built twice, in different directories, and the bytes must be identical."""
    result = {}
    with tempfile.TemporaryDirectory(prefix="vm-initrd-go-") as tmp:
        for name, package in sorted(closure["go_mains"].items()):
            outs = []
            for label in ("a", "b"):
                (Path(tmp) / label).mkdir(exist_ok=True)
                outs.append(Path(tmp) / label / name.replace("/", "_"))
            first, second = go_build(module_dir, package, outs[0]), go_build(module_dir, package, outs[1])
            require(first == second, f"{name}: two builds differ")
            base.static_elf(first)
            require(CUT_HOOK_MARKER not in first, f"{name} contains the vmcuttest hook")
            result[name] = first
    return result


def read_tools(closure: dict, tools: Path) -> dict[str, bytes]:
    result = {}
    for name in closure["static_tools"]:
        path = tools / name.rsplit("/", 1)[-1]
        require(path.is_file() and not path.is_symlink(), f"static tool missing: {path.name}")
        result[name] = base.read_bounded(path, 64 * 1024 * 1024)
    return result


def read_modules(closure: dict, modules: Path) -> dict[str, bytes]:
    """The module tree of one release. Never follows a link; the listed set must match exactly when
    the closure is pinned."""
    release = closure["kernel_release"]
    require(RELEASE_RE.fullmatch(release) is not None, "the closure names no kernel release")
    result, total = {}, 0
    require(modules.is_dir() and not modules.is_symlink(), "module directory")
    for path in sorted(modules.rglob("*")):
        mode = path.lstat().st_mode
        require(not path.is_symlink(), f"module tree has a link: {path.name}")
        if stat.S_ISDIR(mode):
            continue
        require(stat.S_ISREG(mode), "module tree has a special file")
        name = f"usr/lib/modules/{release}/" + path.relative_to(modules).as_posix()
        require(base.valid_path(name), f"unsafe module path {name}")
        data = base.read_bounded(path, 64 * 1024 * 1024)
        total += len(data)
        require(total <= MAX_BYTES and len(result) < MAX_ENTRIES, "module tree exceeds the limit")
        result[name] = data
    return result


def gather(closure: dict, module_dir: Path, tools: Path, modules: Path) -> dict[str, bytes]:
    files = {**build_go_mains(closure, module_dir), **read_tools(closure, tools)}
    files.update(read_modules(closure, modules))
    return files


def pinned_view(closure: dict, files: dict[str, bytes]) -> dict:
    pinned = json.loads(json.dumps(closure))
    pinned["status"] = "pinned"
    pinned["executables"] = {n: sha256_hex(files[n]) for n in sorted(closure["executables"])}
    pinned["modules"] = {n: sha256_hex(d) for n, d in sorted(files.items()) if n not in closure["executables"]}
    return pinned


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("pin", "build", "check"))
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--module-dir", type=Path, help="the custom-guest Go module (room-kit/custom-guest)")
    parser.add_argument("--tools", type=Path, help="directory of the four static C tools")
    parser.add_argument("--modules", type=Path, help="the kernel's module tree for the release")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args(argv)
    closure = load_closure(args.closure)
    if args.action == "check":
        require(args.archive is not None, "check needs --archive")
        packed = base.read_bounded(args.archive, MAX_BYTES)
        unpack(packed, closure)
    else:
        require(args.module_dir and args.tools and args.modules, "this action needs --module-dir, --tools and --modules")
        files = gather(closure, args.module_dir, args.tools, args.modules)
        if args.action == "pin":
            print(json.dumps(pinned_view(closure, files), indent=2, sort_keys=True))
            return 0
        require(args.archive is not None and not args.archive.exists(), "build needs a new --archive path")
        packed = pack(build_raw(files, closure), closure)
        with args.archive.open("xb") as out:
            out.write(packed)
    print(json.dumps({"sha256": hashlib.sha256(packed).hexdigest(), "bytes": len(packed),
                      "kernel_release": closure["kernel_release"], "status": "archive_verified",
                      "boot_verified": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"error": "vm_initrd_failed", "reason": str(exc)}), file=sys.stderr)
        sys.exit(1)
