#!/usr/bin/env python3
"""Build the four static C tools of the sealed VM initrd (AB#999, VM runtime spec r3 section 5):
cryptsetup 2.8.4 (LUKS), veritysetup 2.8.4 (dm-verity, same source), and mke2fs and resize2fs from
e2fsprogs 1.47.3.

Every source and development package is pinned by URL and sha256 in the adjacent
vm_initrd_tools_inputs.json. The cryptsetup, LVM2 and Ubuntu package pins are those of
custom_guest_verity_inputs.json; the e2fsprogs source is new. `fetch` downloads into an empty
directory and checks each digest; `build` takes a directory that holds exactly the pinned files
and downloads nothing. Output is built twice in separate directories and must be identical; each
tool must be a static ELF with no interpreter and no shared library, and print its pinned version.

  build_vm_initrd_tools.py fetch --inputs NEW_EMPTY_DIR
  build_vm_initrd_tools.py build --inputs PINNED_DIR --output NEW_DIR --log NEW_FILE
  build_vm_initrd_tools.py lock-check            (the lock's shape; no network)

This is a toolchain-specific reproducibility check, not a hermetic bootstrap, and not a boot proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "room-kit"))
from custom_guest_initrd import static_elf  # noqa: E402

LOCK = Path(__file__).with_name("vm_initrd_tools_inputs.json")
SCHEMA = "cathedral.vm.initrd-tools-inputs/v1"
SOURCE_DATE_EPOCH = "1795770000"
HEX64 = re.compile(r"[0-9a-f]{64}")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+~-]{0,127}")
VERSIONS = {  # the first line of `<tool> --version` must start with this
    "cryptsetup": "cryptsetup 2.8.4",
    "veritysetup": "veritysetup 2.8.4",
}
E2FS_VERSION = "1.47.3"
SOURCES = ("LVM2.2.03.31.tgz", "cryptsetup-2.8.4.tar.xz", f"e2fsprogs-{E2FS_VERSION}.tar.xz")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_lock() -> dict:
    doc = json.loads(LOCK.read_text(), object_pairs_hook=_unique)
    if doc.get("schema") != SCHEMA or set(doc) != {"schema", "note", "files"}:
        raise ValueError("lock schema")
    files = doc["files"]
    for name in SOURCES:
        if name not in files:
            raise ValueError(f"lock lacks {name}")
    for name, item in files.items():
        if not NAME_RE.fullmatch(name) or set(item) != {"sha256", "url"} or not HEX64.fullmatch(item["sha256"]):
            raise ValueError(f"lock entry {name}")
        if not re.fullmatch(r"https?://[A-Za-z0-9.-]+/[A-Za-z0-9._~%+/-]+", item["url"]):
            raise ValueError(f"lock url {name}")
    return files


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate lock key")
        out[key] = value
    return out


def fetch(target: Path) -> None:
    files = load_lock()
    if target.exists() and any(target.iterdir()):
        raise SystemExit("--inputs must be a new or empty directory")
    target.mkdir(parents=True, exist_ok=True)
    for name, item in files.items():
        for attempt in range(4):  # a reset connection is not a reason to fail; the digest decides
            try:
                with urllib.request.urlopen(item["url"], timeout=120) as response:
                    data = response.read(512 * 1024 * 1024)
                break
            except OSError as exc:
                if attempt == 3:
                    raise SystemExit(f"cannot download {name}: {exc}")
                time.sleep(5 * (attempt + 1))
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise SystemExit(f"digest mismatch after download: {name} from {item['url']}")
        (target / name).write_bytes(data)
        print(f"fetched {name}", file=sys.stderr)


def run(argv, cwd, env, log):
    subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=log, check=True)


def clean_env(work: Path) -> dict:
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "ARFLAGS": "crD"})
    # Do not inherit caller compiler, linker or configure overrides.
    for key in ("CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "LIBS", "PKG_CONFIG_PATH",
                "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR", "CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH",
                "LD_LIBRARY_PATH", "CONFIG_SITE", "MAKEFLAGS"):
        env.pop(key, None)
    env["CONFIG_SITE"] = "/dev/null"
    return env


def build(inputs: Path, work: Path, log) -> dict[str, Path]:
    env = clean_env(work)
    stage = work / "deps"
    stage.mkdir()
    for path in sorted(inputs.glob("*.deb")):
        run(["dpkg-deb", "-x", str(path), str(stage)], work, env, log)
    for name in SOURCES:
        run(["tar", "-xf", str(inputs / name)], work, env, log)
    libs = stage / "usr/lib/x86_64-linux-gnu"
    include = stage / "usr/include"
    gcc_include = subprocess.check_output(["gcc", "-print-file-name=include"], env=env, text=True).strip()
    # Pin packaged headers and libraries, and keep scratch paths out of the output bytes.
    env["CFLAGS"] = (f"-O2 -ffile-prefix-map={work}=/usr/src/cathedral-vm-tools -nostdinc -isystem {gcc_include} "
                     f"-isystem {include / 'x86_64-linux-gnu'} -isystem {include}")
    env["LDFLAGS"] = f"-L{libs}"
    env["LIBS"] = "-lm"
    env["PKG_CONFIG_LIBDIR"] = str(libs / "pkgconfig")
    env["PKG_CONFIG_SYSROOT_DIR"] = str(stage)

    dm = work / "LVM2.2.03.31"
    run(["./configure", "--prefix=/usr", "--enable-static_link", "--disable-readline", "--disable-selinux",
         "--without-systemd", "--without-udev", "--disable-systemd-journal"], dm, env, log)
    run(["make", "-j2", "device-mapper"], dm, env, log)
    shutil.copyfile(dm / "libdm/ioctl/libdevmapper.a", libs / "libdevmapper.a")
    shutil.copyfile(dm / "libdm/libdevmapper.pc", libs / "pkgconfig/devmapper.pc")

    crypt = work / "cryptsetup-2.8.4"
    run(["./configure", "--enable-static", "--disable-shared", "--enable-static-cryptsetup", "--disable-udev",
         "--disable-ssh-token", "--disable-external-tokens", "--disable-blkid", "--disable-kernel_crypto",
         "--disable-luks2-reencryption", "--disable-nls", "--disable-asciidoc", "--with-crypto_backend=openssl"],
        crypt, env, log)
    run(["make", "-j2", "veritysetup.static", "cryptsetup.static"], crypt, env, log)

    e2 = work / f"e2fsprogs-{E2FS_VERSION}"
    e2env = dict(env)
    e2env["LDFLAGS"] = f"-static -L{libs}"  # the pinned libc.a, not the image's
    e2env.pop("LIBS", None)
    # e2fsprogs builds its own bundled libuuid, libblkid and libcom_err (the default; --disable-libuuid
    # would ask for the system ones). The C library and compiler headers are still the pinned ones.
    run(["./configure", "--disable-nls", "--disable-elf-shlibs", "--disable-bsd-shlibs", "--disable-uuidd",
         "--disable-fuse2fs", "--disable-defrag", "--disable-e2initrd-helper", "--disable-fsck"],
        e2, e2env, log)
    run(["make", "-j2", "libs"], e2, e2env, log)
    run(["make", "-j2", "-C", "misc", "mke2fs"], e2, e2env, log)
    run(["make", "-j2", "-C", "resize", "resize2fs"], e2, e2env, log)

    out = work / "out"
    out.mkdir()
    built = {"cryptsetup": crypt / "cryptsetup.static", "veritysetup": crypt / "veritysetup.static",
             "mke2fs": e2 / "misc/mke2fs", "resize2fs": e2 / "resize/resize2fs"}
    result = {}
    for name, path in built.items():
        data = path.read_bytes()
        static_elf(data)
        dest = out / name
        dest.write_bytes(data)
        dest.chmod(0o755)
        result[name] = dest
    check_versions(result, env)
    return result


def check_versions(tools: dict[str, Path], env: dict) -> None:
    for name, prefix in VERSIONS.items():
        text = subprocess.run([str(tools[name]), "--version"], env=env, capture_output=True, text=True).stdout
        if not text.startswith(prefix + " "):
            raise ValueError(f"unexpected {name} version: {text[:80]!r}")
    # mke2fs and resize2fs print their version on stderr.
    for name in ("mke2fs", "resize2fs"):
        probe = subprocess.run([str(tools[name]), "-V"], env=env, capture_output=True, text=True)
        if f"{E2FS_VERSION} " not in (probe.stderr + probe.stdout).split("\n")[0] + " ":
            raise ValueError(f"unexpected {name} version: {(probe.stderr + probe.stdout)[:80]!r}")


def build_all(inputs: Path, output: Path, log_path: Path) -> dict:
    files = load_lock()
    inputs = inputs.resolve(strict=True)
    if set(p.name for p in inputs.iterdir()) != set(files):
        raise SystemExit("the input directory must contain exactly the pinned files")
    for name, item in files.items():
        path = inputs / name
        if path.is_symlink() or not path.is_file() or digest(path) != item["sha256"]:
            raise SystemExit(f"input digest mismatch: {name}")
    gcc = subprocess.check_output(["gcc", "-dumpfullversion"], text=True).strip()
    if not gcc.startswith("15."):
        raise SystemExit(f"gcc 15 is required, found {gcc}")
    make = subprocess.check_output(["make", "--version"], text=True).splitlines()[0]
    if output.exists() or output.is_symlink() or log_path.exists():
        raise SystemExit("output and log must not exist")
    with log_path.open("x") as log, tempfile.TemporaryDirectory(prefix="cathedral-vm-tools-") as tmp:
        work = Path(tmp)
        snapshot = work / "inputs"
        snapshot.mkdir()
        for name, item in files.items():
            shutil.copyfile(inputs / name, snapshot / name)
            if digest(snapshot / name) != item["sha256"]:
                raise SystemExit(f"input changed during copy: {name}")
        builds = []
        for label in ("first", "second"):
            directory = work / label
            directory.mkdir()
            builds.append(build(snapshot, directory, log))
        for name in builds[0]:
            if builds[0][name].read_bytes() != builds[1][name].read_bytes():
                raise SystemExit(f"two builds of {name} differ")
        output.mkdir()
        for name, path in builds[0].items():
            shutil.copyfile(path, output / name)
            (output / name).chmod(0o755)
    return {"output": str(output), "double_build_identical": True, "static_elf": True, "gcc": gcc, "make": make,
            "sha256": {name: digest(output / name) for name in sorted(builds[0])},
            "inputs_lock_sha256": digest(LOCK), "boot_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("fetch", "build", "lock-check"))
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()
    if args.action == "lock-check":
        print(json.dumps({"files": len(load_lock()), "lock_sha256": digest(LOCK)}))
    elif args.action == "fetch":
        if not args.inputs:
            parser.error("fetch needs --inputs")
        fetch(args.inputs)
    else:
        if not (args.inputs and args.output and args.log):
            parser.error("build needs --inputs, --output and --log")
        print(json.dumps(build_all(args.inputs, args.output, args.log), sort_keys=True))


if __name__ == "__main__":
    main()
