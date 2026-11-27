#!/usr/bin/env python3
"""Build the static reference verity helper (and optionally cryptsetup) from the adjacent pinned input lock.

cryptsetup is the same pinned 2.8.4 source and flags, static, for cathedral-data. It is never
the root's own cryptsetup (spec 5.6; decision 4): cathedral-data pins this binary's digest.

Inputs are acquired separately. No downloads, install, mount or device mutation.
This produces a candidate executable; it does not boot or qualify a guest.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "room-kit"))
from custom_guest_initrd import static_elf  # noqa: E402


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv, cwd, env, log):
    subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=log, check=True)


def build(inputs, work, log):
    env = os.environ.copy()
    env.update({
        "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1795770000",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "ARFLAGS": "crD",
    })
    # Do not inherit caller compiler/linker/configure overrides.
    for key in ("CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "LIBS",
                "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR",
                "CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH", "LD_LIBRARY_PATH",
                "CONFIG_SITE", "MAKEFLAGS"):
        env.pop(key, None)
    env["CONFIG_SITE"] = "/dev/null"
    stage = work / "deps"
    stage.mkdir()
    for path in sorted(inputs.glob("*.deb")):
        run(["dpkg-deb", "-x", str(path), str(stage)], work, env, log)
    for name in ("LVM2.2.03.31.tgz", "cryptsetup-2.8.4.tar.xz"):
        run(["tar", "-xf", str(inputs / name)], work, env, log)
    libs = stage / "usr/lib/x86_64-linux-gnu"
    include = stage / "usr/include"
    gcc_include = subprocess.check_output(["gcc", "-print-file-name=include"], env=env, text=True).strip()
    # Pin packaged headers/libraries, and keep scratch paths out of output bytes.
    env["CFLAGS"] = (
        f"-O2 -ffile-prefix-map={work}=/usr/src/cathedral-verity "
        f"-nostdinc -isystem {gcc_include} -isystem {include / 'x86_64-linux-gnu'} -isystem {include}"
    )
    env["LDFLAGS"] = f"-L{libs}"
    env["LIBS"] = "-lm"
    env["PKG_CONFIG_LIBDIR"] = str(libs / "pkgconfig")
    env["PKG_CONFIG_SYSROOT_DIR"] = str(stage)
    dm = work / "LVM2.2.03.31"
    run(["./configure", "--prefix=/usr", "--enable-static_link", "--disable-readline",
         "--disable-selinux", "--without-systemd", "--without-udev", "--disable-systemd-journal"], dm, env, log)
    run(["make", "-j2", "device-mapper"], dm, env, log)
    shutil.copyfile(dm / "libdm/ioctl/libdevmapper.a", libs / "libdevmapper.a")
    shutil.copyfile(dm / "libdm/libdevmapper.pc", libs / "pkgconfig/devmapper.pc")
    crypt = work / "cryptsetup-2.8.4"
    run(["./configure", "--enable-static", "--disable-shared", "--enable-static-cryptsetup",
         "--disable-udev", "--disable-ssh-token", "--disable-external-tokens", "--disable-blkid",
         "--disable-kernel_crypto", "--disable-luks2-reencryption", "--disable-nls",
         "--disable-asciidoc", "--with-crypto_backend=openssl"], crypt, env, log)
    run(["make", "-j2", "veritysetup.static", "cryptsetup.static"], crypt, env, log)
    result = {}
    for name, banner in (("veritysetup", "veritysetup 2.8.4 "), ("cryptsetup", "cryptsetup 2.8.4 ")):
        built = crypt / f"{name}.static"
        static_elf(built.read_bytes())
        version = subprocess.check_output([str(built), "--version"], env=env, text=True)
        if not version.startswith(banner):
            raise ValueError(f"unexpected {name} version")
        result[name] = built
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cryptsetup-output", type=Path, help="also write the static cryptsetup here")
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    for out in (args.output, args.cryptsetup_output):
        if out is not None and (out.exists() or out.is_symlink()):
            parser.error("output must not exist")
    inputs = args.inputs.resolve(strict=True)
    lock = json.loads(Path(__file__).with_name("custom_guest_verity_inputs.json").read_text())
    if set(p.name for p in inputs.iterdir()) != set(lock):
        parser.error("input directory must contain exactly the pinned files")
    for name, expected in lock.items():
        p = inputs / name
        if p.is_symlink() or not p.is_file() or digest(p) != expected:
            parser.error(f"input digest mismatch: {name}")
    if subprocess.check_output(["gcc", "-dumpfullversion"], text=True).strip() != "15.2.0":
        parser.error("gcc 15.2.0 required")
    if subprocess.check_output(["make", "--version"], text=True).splitlines()[0] != "GNU Make 4.4.1":
        parser.error("GNU Make 4.4.1 required")
    with args.log.open("x") as log, tempfile.TemporaryDirectory(prefix="cathedral-verity-") as tmp:
        work = Path(tmp)
        snapshot = work / "inputs"
        snapshot.mkdir()
        for name, expected in lock.items():
            shutil.copyfile(inputs / name, snapshot / name)
            if digest(snapshot / name) != expected:
                raise ValueError(f"input changed during copy: {name}")
        built = []
        for name in ("first", "second"):
            directory = work / name
            directory.mkdir()
            built.append(build(snapshot, directory, log))
        for name in ("veritysetup", "cryptsetup"):
            if built[0][name].read_bytes() != built[1][name].read_bytes():
                raise ValueError(f"static {name} builds differ")
        for name, destination in (("veritysetup", args.output), ("cryptsetup", args.cryptsetup_output)):
            if destination is not None:
                with destination.open("xb") as out:
                    out.write(built[0][name].read_bytes())
                destination.chmod(0o755)
    summary = {}
    if args.cryptsetup_output is not None:
        summary = {"cryptsetup_output": str(args.cryptsetup_output),
                   "cryptsetup_sha256": digest(args.cryptsetup_output)}
    print(json.dumps({**summary, "output": str(args.output), "sha256": digest(args.output),
                      "double_build_identical": True, "static_elf": True,
                      "inputs_lock_sha256": digest(Path(__file__).with_name("custom_guest_verity_inputs.json")),
                      "boot_verified": False}, sort_keys=True))


if __name__ == "__main__":
    main()
