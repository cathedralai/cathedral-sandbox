#!/usr/bin/env python3
"""Compare the two lanes of the VM bundle build and write the published set.

  vm_bundle_build_summary.py tree ROOT
      one line per entry of a root tree (type, mode, owner, mtime, links, size, sha256 or
      link target, path), so two lanes' base roots can be diffed file by file
  vm_bundle_build_summary.py compare --lanes DIR --out DIR
      DIR holds the downloaded artifacts tools-first, tools-second, bundle-first and
      bundle-second. Every file must be byte-identical across the two lanes (toolchain.txt is
      recorded, not compared). On any difference it prints which file differs, with both
      sha256 and, for text and tar files, where inside, and fails: it never picks one lane.
      Otherwise --out gets the files, SHA256SUMS, summary.json and summary.md. With a pinned
      base root (--pin, default room-kit/vm/base_root_pin.json) it also fails unless the
      lanes' base root, its lock, verity root, data bytes and epoch are the pin's.
  vm_bundle_build_summary.py epoch --snapshot ID --lock FILE [--pin FILE]
      "pinned EPOCH" when the base root is pinned (and the snapshot, the base lock and the
      recipe are the pin's, else it fails), or "unpinned": the workflow then takes the
      commit time. A pinned epoch makes every commit build the same base root bytes, so two
      bundles can share one base root (spec r3 7.5 rebundle, AB#1022).
  vm_bundle_build_summary.py recipe
      the sha256 of every base-root recipe input, and recipe_sha256 over them all

Nothing here boots or qualifies a VM: summary.json records boot_verified false.
A VM copy of scripts/reference_build_summary.py (#808); the two fold together later.
"""
import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLOSURE = REPO / "room-kit" / "vm" / "vm_initrd_closure.json"
PIN = REPO / "room-kit" / "vm" / "base_root_pin.json"
PIN_SCHEMA = "cathedral.vm.base-root-pin/v1"
# What decides the base root's bytes besides the lock, the snapshot and the epoch, which the pin
# holds itself. A change to any of these without a new recipe_sha256 fails the unit tests; a
# change that moves the bytes fails the pinned build's byte check anyway (the gate), since the
# workflow's paths filter covers every file named here.
RECIPE_SCRIPT = "room-kit/vm/build-bundle.sh"
RECIPE_FUNCTIONS = ("build_base_root", "pinned_root", "clamp", "uuid_of", "host_leaks", "e2fsprogs_floor")
RECIPE_LINES = ("BASE_PKGS=",)
# The static mke2fs and veritysetup the image is made with ($TOOLS), and mmdebstrap.
RECIPE_FILES = ("scripts/vm_initrd_tools_inputs.json", "scripts/build_vm_initrd_tools.py")
RECIPE_HOST_INPUT = ("scripts/vm_bundle_build_inputs.json", "mmdebstrap_1.5.7-3_all.deb")
HEX64 = re.compile(r"[0-9a-f]{64}")
LANES = ("first", "second")
KINDS = ("tools", "bundle")
RECORD_ONLY = {"toolchain.txt"}
TEXT_LIMIT = 4 << 20


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def tree(root):
    """Print the listing of ROOT. Never follows a link."""
    root = Path(root)
    out = sys.stdout
    for top, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(dirs + files):
            path = Path(top) / name
            st = path.lstat()
            if stat.S_ISREG(st.st_mode):
                kind, payload = "f", sha_file(path)
            elif stat.S_ISLNK(st.st_mode):
                kind, payload = "l", json.dumps(os.readlink(path))
            elif stat.S_ISDIR(st.st_mode):
                kind, payload = "d", "-"
            else:
                kind, payload = "s", f"rdev={st.st_rdev}"
            rel = path.relative_to(root).as_posix()
            # A directory's size is the build host's: its file system grows a directory as
            # entries are made and removed, and never shrinks it. mke2fs -d builds each
            # directory afresh, so that size is not in the image; it is left out here.
            size = "-" if kind == "d" else st.st_size
            out.write(f"{kind} {stat.S_IMODE(st.st_mode):04o} {st.st_uid}:{st.st_gid} {int(st.st_mtime)} "
                      f"{st.st_nlink} {size} {payload} {json.dumps(rel)}\n")


def shell_function(text, name):
    """The source of shell function NAME in TEXT: a one-line "name() { ...; }" or the lines from
    "name() {" to the first line that is "}". A missing function is an error, so a rename
    cannot drop an input from the recipe."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(f"{name}() {{"):
            if line.rstrip().endswith("}") and line.count("{") == line.count("}"):
                return line + "\n"
            for j in range(i + 1, len(lines)):
                if lines[j] == "}":
                    return "\n".join(lines[i:j + 1]) + "\n"
    raise ValueError(f"{RECIPE_SCRIPT}: no shell function {name}")


def recipe_inputs(repo=REPO):
    """{input name: sha256} for every base-root recipe input."""
    repo = Path(repo)
    script = (repo / RECIPE_SCRIPT).read_text()
    parts = {f"{RECIPE_SCRIPT}:{name}()": shell_function(script, name).encode() for name in RECIPE_FUNCTIONS}
    for prefix in RECIPE_LINES:
        found = [line for line in script.splitlines() if line.startswith(prefix)]
        if len(found) != 1:
            raise ValueError(f"{RECIPE_SCRIPT}: expected one line starting {prefix}")
        parts[f"{RECIPE_SCRIPT}:{prefix}"] = found[0].encode()
    for name in RECIPE_FILES:
        parts[name] = (repo / name).read_bytes()
    path, entry = RECIPE_HOST_INPUT
    pinned = json.loads((repo / path).read_text())["files"][entry]
    parts[f"{path}:{entry}"] = json.dumps(pinned, sort_keys=True, separators=(",", ":")).encode()
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(parts.items())}


def recipe_sha256(repo=REPO):
    inputs = recipe_inputs(repo)
    return hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_pin(path):
    """The base root pin, checked field by field."""
    pin = json.loads(Path(path).read_text())
    if not isinstance(pin, dict) or pin.get("schema") != PIN_SCHEMA:
        raise ValueError(f"{path}: schema must be {PIN_SCHEMA}")
    if pin.get("status") == "unpinned":
        return pin
    if pin.get("status") != "pinned":
        raise ValueError(f"{path}: status must be pinned or unpinned")
    checks = {
        "source_date_epoch": lambda v: type(v) is int and v > 0,
        "snapshot": lambda v: isinstance(v, str) and re.fullmatch(r"\d{8}T\d{6}Z", v) is not None,
        "base_root_packages_lock_sha256": lambda v: isinstance(v, str) and HEX64.fullmatch(v) is not None,
        "base_root_raw_sha256": lambda v: isinstance(v, str) and HEX64.fullmatch(v) is not None,
        "base_root_verity": lambda v: isinstance(v, str) and HEX64.fullmatch(v) is not None,
        "base_root_data_bytes": lambda v: type(v) is int and v > 0 and v % 4096 == 0,
        "recipe_sha256": lambda v: isinstance(v, str) and HEX64.fullmatch(v) is not None,
        "from_run": lambda v: isinstance(v, str) and v.isdigit(),
    }
    for field, ok in checks.items():
        if not ok(pin.get(field)):
            raise ValueError(f"{path}: {field} missing or invalid")
    return pin


def pin_epoch(pin_path, snapshot, lock):
    """The epoch line for bundle.env: the pin's, after its snapshot, lock and recipe check out."""
    pin = load_pin(pin_path)
    if pin["status"] == "unpinned":
        return "unpinned"
    problems = []
    if snapshot != pin["snapshot"]:
        problems.append(f"VM_BUNDLE_SNAPSHOT is {snapshot}; the pin's base root is from {pin['snapshot']}")
    have = sha_file(Path(lock))
    if have != pin["base_root_packages_lock_sha256"]:
        problems.append(f"the base lock's sha256 is {have}; the pin's is {pin['base_root_packages_lock_sha256']}")
    recipe = recipe_sha256()
    if recipe != pin["recipe_sha256"]:
        problems.append(f"the base-root recipe's sha256 is {recipe}; the pin's is {pin['recipe_sha256']}")
    if problems:
        raise ValueError("base root pin: " + "; ".join(problems) +
                         ". A new base root needs a new pin and a new first bundle (room-kit/vm/README.md)")
    return f"pinned {pin['source_date_epoch']}"


def pin_problems(pin, agreed, bundle):
    """Why the lanes' base root is not the pinned one (empty when it is)."""
    want = {
        "base-root.raw sha256": (agreed.get("base-root.raw", ""), pin["base_root_raw_sha256"]),
        "base-root.packages.lock sha256": (agreed.get("base-root.packages.lock", ""),
                                           pin["base_root_packages_lock_sha256"]),
        "base_root_verity": (read(bundle, "base-root.verity"), pin["base_root_verity"]),
        "base_root_data_bytes": (read(bundle, "base-root.data-bytes"), str(pin["base_root_data_bytes"])),
        "source_date_epoch": (read(bundle, "source-date-epoch"), str(pin["source_date_epoch"])),
        "snapshot": (os.environ.get("VM_BUNDLE_SNAPSHOT", ""), pin["snapshot"]),
    }
    return [f"{name}: built {have or 'nothing'}, pinned {expected}"
            for name, (have, expected) in want.items() if have != expected]


def listing(directory):
    return sorted(p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file())


def text_or_none(path):
    if path.stat().st_size > TEXT_LIMIT:
        return None
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def tar_members(path):
    result = {}
    with tarfile.open(path) as tar:
        for member in tar:
            data = tar.extractfile(member).read() if member.isfile() else b""
            result[member.name] = (member.type, member.mode, member.uid, member.gid, member.mtime,
                                   member.linkname, hashlib.sha256(data).hexdigest())
    return result


def explain(first, second):
    """Lines that say where inside two differing files the difference is."""
    if first.suffix == ".tar":
        a, b = tar_members(first), tar_members(second)
        names = sorted(n for n in set(a) | set(b) if a.get(n) != b.get(n))
        return [f"  member {n}: first {a.get(n)} second {b.get(n)}" for n in names[:20]]
    a, b = text_or_none(first), text_or_none(second)
    if a is None or b is None:
        return []
    return ["  " + line for line in list(difflib.unified_diff(a, b, "first", "second", lineterm="", n=0))[:60]]


def compare(lanes):
    """Return {kind: {name: sha256}} when both lanes agree, else print every difference and exit."""
    agreed, problems = {}, []
    for kind in KINDS:
        dirs = [lanes / f"{kind}-{lane}" for lane in LANES]
        names = [set(listing(d)) - RECORD_ONLY for d in dirs]
        for name in sorted(names[0] ^ names[1]):
            problems.append(f"{kind} {name}: only in lane {'first' if name in names[0] else 'second'}")
        agreed[kind] = {}
        for name in sorted(names[0] & names[1]):
            a, b = (d / name for d in dirs)
            sa, sb = sha_file(a), sha_file(b)
            if sa == sb:
                agreed[kind][name] = sa
            else:
                problems.append(f"{kind} {name} differs between lanes: first {sa} second {sb}")
                problems.extend(explain(a, b))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        raise SystemExit("vm_bundle_build_summary: the lanes differ; nothing is published")
    return agreed


def read(directory, name):
    path = directory / name
    return path.read_text().strip() if path.is_file() else ""


def closure_rows(pinned):
    """The digests a reviewer pins: the executables, then every module tree file (the boot
    modules, their dependencies and the indexes)."""
    rows = dict(sorted(pinned.get("executables", {}).items()))
    rows.update(sorted(pinned.get("modules", {}).items()))
    return rows


def measurement_line(measurement):
    if not measurement:
        return "not measured (closure unpinned)"
    return (f"measurement `{measurement.get('expected_measurement', '')}`, "
            f"identity sha256 `{measurement.get('identity_sha256', '')}`")


def pin_line(pin, to_pin):
    if pin["status"] == "pinned":
        return f"pinned (run {pin['from_run']}); this build's base root equals it byte for byte"
    return "unpinned. To pin this base root, commit as room-kit/vm/base_root_pin.json: `" + \
        json.dumps(to_pin, sort_keys=True, separators=(", ", ": ")) + "`"


def same_toolchain(first, second):
    """Toolchains compared without the runner image line: lanes may land on two image versions
    during a rollout, and the bytes are compared anyway."""
    def strip(text):
        return [line for line in text.splitlines() if not line.startswith("image:")]
    return strip(first) == strip(second)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("tree")
    p.add_argument("root", type=Path)
    p = sub.add_parser("compare")
    p.add_argument("--lanes", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True, help="new directory")
    p.add_argument("--pin", type=Path, default=PIN)
    p = sub.add_parser("epoch")
    p.add_argument("--snapshot", required=True)
    p.add_argument("--lock", type=Path, required=True)
    p.add_argument("--pin", type=Path, default=PIN)
    sub.add_parser("recipe")
    args = parser.parse_args()
    if args.command == "tree":
        tree(args.root)
        return 0
    if args.command == "epoch":
        print(pin_epoch(args.pin, args.snapshot, args.lock))
        return 0
    if args.command == "recipe":
        print(json.dumps({"inputs": recipe_inputs(), "recipe_sha256": recipe_sha256()}, indent=1, sort_keys=True))
        return 0
    pin = load_pin(args.pin)
    agreed = compare(args.lanes)
    first = {kind: args.lanes / f"{kind}-first" for kind in KINDS}
    if pin["status"] == "pinned":
        problems = pin_problems(pin, agreed["bundle"], first["bundle"])
        if problems:
            print("\n".join(problems), file=sys.stderr)
            raise SystemExit("vm_bundle_build_summary: the lanes agree, but their base root is not the pinned one "
                             f"({args.pin}); nothing is published")
        to_pin = None
    else:
        # What a reviewer commits to pin this run's base root.
        to_pin = {
            "schema": PIN_SCHEMA, "status": "pinned",
            "source_date_epoch": int(read(first["bundle"], "source-date-epoch") or 0),
            "snapshot": os.environ.get("VM_BUNDLE_SNAPSHOT", ""),
            "base_root_packages_lock_sha256": agreed["bundle"].get("base-root.packages.lock", ""),
            "base_root_raw_sha256": agreed["bundle"].get("base-root.raw", ""),
            "base_root_verity": read(first["bundle"], "base-root.verity"),
            "base_root_data_bytes": int(read(first["bundle"], "base-root.data-bytes") or 0),
            "from_run": os.environ.get("GITHUB_RUN_ID", ""),
            "recipe_sha256": recipe_sha256(),
        }
    args.out.mkdir()
    files = {}
    for kind in KINDS:
        for name, digest in agreed[kind].items():
            published = name if kind == "bundle" else f"tools/{name}"
            (args.out / published).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(first[kind] / name, args.out / published)
            files[published] = {"sha256": digest, "bytes": (args.out / published).stat().st_size}
    toolchains = {f"{kind}-{lane}": read(args.lanes / f"{kind}-{lane}", "toolchain.txt")
                  for kind in KINDS for lane in LANES}
    # An unpinned closure: the lanes' pin output. A pinned one: the committed closure, which the
    # lanes' initrd build was checked against.
    pinned_path = first["bundle"] / "pinned-closure.json"
    pinned = json.loads((pinned_path if pinned_path.is_file() else CLOSURE).read_text())
    measurement_path = first["bundle"] / "measurement.json"
    summary = {
        "schema": "cathedral.vm.bundle-build-summary/v1",
        # The commit the lanes built (on a pull request its head, not the test merge) and the
        # epoch every timestamp in the base root and the module tar is set to.
        "source_commit": os.environ.get("SOURCE_SHA", ""),
        "source_date_epoch": read(first["bundle"], "source-date-epoch"),
        "event": os.environ.get("GITHUB_EVENT_NAME", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "run": f"{os.environ.get('GITHUB_RUN_ID', '')}/{os.environ.get('GITHUB_RUN_ATTEMPT', '')}",
        "snapshot": os.environ.get("VM_BUNDLE_SNAPSHOT", ""),
        "kernel_release": read(first["bundle"], "kernel-release"),
        "boot_modules": read(first["bundle"], "boot-modules.txt").splitlines(),
        "base_root_verity": read(first["bundle"], "base-root.verity"),
        "base_root_data_bytes": read(first["bundle"], "base-root.data-bytes"),
        "base_root_pin": pin["status"],
        "base_root_to_pin": to_pin,
        "closure_digests": closure_rows(pinned),
        "closure_module_files": len(pinned.get("modules", {})),
        "bundle_id": agreed["bundle"].get("manifest.json", ""),
        "initrd_bytes": files.get("initrd.cpio.zst", {}).get("bytes"),
        "measurement": json.loads(measurement_path.read_text()) if measurement_path.is_file() else None,
        "files": files,
        "lanes_byte_identical": True,
        "toolchains_identical": all(same_toolchain(toolchains[f"{kind}-first"], toolchains[f"{kind}-second"])
                                    for kind in KINDS),
        "runner_images": sorted({line for text in toolchains.values() for line in text.splitlines()
                                 if line.startswith("image:")}),
        "boot_verified": False,
    }
    for name, text in toolchains.items():
        (args.out / f"toolchain-{name}.txt").write_text(text + "\n")
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (args.out / "SHA256SUMS").write_text("".join(f"{v['sha256']}  {k}\n" for k, v in sorted(files.items())))
    file_rows = "".join(f"| `{name}` | `{v['sha256']}` | {v['bytes']} |\n" for name, v in sorted(files.items()))
    digest_rows = "".join(f"| `{path}` | `{digest}` |\n" for path, digest in summary["closure_digests"].items())
    module_rows = "".join(f"- `{line}`\n" for line in summary["boot_modules"])
    (args.out / "summary.md").write_text(
        "## VM bundle build\n\n"
        f"- Snapshot: `{summary['snapshot']}`\n"
        f"- Kernel release: `{summary['kernel_release']}`\n"
        f"- Base root verity: `{summary['base_root_verity']}`, data bytes {summary['base_root_data_bytes']}\n"
        f"- Base root pin: {pin_line(pin, to_pin)}\n"
        f"- Bundle id (sha256 of manifest.json): `{summary['bundle_id'] or 'not built (closure unpinned)'}`\n"
        f"- Fixture identity a, 2 vCPU, genoa: {measurement_line(summary['measurement'])}\n"
        f"- Initrd: {summary['initrd_bytes'] if summary['initrd_bytes'] is not None else 'not built'} bytes\n"
        f"- Source commit: `{summary['source_commit']}` ({summary['event']} {summary['ref']}), "
        f"SOURCE_DATE_EPOCH {summary['source_date_epoch']}\n"
        "- Both lanes byte-identical: yes. Boot verified: no (this run builds; it does not boot).\n"
        f"- Toolchains identical across lanes: {'yes' if summary['toolchains_identical'] else 'no (see toolchain-*.txt)'}\n\n"
        "### Boot modules (module file or built in)\n\n" + module_rows +
        f"\n### Closure digests ({summary['closure_module_files']} module tree files)\n\n"
        "| Path | sha256 |\n|---|---|\n" + digest_rows +
        "\n### Files\n\n| File | sha256 | bytes |\n|---|---|---|\n" + file_rows)
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, tarfile.TarError) as error:
        sys.exit(f"vm_bundle_build_summary: {error}")
