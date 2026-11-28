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
      Otherwise --out gets the files, SHA256SUMS, summary.json and summary.md.

Nothing here boots or qualifies a VM: summary.json records boot_verified false.
A VM copy of scripts/reference_build_summary.py (#808); the two fold together later.
"""
import argparse
import difflib
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLOSURE = REPO / "room-kit" / "vm" / "vm_initrd_closure.json"
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
            out.write(f"{kind} {stat.S_IMODE(st.st_mode):04o} {st.st_uid}:{st.st_gid} {int(st.st_mtime)} "
                      f"{st.st_nlink} {st.st_size} {payload} {json.dumps(rel)}\n")


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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("tree")
    p.add_argument("root", type=Path)
    p = sub.add_parser("compare")
    p.add_argument("--lanes", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True, help="new directory")
    args = parser.parse_args()
    if args.command == "tree":
        tree(args.root)
        return 0
    agreed = compare(args.lanes)
    first = {kind: args.lanes / f"{kind}-first" for kind in KINDS}
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
        "source_commit": os.environ.get("GITHUB_SHA", ""),
        "run": f"{os.environ.get('GITHUB_RUN_ID', '')}/{os.environ.get('GITHUB_RUN_ATTEMPT', '')}",
        "snapshot": os.environ.get("VM_BUNDLE_SNAPSHOT", ""),
        "kernel_release": read(first["bundle"], "kernel-release"),
        "boot_modules": read(first["bundle"], "boot-modules.txt").splitlines(),
        "base_root_verity": read(first["bundle"], "base-root.verity"),
        "base_root_data_bytes": read(first["bundle"], "base-root.data-bytes"),
        "closure_digests": closure_rows(pinned),
        "closure_module_files": len(pinned.get("modules", {})),
        "bundle_id": agreed["bundle"].get("manifest.json", ""),
        "measurement": json.loads(measurement_path.read_text()) if measurement_path.is_file() else None,
        "files": files,
        "lanes_byte_identical": True,
        "toolchains_identical": all(toolchains[f"{kind}-first"] == toolchains[f"{kind}-second"] for kind in KINDS),
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
        f"- Bundle id (sha256 of manifest.json): `{summary['bundle_id'] or 'not built (closure unpinned)'}`\n"
        f"- Fixture identity a, 2 vCPU, genoa: {measurement_line(summary['measurement'])}\n"
        f"- Source commit: `{summary['source_commit']}`\n"
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
