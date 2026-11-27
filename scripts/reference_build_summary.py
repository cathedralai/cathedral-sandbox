#!/usr/bin/env python3
"""Compare the two lanes of the reference guest build and write the published set.

--lanes holds the downloaded artifacts kernel-first, kernel-second, initrd-first and
initrd-second. Every listed output must be byte-identical across the two lanes, the
embedded kernel config must equal kernel.config, and the closure must name the digests of
the files built beside it. The set written to --out is what the site publishes:

  vmlinuz, kernel.config                     the reference kernel (and the test image kernel)
  cathedral-custom-initrd-<version>.cpio.zst the reference initrd
  closure-list.txt                           its closure, "<sha256>  <path>" per line (sha256sum -c)
  closure.json                               the same closure as make_custom_guest_initrd.py wrote it
  cathedral-init, veritysetup                the two closure files
  cathedral-attest, cathedral-data, cryptsetup  the helpers the init and data volume pin
  summary.json, summary.md, SHA256SUMS

Nothing here boots or qualifies a guest: summary.json records boot_verified false.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

KERNEL = ("vmlinuz", "kernel.config", "embedded.config")
INITRD = ("initrd.cpio.zst", "closure.json", "cathedral-init", "cathedral-attest", "cathedral-data",
          "veritysetup", "cryptsetup")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
LANES = ("first", "second")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def kernel_version(image):
    """The version string the x86 boot header points at (setup header kernel_version)."""
    if image[0x202:0x206] != b"HdrS":
        raise ValueError("vmlinuz has no x86 setup header")
    start = 0x200 + struct.unpack_from("<H", image, 0x20e)[0]
    return image[start:image.index(b"\0", start)].decode("ascii")


def same(lanes, kind, name):
    blobs = [(lanes / f"{kind}-{lane}" / name).read_bytes() for lane in LANES]
    if blobs[0] != blobs[1]:
        raise ValueError(f"{kind} {name} differs between lanes: {sha(blobs[0])} {sha(blobs[1])}")
    return blobs[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lanes", type=Path, required=True)
    parser.add_argument("--initrd-version", required=True)
    parser.add_argument("--out", type=Path, required=True, help="new directory")
    args = parser.parse_args()
    if not VERSION.fullmatch(args.initrd_version):
        parser.error("initrd version must match " + VERSION.pattern)
    built = {name: same(args.lanes, "kernel", name) for name in KERNEL}
    built.update({name: same(args.lanes, "initrd", name) for name in INITRD})
    if built["embedded.config"] != built["kernel.config"]:
        raise ValueError("the config embedded in vmlinuz differs from kernel.config")
    closure = json.loads(built["closure.json"])
    expected = {"init": sha(built["cathedral-init"]), "usr/lib/cathedral/veritysetup": sha(built["veritysetup"])}
    if closure != expected:
        raise ValueError("closure.json does not name the cathedral-init and veritysetup built beside it")
    initrd_name = f"cathedral-custom-initrd-{args.initrd_version}.cpio.zst"
    published = {
        "vmlinuz": built["vmlinuz"], "kernel.config": built["kernel.config"],
        initrd_name: built["initrd.cpio.zst"],
        "closure-list.txt": "".join(f"{closure[p]}  {p}\n" for p in sorted(closure)).encode(),
        "closure.json": built["closure.json"],
    }
    for name in ("cathedral-init", "veritysetup", "cathedral-attest", "cathedral-data", "cryptsetup"):
        published[name] = built[name]
    toolchains = {f"{kind}-{lane}": (args.lanes / f"{kind}-{lane}" / "toolchain.txt").read_text()
                  for kind in ("kernel", "initrd") for lane in LANES}
    summary = {
        "schema": "cathedral.custom_guest.reference-build-summary/v1",
        "source_commit": os.environ.get("GITHUB_SHA", ""),
        "run": f"{os.environ.get('GITHUB_RUN_ID', '')}/{os.environ.get('GITHUB_RUN_ATTEMPT', '')}",
        "kernel_version": kernel_version(built["vmlinuz"]),
        "initrd_version": args.initrd_version,
        "files": {name: {"sha256": sha(data), "bytes": len(data)} for name, data in published.items()},
        "closure": closure,
        "lanes_byte_identical": True,
        "toolchains_identical": len({toolchains[f"kernel-{lane}"] for lane in LANES}) == 1
        and len({toolchains[f"initrd-{lane}"] for lane in LANES}) == 1,
        "boot_verified": False,
    }
    args.out.mkdir()
    for name, data in published.items():
        (args.out / name).write_bytes(data)
    for name, text in toolchains.items():
        (args.out / f"toolchain-{name}.txt").write_text(text)
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (args.out / "SHA256SUMS").write_text("".join(f"{v['sha256']}  {k}\n" for k, v in sorted(summary["files"].items())))
    rows = "".join(f"| `{name}` | `{v['sha256']}` | {v['bytes']} |\n" for name, v in summary["files"].items())
    closure_rows = "".join(f"| `{path}` | `{closure[path]}` |\n" for path in sorted(closure))
    (args.out / "summary.md").write_text(
        "## Reference guest build\n\n"
        f"- Kernel version string: `{summary['kernel_version']}`\n"
        f"- Initrd version: `{args.initrd_version}`\n"
        f"- Source commit: `{summary['source_commit']}`\n"
        "- Both lanes byte-identical: yes. Boot verified: no (this run builds; it does not boot).\n"
        f"- Toolchains identical across lanes: {'yes' if summary['toolchains_identical'] else 'no (see toolchain-*.txt)'}\n\n"
        "| File | sha256 | bytes |\n|---|---|---|\n" + rows +
        "\n### Closure list\n\n| Path | sha256 |\n|---|---|\n" + closure_rows)
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.exit(f"reference_build_summary: {error}")
