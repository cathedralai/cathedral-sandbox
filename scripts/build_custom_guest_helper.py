#!/usr/bin/env python3
"""Rebuild the static guest report helper twice from identical source in different directories.

This emits a candidate helper and digest, not an approved closure or boot image.
The pinned Go compiler must already be installed; this script never downloads it.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "room-kit"))
from custom_guest_initrd import static_elf

GO_VERSION = "go1.26.11"


def build(go, output):
    source = REPO / "room-kit/custom-guest"
    env = os.environ.copy()
    env.update(GOTOOLCHAIN="local", GOENV="off", GOEXPERIMENT="", GOWORK="off", GOFLAGS="", CGO_ENABLED="0",
               GOOS="linux", GOARCH="amd64", GOAMD64="v1", GOPROXY="off", GOSUMDB="off")
    version = subprocess.run([go, "env", "GOVERSION"], env=env, check=True,
                             capture_output=True, text=True).stdout.strip()
    if version != GO_VERSION:
        raise ValueError(f"use pinned {GO_VERSION}; found {version}")
    paths = sorted([source / "go.mod", *source.rglob("*.go")])
    snapshot = {p.relative_to(source): p.read_bytes() for p in paths}
    digests = {str(p): hashlib.sha256(data).hexdigest() for p, data in snapshot.items()}
    binaries = []
    with tempfile.TemporaryDirectory(prefix="custom-guest-helper-") as directory:
        for lane in ("first", "different-length-second"):
            root = Path(directory) / lane
            for path, data in snapshot.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            target = root / "cathedral-attest"
            subprocess.run([go, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=",
                            "-o", str(target), "./cmd/cathedral-attest"], cwd=root,
                           env=env, check=True, timeout=120)
            binary = target.read_bytes()
            static_elf(binary)
            binaries.append(binary)
    if binaries[0] != binaries[1]:
        raise ValueError("helper is not reproducible across build directories")
    with output.open("xb") as stream:
        stream.write(binaries[0])
        os.fchmod(stream.fileno(), 0o755)
    return {"schema": "cathedral.custom_guest.helper-build/v1", "go": GO_VERSION,
            "sha256": hashlib.sha256(binaries[0]).hexdigest(), "bytes": len(binaries[0]),
            "closure_path": "usr/lib/cathedral/cathedral-attest", "source_sha256": digests,
            "static_elf_checked": True, "rebuild_identical": True, "boot_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=shutil.which("go"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.go:
        parser.error("pinned Go compiler required")
    print(json.dumps(build(str(Path(args.go).resolve()), args.output), sort_keys=True))


if __name__ == "__main__":
    main()
