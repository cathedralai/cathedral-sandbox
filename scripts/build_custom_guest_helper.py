#!/usr/bin/env python3
"""Rebuild the static guest binaries twice from identical source in different directories.

Always builds cathedral-attest (the report helper). With --init-output it also builds
cathedral-init (the measured PID1) and with --data-output cathedral-data (the owner unlock).
The init links in the digests it must pin (veritysetup from --verity-sha256, and the attest
binary built in this same run); the data tool links in --cryptsetup-sha256. Pins are linked,
never read from the host, the root disk or the command line at boot.

This emits candidate binaries and digests, not an approved closure or boot image.
The pinned Go compiler must already be installed; this script never downloads it.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "room-kit"))
from custom_guest_initrd import static_elf

GO_VERSION = "go1.26.11"
HEX64 = re.compile(r"[0-9a-f]{64}")


def check_pin(name, value):
    if value is None or not HEX64.fullmatch(value) or value == "0" * 64:
        raise ValueError(f"{name} must be 64 lowercase hex characters, not all zero")
    return value


def go_build(go, root, env, command, name, pins=()):
    target = root / name
    flags = "-s -w -buildid="
    for symbol, value in pins:
        flags += f" -X main.{symbol}={value}"
    subprocess.run([go, "build", "-trimpath", "-buildvcs=false", f"-ldflags={flags}",
                    "-o", str(target), f"./cmd/{command}"], cwd=root, env=env, check=True, timeout=120)
    binary = target.read_bytes()
    static_elf(binary)
    return binary


def build(go, output, init_output=None, data_output=None, verity_sha256=None, cryptsetup_sha256=None):
    if init_output is not None:
        check_pin("--verity-sha256", verity_sha256)
    if data_output is not None:
        check_pin("--cryptsetup-sha256", cryptsetup_sha256)
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
    lanes = []
    with tempfile.TemporaryDirectory(prefix="custom-guest-helper-") as directory:
        for lane in ("first", "different-length-second"):
            root = Path(directory) / lane
            for path, data in snapshot.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            built = {"attest": go_build(go, root, env, "cathedral-attest", "cathedral-attest")}
            if init_output is not None:
                # The init pins the attest binary of this same build, so the root that carries
                # that exact binary is the only one it will accept.
                pins = (("pinVeritySHA256", verity_sha256),
                        ("pinReportSHA256", hashlib.sha256(built["attest"]).hexdigest()))
                built["init"] = go_build(go, root, env, "cathedral-init", "cathedral-init", pins)
            if data_output is not None:
                built["data"] = go_build(go, root, env, "cathedral-data", "cathedral-data",
                                         (("pinCryptsetupSHA256", cryptsetup_sha256),))
            lanes.append(built)
    if lanes[0] != lanes[1]:
        raise ValueError("helpers are not reproducible across build directories")
    result = {"schema": "cathedral.custom_guest.helper-build/v1", "go": GO_VERSION,
              "sha256": hashlib.sha256(lanes[0]["attest"]).hexdigest(), "bytes": len(lanes[0]["attest"]),
              "closure_path": "usr/lib/cathedral/cathedral-attest", "source_sha256": digests,
              "static_elf_checked": True, "rebuild_identical": True, "boot_verified": False}
    for key, destination, closure_path in (("init", init_output, "init"),
                                           ("data", data_output, "usr/bin/cathedral-data")):
        if destination is not None:
            result[key] = {"sha256": hashlib.sha256(lanes[0][key]).hexdigest(), "bytes": len(lanes[0][key]),
                           "closure_path": closure_path}
    for key, destination in (("attest", output), ("init", init_output), ("data", data_output)):
        if destination is not None:
            with destination.open("xb") as stream:
                stream.write(lanes[0][key])
                os.fchmod(stream.fileno(), 0o755)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=shutil.which("go"))
    parser.add_argument("--output", type=Path, required=True, help="cathedral-attest")
    parser.add_argument("--init-output", type=Path, help="also build cathedral-init (needs --verity-sha256)")
    parser.add_argument("--verity-sha256", help="digest of the static veritysetup the init will execute")
    parser.add_argument("--data-output", type=Path, help="also build cathedral-data (needs --cryptsetup-sha256)")
    parser.add_argument("--cryptsetup-sha256", help="digest of the static cryptsetup cathedral-data will execute")
    args = parser.parse_args()
    if not args.go:
        parser.error("pinned Go compiler required")
    try:
        result = build(str(Path(args.go).resolve()), args.output, args.init_output, args.data_output,
                       args.verity_sha256, args.cryptsetup_sha256)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
