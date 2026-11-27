#!/usr/bin/env python3
"""Download the pinned inputs of the reference guest build and check each sha256.

Writes one directory per group under --out:
  verity/       exactly the files of scripts/custom_guest_verity_inputs.json, under the names
                build_custom_guest_verity.py requires. Names and sha256 come from that lock; each
                URL is the one scripts/vm_initrd_tools_inputs.json gives for the same sha256.
  kernel/, kernel-host/, go/, python/
                the files of scripts/reference_build_inputs.json, by their "group".

A file whose bytes do not match its pin is deleted and the run fails. Nothing is executed.
"""
import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SCHEMA = "cathedral.custom_guest.reference-build-inputs/v1"
GROUPS = ("verity", "kernel", "kernel-host", "go", "python")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~%-]{0,200}")
HEX64 = re.compile(r"[0-9a-f]{64}")
LIMIT = 512 << 20


def plan():
    """Return {group: {name: (url, sha256)}} for every pinned input."""
    verity = json.loads((SCRIPTS / "custom_guest_verity_inputs.json").read_text())
    urls = {}
    for entry in json.loads((SCRIPTS / "vm_initrd_tools_inputs.json").read_text())["files"].values():
        urls.setdefault(entry["sha256"], entry["url"])
    lock = json.loads((SCRIPTS / "reference_build_inputs.json").read_text())
    if lock.get("schema") != SCHEMA:
        raise ValueError("unknown reference build input schema")
    result = {group: {} for group in GROUPS}
    for name, sha256 in verity.items():
        if sha256 not in urls:
            raise ValueError(f"no URL pinned for {name}")
        result["verity"][name] = (urls[sha256], sha256)
    for name, entry in lock["files"].items():
        if entry.get("group") not in GROUPS or entry["group"] == "verity":
            raise ValueError(f"bad group for {name}")
        result[entry["group"]][name] = (entry["url"], entry["sha256"])
    for names in result.values():
        for name, (url, sha256) in names.items():
            if not NAME.fullmatch(name) or not HEX64.fullmatch(sha256) or not url.startswith(("https://", "http://")):
                raise ValueError(f"bad pin for {name}")
    return result


def fetch(url, sha256, target):
    # http is acceptable only because the bytes are checked against the pin before any use.
    request = urllib.request.Request(url, headers={"User-Agent": "cathedral-reference-build"})
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request, timeout=120) as response, target.open("xb") as out:
        while chunk := response.read(1 << 20):
            size += len(chunk)
            if size > LIMIT:
                break
            digest.update(chunk)
            out.write(chunk)
    if size > LIMIT or digest.hexdigest() != sha256:
        target.unlink()
        raise ValueError(f"{target.name}: sha256 differs from its pin")
    return size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="new directory")
    parser.add_argument("--group", action="append", choices=GROUPS, required=True)
    parser.add_argument("--check", action="store_true", help="only resolve every pin; download nothing")
    args = parser.parse_args()
    pins = plan()
    groups = sorted(set(args.group))
    if args.check:
        print(json.dumps({group: sorted(pins[group]) for group in groups}, sort_keys=True))
        return 0
    if args.out is None:
        parser.error("--out is required")
    args.out.mkdir()
    fetched = {}
    for group in groups:
        directory = args.out / group
        directory.mkdir()
        for name, (url, sha256) in sorted(pins[group].items()):
            fetched[f"{group}/{name}"] = {"sha256": sha256, "bytes": fetch(url, sha256, directory / name)}
    print(json.dumps(fetched, sort_keys=True, indent=1))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as error:
        sys.exit(f"fetch_reference_build_inputs: {error}")
