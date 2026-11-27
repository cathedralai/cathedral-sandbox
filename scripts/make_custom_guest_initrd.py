#!/usr/bin/env python3
"""Assemble the dedicated custom guest initrd from reviewed inputs.

scripts/custom_guest_initrd_closure.json is the reviewed recipe: exactly which executables
the initrd may contain and the input each comes from. This tool adds nothing to it. It takes
one file per input name, refuses any extra or missing input, any symlink and any ELF that is
not static, derives the {path: sha256} closure that room-kit/custom_guest_initrd.py enforces,
builds the archive twice, requires identical bytes, and checks the result by unpacking it
against that closure. The closure is written next to the archive for review and publication.

Inputs come from build_custom_guest_helper.py (cathedral-init, linked with its pins) and
build_custom_guest_verity.py (veritysetup). Nothing is downloaded or executed.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "room-kit"))
import custom_guest_initrd as archive  # noqa: E402

RECIPE = Path(__file__).with_name("custom_guest_initrd_closure.json")
SCHEMA = "cathedral.custom_guest.initrd-recipe/v1"


def load_recipe(path=RECIPE):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            archive.require(key not in result, "duplicate recipe key")
            result[key] = value
        return result
    recipe = json.loads(archive.read_bounded(path, 32768), object_pairs_hook=unique)
    archive.require(isinstance(recipe, dict) and set(recipe) == {"schema", "executables"}
                    and recipe["schema"] == SCHEMA, "unknown recipe schema")
    executables = recipe["executables"]
    archive.require(isinstance(executables, dict) and executables, "recipe lists no executables")
    names = list(executables.values())
    archive.require(all(isinstance(n, str) and archive.valid_path(n) and "/" not in n for n in names)
                    and len(set(names)) == len(names), "invalid or repeated input name")
    # The same path rules the archive checker applies to a closure.
    archive.closure_check({path: "0" * 64 for path in executables})
    return executables


def read_input(path):
    archive.require(not path.is_symlink() and path.is_file(), f"input is not a regular file: {path.name}")
    data = archive.read_bounded(path)
    archive.static_elf(data)
    return data


def assemble(inputs, executables):
    """inputs: input name -> Path. Returns (files, closure) keyed by archive path."""
    archive.require(set(inputs) == set(executables.values()),
                    "inputs must be exactly: " + ", ".join(sorted(executables.values())))
    files = {path: read_input(Path(inputs[name])) for path, name in executables.items()}
    closure = {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}
    return files, closure


def build(inputs, executables, archive_path, closure_path):
    files, closure = assemble(inputs, executables)
    builds = [archive.pack(archive.build_raw(files, closure), closure) for _ in range(2)]
    archive.require(builds[0] == builds[1], "initrd build is not reproducible")
    archive.unpack(builds[0], closure)
    with archive_path.open("xb") as out:
        out.write(builds[0])
    with closure_path.open("x") as out:
        json.dump(closure, out, sort_keys=True, indent=2)
        out.write("\n")
    return {"sha256": hashlib.sha256(builds[0]).hexdigest(), "bytes": len(builds[0]), "closure": closure,
            "double_build_identical": True, "status": "archive_verified", "boot_verified": False}


def main():
    executables = load_recipe()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in sorted(executables.values()):
        parser.add_argument(f"--{name}", type=Path, required=True, dest=name.replace("-", "_"))
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--closure-out", type=Path, required=True)
    args = parser.parse_args()
    inputs = {name: getattr(args, name.replace("-", "_")) for name in executables.values()}
    print(json.dumps(build(inputs, executables, args.archive, args.closure_out), sort_keys=True))


if __name__ == "__main__":
    main()
