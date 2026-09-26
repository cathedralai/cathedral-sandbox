#!/usr/bin/env python3
"""Atomically install, enable or disable one operator-managed allocation."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 1024 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$")


def validate_configuration(document: dict) -> None:
    """Keep the shared file readable by workers_capacity_store, even disabled rows.

    The API parses the complete snapshot before selecting a customer. Validate
    every field at the producer boundary so one prepared package cannot break
    unrelated assignments. Unknown fields remain preserved for compatibility.
    """
    def text(row, name, identifier=False):
        value = row.get(name)
        if (not isinstance(value, str) or not value or len(value) > 2048
                or (identifier and not IDENTIFIER.fullmatch(value))):
            raise ValueError("invalid configuration field")
        return value

    def limit(row):
        value = row.get("concurrent_limit")
        if type(value) is not int or not 1 <= value <= 512:
            raise ValueError("invalid allocation capacity")
        return value

    allocations = {}
    endpoints = set()
    for row in document["allocations"]:
        for key in ("allocation_id", "owner_id"):
            text(row, key, True)
        endpoint = text(row, "endpoint").rstrip("/")
        url = urlsplit(endpoint)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.query or url.fragment or url.path not in ("", "/")):
            raise ValueError("executor requires an HTTPS origin")
        _ = url.port
        for key in ("ca_cert", "client_cert", "client_key"):
            if not Path(text(row, key)).is_absolute():
                raise ValueError("TLS paths must be absolute")
        if (not re.fullmatch(r"grader-sha256:[0-9a-f]{64}", text(row, "runtime_id"))
                or type(row.get("enabled")) is not bool):
            raise ValueError("invalid runtime or enabled flag")
        limit(row)
        if row["enabled"]:
            if endpoint.lower() in endpoints:
                raise ValueError("executor origin already enabled")
            endpoints.add(endpoint.lower())
        allocations[row["allocation_id"]] = row
    owners = set()
    now = datetime.now(timezone.utc)
    for row in document["grants"]:
        for key in ("grant_id", "owner_id", "allocation_id", "source"):
            text(row, key, True)
        expiry = datetime.fromisoformat(text(row, "expires_at").replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            raise ValueError("expiry requires a timezone")
        limit(row)
        if expiry > now:
            allocation = allocations.get(row["allocation_id"])
            if (row["owner_id"] in owners or allocation is None
                    or allocation["owner_id"] != row["owner_id"]
                    or allocation["concurrent_limit"] != row["concurrent_limit"]):
                raise ValueError("invalid or overlapping active owner assignment")
            owners.add(row["owner_id"])


def read_document(path: Path) -> tuple[dict, bytes]:
    if path.is_symlink():
        raise ValueError("configuration must not be a symlink")
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("configuration must be a regular file")
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("configuration exceeds 1 MiB")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def reject(value):
        raise ValueError("non-finite JSON value")
    document = json.loads(raw, object_pairs_hook=unique, parse_constant=reject)
    if (not isinstance(document, dict) or document.get("schema") != "polaris_workers_grants_v1"
            or not isinstance(document.get("allocations"), list) or not isinstance(document.get("grants"), list)):
        raise ValueError("unsupported allocation document")
    for collection, key in (("allocations", "allocation_id"), ("grants", "grant_id")):
        values = [item.get(key) for item in document[collection] if isinstance(item, dict)]
        if (len(values) != len(document[collection]) or any(not isinstance(v, str) or not v for v in values)
                or len(values) != len(set(values))):
            raise ValueError("invalid or duplicate record identifier")
    return document, raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "enable", "disable"))
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--package", type=Path, help="Prepared api/grants.json, for install only")
    parser.add_argument("--allocation-id", help="Existing allocation, for enable/disable")
    args = parser.parse_args()
    if args.action == "install":
        if not args.package or args.allocation_id:
            parser.error("install requires --package and no --allocation-id")
    elif not args.allocation_id or args.package:
        parser.error("enable/disable requires --allocation-id and no --package")
    store = args.store.expanduser().absolute()
    store.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = store.with_name(store.name + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("configuration lock must be an owned regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if store.exists() or store.is_symlink():
            document, previous = read_document(store)
            metadata = store.stat()
            if metadata.st_uid != os.getuid():
                raise ValueError("run as the configuration owner to preserve file ownership")
        else:
            if args.action != "install":
                raise ValueError("allocation store does not exist")
            document = {"schema": "polaris_workers_grants_v1", "allocations": [], "grants": []}
            previous, metadata = None, None
        if args.action == "install":
            package, _ = read_document(args.package)
            if len(package["allocations"]) != 1 or len(package["grants"]) != 1:
                raise ValueError("install exactly one prepared allocation and grant")
            allocation, grant = package["allocations"][0], package["grants"][0]
            if (allocation.get("enabled") is not False or grant.get("allocation_id") != allocation["allocation_id"]
                    or allocation.get("owner_id") != grant.get("owner_id")
                    or allocation.get("concurrent_limit") != 50 or grant.get("concurrent_limit") != 50):
                raise ValueError("package must contain a disabled matching 50-slot grant")
            if (any(a["allocation_id"] == allocation["allocation_id"] for a in document["allocations"])
                    or any(g["grant_id"] == grant["grant_id"] for g in document["grants"])):
                raise ValueError("allocation or grant already exists; refusing to replace it")
            # The API resolves unexpired owner grants before checking the
            # allocation's enabled flag. A disabled second allocation must not
            # add an overlapping grant and interrupt the existing customer.
            now = datetime.now(timezone.utc)
            if any(g.get("owner_id") == grant.get("owner_id")
                   and datetime.fromisoformat(g["expires_at"].replace("Z", "+00:00")) > now
                   for g in document["grants"]):
                raise ValueError("owner already has an unexpired grant; refusing an overlapping installation")
            document["allocations"].append(allocation)
            document["grants"].append(grant)
            changed_id = allocation["allocation_id"]
        else:
            matches = [a for a in document["allocations"] if a["allocation_id"] == args.allocation_id]
            if len(matches) != 1:
                raise ValueError("allocation not found")
            allocation = matches[0]
            if args.action == "enable":
                now = datetime.now(timezone.utc)
                grants = [g for g in document["grants"] if g.get("allocation_id") == args.allocation_id
                          and datetime.fromisoformat(g["expires_at"].replace("Z", "+00:00")) > now]
                if (len(grants) != 1 or grants[0].get("owner_id") != allocation.get("owner_id")
                        or grants[0].get("concurrent_limit") != allocation.get("concurrent_limit")):
                    raise ValueError("allocation needs one matching unexpired grant")
                if any(a.get("enabled") and a["allocation_id"] != args.allocation_id
                       and (a.get("endpoint", "").rstrip("/").lower() == allocation.get("endpoint", "").rstrip("/").lower()
                            or a.get("owner_id") == allocation.get("owner_id")) for a in document["allocations"]):
                    raise ValueError("owner or executor already has an enabled allocation")
            allocation["enabled"] = args.action == "enable"
            changed_id = args.allocation_id
        if len(document["allocations"]) > 64 or len(document["grants"]) > 256:
            raise ValueError("configuration record limit exceeded")
        validate_configuration(document)
        encoded = (json.dumps(document, indent=2, allow_nan=False) + "\n").encode()
        if len(encoded) > MAX_BYTES:
            raise ValueError("configuration exceeds 1 MiB")
        if previous is not None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            backup = store.with_name(f"{store.name}.{stamp}.bak")
            backup_fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(backup_fd, "wb") as stream:
                stream.write(previous)
                stream.flush()
                os.fsync(stream.fileno())
        new_fd, temporary = tempfile.mkstemp(prefix=".workers-grants-", dir=store.parent)
        try:
            if metadata is not None:
                os.fchown(new_fd, metadata.st_uid, metadata.st_gid)
            os.fchmod(new_fd, stat.S_IMODE(metadata.st_mode) if metadata is not None else 0o600)
            with os.fdopen(new_fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, store)
            directory_fd = os.open(store.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        print(json.dumps({"allocation_id": changed_id, "action": args.action,
                          "store": str(store), "qualification": "UNCHANGED"}))
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError):
        raise SystemExit("Admission configuration failed. Check the package, ownership and allocation. No credentials were printed.")
