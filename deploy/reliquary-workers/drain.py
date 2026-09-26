#!/usr/bin/env python3
"""Fence every inventoried API process, then observe physical executor drain."""
from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit


def request_json(origin, path, *, method="GET", token=None, context=None, timeout=5):
    url = urlsplit(origin)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment):
        raise ValueError("HTTPS origin required")
    connection = http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=timeout)
    try:
        headers = {"Accept": "application/json", "Connection": "close"}
        if token:
            headers["Authorization"] = "Bearer " + token
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        raw = response.read(65537)
        if response.status not in (200, 503) or len(raw) > 65536:
            raise ValueError("operator or executor response unavailable")
        return json.loads(raw)
    finally:
        connection.close()


def validate_replica(state, expected, allocation_id, runtime_id):
    if (state.get("replica_id") != expected["replica_id"] or state.get("boot_id") != expected["boot_id"]
            or state.get("allocation_id") != allocation_id or state.get("runtime_id") != runtime_id
            or state.get("configuration_enabled") is not False or state.get("admission_closed") is not True):
        raise ValueError("missing fence, changed boot or wrong replica")
    for name in ("dispatches_pending", "dispatches_unknown"):
        if type(state.get(name)) is not int or state[name] < 0:
            raise ValueError("invalid dispatch count")
    if state["dispatches_unknown"]:
        raise ValueError("ambiguous dispatch requires executor stop and recovery, not a graceful-drain claim")
    return state["dispatches_pending"] == 0


def wait_for_drain(args, replicas, token, context, *, request=request_json, monotonic=time.monotonic, sleep=time.sleep):
    deadline = monotonic() + args.timeout
    while monotonic() < deadline:
        all_closed = True
        for replica in replicas:
            state = request(replica["origin"], f"/v1/workers/operator/fence/{args.allocation_id}",
                            method="POST", token=token, timeout=min(5, max(0.001, deadline - monotonic())))
            all_closed = validate_replica(state, replica, args.allocation_id, args.runtime_id) and all_closed
        if all_closed:
            health = request(args.endpoint, "/v1/health", context=context,
                             timeout=min(5, max(0.001, deadline - monotonic())))
            if health.get("runtime_id") != args.runtime_id or health.get("executor_id") != args.allocation_id:
                raise ValueError("executor identity mismatch")
            inflight = health["api"]["inflight"]
            if type(inflight) is not int or inflight < 0:
                raise ValueError("invalid physical inflight")
            if inflight == 0:
                return {"status": "drained", "allocation_id": args.allocation_id, "inflight": 0,
                        "runtime_id": args.runtime_id, "replicas": [r["replica_id"] for r in replicas],
                        "cleanup_qualification": "NOT_ASSESSED"}
        sleep(min(0.5, max(0, deadline - monotonic())))
    raise ValueError("drain deadline exceeded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--pki", type=Path, required=True)
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--allocation-id", required=True)
    parser.add_argument("--replicas", type=Path, required=True, help="Complete serving-process inventory recorded BEFORE enabling admission")
    parser.add_argument("--operator-token-file", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=150)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", args.allocation_id) or not 1 <= args.timeout <= 600:
        parser.error("invalid allocation or timeout")
    inventory = json.loads(args.replicas.read_text())
    replicas = inventory["replicas"]
    if (inventory.get("allocation_id") != args.allocation_id or not replicas or len(replicas) > 64
            or len({r["replica_id"] for r in replicas}) != len(replicas)
            or len({r["origin"] for r in replicas}) != len(replicas)
            or any(not r["boot_id"] for r in replicas)):
        raise ValueError("invalid complete replica inventory")
    token = args.operator_token_file.read_text().strip()
    if not 32 <= len(token) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("invalid operator token")
    context = ssl.create_default_context(cafile=str(args.pki / "ca.crt"))
    context.load_cert_chain(str(args.pki / "client.crt"), str(args.pki / "client.key"))
    print(json.dumps(wait_for_drain(args, replicas, token, context)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        raise SystemExit("Drain NOT CONFIRMED. Keep admission disabled. Check every replica, boot identity and uncertain dispatch before stopping the executor. No credentials were printed.")
