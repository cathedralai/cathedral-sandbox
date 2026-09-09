#!/usr/bin/env python3
"""Wait for actual executor inflight to reach zero after disabling admission."""
from __future__ import annotations

import argparse
import http.client
import json
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--pki", type=Path, required=True, help="API client TLS package")
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--timeout", type=int, default=150)
    args = parser.parse_args()
    url = urlsplit(args.endpoint)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment or not 1 <= args.timeout <= 600):
        parser.error("provide an HTTPS executor origin and a timeout between 1 and 600 seconds")
    context = ssl.create_default_context(cafile=str(args.pki / "ca.crt"))
    context.load_cert_chain(str(args.pki / "client.crt"), str(args.pki / "client.key"))
    deadline = time.monotonic() + args.timeout
    idle_since = None
    while time.monotonic() < deadline:
        with_connection = http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=5)
        try:
            with_connection.request("GET", "/v1/health", headers={"Accept": "application/json", "Connection": "close"})
            response = with_connection.getresponse()
            raw = response.read(65537)
            if len(raw) > 65536 or response.status not in (200, 503):
                raise ValueError("health unavailable")
            health = json.loads(raw)
            if health.get("runtime_id") != args.runtime_id:
                raise ValueError("runtime mismatch")
            inflight = health["api"]["inflight"]
            if type(inflight) is not int or inflight < 0:
                raise ValueError("invalid inflight")
            if inflight == 0:
                idle_since = idle_since or time.monotonic()
                # Allow requests admitted immediately before the file change
                # to reach the executor before declaring the HTTP work drained.
                if time.monotonic() - idle_since >= 10:
                    print(json.dumps({"status": "drained", "inflight": 0,
                                      "runtime_id": args.runtime_id, "cleanup_qualification": "NOT_ASSESSED"}))
                    return 0
            else:
                idle_since = None
        finally:
            with_connection.close()
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
    raise SystemExit("Executor did not drain before the deadline. Do not force-stop it as a successful drain.")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        raise SystemExit("Unable to confirm drain. Admission should remain disabled. No credential contents were printed.")
