#!/usr/bin/env python3
"""Offline CLI rejection contract. No hardware, customer payload or secret files."""

import json
import subprocess
import sys

result = subprocess.run(
    [sys.executable, "-m", "cathedral.cli", "executor", "check-grant"],
    input=json.dumps({"grant": {}, "control_plane_public_key": "00" * 32, "now": 1}),
    text=True,
    capture_output=True,
    timeout=10,
)
try:
    body = json.loads(result.stdout)
except ValueError:
    raise SystemExit("FAIL: executor CLI has no stable rejection contract")
assert result.returncode == 2 and body.get("code") == "invalid_executor_grant", body
assert body.get("eligible") is False, body
print(json.dumps({"status": "PASS", "scope": "CLI invalid grant rejects without external calls"}))
