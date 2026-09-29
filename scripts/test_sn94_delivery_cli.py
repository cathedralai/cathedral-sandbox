#!/usr/bin/env python3
"""Local CLI contract test. No wallet, host, provider, or signing secret file."""

import json
import subprocess
import sys

request = {"receipt": {}, "executor_public_key": "00" * 32, "control_plane_public_key": "00" * 32}
result = subprocess.run(
    [sys.executable, "-m", "cathedral.cli", "delivery-receipt", "check"],
    input=json.dumps(request),
    text=True,
    capture_output=True,
    timeout=10,
)
try:
    body = json.loads(result.stdout)
except ValueError:
    raise SystemExit("FAIL: delivery-receipt CLI has no stable rejection contract")
assert result.returncode == 2 and body.get("code") == "invalid_delivery_receipt", body
assert body.get("eligible") is False, body
print(json.dumps({"status": "PASS", "scope": "CLI invalid receipt rejects without external calls"}))
