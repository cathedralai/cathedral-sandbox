#!/usr/bin/env python3
"""Owner signature for a create on a dedicated sealed machine.

A dedicated machine names one owner key in its chip-signed HOST_DATA, and its
measured receipts front refuses every room create that the owner did not
sign. This prints the two headers for one create body:

  X-Cathedral-Owner-Timestamp: <unix seconds>
  X-Cathedral-Owner-Signature: <base64 Ed25519 signature>

The signature is over
  "cathedral-owner-create-v1\\n" || timestamp || "\\n" || owner_request_sha256
where owner_request_sha256 is the sha256 of the canonical JSON of the create
as the hotel receives it (room_receipts.owner_request_sha256). The broker
changes a create before the hotel sees it, so this script makes the same
changes first:
  - a missing or null "network" becomes {"mode": "deny_all", "allow": []};
  - "count" and the placement fields ("hotels", "hotel_labels",
    "exclude_hotel_labels", "sealed", "placement") are removed;
  - a workspace named "<hotel>.<name>" becomes "<name>";
  - labels gets "broker_guest": <your broker guest id>.
The broker also adds a random "broker_batch" label; the hotel leaves that
one out of the digest. A create that names a "template" without an image, or
a "snapshot_id", is refused here: the broker rewrites those, so the hotel
would not see the body that was signed.

The signature is good for 300 s on the hotel clock, and for every room of a
"count" batch (each room's create carries the same body).

Key: an Ed25519 private key in PEM (openssl genpkey -algorithm ed25519 -out owner.pem).

Usage:
  owner_sign.py --key owner.pem --guest <guest id> --body create.json
  curl -H @<(owner_sign.py --key owner.pem --guest acme --body create.json) \\
       -H "Authorization: Bearer $KEY" --data @create.json https://<broker>/v1/sandboxes
  owner_sign.py --key owner.pem --public                 # base64, for verify_receipts.py --owner-pubkey
  owner_sign.py --key owner.pem --public --raw-out owner.pub  # 32 raw bytes, for SEALED_OWNER_PUBKEY_FILE
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BROKER_PLACEMENT_FIELDS = ("hotels", "hotel_labels", "exclude_hotel_labels", "sealed", "placement")
# Same rule as room_receipts.owner_request_sha256: the only label left out.
OWNER_UNSIGNED_LABELS = ("broker_batch",)


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _whole_numbers(doc):
    """2.0 -> 2, recursively, as in room_receipts.py (the broker re-encodes numbers)."""
    if isinstance(doc, float) and doc.is_integer():
        return int(doc)
    if isinstance(doc, dict):
        return {k: _whole_numbers(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_whole_numbers(v) for v in doc]
    return doc


def hotel_form(doc: dict, guest: str) -> dict:
    """The create as the broker sends it to the hotel, without broker_batch.

    Mirrors broker/main.go handleCreate and createMany, broker/images.go
    placement.apply and broker/workspaces.go findWorkspace. Raises ValueError
    for a create the broker rewrites in a way the guest cannot predict.
    """
    if not isinstance(doc, dict):
        raise ValueError("the create body is not a JSON object")
    if not guest:
        raise ValueError("the broker guest id is required (it becomes the broker_guest label)")
    out = dict(doc)
    if out.get("template") and not out.get("image") and not out.get("image_id"):
        raise ValueError("name the image: the broker rewrites a template create, so the hotel would not see this body")
    if out.get("snapshot_id"):
        raise ValueError("a snapshot fork is rewritten by the broker (hotel snapshot id); not signable yet")
    if out.get("network") in (None, ""):
        out["network"] = {"mode": "deny_all", "allow": []}
    ws = out.get("workspace")
    name = ws if isinstance(ws, str) else (ws.get("name") if isinstance(ws, dict) else None)
    if isinstance(name, str) and "." in name:  # the broker cuts "<hotel>." off and sends the hotel's name
        bare = name.split(".", 1)[1]
        out["workspace"] = bare if isinstance(ws, str) else {**ws, "name": bare}
    for k in BROKER_PLACEMENT_FIELDS + ("count",):
        out.pop(k, None)
    labels = dict(out["labels"]) if isinstance(out.get("labels"), dict) else {}
    labels["broker_guest"] = guest
    for k in OWNER_UNSIGNED_LABELS:
        labels.pop(k, None)
    out["labels"] = labels
    return out


def owner_request_sha256(doc: dict) -> str:
    return hashlib.sha256(canonical(_whole_numbers(doc))).hexdigest()


def sign_create(key: Ed25519PrivateKey, body: bytes, guest: str, now: int | None = None) -> dict[str, str]:
    """The two headers for one create body (bytes as the guest sends them)."""
    ts = str(int(time.time()) if now is None else int(now))
    digest = owner_request_sha256(hotel_form(json.loads(body), guest))
    sig = key.sign(f"cathedral-owner-create-v1\n{ts}\n{digest}".encode())
    return {"X-Cathedral-Owner-Timestamp": ts, "X-Cathedral-Owner-Signature": base64.b64encode(sig).decode()}


def load_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} is not an Ed25519 private key")
    return key


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", required=True, help="owner Ed25519 private key, PEM")
    ap.add_argument("--body", help="create body file (JSON), exactly as sent to the broker")
    ap.add_argument("--guest", help="your broker guest id (the broker_guest label)")
    ap.add_argument("--timestamp", type=int, help="unix seconds (default: now)")
    ap.add_argument("--public", action="store_true", help="print the public key (base64) and exit")
    ap.add_argument("--raw-out", help="with --public: also write the 32 raw public key bytes here")
    a = ap.parse_args()
    key = load_key(a.key)
    if a.public:
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if a.raw_out:
            with open(a.raw_out, "wb") as f:
                f.write(raw)
        print(base64.b64encode(raw).decode())
        return 0
    if not a.body or not a.guest:
        ap.error("--body and --guest are required to sign a create")
    with open(a.body, "rb") as f:
        body = f.read()
    try:
        headers = sign_create(key, body, a.guest, a.timestamp)
    except ValueError as exc:
        print(f"owner_sign: {exc}", file=sys.stderr)
        return 1
    for k, v in headers.items():
        print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
