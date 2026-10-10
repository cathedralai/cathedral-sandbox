#!/usr/bin/env python3
"""Drive B.b (and helpers) on measured SNP once Fred-signed materials exist.

Uses the operator central seed + Fred-signed delegation / revocation list.
Does not mint root signatures. Does not overwrite measured central-root-keys.

Env:
  CENTRAL_SEED   path to central seed (base64 32-byte Ed25519)
  MATERIALS      dir with delegation-full.json + revocations-first.json
  WORKER_HOST    default 127.0.0.1
  WORKER_PORT    default 8443
  WORKER_HOTKEY  default smoke hotkey
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cathedral.central_access import (  # noqa: E402
    CENTRAL_REQUEST_HEADER,
    build_central_request_header,
)
from cathedral.channel import tls_spki_binding  # noqa: E402

HOTKEY = os.environ.get(
    "WORKER_HOTKEY", "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
)
NETWORK, NETUID = "finney", 94
DEFAULT_MATERIALS = Path(__file__).resolve().parent / "central_access_materials"


def _die(msg: str, code: int = 2) -> int:
    print(f"FAIL: {msg}", file=sys.stderr)
    return code


def _load_seed(path: Path) -> bytes:
    raw = path.read_text().strip()
    seed = base64.b64decode(raw, validate=True)
    if len(seed) != 32:
        raise SystemExit(f"central seed must be 32 bytes, got {len(seed)}")
    return seed


def _materials_dir() -> Path:
    return Path(os.environ.get("MATERIALS", str(DEFAULT_MATERIALS)))


def _load_json(name: str) -> dict:
    path = _materials_dir() / name
    if not path.is_file():
        raise SystemExit(f"missing {path} — drop Fred's signed file here")
    return json.loads(path.read_bytes())


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _peer_binding(host: str, port: int) -> bytes:
    import http.client

    conn = http.client.HTTPSConnection(host, port, context=_tls_context(), timeout=30)
    try:
        conn.connect()
        peer = conn.sock.getpeercert(binary_form=True)
        return tls_spki_binding(peer)
    finally:
        conn.close()


def call(
    *,
    method: str,
    path: str,
    body: bytes | None,
    delegation: dict,
    seed: bytes,
    host: str,
    port: int,
) -> tuple[int, object]:
    import http.client

    binding = _peer_binding(host, port)
    now = datetime.now(UTC).replace(microsecond=0)
    header = build_central_request_header(
        delegation=delegation,
        central_seed=seed,
        worker_hotkey=HOTKEY,
        network=NETWORK,
        netuid=NETUID,
        method=method,
        path=path,
        body=body or b"",
        channel_binding=binding,
        nonce=secrets.token_bytes(32),
        issued_at=now,
        expires_at=now + timedelta(seconds=110),
    )
    conn = http.client.HTTPSConnection(host, port, context=_tls_context(), timeout=120)
    try:
        conn.connect()
        peer = conn.sock.getpeercert(binary_form=True)
        if tls_spki_binding(peer) != binding:
            raise RuntimeError("TLS SPKI changed between pin and request")
        conn.request(
            method,
            path,
            body=body,
            headers={CENTRAL_REQUEST_HEADER: header},
        )
        resp = conn.getresponse()
        data = resp.read()
        status = resp.status
    finally:
        conn.close()
    try:
        document: object = json.loads(data)
    except ValueError:
        document = data[:500].decode("utf-8", "replace")
    return status, document


def cmd_push_revocations(args: argparse.Namespace) -> int:
    seed_path = Path(os.environ.get("CENTRAL_SEED", ""))
    if not seed_path.is_file():
        return _die("set CENTRAL_SEED to the central seed path")
    seed = _load_seed(seed_path)
    delegation = _load_json("delegation-full.json")
    rev_path = _materials_dir() / "revocations-first.json"
    if not rev_path.is_file():
        return _die(f"missing {rev_path}")
    body = rev_path.read_bytes()
    status, doc = call(
        method="POST",
        path="/v1/box/revocations",
        body=body,
        delegation=delegation,
        seed=seed,
        host=args.host,
        port=args.port,
    )
    print(json.dumps({"status": status, "body": doc}, indent=2, default=str))
    return 0 if status in (200, 204) or (
        isinstance(doc, dict) and doc.get("ok") is True
    ) else 1


def cmd_get_box(args: argparse.Namespace) -> int:
    seed_path = Path(os.environ.get("CENTRAL_SEED", ""))
    if not seed_path.is_file():
        return _die("set CENTRAL_SEED to the central seed path")
    seed = _load_seed(seed_path)
    delegation = _load_json("delegation-full.json")
    status, doc = call(
        method="GET",
        path="/v1/box",
        body=None,
        delegation=delegation,
        seed=seed,
        host=args.host,
        port=args.port,
    )
    print(json.dumps({"status": status, "body": doc}, indent=2, default=str))
    return 0 if status == 200 else 1


def cmd_smoke_bb(args: argparse.Namespace) -> int:
    """B.b-shaped smoke: get-box before/after push; expect routes open after."""

    print("== get-box (may be open for GET without list) ==")
    rc1 = cmd_get_box(args)
    print("== push first revocations list ==")
    rc2 = cmd_push_revocations(args)
    print("== get-box after push ==")
    rc3 = cmd_get_box(args)
    if rc2 != 0:
        return _die("revocations push failed — check Fred list + tee-box:revocations scope")
    if rc3 != 0:
        return _die("get-box failed after push")
    print("B.b smoke: push + get-box OK (record full matrix separately)")
    return 0 if rc1 in (0, 1) else rc1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=os.environ.get("WORKER_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("WORKER_PORT", "8443")))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("push-revocations").set_defaults(func=cmd_push_revocations)
    sub.add_parser("get-box").set_defaults(func=cmd_get_box)
    sub.add_parser("smoke-bb").set_defaults(func=cmd_smoke_bb)
    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
