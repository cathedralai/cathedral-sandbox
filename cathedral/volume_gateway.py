"""Storage gateway for synced volumes: restic's REST protocol behind a per-request sub-token check (AB#789).

The sealed guest never holds the bucket's keys. It talks to this gateway with the
per-mount sub-token the registry issued (volume_subtoken.py) as the HTTP Basic
password, base64url of the token's JSON. Every request is checked with
volume_subtoken.authorize() for its operation, its object key and the TCP peer
address, before anything is read or written:

    GET, HEAD           get
    POST                put
    GET <type>/         list
    DELETE              delete (no guest sub-token carries it; a prune token does)

Objects are kept under <root>/<key>, key = the URL path without its leading "/",
so the volume's repo URL is rest:http://<gateway>/volumes/<volume_id>/ and every
key starts with the token's prefix. This module keeps objects on a local
directory, which is what the two-host proof runs against. In front of the
Hippius bucket (AB#394) the same check runs before the request is forwarded.

restic removes its lock file after every run. A guest token has no delete, so
that removal is refused and the lock stays; restic warns and the snapshot is
already stored. A stale lock is reclaimed by restic after 30 minutes, and prune
(control plane, prune token) clears them.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cathedral import volume_subtoken
from cathedral.volume_chain import VolumeRefused

TYPES = ("data", "keys", "locks", "snapshots", "index")
NAME_RE = re.compile(r"[0-9a-f]{64}")
MAX_BODY = 512 * 1024 * 1024
MAX_TOKEN_HEADER = 8192
V2 = "application/vnd.x.restic.rest.v2"


def encode_token(token: dict) -> str:
    """The Basic password a guest sends: base64url of the token's canonical JSON, no padding."""
    raw = json.dumps(token, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_token(header: str | None) -> dict:
    if not header or len(header) > MAX_TOKEN_HEADER or not header.startswith("Basic "):
        raise VolumeRefused("no_token")
    try:
        userpass = base64.b64decode(header[6:], validate=True).decode()
        _, _, password = userpass.partition(":")
        padded = password + "=" * (-len(password) % 4)
        token = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise VolumeRefused("malformed") from None
    if not isinstance(token, dict):
        raise VolumeRefused("malformed")
    return token


def parse_path(path: str) -> tuple[str, str | None, str | None]:
    """(repo key prefix, type, name) for a restic REST path. Raises VolumeRefused on anything else.

    /volumes/v1/config           -> ("volumes/v1/", None, None) with the key volumes/v1/config
    /volumes/v1/data/            -> list of data
    /volumes/v1/data/<64 hex>    -> one object
    """
    path = unquote(urlsplit(path).path)
    if not path.startswith("/volumes/") or "\x00" in path:
        raise VolumeRefused("outside_prefix")
    parts = path[1:].split("/")
    if len(parts) < 3 or not parts[1] or any(p in (".", "..") for p in parts):
        raise VolumeRefused("outside_prefix")
    repo = "/".join(parts[:2]) + "/"
    rest = parts[2:]
    if rest == [""]:
        return repo, "", None  # the repo root (create)
    if rest == ["config"]:
        return repo, "config", None
    if len(rest) == 2 and rest[0] in TYPES:
        if rest[1] == "":
            return repo, rest[0], None
        if NAME_RE.fullmatch(rest[1]):
            return repo, rest[0], rest[1]
    raise VolumeRefused("outside_prefix")


class Gateway:
    def __init__(self, root: Path, registry_public_b64: str):
        self.root = Path(root)
        self.registry_public_b64 = registry_public_b64
        self.refusals: list[dict] = []
        self.lock = threading.Lock()

    def file(self, key: str) -> Path:
        target = (self.root / key).resolve()
        if not str(target).startswith(str(self.root.resolve()) + os.sep):
            raise VolumeRefused("outside_prefix")
        return target

    def check(self, header: str | None, op: str, key: str, peer: str) -> None:
        try:
            volume_subtoken.authorize(decode_token(header), self.registry_public_b64, op=op, key=key,
                                      source_ip=peer)
        except VolumeRefused as refused:
            with self.lock:
                self.refusals.append({"op": op, "key": key, "code": refused.code})
            raise


def make_handler(gateway: Gateway):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # requests carry tokens in headers, never log them
            return

        def _send(self, code: int, body: bytes = b"", ctype: str = "application/octet-stream") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)

        def _refuse(self, refused: VolumeRefused) -> None:
            code = 401 if refused.code in ("no_token", "malformed", "bad_signature", "wrong_schema",
                                           "token_expired") else 403
            if refused.code == "outside_prefix":
                code = 404 if self.command in ("GET", "HEAD") else 403
            self._send(code, json.dumps({"error": refused.code}).encode(), "application/json")

        def _drain(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            if length < 0 or length > MAX_BODY:
                raise VolumeRefused("too_large")
            return self.rfile.read(length) if length else b""

        def _handle(self) -> None:
            peer = self.client_address[0]
            auth = self.headers.get("Authorization")
            try:
                repo, kind, name = parse_path(self.path)
                if kind in ("", "config"):
                    key = repo + kind
                else:
                    key = repo + kind + "/" + (name or "")
                if self.command == "POST" and kind == "":
                    gateway.check(auth, "put", repo + "config", peer)
                    self._drain()
                    gateway.file(repo).mkdir(parents=True, exist_ok=True)
                    return self._send(200)
                if kind not in ("config", "") and name is None:
                    if self.command != "GET":
                        raise VolumeRefused("op_not_allowed")
                    gateway.check(auth, "list", key, peer)
                    folder = gateway.file(key)
                    entries = sorted(folder.iterdir()) if folder.is_dir() else []
                    if V2 in (self.headers.get("Accept") or ""):
                        body = [{"name": e.name, "size": e.stat().st_size} for e in entries if e.is_file()]
                        return self._send(200, json.dumps(body).encode(), V2)
                    return self._send(200, json.dumps([e.name for e in entries]).encode(), "application/json")
                op = {"GET": "get", "HEAD": "get", "POST": "put", "DELETE": "delete"}.get(self.command)
                if op is None:
                    raise VolumeRefused("op_not_allowed")
                gateway.check(auth, op, key, peer)
                target = gateway.file(key)
                if op == "put":
                    data = self._drain()
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # restic objects are content-addressed and never rewritten; config is written once at init.
                    if target.exists():
                        return self._send(403, b'{"error":"exists"}', "application/json")
                    fd, tmp = tempfile.mkstemp(dir=target.parent)
                    with os.fdopen(fd, "wb") as out:
                        out.write(data)
                    os.replace(tmp, target)
                    return self._send(200)
                if op == "delete":
                    if target.is_file():
                        target.unlink()
                    return self._send(200)
                if not target.is_file():
                    return self._send(404)
                data = target.read_bytes()
                span = self.headers.get("Range")
                if span and self.command == "GET":
                    match = re.fullmatch(r"bytes=(\d+)-(\d*)", span.strip())
                    if not match:
                        return self._send(416)
                    start = int(match.group(1))
                    end = int(match.group(2)) if match.group(2) else len(data) - 1
                    if start >= len(data) or end < start:
                        return self._send(416)
                    part = data[start:end + 1]
                    self.send_response(206)
                    self.send_header("Content-Length", str(len(part)))
                    self.send_header("Content-Range", f"bytes {start}-{start + len(part) - 1}/{len(data)}")
                    self.end_headers()
                    self.wfile.write(part)
                    return None
                if self.command == "HEAD":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    return None
                return self._send(200, data)
            except VolumeRefused as refused:
                self.close_connection = True
                return self._refuse(refused)

        do_GET = do_HEAD = do_POST = do_DELETE = _handle

    return Handler


def serve(root: Path, registry_public_b64: str, host: str = "127.0.0.1", port: int = 0):
    """Start a gateway on a thread. Returns (server, gateway); server.server_address has the port."""
    gateway = Gateway(root, registry_public_b64)
    server = ThreadingHTTPServer((host, port), make_handler(gateway))
    threading.Thread(target=server.serve_forever, name="volume-gateway", daemon=True).start()
    return server, gateway


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", required=True)
    parser.add_argument("--registry-public-b64", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8460)
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(Gateway(Path(args.root),
                                                                               args.registry_public_b64)))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
