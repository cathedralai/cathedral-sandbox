"""Run the checker's command line on one golden case and return its stdout bytes and exit code."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKER = HERE.parents[2] / "room-kit" / "verify_receipts.py"


def _broker(case: Path):
    attestation = (case / "attestation_doc.json").read_bytes()
    page = (case / "receipts.json").read_bytes()
    archive = json.loads((case / "archive.json").read_text())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            return

        def _send(self, status: int, body: bytes = b"") -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            token = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
            if self.path.startswith("/v1/broker/bindings/") and token == "operator":
                binding = archive.get(self.path.rsplit("/", 1)[-1])
                body = (json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                        if binding else b"")
                return self._send(200 if binding else 404, body)
            if self.path == "/v1/hotels/h1/attestation" and token == "guest":
                return self._send(200, attestation)
            if self.path.startswith("/v1/hotels/h1/receipts") and token == "guest":
                return self._send(200, page)
            return self._send(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run_case(name: str) -> tuple[bytes, int]:
    spec = json.loads((HERE / "cases.json").read_text())[name]
    case = HERE / "cases" / name
    server = _broker(case) if spec.get("broker") else None
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}" if server else ""
        args = [a.replace("{dir}", str(case)).replace("{broker}", base) for a in spec["args"]]
        proc = subprocess.run([sys.executable, str(CHECKER), *args], capture_output=True)
        return proc.stdout, proc.returncode
    finally:
        if server:
            server.shutdown()
