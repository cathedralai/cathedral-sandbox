#!/usr/bin/env python3
"""Room kit: Preview URL ingress served from inside the sealed guest (AB#422).

The receipts front runs this when ROOM_GUEST_INGRESS=1 and the measured
room.env names a zone (ROOM_INGRESS_ZONE) and the broker (ROOM_INGRESS_BROKER_URL).

- TLS ends here, in the front's own process, on the ingress key the front made
  at start (room_receipts.GuestIngress) and the binding names
  (guest_ingress.tls_spki_sha256). The private key is never written to the
  scratch or data disk: ssl.load_cert_chain reads a file only, so the PEM is
  written root-only into the front's private store on /run (tmpfs, guest
  memory), loaded and removed at once, as for the miner hotel key.
- Until the CA answers, the listener serves the same key under its
  self-issued certificate. The keeper (CertKeeper) gets a certificate for
  <hotel>.<zone> and *.<hotel>.<zone> over DNS-01 (room_acme.py) and swaps it
  in; it renews two thirds into the certificate's life.
- A signed expose (POST /v1/sandboxes/<id>/expose at the front) names the URL
  https://<room label>-<port>.<hotel>.<zone>/ and records it here. A request
  to that host is passed, as one HTTP request and answer, to the room API's
  guest port dial (POST /v1/sandboxes/<id>/ports/<port>/http, AB#605), which
  reaches 127.0.0.1:<port> inside the room. Hosts nothing exposed answer 404.
  No WebSocket or streamed answer yet: the dial buffers.
"""
from __future__ import annotations

import http.client
import os
import re
import ssl
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import room_acme  # noqa: E402  (installed beside this file)

DNS_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
DNS_ZONE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ROOM_ID = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*$")
MAX_BODY = 16 << 20
UPSTREAM_TIMEOUT = 60
# Never passed on to the room API: hop headers, and the ones the front sets itself.
DROP_REQUEST = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization",
                "proxy-authenticate", "content-length", "host", "authorization", "x-guest-method", "x-guest-target",
                "x-cathedral-guest", "x-room-exec-handle"}
DROP_RESPONSE = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization",
                 "proxy-authenticate", "content-length"}
FIRST_RETRY_SECONDS = 30
MAX_RETRY_SECONDS = 3600
MIN_RENEW_WAIT_SECONDS = 3600


@dataclass(frozen=True)
class IngressConfig:
    zone: str
    broker_url: str
    listen: tuple[str, int]
    public_port: int = 443
    directory_url: str = room_acme.LETS_ENCRYPT_DIRECTORY
    contact_email: str = ""
    dns_wait: float = 20.0

    @staticmethod
    def from_env(env) -> "IngressConfig | None":
        """None when no zone is set: the key is made and named, nothing serves (as before AB#422's server)."""
        zone = (env.get("ROOM_INGRESS_ZONE") or "").strip()
        if not zone:
            return None
        if not DNS_ZONE.fullmatch(zone) or len(zone) > 200:
            raise ValueError("ROOM_INGRESS_ZONE must be a lower-case DNS name")
        broker = (env.get("ROOM_INGRESS_BROKER_URL") or "").strip()
        if not broker or not room_acme.loopback_http_ok(broker):
            raise ValueError("ROOM_INGRESS_BROKER_URL must be the broker's https URL")
        directory = (env.get("ROOM_ACME_DIRECTORY") or room_acme.LETS_ENCRYPT_DIRECTORY).strip()
        if not room_acme.loopback_http_ok(directory):
            raise ValueError("ROOM_ACME_DIRECTORY must be an https URL")
        host, _, port = (env.get("ROOM_INGRESS_TLS_LISTEN") or "").rpartition(":")
        public = env.get("ROOM_INGRESS_PUBLIC_PORT") or "443"
        if not host or not port.isdigit() or not 0 < int(port) < 65536 or not public.isdigit() \
                or not 0 < int(public) < 65536:
            raise ValueError("ROOM_INGRESS_TLS_LISTEN must be host:port and ROOM_INGRESS_PUBLIC_PORT a port")
        wait = float(env.get("ROOM_ACME_DNS_WAIT") or "20")
        return IngressConfig(zone=zone, broker_url=broker, listen=(host, int(port)), public_port=int(public),
                             directory_url=directory, contact_email=(env.get("ROOM_ACME_EMAIL") or "").strip(),
                             dns_wait=max(0.0, min(wait, 600.0)))


def room_label(room: str, port: int) -> str | None:
    """The one DNS label of a room port's URL: sbx_0123abcd and 8080 give sbx-0123abcd-8080."""
    if not ROOM_ID.fullmatch(room or ""):
        return None
    label = f"{room.replace('_', '-')}-{port}"
    return label if DNS_LABEL.fullmatch(label) else None


class IngressState:
    """The serving side of the guest ingress key: TLS context, certificate state, exposed ports."""

    def __init__(self, ingress, hotel: str, config: IngressConfig, private_dir: str):
        if not DNS_LABEL.fullmatch(hotel or ""):
            raise ValueError("the hotel id must be one lower-case DNS label to get a Preview URL name")
        self.ingress, self.hotel, self.config, self.private_dir = ingress, hotel, config, private_dir
        self.base = f"{hotel}.{config.zone}"
        self.lock = threading.Lock()
        self.exposed: dict[str, tuple[str, int]] = {}  # label -> (room, port)
        self.leaf: x509.Certificate | None = None  # the CA certificate in use; None: self-issued
        self.context = self._context(ingress.cert_pem)

    def __repr__(self) -> str:
        return f"IngressState(base={self.base!r}, ready={self.ready})"

    @property
    def ready(self) -> bool:
        return self.leaf is not None

    def names(self) -> list[str]:
        return [self.base, f"*.{self.base}"]

    def private_key(self):
        return load_pem_private_key(self.ingress.key_pem(), password=None)

    def _context(self, chain_pem: bytes) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["http/1.1"])
        fd, path = tempfile.mkstemp(prefix=".ingress.", dir=self.private_dir)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, self.ingress.key_pem() + chain_pem)
            os.close(fd)
            fd = -1
            ctx.load_cert_chain(path)
        finally:
            if fd >= 0:
                os.close(fd)
            os.unlink(path)
        return ctx

    def install_chain(self, chain_pem: str) -> x509.Certificate:
        """Serve *chain_pem* from the next handshake on. Its leaf must be the ingress key and name both names."""
        leaf = room_acme.check_chain(chain_pem, self.names(), self.private_key())
        ctx = self._context(chain_pem.encode())
        with self.lock:
            self.context, self.leaf = ctx, leaf
        return leaf

    def url_for(self, label: str) -> tuple[str, str]:
        host = f"{label}.{self.base}"
        port = "" if self.config.public_port == 443 else f":{self.config.public_port}"
        return host, f"https://{host}{port}/"

    def expose(self, room: str, port: int) -> tuple[str, str]:
        """Record room:port as served; returns (host, url). ValueError: no URL can name this room."""
        label = room_label(room, port)
        if label is None:
            raise ValueError("this room id cannot be a DNS label")
        with self.lock:
            held = self.exposed.get(label)
            if held is not None and held != (room, port):
                raise ValueError("another room holds this URL")
            self.exposed[label] = (room, port)
        return self.url_for(label)

    def lookup(self, host_header: str) -> tuple[str, int] | None:
        host = (host_header or "").strip().lower()
        if host.startswith("["):
            return None
        host = host.rsplit(":", 1)[0] if ":" in host else host
        host = host.rstrip(".")
        suffix = "." + self.base
        if not host.endswith(suffix):
            return None
        label = host[: -len(suffix)]
        if "." in label:
            return None
        with self.lock:
            return self.exposed.get(label)

    def forget_room(self, room: str) -> None:
        with self.lock:
            for label in [k for k, (r, _p) in self.exposed.items() if r == room]:
                del self.exposed[label]


class CertKeeper(threading.Thread):
    """Gets the CA certificate for the ingress key and renews it. Retries with backoff on any failure."""

    def __init__(self, state: IngressState, receipt_key, binding_sha256: str, *, client=None, dns=None,
                 sleep=None, log=print):
        super().__init__(daemon=True, name="ingress-cert")
        cfg = state.config
        self.state = state
        self.client = client or room_acme.AcmeClient(cfg.directory_url, contact_email=cfg.contact_email)
        self.dns = dns or room_acme.BrokerDNS01(cfg.broker_url, cfg.zone, state.hotel, receipt_key, binding_sha256)
        self._stop = threading.Event()
        self._sleep = sleep or self._stop.wait
        self.log = log
        self.attempts = 0

    def stop(self) -> None:
        self._stop.set()

    def once(self) -> float:
        """One order. Returns how long to wait before the next (renewal)."""
        self.attempts += 1
        chain = self.client.obtain(self.state.names(), self.state.private_key(), self.dns,
                                   dns_wait=self.state.config.dns_wait)
        leaf = self.state.install_chain(chain)
        self.log(f"room-receipts: ingress certificate for {self.state.base} valid to "
                 f"{leaf.not_valid_after_utc.isoformat()}, key {self.state.ingress.tls_spki_sha256}", flush=True)
        return max(room_acme_renew_wait(leaf), MIN_RENEW_WAIT_SECONDS)

    def run(self) -> None:
        delay = FIRST_RETRY_SECONDS
        while not self._stop.is_set():
            try:
                wait = self.once()
                delay = FIRST_RETRY_SECONDS
            except Exception as exc:  # noqa: BLE001 keep serving the old certificate; try again later
                self.log(f"room-receipts: ingress certificate: {exc}; next try in {delay} s", flush=True)
                if not isinstance(exc, room_acme.AcmeError):
                    traceback.print_exc()
                wait, delay = delay, min(delay * 2, MAX_RETRY_SECONDS)
            if self._sleep(wait):
                return


def room_acme_renew_wait(leaf: x509.Certificate, now: float | None = None) -> float:
    return room_acme.renew_at(leaf) - (time.time() if now is None else now)


class IngressServer(ThreadingHTTPServer):
    """HTTPS on the ingress port. The handshake runs in the request's own thread."""

    daemon_threads = True
    request_queue_size = 1024
    handshake_timeout = 30

    def __init__(self, addr, state: IngressState, api_port: int, api_key: bytes):
        self.state, self.api_port, self.api_key = state, api_port, api_key
        super().__init__(addr, IngressHandler)

    def finish_request(self, request, client_address):
        request.settimeout(self.handshake_timeout)
        with self.state.lock:
            ctx = self.state.context
        try:
            conn = ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            conn.settimeout(UPSTREAM_TIMEOUT * 2)
            self.RequestHandlerClass(conn, client_address, self)
        finally:
            conn.close()


class IngressHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cathedral-room"
    sys_version = ""

    def log_message(self, *args):  # no request logs: hosts and paths are the customer's
        pass

    def answer(self, status: int, body: bytes, headers=None, ctype="text/plain; charset=utf-8"):
        self.send_response(status)
        sent = set()
        for k, v in headers or []:
            self.send_header(k, v)
            sent.add(k.lower())
        if "content-type" not in sent:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def handle_any(self):
        state: IngressState = self.server.state
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            self.close_connection = True
            return self.answer(411, b"length required\n")
        target = state.lookup(self.headers.get("Host", ""))
        if target is None:
            self.close_connection = True
            return self.answer(404, b"nothing is exposed at this address\n")
        lengths = self.headers.get_all("Content-Length", [])
        try:
            # One length, digits only: two lengths could be read two ways on a kept-alive connection.
            n = int(lengths[0]) if len(lengths) == 1 and lengths[0].strip().isdigit() else (0 if not lengths else -1)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            self.close_connection = True
            return self.answer(413, b"request body too large\n")
        body = self.rfile.read(n) if n else b""
        if not self.path.startswith("/"):
            return self.answer(400, b"bad request target\n")
        room, port = target
        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP_REQUEST}
        headers.update({"Authorization": "Bearer " + self.server.api_key.decode(),
                        "X-Guest-Method": self.command, "X-Guest-Target": self.path,
                        "Content-Length": str(len(body))})
        conn = http.client.HTTPConnection("127.0.0.1", self.server.api_port, timeout=UPSTREAM_TIMEOUT)
        try:
            conn.request("POST", f"/v1/sandboxes/{room}/ports/{port}/http", body=body, headers=headers)
            res = conn.getresponse()
            status, out_headers, out = res.status, res.getheaders(), res.read()
        except (http.client.HTTPException, OSError):
            return self.answer(502, b"the room did not answer\n")
        finally:
            conn.close()
        keep = [(k, v) for k, v in out_headers if k.lower() not in DROP_RESPONSE]
        return self.answer(status, out, keep)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_any


def start(ledger, env, api_port: int, api_key: bytes, private_dir: str, log=print):
    """Turn the ingress on for a sealed ledger with an ingress key. Returns the state, or None when off."""
    if ledger.ingress is None:
        return None
    config = IngressConfig.from_env(env)
    if config is None:
        return None
    state = IngressState(ledger.ingress, ledger.hotel, config, private_dir)
    srv = IngressServer(config.listen, state, api_port, api_key)
    ledger.ingress.serving = state  # only once the port is bound: until then expose stays the API's
    threading.Thread(target=srv.serve_forever, daemon=True, name="ingress").start()
    CertKeeper(state, ledger.key, ledger.binding_sha256, log=log).start()
    log(f"room-receipts: guest ingress serving https on {config.listen[0]}:{config.listen[1]} for "
        f"*.{state.base}; certificate from {config.directory_url} over DNS-01 via {config.broker_url}", flush=True)
    return state
