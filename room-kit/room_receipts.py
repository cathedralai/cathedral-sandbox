#!/usr/bin/env python3
"""Room kit: signed receipts for a hotel.

Two modes. The mode is chosen at start from the TSM provider.

Level 1, every host (TSM provider is not sev_guest). An Ed25519 receipt key
in memory and a binding that says level "hotel". No read of
/sys/kernel/config/tsm/report, no SNP measurement, and health does not say
sealed. Schema cathedral_hotel_binding_v1 / cathedral_hotel_receipt_v1.

Sealed (TSM provider sev_guest). The same chain, plus an SNP report whose
REPORT_DATA is sha256(canonical(binding)) followed by 32 zero bytes. Schema
cathedral_sealed_hotel_binding_v1 / cathedral_sealed_hotel_receipt_v1, and
health sealed is true. That path is the sealed guest, not level 1.

Then it listens on ROOM_RECEIPTS_LISTEN and passes every request to the room
API (127.0.0.1:ROOM_API_PORT) and /room/health to the health endpoint. For each
create, exec, background process start and delete it signs one receipt. The
receipts make one chain per boot: each statement carries the sha256 of the
statement before it; the first one carries the binding's sha256.

Routes it adds:
  GET /room/attestation            binding, binding_sha256, report (base64)
  POST /room/attest                a fresh SNP report over caller REPORT_DATA (sealed only);
                                   with "sandbox_id", also that room's signed create receipt
  GET /room/receipts?after=&limit= the chain of this boot, in order
  GET /v1/sandboxes/<id>/receipts  the receipts of one room
Response header on a signed operation:
  X-Room-Receipt: base64url(canonical(receipt))

Canonical JSON: sort_keys, separators (",", ":"), ensure_ascii=False, UTF-8.
Verify offline with verify_receipts.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BINDING_SCHEMA = "cathedral_sealed_hotel_binding_v1"
RECEIPT_SCHEMA = "cathedral_sealed_hotel_receipt_v1"
HOTEL_BINDING_SCHEMA = "cathedral_hotel_binding_v1"
HOTEL_RECEIPT_SCHEMA = "cathedral_hotel_receipt_v1"
TSM = "/sys/kernel/config/tsm/report"


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------- attestation

# The sealed path's first report uses 64 zero bytes. tsm_provider() reads that
# report once; snp_report() returns it instead of asking the processor again.
_ZERO_REPORT: tuple[str, bytes] | None = None


def _read_tsm(report_data: bytes) -> tuple[str, bytes]:
    """One configfs-tsm report: provider name and outblob."""
    provider, report, _aux = _read_tsm_aux(report_data)
    return provider, report


def _read_tsm_aux(report_data: bytes, want_aux: bool = False) -> tuple[str, bytes, bytes]:
    """One configfs-tsm report: provider, outblob and (if asked) auxblob.

    auxblob is the host's certificate table (VCEK, ASK, ARK) when the host
    stored one and the kernel exposes it; otherwise it is empty.
    """
    assert len(report_data) == 64
    entry = os.path.join(TSM, "room-" + uuid.uuid4().hex[:12])
    os.mkdir(entry)
    aux = b""
    try:
        with open(os.path.join(entry, "inblob"), "wb") as f:
            f.write(report_data)
        with open(os.path.join(entry, "outblob"), "rb") as f:
            report = f.read()
        with open(os.path.join(entry, "provider")) as f:
            provider = f.read().strip()
        if want_aux:
            try:
                with open(os.path.join(entry, "auxblob"), "rb") as f:
                    aux = f.read()
            except OSError:
                aux = b""  # older kernel or no host certificates: the caller fetches from AMD KDS
    finally:
        os.rmdir(entry)
    return provider, report, aux


# GHCB certificate table GUIDs (AMD SEV-SNP firmware ABI / GHCB spec).
_CERT_GUIDS = {
    "vcek": "63da758d-e664-4564-adc5-f4b93be8accd",
    "ask": "4ab7b379-bbac-4fe4-a02f-05aef327c782",
    "ark": "c0b406a4-a803-4952-9743-3fb6014cd0ae",
}


def cert_chain(aux: bytes) -> dict | None:
    """VCEK, ASK and ARK (base64 DER) from an SNP certificate table, or None.

    The table is entries of GUID (16 bytes), offset (u32 LE) and length (u32
    LE), ended by an all-zero entry; offsets count from the table start. The
    GUID is matched in both byte orders. None unless all three are present
    and in range: a partial chain is not handed out as a chain.
    """
    names = {}
    for name, g in _CERT_GUIDS.items():
        u = uuid.UUID(g)
        names[u.bytes], names[u.bytes_le] = name, name
    found: dict[str, str] = {}
    pos = 0
    while pos + 24 <= len(aux):
        guid = aux[pos:pos + 16]
        if guid == bytes(16):
            break
        off = int.from_bytes(aux[pos + 16:pos + 20], "little")
        ln = int.from_bytes(aux[pos + 20:pos + 24], "little")
        name = names.get(guid)
        if name and ln and off + ln <= len(aux):
            found[name] = b64(aux[off:off + ln])
        pos += 24
    return found if set(found) == set(_CERT_GUIDS) else None


def tsm_provider() -> str | None:
    """The configfs-tsm provider, or None when this host has no TSM report.

    No configfs directory means level 1. A probe writes a zero REPORT_DATA
    and reads provider. sev_guest is the sealed path. Any other provider is
    level 1. A probe error is raised: a sealed guest with a broken TSM must
    not publish a hotel binding instead. The zero report is kept for
    snp_report(), so a sealed start still asks for two reports, as before.
    """
    global _ZERO_REPORT
    if not os.path.isdir(TSM):
        return None
    provider, report = _read_tsm(bytes(64))
    _ZERO_REPORT = (provider, report)
    return provider or None


def snp_report(report_data: bytes) -> bytes:
    """One SNP attestation report through configfs-tsm (Linux TSM reports)."""
    global _ZERO_REPORT
    if report_data == bytes(64) and _ZERO_REPORT is not None:
        provider, report = _ZERO_REPORT
        _ZERO_REPORT = None
    else:
        provider, report = _read_tsm(report_data)
    if provider != "sev_guest" or len(report) < 0x4A0:
        raise RuntimeError(f"unexpected TSM provider {provider!r} or report size {len(report)}")
    return report


def fresh_report(report_data: bytes) -> tuple[bytes, dict | None]:
    """A new SNP report whose REPORT_DATA is report_data, byte for byte.

    No hashing here: the caller chooses the 64 bytes and so the binding.
    Returns the report and the certificate chain when the host gave one.
    """
    provider, report, aux = _read_tsm_aux(report_data, want_aux=True)
    if provider != "sev_guest" or len(report) < 0x4A0:
        raise RuntimeError(f"unexpected TSM provider {provider!r} or report size {len(report)}")
    return report, cert_chain(aux)


def report_fields(report: bytes) -> dict:
    u64 = lambda o: int.from_bytes(report[o:o + 8], "little")  # noqa: E731
    return {
        "version": int.from_bytes(report[0:4], "little"),
        "policy": hex(u64(0x08)),
        "measurement": report[0x90:0xC0].hex(),
        "host_data": report[0xC0:0xE0].hex(),
        "reported_tcb": u64(0x180).to_bytes(8, "little").hex(),
        "chip_id": report[0x1A0:0x1E0].hex(),
    }


def read(path: str, default: str = "") -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


class Ledger:
    """The receipt key, the binding and the chain of this boot."""

    def __init__(self, hotel: str, store: str):
        if tsm_provider() == "sev_guest":
            self._init_sealed(hotel, store)
        else:
            self._init_hotel(hotel, store)

    def _init_sealed(self, hotel: str, store: str) -> None:
        """SNP binding. Same schema, report and fields as the sealed guest."""
        self.sealed = True
        self.receipt_schema = RECEIPT_SCHEMA
        self.hotel = hotel
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # A first report (zero REPORT_DATA) gives the launch facts the binding names.
        facts = report_fields(snp_report(bytes(64)))
        self.binding = {
            "schema": BINDING_SCHEMA,
            "hotel": hotel,
            "boot_id": read("/proc/sys/kernel/random/boot_id"),
            "created_at": int(time.time()),
            "receipt_key_ed25519_b64": b64(pub),
            "measurement": facts["measurement"],
            "chip_id": facts["chip_id"],
            "reported_tcb": facts["reported_tcb"],
            "policy": facts["policy"],
            "host_data": facts["host_data"],
            "kernel_cmdline": read("/proc/cmdline"),
            "kernel_release": os.uname().release,
            "software": {
                "room_kit": read("/opt/room-kit/KIT_COMMIT", "unknown"),
                "cathedral": read("/opt/pool-room/src/COMMIT", "unknown"),
            },
        }
        self.binding_sha256 = sha(canonical(self.binding))
        self.report = snp_report(bytes.fromhex(self.binding_sha256) + bytes(32))
        if report_fields(self.report)["measurement"] != facts["measurement"]:
            raise RuntimeError("measurement changed between the two reports")
        self._open_store(store)

    def _init_hotel(self, hotel: str, store: str) -> None:
        """Level 1: an Ed25519 hotel chain. No SNP report and no measurement."""
        self.sealed = False
        self.receipt_schema = HOTEL_RECEIPT_SCHEMA
        self.hotel = hotel
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.binding = {
            "schema": HOTEL_BINDING_SCHEMA,
            "level": "hotel",
            "hotel": hotel,
            "boot_id": read("/proc/sys/kernel/random/boot_id"),
            "created_at": int(time.time()),
            "receipt_key_ed25519_b64": b64(pub),
            "kernel_cmdline": read("/proc/cmdline"),
            "kernel_release": os.uname().release,
            "software": {
                "room_kit": read("/opt/room-kit/KIT_COMMIT", "unknown"),
                "cathedral": read("/opt/pool-room/src/COMMIT", "unknown"),
            },
        }
        self.binding_sha256 = sha(canonical(self.binding))
        self.report = b""
        self._open_store(store)

    def _open_store(self, store: str) -> None:
        self.lock = threading.Lock()
        self.attest_lock = threading.Lock()
        # Fresh-report slots keyed by guest id (X-Cathedral-Guest). A shared
        # hotel serves many guests; a per-hotel counter let one guest starve
        # the others (Spock / Escape capacity).
        self.attest_times: dict[str, list[float]] = {}
        self.chain: list[dict] = []
        self.by_room: dict[str, list[int]] = {}
        self.head = self.binding_sha256
        os.makedirs(store, mode=0o700, exist_ok=True)
        self.store = open(os.path.join(store, f"chain-{self.binding['boot_id']}.jsonl"), "ab", buffering=0)
        with open(os.path.join(store, f"attestation-{self.binding['boot_id']}.json"), "w") as f:
            json.dump(self.attestation(), f)

    def attestation(self) -> dict:
        doc = {"binding": self.binding, "binding_sha256": self.binding_sha256}
        if self.sealed:
            doc["report_b64"] = b64(self.report)
        return doc

    def attest_slot(self, guest: str, per_minute: int) -> float:
        """Take one fresh-report slot for *guest*. 0 when taken, else seconds to wait."""
        key = guest if guest else "_direct"
        now = time.monotonic()
        with self.attest_lock:
            times = self.attest_times.setdefault(key, [])
            times[:] = [t for t in times if now - t < 60]
            if len(times) >= per_minute:
                return max(0.001, 60 - (now - times[0]))
            times.append(now)
            return 0.0

    def attest(self, report_data: bytes) -> dict:
        """A fresh SNP report over the caller's 64 bytes, tied to this boot's binding."""
        report, chain = fresh_report(report_data)
        measurement = report_fields(report)["measurement"]
        if measurement != self.binding["measurement"]:
            raise RuntimeError("measurement changed since the binding")
        # Field name matches the receipt (cathedral_challenge_receipt_v1_1
        # tee.cert_chain): DER base64 for vcek/ask/ark, or null.
        return {"report_b64": b64(report), "cert_chain": chain, "binding_sha256": self.binding_sha256,
                "measurement": measurement, "generated_at": int(time.time())}

    def create_receipt(self, room: str) -> dict | None:
        """The last successful create receipt of *room* in this boot's chain, or None."""
        with self.lock:
            for i in reversed(self.by_room.get(room, [])):
                st = self.chain[i]["statement"]
                if st.get("action") == "create" and 200 <= int(st.get("status") or 0) < 300:
                    return self.chain[i]
        return None

    def sign(self, fields: dict) -> dict:
        with self.lock:
            statement = {"schema": self.receipt_schema, "binding_sha256": self.binding_sha256, "hotel": self.hotel,
                         "operation_id": str(uuid.uuid4()), "sequence": len(self.chain) + 1,
                         "previous_receipt_sha256": self.head, "issued_at": int(time.time()), **fields}
            receipt = {"statement": statement, "signature_b64": b64(self.key.sign(canonical(statement))),
                       "receipt_sha256": sha(canonical(statement))}
            self.head = receipt["receipt_sha256"]
            self.chain.append(receipt)
            room = statement.get("sandbox_id")
            if room:
                self.by_room.setdefault(room, []).append(len(self.chain) - 1)
            self.store.write(canonical(receipt) + b"\n")
            return receipt


# ---------------------------------------------------------------- proxy

ROOM = r"/v1/sandboxes/(?P<id>[^/]+)"
SIGNED = [  # (method, path pattern, action)
    ("POST", re.compile(r"^/v1/sandboxes$"), "create"),
    ("POST", re.compile("^" + ROOM + r"/exec$"), "exec"),
    ("POST", re.compile("^" + ROOM + r"/processes$"), "process_start"),
    ("DELETE", re.compile("^" + ROOM + r"$"), "delete"),
    ("PUT", re.compile("^" + ROOM + r"/network$"), "network_set"),
    ("POST", re.compile("^" + ROOM + r"/network$"), "network_set"),
    ("PATCH", re.compile("^" + ROOM + r"/network$"), "network_set"),
    ("DELETE", re.compile(r"^/v1/sandboxes$"), "bulk_delete"),
]
HEX64 = re.compile(r"[0-9a-fA-F]{128}")
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization",
       "proxy-authenticate", "content-length", "host"}


class Upstreams(threading.local):
    def conn(self, port: int) -> http.client.HTTPConnection:
        conns = self.__dict__.setdefault("conns", {})
        if port not in conns:
            conns[port] = http.client.HTTPConnection("127.0.0.1", port, timeout=1800)
        return conns[port]

    def drop(self, port: int) -> None:
        c = self.__dict__.get("conns", {}).pop(port, None)
        if c:
            c.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "room-receipts"

    def log_message(self, *args):  # no request logs
        pass

    # -- helpers
    def reply(self, status: int, body: bytes, headers: dict | None = None, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def authorized(self) -> bool:
        raw = self.headers.get("Authorization", "")
        return raw[:7].lower() == "bearer " and hmac.compare_digest(raw[7:].strip().encode(), self.server.api_key)

    def upstream(self, port: int, body: bytes | None):
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        if self.command not in ("GET", "HEAD"):
            # A write may have run before its answer was lost, so it is never
            # sent twice: a fresh connection (no stale keep-alive) and no
            # retry. A lost answer is a 502, and the receipt records it.
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1800)
            try:
                c.request(self.command, self.path, body=body, headers=headers)
                r = c.getresponse()
                return r.status, r.getheaders(), r.read()
            except (http.client.HTTPException, OSError):
                return 502, [], b'{"error":{"code":"hotel_api_no_answer","message":"the API did not answer; the request may have run"}}'
            finally:
                c.close()
        for attempt in (1, 2):
            c = UP.conn(port)
            try:
                c.request(self.command, self.path, body=body, headers=headers)
                r = c.getresponse()
                return r.status, r.getheaders(), r.read()
            except (http.client.HTTPException, OSError):
                UP.drop(port)
                if attempt == 2:
                    raise

    # -- routes
    def handle_any(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            # Only Content-Length bodies are read and signed; a chunked body
            # would be signed as empty and its bytes left on the connection.
            self.close_connection = True
            return self.reply(411, b'{"error":"length_required"}')
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else (b"" if self.command in ("POST", "PUT", "PATCH") else None)
        path = urlsplit(self.path).path
        ledger: Ledger = self.server.ledger
        if self.command == "GET" and path == "/room/attestation":
            return self.reply(200, canonical(ledger.attestation()))
        if path == "/room/attest":
            return self.handle_attest(ledger, body)
        if self.command == "GET" and path == "/room/receipts":
            if not self.authorized():
                return self.reply(401, b'{"error":"unauthorized"}')
            q = parse_qs(urlsplit(self.path).query)
            try:
                after, limit = int(q.get("after", ["0"])[0]), min(int(q.get("limit", ["1000"])[0]), 10000)
            except ValueError:
                after = limit = -1
            if after < 0 or limit < 1:
                return self.reply(400, b'{"error":"after must be >= 0 and limit >= 1"}')
            with ledger.lock:
                page = ledger.chain[after:after + limit]
                head = ledger.head
            return self.reply(200, canonical({"binding_sha256": ledger.binding_sha256, "head": head,
                                              "count": len(page), "receipts": page}))
        m = re.match("^" + ROOM + r"/receipts$", path)
        if self.command == "GET" and m:
            if not self.authorized():
                return self.reply(401, b'{"error":"unauthorized"}')
            with ledger.lock:
                page = [ledger.chain[i] for i in ledger.by_room.get(m["id"], [])]
            return self.reply(200, canonical({"sandbox_id": m["id"], "binding_sha256": ledger.binding_sha256,
                                              "receipts": page}))
        if path == "/room/health":
            # Served from the cache that health_loop fills. No upstream call,
            # no subprocess and no ledger lock in the request, so health
            # answers at once when the guest CPU is full.
            if not self.authorized():
                return self.reply(401, b'{"error":"unauthorized"}')
            with self.server.health_lock:
                status, out, at = self.server.health
            if out is None:
                return self.reply(503, b'{"error":"health_not_ready"}')
            return self.reply(status, out, {"X-Health-Age-Ms": str(int((time.time() - at) * 1000))})
        action = next((a for meth, pat, a in SIGNED if meth == self.command and pat.match(path)), None)
        if action and body:
            # A JSON escape of a lone surrogate parses, but cannot be encoded
            # when the statement is signed. Refuse it before the API runs
            # the action: an action with no receipt is the one thing this
            # front must never produce.
            try:
                canonical(json.loads(body))
            except UnicodeEncodeError:  # before ValueError: it is a subclass
                return self.reply(400, b'{"error":{"code":"invalid_request","message":"the body holds a lone surrogate escape"}}')
            except ValueError:
                pass  # not JSON: the API answers
        status, headers, out = self.upstream(self.server.api_port, body)
        extra = {}
        if action and self.authorized():
            try:
                extra["X-Room-Receipt"] = base64.urlsafe_b64encode(
                    canonical(ledger.sign(self.fields(action, path, body, status, out)))).decode()
            except Exception as exc:  # noqa: BLE001 the action ran: answer, and say the receipt is missing
                traceback.print_exc()
                extra["X-Room-Receipt-Error"] = type(exc).__name__
        ctype = next((v for k, v in headers if k.lower() == "content-type"), "application/json")
        passthrough = {k: v for k, v in headers if k.lower() not in HOP and k.lower() != "content-type"}
        return self.reply(status, out, {**passthrough, **extra}, ctype)

    def handle_attest(self, ledger: "Ledger", body: bytes | None):
        """POST /room/attest {"report_data_hex": <128 hex>}: a fresh SNP report.

        REPORT_DATA is the caller's 64 bytes verbatim. The caller must put a
        digest of what it binds there (for example sha512 of its statement);
        the hotel does not hash it again.
        """
        if self.command != "POST":
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "POST"})
        if not self.authorized():
            return self.reply(401, b'{"error":"unauthorized"}')
        if not ledger.sealed:
            return self.reply(503, b'{"error":"not_sealed"}')
        try:
            doc = json.loads(body or b"")
        except ValueError:
            doc = None
        raw = doc.get("report_data_hex") if isinstance(doc, dict) else None
        if not isinstance(raw, str) or not HEX64.fullmatch(raw):
            return self.reply(400, b'{"error":"report_data_hex must be 128 hex characters (64 bytes)"}')
        room = doc.get("sandbox_id")
        if room is not None and (not isinstance(room, str) or not re.fullmatch(r"[^/\s]{1,200}", room)):
            return self.reply(400, b'{"error":"sandbox_id must be a room id"}')
        # Broker sets X-Cathedral-Guest; a direct hotel-key call has no guest
        # and shares the "_direct" bucket. Limit is per guest, not per hotel.
        guest = (self.headers.get("X-Cathedral-Guest") or "").strip()
        wait = ledger.attest_slot(guest, self.server.attest_per_minute)
        if wait:
            return self.reply(429, b'{"error":"attest_rate_limit"}', {"Retry-After": str(int(wait) + 1)})
        try:
            out = ledger.attest(bytes.fromhex(raw))
        except Exception as exc:  # noqa: BLE001 a TSM failure is the hotel's, not the caller's
            traceback.print_exc()
            return self.reply(500, canonical({"error": "attest_failed", "detail": type(exc).__name__}))
        if room is not None:
            # The room's signed create receipt (its tunables and tunables_sha256, when it
            # has them), under the receipt key of the binding this report names.
            out["room"] = {"sandbox_id": room, "create_receipt": ledger.create_receipt(room)}
        return self.reply(200, canonical(out))

    def fields(self, action: str, path: str, body: bytes | None, status: int, out: bytes) -> dict:
        req = {}
        try:
            req = json.loads(body) if body else {}
        except ValueError:
            pass
        res = {}
        try:
            res = json.loads(out) if out else {}
        except ValueError:
            pass
        m = re.match("^" + ROOM, path)
        sandbox = m["id"] if m else (res.get("id") if isinstance(res, dict) else None)
        command = (req.get("cmd", req.get("command")) if isinstance(req, dict) else None)
        image = req.get("image") if action == "create" and isinstance(req, dict) else None
        if isinstance(image, dict):
            # The object form carries registry_auth: record the reference only.
            image = image.get("image")
        if not isinstance(image, str):
            image = None
        policy = self.network_policy(action, status, res)
        tunables = self.room_tunables(action, status, res)
        return {
            "action": action,
            "target": f"{self.command} {self.path}",
            "sandbox_id": sandbox if isinstance(sandbox, str) else None,
            "customer_request_sha256": sha(body or b""),
            "command_sha256": sha(canonical(command)) if command is not None else None,
            "image": image,
            "image_digest": self.server.image_digest(image) if image and status in (200, 201, 202) else None,
            "status": status,
            "result_sha256": sha(out),
            # Create and network switch: the egress policy the hotel applied
            # (canonical {"mode", "allow", "credentials"?}) and its sha256. The sha256 is
            # computed here from the policy, not copied from the API.
            **({"network_policy": policy, "network_policy_sha256": sha(canonical(policy))} if policy else {}),
            # Create with per-room tunables: the values the room started under, the runsc
            # runtime and its args. tunables_sha256 is computed here from the values (it is
            # the tunables document's sha256, the one the Escape challenge records), not
            # copied from the API. The receipt key is in the binding, whose sha256 is the
            # boot report's REPORT_DATA, so a sealed hotel's SNP report covers this field.
            **(tunables or {}),
        }

    @staticmethod
    def room_tunables(action: str, status: int, res) -> dict | None:
        if action != "create" or not 200 <= status < 300 or not isinstance(res, dict):
            return None
        view = res.get("tunables")
        values = view.get("values") if isinstance(view, dict) else None
        if not isinstance(values, dict) or view.get("status") != "applied":
            return None
        return {"tunables": values, "tunables_sha256": sha(canonical(values)),
                "tunables_runtime": str(view.get("runtime")),
                "tunables_runtime_args": [str(a) for a in view.get("runtime_args") or []]}

    @staticmethod
    def network_policy(action: str, status: int, res) -> dict | None:
        if action not in ("create", "network_set") or not 200 <= status < 300 or not isinstance(res, dict):
            return None
        net = res.get("network")
        policy = net.get("policy") if isinstance(net, dict) else None
        if not (isinstance(policy, dict) and isinstance(policy.get("mode"), str) and isinstance(policy.get("allow"), list)):
            return None
        out = {"mode": policy["mode"], "allow": [str(x) for x in policy["allow"]]}
        # #304: credential references (host, header name, secret name). The
        # policy never carries a secret value.
        creds = policy.get("credentials")
        if isinstance(creds, list) and creds:
            out["credentials"] = [{"host": str(c.get("host")), "header": str(c.get("header")),
                                   "secret": str(c.get("secret"))} for c in creds if isinstance(c, dict)]
        return out

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = handle_any


UP = Upstreams()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 1024

    def __init__(self, addr, ledger, api_port, health_port, api_key, docker_sock, attest_per_minute=30):
        super().__init__(addr, Handler)
        self.attest_per_minute = max(1, int(attest_per_minute))
        self.ledger, self.api_port, self.health_port, self.api_key = ledger, api_port, health_port, api_key
        self.docker_sock = docker_sock
        self._digests: dict[str, str | None] = {}
        self.health_lock = threading.Lock()
        self.health: tuple[int, bytes | None, float] = (503, None, 0.0)
        threading.Thread(target=self.health_loop, daemon=True).start()

    def health_loop(self) -> None:
        """Build the health answer once a second, off the request path."""
        up = http.client.HTTPConnection("127.0.0.1", self.health_port, timeout=30)
        auth = {"Authorization": "Bearer " + self.api_key.decode()}
        while True:
            try:
                up.request("GET", "/room/health", headers=auth)
                r = up.getresponse()
                status, out = r.status, r.read()
                if status == 200:
                    doc = json.loads(out)
                    # Sealed guests only. Level 1 must not claim an SNP binding.
                    if self.ledger.sealed:
                        doc["sealed"] = True
                    doc["receipts"] = {"binding_sha256": self.ledger.binding_sha256, "count": len(self.ledger.chain)}
                    doc["runsc_sandbox_procs"] = int(subprocess.run(
                        ["pgrep", "-cf", "[r]unsc-sandbox"], capture_output=True, text=True, timeout=20).stdout.strip() or 0)
                    doc["guest_kernel_sev"] = self.sev_log()
                    out = canonical(doc)
                with self.health_lock:
                    self.health = (status, out, time.time())
            except (http.client.HTTPException, OSError, ValueError, subprocess.SubprocessError):
                up.close()
                up = http.client.HTTPConnection("127.0.0.1", self.health_port, timeout=30)
            time.sleep(1)

    def sev_log(self) -> list[str]:
        """The guest kernel's own SEV lines (dmesg), read once."""
        if not hasattr(self, "_sev"):
            out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
            self._sev = [ln.strip() for ln in out.splitlines() if "SEV" in ln][:12]
        return self._sev

    def image_digest(self, ref: str) -> str | None:
        if not isinstance(ref, str):
            return None
        if ref not in self._digests:
            try:
                r = subprocess.run(["docker", "-H", "unix://" + self.docker_sock, "image", "inspect", "--format",
                                    "{{.Id}}", ref], capture_output=True, text=True, timeout=30)
            except (subprocess.SubprocessError, OSError):
                return None  # a digest is a bonus; the receipt is the product
            self._digests[ref] = r.stdout.strip() or None if r.returncode == 0 else None
        return self._digests[ref]


def main() -> int:
    env = os.environ
    host, port = env["ROOM_RECEIPTS_LISTEN"].rsplit(":", 1)
    with open(env.get("ROOM_API_KEY_PATH", "/etc/pool-room/api.key"), "rb") as f:
        api_key = f.read().strip()
    ledger = Ledger(env["ROOM_HOTEL_NAME"], env.get("ROOM_RECEIPTS_DIR", "/run/room-receipts"))
    if ledger.sealed:
        print(f"room-receipts: binding {ledger.binding_sha256} measurement {ledger.binding['measurement']}", flush=True)
    else:
        print(f"room-receipts: binding {ledger.binding_sha256} level hotel", flush=True)
    srv = Server((host, int(port)), ledger, int(env.get("ROOM_API_PORT", "18090")),
                 int(env.get("ROOM_HEALTH_PORT", "18091")), api_key, env.get("ROOM_DOCKER_SOCK", "/run/pool-room/docker.sock"),
                 int(env.get("ROOM_ATTEST_PER_MINUTE", "30")))
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
