#!/usr/bin/env python3
"""Sign a miner hotel offer (cathedral_hotel_offer_v1) with the miner hotkey.

A miner hotel is a sealed room-kit guest on a roster machine. The control plane
accepts it only after the miner signs an offer naming the guest's public HTTPS
origin and the binding_sha256 of this boot. This builds that offer from the
guest's own GET /room/attestation, signs it (sr25519, the hotkey), and prints
it or POSTs it to /v1/cathedral/snp/hotel-offers. The offer grants nothing:
the API fetches the attestation itself and checks the TLS key, the AMD chain,
the published measurement and the roster machine.

Wire format and signing rule are fixed by polariscomputer
polaris/services/cathedral_hotel_offers.py:
  offer_id  = "sha256:" + sha256(canonical(offer without offer_id, signature))
  signature = sr25519(hotkey, b"cathedral-hotel-offer-v1\\x00" || offer_id)

Checks before signing (a failure exits 1 and signs nothing):
  - binding_sha256 is the sha256 of the canonical binding;
  - the report is present (a sealed guest) and its REPORT_DATA commits to the binding;
  - the binding's chip_id is the report's CHIP_ID, and the CPUID names a known generation;
  - over --origin: the TLS key that answered is binding.tls_spki_sha256.

Hotkey: --hotkey-file reads a Bittensor hotkey file (plaintext JSON with
"secretSeed") or a file holding the 32-byte seed as 0x hex. An encrypted
keyfile is refused: export the seed on this host instead. The file must not be
readable by group or others. Needs py-sr25519-bindings (pip install
py-sr25519-bindings==0.2.2); the guest does not need it.

Usage:
  hotel_offer.py --origin https://203.0.113.9:9443 --hotkey-file ~/.bittensor/wallets/w/hotkeys/h
  hotel_offer.py --origin https://203.0.113.9:9443 --attestation-url https://10.200.0.2:18443 --hotkey-file h
  hotel_offer.py --attestation att.json --origin https://203.0.113.9:9443 --hotkey-file h \\
      --post https://api.example/v1/cathedral/snp/hotel-offers
  hotel_offer.py ... --withdraw     # take the hotel off the roster's offers
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

SCHEMA = "cathedral_hotel_offer_v1"
SIGNING_DOMAIN = b"cathedral-hotel-offer-v1\x00"
HARDWARE_DOMAIN = b"cathedral.amd-sev-snp.hardware-v1\x00"
ATTESTATION_ROUTE = "/room/attestation"
ATTESTATION_MAX_BYTES = 64 * 1024
SNP_REPORT_BYTES = 1184
REPORT_DATA_OFFSET = 0x50
CHIP_ID_OFFSET = 0x1A0
CPUID_FAMILY_OFFSET, CPUID_MODEL_OFFSET = 0x188, 0x189
SS58_FORMAT = 42  # Bittensor
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class OfferError(Exception):
    """A check failed. The message names the check and never carries key material."""


def canonical(doc) -> bytes:
    """Polaris canonical JSON (ASCII-escaped, sorted, no spaces); integers only."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def room_kit_canonical(doc) -> bytes:
    """room_receipts.canonical: the bytes binding_sha256 is taken over (not ASCII-escaped)."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def ss58_address(public_key: bytes) -> str:
    payload = bytes([SS58_FORMAT]) + public_key
    body = payload + hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()[:2]
    number = int.from_bytes(body, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58[rem] + out
    return "1" * (len(body) - len(body.lstrip(b"\x00"))) + out


def generation(report: bytes) -> str:
    """Same table as cathedral.verify.snp._snp_generation (pinned snpguest v0.10.0)."""
    family, model = report[CPUID_FAMILY_OFFSET], report[CPUID_MODEL_OFFSET]
    if family == 0x19:
        if 0x00 <= model <= 0x0F:
            return "milan"
        if 0x10 <= model <= 0x1F or 0xA0 <= model <= 0xAF:
            return "genoa"
    if family == 0x1A and 0x00 <= model <= 0x11:
        return "turin"
    raise OfferError("report CPUID names no known AMD generation")


def machine_id(gen: str, chip_id_hex: str) -> str:
    if not _HEX128.fullmatch(chip_id_hex):
        raise OfferError("chip_id is not 128 lowercase hex")
    return hashlib.sha256(HARDWARE_DOMAIN + gen.encode("ascii") + b"\x00" + bytes.fromhex(chip_id_hex)).hexdigest()


def check_origin(origin: str) -> str:
    """The API's endpoint rule: an explicit HTTPS origin on a public IP literal, no path."""
    try:
        parsed = urlsplit(origin)
        port = parsed.port
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        raise OfferError("origin must be https://<public ip>:<port>") from None
    if (origin != origin.strip() or not origin.isascii() or parsed.scheme != "https" or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment or parsed.path or not port
            or not address.is_global):
        raise OfferError("origin must be https://<public ip>:<port>, a public address, no path")
    return origin


def check_fetch_url(url: str) -> str:
    """Where to read the attestation from: https://<ip>:<port>, no path. Any address, private included.

    On a miner using sealed/host-net.sh the guest address
    (https://<guest ip>:<SEALED_MINER_TLS_PORT>) is the direct path while the offer
    advertises the public origin. host-net.sh releases before AB#822 forwarded the
    public port in PREROUTING only, so there the host cannot reach its own public address.
    """
    try:
        parsed = urlsplit(url)
        port = parsed.port
        ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        raise OfferError("attestation URL must be https://<ip>:<port>") from None
    if (url != url.strip() or not url.isascii() or parsed.scheme != "https" or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment or parsed.path or not port):
        raise OfferError("attestation URL must be https://<ip>:<port>, no path")
    return url


def fetch_attestation(origin: str, timeout: float = 10.0):
    """GET /room/attestation over TLS. No CA check (the guest's certificate is self-issued at boot).

    Returns (document, sha256 of the TLS peer's SPKI). The caller compares the
    SPKI with the binding, which is what makes the missing CA check safe.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    parsed = urlsplit(origin)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=timeout) as raw:
            with context.wrap_socket(raw) as tls:
                der = tls.getpeercert(binary_form=True)
                conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
                conn.sock = tls
                conn.request("GET", ATTESTATION_ROUTE)
                response = conn.getresponse()
                if response.status != 200:
                    raise OfferError(f"GET {ATTESTATION_ROUTE} answered HTTP {response.status}")
                body = response.read(ATTESTATION_MAX_BYTES + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise OfferError(f"cannot reach {origin}: {type(exc).__name__}") from None
    if len(body) > ATTESTATION_MAX_BYTES or not der:
        raise OfferError("attestation too large or no TLS peer certificate")
    key = x509.load_der_x509_certificate(der).public_key()
    spki = hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    try:
        return json.loads(body), spki
    except ValueError:
        raise OfferError("attestation is not JSON") from None


def check_attestation(attestation, *, peer_spki: str | None):
    """Validate the guest's attestation. Returns (binding_sha256, machine_id, binding)."""
    if not isinstance(attestation, dict) or not isinstance(attestation.get("binding"), dict):
        raise OfferError("attestation has no binding")
    binding = attestation["binding"]
    digest = hashlib.sha256(room_kit_canonical(binding)).hexdigest()
    if attestation.get("binding_sha256") != digest:
        raise OfferError("binding_sha256 is not the digest of the binding")
    if binding.get("level") == "hotel" or not attestation.get("report_b64"):
        raise OfferError("this hotel is not sealed (no SNP report); a miner hotel is a sealed guest")
    try:
        report = base64.b64decode(attestation["report_b64"], validate=True)
    except (ValueError, TypeError):
        raise OfferError("report_b64 is not base64") from None
    if len(report) != SNP_REPORT_BYTES:
        raise OfferError("report is not an SNP report of the expected size")
    if report[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + 64] != bytes.fromhex(digest) + bytes(32):
        raise OfferError("report REPORT_DATA does not commit to the binding")
    chip = report[CHIP_ID_OFFSET:CHIP_ID_OFFSET + 64].hex()
    if binding.get("chip_id") != chip:
        raise OfferError("binding chip_id is not the report CHIP_ID")
    tls = binding.get("tls_spki_sha256")
    if not isinstance(tls, str) or not _HEX64.fullmatch(tls):
        raise OfferError("binding has no tls_spki_sha256: this is not a miner hotel")
    if peer_spki is not None and tls != peer_spki:
        raise OfferError("the TLS key that answered is not the key in the binding (not the guest)")
    return digest, machine_id(generation(report), chip), binding


def load_seed(path: str) -> bytes:
    """The 32-byte sr25519 mini secret from a plaintext hotkey file or a 0x hex file."""
    info = os.stat(path)
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise OfferError("hotkey file must not be readable by group or others (chmod 600)")
    with open(path, "rb") as handle:
        raw = handle.read(64 * 1024).strip()
    text = raw.decode("utf-8", "replace")
    if text.startswith("{"):
        try:
            text = json.loads(text)["secretSeed"]
        except (ValueError, KeyError, TypeError):
            raise OfferError("hotkey file is JSON without secretSeed (encrypted keyfile? export the seed)") from None
    elif not text.startswith("0x") and not re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raise OfferError("hotkey file is not plaintext JSON or a hex seed (encrypted keyfile? export the seed)")
    text = text[2:] if text.startswith("0x") else text
    if not re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raise OfferError("hotkey seed must be 32 bytes of hex")
    return bytes.fromhex(text)


def build_offer(*, seed: bytes, network: str, netuid: int, origin: str, binding_sha256: str, machine: str,
                sequence: int, issued_at: str, withdraw: bool) -> dict:
    try:
        import sr25519
    except ImportError:
        raise OfferError("py-sr25519-bindings is not installed (pip install py-sr25519-bindings==0.2.2)") from None
    pair = sr25519.pair_from_seed(seed)
    public = pair[0]
    doc = {"schema": SCHEMA, "network": network, "netuid": netuid, "hotkey": ss58_address(public),
           "machine_id": machine, "api": origin, "health": origin, "binding_sha256": binding_sha256,
           "sequence": sequence, "issued_at": issued_at, "withdraw": withdraw}
    doc["offer_id"] = "sha256:" + hashlib.sha256(canonical(doc)).hexdigest()
    signature = sr25519.sign(pair, SIGNING_DOMAIN + doc["offer_id"].encode("ascii"))
    doc["signature"] = {"algorithm": "sr25519", "value_base64": base64.b64encode(signature).decode()}
    return doc


def post(url: str, document: dict, timeout: float = 20.0) -> str:
    body = canonical(document)
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return f"HTTP {response.status} {response.read(65536).decode('utf-8', 'replace')}"
    except urllib.error.HTTPError as exc:
        # 422 carries the refusal reason (a short code), which is what the miner needs.
        # It is raised, not returned, so a rejected offer exits non-zero for scripts.
        raise OfferError(f"the API refused the offer: HTTP {exc.code} {exc.read(65536).decode('utf-8', 'replace')}") from None
    except OSError as exc:
        raise OfferError(f"cannot POST to {url}: {type(exc).__name__}") from None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sign and print or POST a cathedral_hotel_offer_v1.")
    ap.add_argument("--origin", required=True, help="public hotel origin, https://<ip>:<port>; also fetched unless --attestation or --attestation-url")
    ap.add_argument("--attestation", help="JSON saved from GET /room/attestation (skips the fetch and the TLS key check)")
    ap.add_argument("--attestation-url", help="fetch from this https://<ip>:<port> instead of --origin; on a host using "
                    "sealed/host-net.sh use the guest address https://<guest ip>:<SEALED_MINER_TLS_PORT>")
    ap.add_argument("--hotkey-file", required=True)
    ap.add_argument("--network", default="finney")
    ap.add_argument("--netuid", type=int, default=94)
    ap.add_argument("--sequence", type=int, help="must grow with each offer for this machine (default: unix time)")
    ap.add_argument("--withdraw", action="store_true", help="withdraw this machine's offer")
    ap.add_argument("--post", metavar="URL", help="POST the offer to this /v1/cathedral/snp/hotel-offers URL")
    a = ap.parse_args(argv)
    try:
        origin = check_origin(a.origin)
        if a.attestation:
            with open(a.attestation, "rb") as handle:
                attestation, peer = json.loads(handle.read(ATTESTATION_MAX_BYTES + 1)), None
        else:
            attestation, peer = fetch_attestation(check_fetch_url(a.attestation_url) if a.attestation_url else origin)
        binding_sha256, machine, _ = check_attestation(attestation, peer_spki=peer)
        now = int(time.time())
        sequence = now if a.sequence is None else a.sequence
        if not 0 <= sequence <= 2**62:
            raise OfferError("sequence out of range")
        offer = build_offer(seed=load_seed(a.hotkey_file), network=a.network, netuid=a.netuid, origin=origin,
                            binding_sha256=binding_sha256, machine=machine, sequence=sequence,
                            issued_at=datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            withdraw=a.withdraw)
        if a.post:
            print(post(a.post, offer))
        else:
            print(json.dumps(offer, indent=2, sort_keys=True))
    except (OfferError, OSError, ValueError) as exc:
        print(f"hotel_offer: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
