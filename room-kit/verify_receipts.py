#!/usr/bin/env python3
"""Offline verifier for hotel receipts (room_receipts.py).

Level 1 (binding level "hotel", schema cathedral_hotel_binding_v1) has no SNP
report. Checks, in order:
  1. binding: sha256(canonical(binding)) equals binding_sha256, level is hotel,
     and the binding carries no SNP measurement and no report.
  2. receipts: each statement names this binding and the hotel receipt schema,
     receipt_sha256 = sha256(canonical(statement)), the Ed25519 signature
     verifies with the binding's receipt key, and the chain links (sequence 1
     links to the binding; each next receipt links to the one before). A whole
     chain must start at receipt 1 and end at head.
  3. network policy: same as the sealed path below.

Sealed (schema cathedral_sealed_hotel_binding_v1). Checks, in order:
  1. binding: sha256(canonical(binding)) equals binding_sha256.
  2. SNP report: REPORT_DATA = binding_sha256 || 32 zero bytes; measurement,
     chip id, reported TCB, policy and HOST_DATA equal the binding; debug is off;
     optional --expected-measurement (from the guest build manifest).
  3. AMD chain: ARK (self-signed) -> ASK -> VCEK, all RSA-PSS SHA-384, fetched
     from AMD KDS (kdsintf.amd.com) and cached; VCEK hwID and TCB extensions
     equal the report; the report's ECDSA P-384 signature verifies with the VCEK.
     Optional --ark-sha256 pins the ARK certificate; repeat it to accept
     any of several roots (one per product: Milan, Genoa, ...).
  4. receipts: each statement names this binding and the sealed hotel receipt
     schema, receipt_sha256 = sha256(canonical(statement)), the Ed25519
     signature verifies with the binding's receipt key, and the chain links
     (sequence 1 links to the binding; each next receipt links to the one
     before).
  5. network policy: each create and network_set receipt that carries
     network_policy has network_policy_sha256 = sha256(canonical(policy)).
     The output has the policy timeline of each room, in chain order.
  6. tunables: each create receipt that carries tunables has
     tunables_sha256 = sha256(canonical(tunables)), the tunables document's
     sha256. The output lists each room's tunables_sha256.
  7. guest TLS (miner hotels): a binding that names tls_spki_sha256 must name
     a well-formed key, and --tls-spki-sha256 (the SPKI sha256 of the TLS peer
     that served the attestation) must equal it; --require-tls fails a binding
     with no TLS key. --origin https://<ip>:<port> fetches the attestation
     from the guest itself, takes the peer SPKI from that connection, and also
     checks GET /room/hotel-key-install-key: signed by the binding's receipt
     key, for this binding, and the X25519 key the binding names.
  8. owner (--owner-pubkey <base64 of the 32-byte Ed25519 key>): a dedicated
     machine of that owner. The binding says tenancy "dedicated" and names
     that key; the report's HOST_DATA (chip-signed, fixed at launch) equals
     sha256("cathedral-dedicated-v1\0" || manifest_sha256 || key), with
     manifest_sha256 from the binding; and each successful create receipt
     carries an owner signature that verifies with the key. Pair it with
     --expected-measurement: the measurement is what proves the guest runs
     the build whose front refuses creates the owner did not sign.
  9. sandbox link (AB#389): a create receipt that carries cathedral_sandbox_id
     must carry a lower-case UUID. The output maps each room to the Cathedral
     sandbox id its successful create receipt signed. --cathedral-sandbox <id>
     fails unless a successful create receipt names that id.

Not checked here (by design, today): that the measurement is an approved image.
Image approval is a signed policy release; that is a later step.

Usage:
  verify_receipts.py --attestation att.json --receipts chain.json [--receipt-header B64 ...]
  verify_receipts.py --broker https://<broker> --key-file KEY --hotel <hotel id> [--sandbox ID]
  verify_receipts.py --broker ... --operator-key-file OP --hotel <id>   # receipts from earlier boots
  verify_receipts.py --origin https://<miner ip>:<port> --require-sealed [--expected-measurement M]
  add --owner-pubkey B64 --expected-measurement HEX for a dedicated machine

When receipts name a binding_sha256 other than the live attestation, pass --broker and
--operator-key-file so GET /v1/broker/bindings/<sha> can load each archived binding.
The archive holds binding JSON only (no SNP report); those checks cover signatures only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

KDS = "https://kdsintf.amd.com/vcek/v1"
SIGNED_LEN = 0x2A0
HOTEL_BINDING_SCHEMA = "cathedral_hotel_binding_v1"
HOTEL_RECEIPT_SCHEMA = "cathedral_hotel_receipt_v1"
SEALED_RECEIPT_SCHEMA = "cathedral_sealed_hotel_receipt_v1"
INSTALL_ALGORITHM = "x25519-hkdf-sha256-aes256gcm-v1"
INSTALL_PURPOSE = "hotel-key-install"
HEX64 = re.compile(r"[0-9a-f]{64}")
ORIGIN_MAX_BYTES = 64 * 1024
DEDICATED_HOST_DATA_DOMAIN = b"cathedral-dedicated-v1\0"
SANDBOX_LINK_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")  # room_receipts.py


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Fail(Exception):
    pass


def need(cond, msg):
    if not cond:
        raise Fail(msg)


def u64(r: bytes, o: int) -> int:
    return int.from_bytes(r[o:o + 8], "little")


def parse_report(r: bytes) -> dict:
    need(len(r) >= 0x4A0, f"report is {len(r)} bytes, expected 1184")
    version = int.from_bytes(r[0:4], "little")
    return {
        "version": version,
        "policy": u64(r, 0x08),
        "signature_algo": int.from_bytes(r[0x34:0x38], "little"),
        "report_data": r[0x50:0x90],
        "measurement": r[0x90:0xC0].hex(),
        "host_data": r[0xC0:0xE0].hex(),
        "reported_tcb": r[0x180:0x188],
        "cpuid_fam": r[0x188] if version >= 3 else None,
        "cpuid_mod": r[0x189] if version >= 3 else None,
        "chip_id": r[0x1A0:0x1E0],
        "sig_r": int.from_bytes(r[0x2A0:0x2A0 + 72], "little"),
        "sig_s": int.from_bytes(r[0x2E8:0x2E8 + 72], "little"),
    }


def product(rep: dict, override: str | None) -> str:
    if override:
        return override
    fam, mod = rep["cpuid_fam"], rep["cpuid_mod"]
    if fam == 0x19 and mod is not None and mod >= 0x10:
        return "Genoa"
    if fam == 0x19:
        return "Milan"
    raise Fail(f"cannot tell the product from cpuid family {fam} model {mod}; pass --product")


def fetch(url: str, cache: str, name: str) -> bytes:
    path = os.path.join(cache, name)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = resp.read()
    os.makedirs(cache, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return data


def pss_verify(issuer: x509.Certificate, cert: x509.Certificate) -> None:
    issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                               padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384())


def ext_int(cert: x509.Certificate, oid: str) -> int:
    raw = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value.value
    # DER INTEGER: 02 len value
    need(raw[0] == 0x02, f"extension {oid} is not an INTEGER")
    return int.from_bytes(raw[2:2 + raw[1]], "big")


def verify_amd(report: bytes, rep: dict, prod: str, cache: str, ark_sha256: str | list[str] | None) -> dict:
    tcb = rep["reported_tcb"]
    need(prod in ("Genoa", "Milan"), "only Milan and Genoa TCB layouts are handled")
    bl, tee, snp, ucode = tcb[0], tcb[1], tcb[6], tcb[7]
    chain_pem = fetch(f"{KDS}/{prod}/cert_chain", cache, f"{prod}-cert_chain.pem")
    certs = x509.load_pem_x509_certificates(chain_pem)
    need(len(certs) == 2, "KDS cert_chain should hold ASK and ARK")
    ask, ark = certs
    pss_verify(ark, ark)
    pss_verify(ark, ask)
    ark_fp = sha(ark.public_bytes(serialization.Encoding.DER))
    if ark_sha256:
        # Any pin may match: each product has its own ARK, and the chain
        # fetched is the report's product, so one run serves a mixed fleet.
        pins = [ark_sha256] if isinstance(ark_sha256, str) else ark_sha256
        need(ark_fp in {p.lower() for p in pins}, f"ARK sha256 {ark_fp} differs from the pinned value")
    chip = rep["chip_id"].hex()
    vcek_url = f"{KDS}/{prod}/{chip}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}"
    vcek = x509.load_der_x509_certificate(fetch(vcek_url, cache, f"vcek-{chip[:16]}-{tcb.hex()}.der"))
    pss_verify(ask, vcek)
    hwid = vcek.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.3704.1.4")).value.value
    need(hwid[-64:] == rep["chip_id"], "VCEK hwID differs from the report chip id")
    for oid, val, name in (("1.3.6.1.4.1.3704.1.3.1", bl, "bootloader"), ("1.3.6.1.4.1.3704.1.3.2", tee, "tee"),
                           ("1.3.6.1.4.1.3704.1.3.3", snp, "snp"), ("1.3.6.1.4.1.3704.1.3.8", ucode, "microcode")):
        need(ext_int(vcek, oid) == val, f"VCEK {name} SPL differs from the report")
    need(rep["signature_algo"] == 1, "report signature algorithm is not ECDSA P-384 SHA-384")
    sig = encode_dss_signature(rep["sig_r"], rep["sig_s"])
    try:
        vcek.public_key().verify(sig, report[:SIGNED_LEN], ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as exc:
        raise Fail("report signature does not verify with the VCEK") from exc
    return {"product": prod, "ark_sha256": ark_fp, "tcb": {"bootloader": bl, "tee": tee, "snp": snp, "microcode": ucode}}


def is_hotel_level(att: dict) -> bool:
    binding = att.get("binding")
    if not isinstance(binding, dict):
        return False
    return binding.get("level") == "hotel" or binding.get("schema") == HOTEL_BINDING_SCHEMA


def verify_hotel_attestation(att: dict) -> dict:
    """Level 1 binding. Signature and chain are checked in verify_receipts."""
    binding = att["binding"]
    need(binding.get("level") == "hotel", "level 1 binding must say level hotel")
    need(binding.get("schema") == HOTEL_BINDING_SCHEMA, "level 1 binding schema is not a hotel binding")
    bsha = sha(canonical(binding))
    need(bsha == att["binding_sha256"], "binding_sha256 does not match the binding")
    need(not att.get("report_b64"), "a level 1 chain has no SNP report")
    need("measurement" not in binding, "a level 1 binding has no SNP measurement")
    return {"level": "hotel", "binding_sha256": bsha, "hotel": binding.get("hotel")}


def verify_attestation(att: dict, expected_measurement: str | None, prod: str | None, cache: str,
                       ark_sha256: str | list[str] | None, skip_amd: bool) -> dict:
    binding = att["binding"]
    bsha = sha(canonical(binding))
    need(bsha == att["binding_sha256"], "binding_sha256 does not match the binding")
    report = base64.b64decode(att["report_b64"])
    rep = parse_report(report)
    need(rep["report_data"] == bytes.fromhex(bsha) + bytes(32), "REPORT_DATA does not commit to the binding")
    need(rep["measurement"] == binding["measurement"], "report measurement differs from the binding")
    need(rep["chip_id"].hex() == binding["chip_id"], "report chip id differs from the binding")
    need(rep["reported_tcb"].hex() == binding["reported_tcb"], "report TCB differs from the binding")
    need(rep["host_data"] == binding["host_data"], "report HOST_DATA differs from the binding")
    need(hex(rep["policy"]) == binding["policy"], "report policy differs from the binding")
    need(not rep["policy"] & (1 << 19), "guest policy allows debug")
    # A debug build has the same SNP policy but gives the host root SSH into
    # the guest. The flag is on the measured kernel cmdline.
    cmdline = binding.get("kernel_cmdline") or ""
    need("cathedral.debug=1" not in cmdline.split(), "debug build: the host can log in to this guest")
    if expected_measurement:
        need(rep["measurement"] == expected_measurement.lower(), "measurement differs from the expected build")
    out = {"binding_sha256": bsha, "measurement": rep["measurement"], "chip_id": rep["chip_id"].hex()[:16] + "...",
           "policy": hex(rep["policy"]), "host_data": rep["host_data"], "report_version": rep["version"],
           "kernel_cmdline": cmdline}
    if not skip_amd:
        out["amd"] = verify_amd(report, rep, product(rep, prod), cache, ark_sha256)
    return out


def _b64_key(value, what: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True) if isinstance(value, str) else b""
    except ValueError:
        raw = b""
    need(len(raw) == 32, f"{what} is not a base64 32-byte key")
    return raw


def verify_guest_tls(att: dict, peer_spki_sha256: str | None = None, require: bool = False) -> dict | None:
    """The miner hotel fields of a sealed binding (room_receipts.MinerHotel).

    The binding is covered by REPORT_DATA, so a TLS key it names is the
    guest's own. peer_spki_sha256 is the SPKI sha256 of the TLS peer that
    served this attestation: equal means the connection ended in the guest,
    not on the host. Returns None for a binding with no TLS key.
    """
    binding = att["binding"]
    tls = binding.get("tls_spki_sha256")
    if tls is None:
        need(not require and peer_spki_sha256 is None,
             "the binding names no guest TLS key: this hotel's TLS (if any) is not attested")
        return None
    need(isinstance(tls, str) and HEX64.fullmatch(tls) is not None, "binding tls_spki_sha256 is not 64 lower-case hex")
    if peer_spki_sha256 is not None:
        need(peer_spki_sha256.lower() == tls, "the TLS peer is not the key the binding names (the host answered?)")
    install = _b64_key(binding.get("hotel_key_install_x25519_b64"), "binding hotel_key_install_x25519_b64")
    signers = binding.get("hotel_key_install_signers_ed25519_b64")
    need(isinstance(signers, list) and signers, "binding names no hotel key install signer")
    for item in signers:
        _b64_key(item, "binding install signer")
    need(binding.get("hotel_key_source") == "install", "binding hotel_key_source is not install")
    return {"tls_spki_sha256": tls, "peer_checked": peer_spki_sha256 is not None,
            "hotel_key_install_x25519_b64": base64.b64encode(install).decode(),
            "hotel_key_install_signers_ed25519_b64": signers, "hotel_key_source": "install"}


def verify_install_key(doc: dict, att: dict) -> str:
    """GET /room/hotel-key-install-key: signed by the binding's receipt key, for this binding,
    and the X25519 key the binding names. Returns the X25519 key (base64)."""
    binding = att["binding"]
    statement = {k: doc.get(k) for k in ("algorithm", "binding_sha256", "purpose", "x25519_public_b64")}
    need(statement["algorithm"] == INSTALL_ALGORITHM and statement["purpose"] == INSTALL_PURPOSE,
         "install key document is not a hotel-key-install key")
    need(statement["binding_sha256"] == att["binding_sha256"], "install key document names another binding")
    receipt_key = Ed25519PublicKey.from_public_bytes(_b64_key(binding.get("receipt_key_ed25519_b64"), "receipt key"))
    try:
        signature = base64.b64decode(doc.get("signature_b64") or "", validate=True)
        receipt_key.verify(signature, canonical(statement))
    except (InvalidSignature, ValueError) as exc:
        raise Fail("install key document is not signed by the binding's receipt key") from exc
    _b64_key(statement["x25519_public_b64"], "install key")
    named = binding.get("hotel_key_install_x25519_b64")
    need(named is None or named == statement["x25519_public_b64"], "install key differs from the one the binding names")
    return statement["x25519_public_b64"]


def spki_sha256_of_certificate(der: bytes) -> str:
    cert = x509.load_der_x509_certificate(der)
    return sha(cert.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo))


def fetch_origin(origin: str, paths: list[str], timeout: float = 30.0) -> tuple[list[tuple[int, bytes]], str]:
    """GET each path from a miner hotel over ONE TLS connection; returns the answers and the peer SPKI sha256.

    The certificate is self-issued by the guest, so there is no CA check: the
    caller compares the SPKI with the attested binding (verify_guest_tls).
    """
    parts = urlsplit(origin)
    need(parts.scheme == "https" and parts.hostname and not parts.path.strip("/"),
         "--origin must be https://<host>:<port>")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=ctx)
    try:
        conn.connect()
        spki = spki_sha256_of_certificate(conn.sock.getpeercert(binary_form=True))
        # One connection and one handshake: every answer comes from the peer
        # whose SPKI was read. No silent reconnect to another peer.
        conn.auto_open = 0
        out = []
        for path in paths:
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read(ORIGIN_MAX_BYTES + 1)
            need(len(body) <= ORIGIN_MAX_BYTES, f"{path} answer is too large")
            out.append((resp.status, body))
        return out, spki
    finally:
        conn.close()


def owner_key_bytes(owner_b64: str) -> bytes:
    try:
        key = base64.b64decode(owner_b64.strip(), validate=True)
    except ValueError as exc:
        raise Fail("--owner-pubkey is not base64") from exc
    need(len(key) == 32, f"--owner-pubkey is {len(key)} bytes, expected a 32-byte Ed25519 public key")
    return key


def verify_owner(att: dict, owner: bytes) -> dict:
    """The binding and the chip-signed HOST_DATA name this owner (check 8).

    Run after verify_attestation, which checks the report against the
    binding and REPORT_DATA against the binding's sha256.
    """
    binding = att["binding"]
    need(binding.get("tenancy") == "dedicated",
         f"the binding says tenancy {binding.get('tenancy')!r}, not \"dedicated\": other customers may share this machine")
    try:
        named = base64.b64decode(binding.get("owner_ed25519_b64") or "", validate=True)
    except ValueError as exc:
        raise Fail("the binding's owner_ed25519_b64 is not base64") from exc
    need(named == owner, "the binding names another owner key")
    manifest = binding.get("manifest_sha256") or ""
    need(isinstance(manifest, str) and len(manifest) == 64, "the binding has no manifest_sha256")
    try:
        manifest_raw = bytes.fromhex(manifest)
    except ValueError as exc:
        raise Fail("the binding's manifest_sha256 is not hex") from exc
    rep = parse_report(base64.b64decode(att["report_b64"]))
    want = hashlib.sha256(DEDICATED_HOST_DATA_DOMAIN + manifest_raw + owner).hexdigest()
    need(rep["host_data"] == want, "report HOST_DATA does not commit to this owner key and manifest")
    return {"tenancy": "dedicated", "owner_ed25519_b64": base64.b64encode(owner).decode(),
            "manifest_sha256": manifest, "host_data": rep["host_data"]}


def owner_signed_creates(receipts: list[dict], owner: bytes) -> int:
    """Every successful create receipt carries a valid owner signature (check 8)."""
    key = Ed25519PublicKey.from_public_bytes(owner)
    n = 0
    for rc in receipts:
        st = rc["statement"]
        if st.get("action") != "create" or not 200 <= int(st.get("status") or 0) < 300:
            continue
        seq = st.get("sequence")
        ts, digest, sig = st.get("owner_timestamp"), st.get("owner_request_sha256"), st.get("owner_signature_b64")
        need(isinstance(ts, int) and isinstance(digest, str) and isinstance(sig, str),
             f"receipt {seq}: a create with no owner signature")
        try:
            key.verify(base64.b64decode(sig, validate=True), f"cathedral-owner-create-v1\n{ts}\n{digest}".encode())
        except (InvalidSignature, ValueError) as exc:
            raise Fail(f"receipt {seq}: the owner signature does not verify") from exc
        n += 1
    return n


def verify_receipts(att: dict, receipts: list[dict], head: str | None = None) -> dict:
    binding = att["binding"]
    bsha = att["binding_sha256"]
    hotel = is_hotel_level(att)
    want_schema = HOTEL_RECEIPT_SCHEMA if hotel else SEALED_RECEIPT_SCHEMA
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(binding["receipt_key_ed25519_b64"]))
    by_seq = {}
    for rc in receipts:
        st = rc["statement"]
        need(st.get("schema") == want_schema,
             f"receipt {st.get('sequence')}: not a {want_schema} statement")
        need(st["binding_sha256"] == bsha, f"receipt {st.get('sequence')} names another binding")
        need(rc["receipt_sha256"] == sha(canonical(st)), f"receipt {st['sequence']}: receipt_sha256 mismatch")
        try:
            key.verify(base64.b64decode(rc["signature_b64"]), canonical(st))
        except InvalidSignature as exc:
            raise Fail(f"receipt {st['sequence']}: signature does not verify") from exc
        # A repeated sequence would be counted twice in the totals below; a chain has one receipt per sequence.
        need(st["sequence"] not in by_seq, f"receipt {st['sequence']}: sequence appears more than once")
        by_seq[st["sequence"]] = rc
    links = 0
    for seq, rc in by_seq.items():
        prev = rc["statement"]["previous_receipt_sha256"]
        if seq == 1:
            need(prev == bsha, "receipt 1 does not link to the binding")
            links += 1
        elif seq - 1 in by_seq:
            need(prev == by_seq[seq - 1]["receipt_sha256"], f"receipt {seq} does not link to receipt {seq - 1}")
            links += 1
    seqs = sorted(by_seq)
    contiguous = bool(seqs) and seqs == list(range(seqs[0], seqs[-1] + 1))
    if head is not None and not seqs:  # a fresh hotel: the head is the binding itself
        need(head == bsha, "the chain is empty but the head is not the binding")
    elif head is not None:  # a whole chain (GET .../receipts from 0): no gap, ends at the head
        need(seqs[0] == 1 and contiguous, "the chain has a gap or does not start at receipt 1")
        need(by_seq[seqs[-1]]["receipt_sha256"] == head, "the chain does not end at the hotel's head")
    check_start_commands(receipts)
    actions = {}
    for rc in receipts:
        actions[rc["statement"]["action"]] = actions.get(rc["statement"]["action"], 0) + 1
    return {"receipts": len(receipts), "signatures_ok": len(receipts), "links_checked": links,
            "contiguous": contiguous, "first": seqs[0] if seqs else None, "last": seqs[-1] if seqs else None,
            "actions": actions}


def room_tunables(receipts: list[dict]) -> dict:
    """Room id -> the tunables_sha256 its signed create receipt carries (rooms with tunables only)."""
    out: dict[str, str] = {}
    for rc in receipts:
        st = rc["statement"]
        if st.get("action") != "create" or "tunables" not in st:
            continue
        need(st.get("tunables_sha256") == sha(canonical(st["tunables"])),
             f"receipt {st['sequence']}: tunables_sha256 does not match the tunables")
        if st.get("sandbox_id"):
            out[st["sandbox_id"]] = st["tunables_sha256"]
    return out


def room_links(receipts: list[dict]) -> dict:
    """Room id -> the Cathedral sandbox id its signed successful create receipt names (AB#389).

    Receipts from guests before AB#389 carry no cathedral_sandbox_id: their rooms are not listed."""
    out: dict[str, str] = {}
    for rc in receipts:
        st = rc["statement"]
        if st.get("action") != "create" or "cathedral_sandbox_id" not in st:
            continue
        linked = st["cathedral_sandbox_id"]
        need(isinstance(linked, str) and SANDBOX_LINK_RE.fullmatch(linked) is not None,
             f"receipt {st['sequence']}: cathedral_sandbox_id is not a lower-case UUID")
        if st.get("sandbox_id") and 200 <= int(st.get("status") or 0) < 300:
            out[st["sandbox_id"]] = linked
    return out


def check_start_commands(receipts: list[dict]) -> None:
    """Each create's start_command_sha256 matches its start_command (AB#709).

    Receipts without start_command are the default ``sleep infinity`` (old or default creates).
    """
    for rc in receipts:
        st = rc["statement"]
        if st.get("action") != "create" or "start_command" not in st:
            continue
        cmd = st.get("start_command")
        if cmd is None:
            need(st.get("start_command_sha256") is None,
                 f"receipt {st['sequence']}: start_command_sha256 must be absent when start_command is null")
            continue
        need(isinstance(cmd, list) and all(isinstance(part, str) for part in cmd),
             f"receipt {st['sequence']}: start_command must be a list of strings")
        need(st.get("start_command_sha256") == sha(canonical(cmd)),
             f"receipt {st['sequence']}: start_command_sha256 does not match the start command")


def policy_timeline(receipts: list[dict]) -> dict:
    """Room id -> the signed policy events of that room, in chain order.

    A room enters the timeline with a create or network_set receipt that
    carries a network policy. Its delete receipt closes the timeline."""
    out: dict[str, list[dict]] = {}
    for rc in sorted(receipts, key=lambda r: r["statement"]["sequence"]):
        st = rc["statement"]
        room = st.get("sandbox_id")
        if not room:
            continue
        policy = st.get("network_policy")
        if policy is not None:
            need(st.get("network_policy_sha256") == sha(canonical(policy)),
                 f"receipt {st['sequence']}: network_policy_sha256 does not match the policy")
            out.setdefault(room, []).append({
                "sequence": st["sequence"], "issued_at": st["issued_at"], "action": st["action"],
                "status": st["status"], "mode": policy["mode"], "allow": policy["allow"],
                "policy_sha256": st["network_policy_sha256"]})
        elif room in out and st["action"] == "delete":
            out[room].append({"sequence": st["sequence"], "issued_at": st["issued_at"], "action": "delete",
                              "status": st["status"]})
    return out


def get(url: str, key: str) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def fetch_archived_binding(broker: str, operator_key: str, binding_sha256: str) -> dict:
    """GET /v1/broker/bindings/<sha256>: binding JSON the broker archived after admission."""
    want = binding_sha256.lower()
    need(HEX64.fullmatch(want) is not None, "binding_sha256 is not 64 lower-case hex")
    try:
        binding = get(f"{broker.rstrip('/')}/v1/broker/bindings/{want}", operator_key)
    except urllib.error.HTTPError as exc:
        # Same wording as binding_archive.fetch_archived_binding.
        if exc.code == 404:
            raise Fail(f"no archived binding with hash {want[:16]}...") from exc
        raise Fail(f"broker binding archive answered {exc.code}") from exc
    need(isinstance(binding, dict), "the archived binding is not a JSON object")
    got = sha(canonical(binding))
    need(got == want, "the archived binding does not hash to its name")
    return {"binding": binding, "binding_sha256": got}


def receipt_binding_shas(receipts: list[dict]) -> set[str]:
    out: set[str] = set()
    for rc in receipts:
        st = rc.get("statement") if isinstance(rc, dict) else None
        if isinstance(st, dict) and isinstance(st.get("binding_sha256"), str):
            out.add(st["binding_sha256"].lower())
    return out


def partition_receipts(receipts: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for rc in receipts:
        st = rc["statement"]
        bsha = st["binding_sha256"].lower()
        groups.setdefault(bsha, []).append(rc)
    return groups


def verify_archived_binding(att: dict) -> dict:
    """An archived binding (no SNP report). Receipt signatures can still be checked.

    Archived sealed bindings are NOT PROVEN for attestation: the broker archive
    stores the binding JSON (self-hash + Ed25519 receipt key) but not the live
    SNP report. Callers must not fold these into an attested PASS.
    """
    binding = att["binding"]
    bsha = att["binding_sha256"]
    need(sha(canonical(binding)) == bsha, "binding_sha256 does not match the binding")
    if is_hotel_level(att):
        out = verify_hotel_attestation(att)
        out["archived_binding"] = True
        out["attestation_proven"] = True
        return out
    need(isinstance(binding.get("receipt_key_ed25519_b64"), str), "the archived binding has no receipt key")
    _b64_key(binding["receipt_key_ed25519_b64"], "receipt key")
    return {"binding_sha256": bsha, "archived_binding": True, "attestation_proven": False,
            "measurement": binding.get("measurement"), "hotel": binding.get("hotel"),
            "note": "archived binding verifies signatures only; no SNP report is archived"}


PAGE = 10000  # the hotel's largest page


def fetch_chain(broker: str, hotel: str, key: str) -> dict:
    """Read the whole receipt chain page by page (after=0, 10000, ...).

    The chain can grow while it is read. Reading stops at the first short
    page; the head of that page is the head the chain must end at.
    """
    receipts: list[dict] = []
    offset = 0
    while True:
        page = get(f"{broker}/v1/hotels/{hotel}/receipts?after={offset}&limit={PAGE}", key)
        receipts.extend(page["receipts"])
        # A guest's page is filtered by the broker: "scanned" is how far the
        # hotel's chain moved, which can be more than the receipts returned.
        scanned = page.get("scanned", len(page["receipts"]))
        offset += scanned
        if scanned < PAGE:
            return {"binding_sha256": page.get("binding_sha256"), "head": page.get("head"),
                    "filtered": bool(page.get("filtered")), "count": len(receipts), "receipts": receipts}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attestation", help="JSON from GET /room/attestation (or the broker's /v1/hotels/<id>/attestation)")
    ap.add_argument("--receipts", help="JSON from GET .../receipts (an object with 'receipts', or a list)")
    ap.add_argument("--receipt-header", action="append", default=[], help="X-Room-Receipt header value")
    ap.add_argument("--broker", help="broker base URL; fetches attestation and receipts itself")
    ap.add_argument("--key-file", help="guest API key file for --broker")
    ap.add_argument("--operator-key-file",
                    help="broker operator key file; fetches archived bindings for receipts from earlier boots")
    ap.add_argument("--hotel", required=False, default=None, help="hotel id (required with --broker)")
    ap.add_argument("--sandbox", help="with --broker: one room's receipts instead of the whole chain")
    ap.add_argument("--expected-measurement")
    ap.add_argument("--ark-sha256", action="append",
                    help="pin the AMD ARK certificate (sha256 of its DER); repeat to accept any of several")
    ap.add_argument("--product", help="Milan or Genoa (default: from the report)")
    ap.add_argument("--kds-cache", default=os.path.expanduser("~/.cache/amd-kds"))
    ap.add_argument("--skip-amd", action="store_true", help="skip the AMD chain (offline smoke test only)")
    ap.add_argument("--require-sealed", action="store_true", help="fail unless the hotel answers an SEV-SNP binding")
    ap.add_argument("--owner-pubkey", help="base64 Ed25519 public key: fail unless this is a dedicated machine of this owner")
    ap.add_argument("--save", help="with --broker: write the fetched attestation and receipts here")
    ap.add_argument("--tls-spki-sha256", help="SPKI sha256 of the TLS peer that served the attestation; "
                                              "fails unless the binding names this key")
    ap.add_argument("--require-tls", action="store_true", help="fail unless the binding names a guest TLS key")
    ap.add_argument("--origin", help="a miner hotel's https://<ip>:<port>: fetch the attestation from the guest "
                                     "and check the TLS peer and the install key")
    ap.add_argument("--cathedral-sandbox", help="a Cathedral sandbox id (UUID): fail unless a successful create "
                                                "receipt names it")
    a = ap.parse_args()
    if a.broker and not a.hotel:
        ap.error("--hotel is required with --broker (no default: a wrong hotel is a wrong chain)")
    if a.origin and (a.broker or a.attestation or a.tls_spki_sha256):
        ap.error("--origin fetches the attestation itself; it takes no --broker, --attestation or --tls-spki-sha256")
    try:
        peer_spki = a.tls_spki_sha256
        install_doc = None
        if a.origin:
            answers, peer_spki = fetch_origin(a.origin, ["/room/attestation", "/room/hotel-key-install-key"])
            need(answers[0][0] == 200, f"GET /room/attestation answered {answers[0][0]}")
            att = json.loads(answers[0][1])
            install_doc = json.loads(answers[1][1]) if answers[1][0] == 200 else None
            doc = json.load(open(a.receipts)) if a.receipts else []
        elif a.broker:
            key = open(a.key_file).read().strip()
            att = get(f"{a.broker}/v1/hotels/{a.hotel}/attestation", key)
            if a.sandbox:
                doc = get(f"{a.broker}/v1/sandboxes/{a.sandbox}/receipts", key)
            else:
                doc = fetch_chain(a.broker, a.hotel, key)
            if a.save:
                os.makedirs(a.save, exist_ok=True)
                json.dump(att, open(os.path.join(a.save, "attestation.json"), "w"), indent=1)
                json.dump(doc, open(os.path.join(a.save, "receipts.json"), "w"), indent=1)
        else:
            att = json.load(open(a.attestation))
            doc = json.load(open(a.receipts)) if a.receipts else []
        receipts = doc["receipts"] if isinstance(doc, dict) else doc
        # A guest's chain from the broker is filtered to its own rooms, so it
        # has gaps by design: check each receipt, not a whole chain to the head.
        # The broker's chain archive (GET /v1/broker/bindings/<sha>/receipts)
        # says complete=false when it holds only a prefix of the chain it saw
        # (AB#386): check each receipt, and never call that the whole chain.
        incomplete = isinstance(doc, dict) and doc.get("complete") is False
        whole = (isinstance(doc, dict) and not doc.get("filtered") and not incomplete
                 and not a.sandbox and not a.receipt_header)
        head = doc.get("head") if whole else None
        for h in a.receipt_header:
            receipts.append(json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4))))
        owner = owner_key_bytes(a.owner_pubkey) if a.owner_pubkey else None
        sealed_asked = a.require_sealed or a.expected_measurement or a.ark_sha256 or a.product or owner
        if is_hotel_level(att) and sealed_asked:
            # A sealed guest whose TSM is missing runs level 1 under the same
            # hotel name. Asking for a measurement means asking for SNP.
            raise Fail("the hotel answered a level 1 (unsealed) binding; an SEV-SNP attestation was asked for")
        live_bsha = att["binding_sha256"].lower()
        stale_shas = receipt_binding_shas(receipts) - {live_bsha}
        if stale_shas and not a.broker:
            raise Fail("some receipts name an earlier binding than the attestation's; "
                       "pass --broker and --operator-key-file to load archived bindings")
        if stale_shas and not a.operator_key_file:
            raise Fail(f"{len(stale_shas)} receipt binding(s) differ from the live attestation; "
                       "pass --operator-key-file to fetch archived bindings from the broker")
        operator_key = open(a.operator_key_file).read().strip() if a.operator_key_file else ""
        groups = partition_receipts(receipts)
        live_receipts = groups.get(live_bsha, [])
        chain_head = head if not stale_shas else None
        archive_chains: list[dict] = []
        unproven_archives: list[str] = []
        if is_hotel_level(att):
            need(not (a.require_tls or a.origin or peer_spki), "a level 1 binding has no attested guest TLS")
            attestation_out = verify_hotel_attestation(att)
            chain_out = verify_receipts(att, live_receipts, chain_head)
        else:
            attestation_out = verify_attestation(att, a.expected_measurement, a.product, a.kds_cache,
                                                 a.ark_sha256, a.skip_amd)
            guest_tls = verify_guest_tls(att, peer_spki, require=bool(a.require_tls or a.origin))
            if guest_tls is not None:
                if a.origin:
                    need(install_doc is not None, "the hotel did not answer GET /room/hotel-key-install-key")
                    guest_tls["install_key_checked"] = verify_install_key(install_doc, att) is not None
                attestation_out["guest_tls"] = guest_tls
            if owner is not None:
                attestation_out["owner"] = verify_owner(att, owner)
                attestation_out["owner"]["signed_creates"] = owner_signed_creates(live_receipts, owner)
            chain_out = verify_receipts(att, live_receipts, chain_head)
        for bsha in sorted(stale_shas):
            att_old = fetch_archived_binding(a.broker, operator_key, bsha)
            archived_out = verify_archived_binding(att_old)
            if not archived_out.get("attestation_proven"):
                unproven_archives.append(bsha)
            if owner is not None:
                owner_signed_creates(groups[bsha], owner)
            part = verify_receipts(att_old, groups[bsha], None)
            part["binding_sha256"] = bsha
            archive_chains.append(part)
        if archive_chains:
            attestation_out["archived_chains"] = archive_chains
            chain_out = {"receipts": len(receipts), "signatures_ok": chain_out.get("signatures_ok", 0)
                         + sum(p["signatures_ok"] for p in archive_chains),
                         "bindings": [live_bsha, *[p["binding_sha256"] for p in archive_chains]],
                         "live": chain_out}
        checked = ("whole chain to the head the server named" if chain_head is not None
                   else "each receipt; not that none are missing")
        # Sealed archives have no SNP report. Signature checks on those receipts
        # are useful, but they must not turn an overall attested PASS into a claim
        # that every receipt's binding was SNP-proven (AB#381 HOLD).
        # Decide on the archived bindings themselves: the live binding says
        # nothing about an earlier boot (a sealed guest whose TSM went missing
        # reboots as level 1 under the same hotel name).
        sealed_archive = bool(unproven_archives)
        if sealed_archive:
            checked += "; archived sealed bindings verify signatures only (NOT PROVEN for attestation)"
            verdict = "NOT PROVEN"
        else:
            if archive_chains:
                checked += "; archived bindings verify signatures only"
            verdict = "PASS"
        if incomplete:
            checked += "; INCOMPLETE archive: a prefix of the chain, not shown to reach the hotel's head"
            verdict = "NOT PROVEN"
        out = {"attestation": attestation_out,
               "chain": chain_out,
               "policy_timeline": policy_timeline(receipts), "room_tunables": room_tunables(receipts),
               "room_links": room_links(receipts), "verdict": verdict,
               "checked": checked}
        not_proven = []
        if sealed_archive:
            not_proven.append(
                "archived sealed bindings have no SNP report; receipt signatures checked, attestation not proven")
        if incomplete:
            not_proven.append("the archived chain is incomplete; receipts after the last one archived are missing")
        if not_proven:
            out["not_proven"] = not_proven
        if a.cathedral_sandbox:
            rooms = sorted(room for room, linked in out["room_links"].items() if linked == a.cathedral_sandbox)
            need(rooms, f"no successful create receipt names Cathedral sandbox {a.cathedral_sandbox}")
            out["sandbox_link"] = {"cathedral_sandbox_id": a.cathedral_sandbox, "rooms": rooms}
        print(json.dumps(out, indent=1))
        return 3 if verdict == "NOT PROVEN" else 0
    except Fail as exc:
        print(json.dumps({"verdict": "FAIL", "reason": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
