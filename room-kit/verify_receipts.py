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
 10. room numbering: a room whose receipts all carry room_sequence and
     room_previous_receipt_sha256 has them run 1 to n with no gap and no repeat,
     each linked to the one before; a per-room list that names room_head and
     count must match them. A room with only some of the fields gets a warning
     in "checked" and no numbering claim; a room with none is read as before.
     A receipt with serial: true must be a successful create and receipt 1 of
     its room, the room has no second create and no lost answer (502), and the
     output says the room is closed to its last action. room_end needs a
     reason. The output's chain.room_numbering lists each room and says what
     the numbering shows and what it does not.
 11. pre-made rooms: a create with pool: true is receipt 1 of its room, is not
     serial and names no sandbox link. Receipt 2 is a claim (target
     POST /v1/sandboxes/<room>/claim, a lower-case UUID cathedral_sandbox_id, a
     positive lifetime_seconds, pooled_from the create's receipt hash), which
     needs numbered receipts. The claim's id is the room's link, so
     --cathedral-sandbox finds it; an unclaimed room, a retired one and a room
     whose claim failed name no link. The output's pool_rooms gives each state.

Run mode (--oneshot FILE, a cathedral_oneshot_bundle_v1) checks one run's file offline against what the
caller expects, in eight checks. The AMD certificates come from the file (amd_certs) and must match
--ark-sha256, which run mode requires. Any missing input is a FAIL, never a guess.
Run mode takes --oneshot, --recipe, --context or --no-context, --run-id, --input-sha256, --input-file,
--output-file, --expected-measurement, --allowed-measurements, --ark-sha256, --product and --require-sealed (which
changes nothing: run mode always requires an SEV-SNP attestation). These flags are usage errors with exit 2:
--receipts, --attestation, --broker, --origin, --key-file, --operator-key-file, --hotel, --sandbox,
--receipt-header, --cathedral-sandbox, --save, --owner-pubkey, --tls-spki-sha256, --require-tls and --kds-cache,
whether given with a value, an empty value or the old default. --skip-amd is a failed check 1 (exit 1). --help
exits 0. The owner check (--owner-pubkey) and the guest TLS key check (--tls-spki-sha256, --require-tls) are
list-mode checks; run mode does not do them.
--product: a report with CPUID fields (version 3 on) names its own product. A family with no layout fails whatever
--product says, and a --product that names another product than the report fails. Only a version 2 report, which
has no CPUID fields, takes the product from --product; there nothing in the report can contradict the name, and
Milan and Genoa share the layout. A report of version 0 or 1, or of a version above 5, fails whatever --product
says ("the report is version N, which has no layout here"); the flag is read for no version but 2. List mode
reads the product the same way.
List mode also refuses, with a reason and never an uncaught error, a receipt that is not an object with a
statement, a statement whose sequence, binding, action, status or room id has the wrong type, a network_policy
that is not an object with a string mode and a list allow, and a receipt that carries a policy (or closes a policy
timeline) without an integer issued_at and status.
  1. attestation, AMD chain, measurement (--expected-measurement, repeatable, or --allowed-measurements FILE),
     every receipt's signature, one binding.
  2. the room's receipts run 1 to m with every link right, receipt 1 is the create and says serial: true,
     no receipt is a lost answer (502).
  3. the actions are exactly: create, put of the context, put of each input, exec, get of each output, put of
     the end marker; each signed target is the exact string the recipe gives (paths, modes, max_bytes).
  4. the create succeeded and names the file's oneshot_id (and --run-id, when given); its bytes (hashed in the
     receipt) hold exactly the create keys of broker/oneshot_create_keys.json, with the recipe's image,
     resources, ttl_seconds, the broker's form of the recipe's network, and the four labels; a repeated key or a
     number that is not an integer is refused; image_digest equals the recipe's image_id when it gives one.
  5. the context put carries the hash of --context (or {} with --no-context); each input put carries the hash
     given by --input-sha256 or --input-file.
  6. the exec returned 200; its bytes hold cmd, timeout_seconds, env (and cwd, user when the recipe has them)
     and nothing else, equal to the recipe's.
  7. each output get returned exactly 200 (an optional output may answer 404 and is then absent); bytes held
     (--output-file, or inline_outputs) must hash to the signed result and fit max_bytes, else the output is
     reported as receipt_only; the end marker put carries the hash of no bytes.
  8. the request in the file equals the recipe (image, command, env, cwd, user, size, timeout, network, outputs,
     input paths and hashes, context) and holds no key that is not a request field.
max_spend_usd is a JSON integer of at least 1 or a decimal string such as "0.50" (greater than zero, at most six
decimals); never a JSON float, and the recipe and the file must hold it in the same form.
create.ttl_seconds must be timeout_seconds plus the room margin (600, room_margin_seconds in
broker/oneshot_create_keys.json).
The recipe (cathedral_oneshot_recipe_v1) is strict: a member the checker does not know, at any level, is
refused. request must hold image, command, env, size, timeout_seconds, network, outputs, inputs and
max_spend_usd (env and inputs may be empty); cwd, user and image_id are optional, and must agree between the
recipe and the file (absent on both is fine, absent on one is a difference). create holds ttl_seconds and,
optionally, broker_guest. size must be a sealed size; it fixes the create's resources (the table is the one in
broker/oneshot_create_keys.json). An output's optional is a JSON boolean and false when absent. The network is
a mode name (deny_all, internet, allowlist) or an object {mode, allow}; it is compared as the machine API
canonicalises it (names lower case, merged, sorted). The context is bound by its signed put (check 5); a context member in the file's request must equal it too.
The output adds "run": the outputs, the exit code (confirmed only when exec_response_b64 hashes to the signed
result; otherwise "not confirmed", and the verdict does not change), what the file shows, and what it does not.

Not checked here (by design, today): that the measurement is an approved image.
Image approval is a signed policy release; that is a later step.

Usage:
  verify_receipts.py --attestation att.json --receipts chain.json [--receipt-header B64 ...]
  verify_receipts.py --broker https://<broker> --key-file KEY --hotel <hotel id> [--sandbox ID]
  verify_receipts.py --broker ... --operator-key-file OP --hotel <id>   # receipts from earlier boots
  verify_receipts.py --origin https://<miner ip>:<port> --require-sealed [--expected-measurement M]
  add --owner-pubkey B64 --expected-measurement HEX for a dedicated machine
  verify_receipts.py --oneshot run.json --recipe recipe.json (--context ctx.json | --no-context) \\
      --ark-sha256 HEX --expected-measurement HEX [--run-id UUID] [--input-sha256 PATH=HEX | --input-file PATH=FILE] \\
      [--output-file PATH=FILE]

When receipts name a binding_sha256 other than the live attestation, pass --broker and
--operator-key-file so GET /v1/broker/bindings/<sha> can load each archived binding.
The archive holds binding JSON only (no SNP report); those checks cover signatures only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import itertools
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import quote_plus, urlencode, urlsplit

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
ONESHOT_BUNDLE_SCHEMA = "cathedral_oneshot_bundle_v1"
ONESHOT_RECIPE_SCHEMA = "cathedral_oneshot_recipe_v1"
# The keys the broker puts in a one-shot create, and its labels. Copied from broker/oneshot_create_keys.json;
# a test fails when the two differ.
ONESHOT_CREATE_KEYS = ("image", "resources", "network", "ttl_seconds", "labels")
ONESHOT_LABEL_KEYS = ("cathedral_sandbox_id", "cathedral_serial", "broker_guest", "broker_batch")
# The sealed sizes and the resources the broker sends the machine for each (broker/oneshot_create_keys.json).
ONESHOT_SIZES = {
    "sealed-1x2": {"vcpu": 1, "memory_gib": 2, "disk_gib": 10},
    "sealed-2x4": {"vcpu": 2, "memory_gib": 4, "disk_gib": 10},
    "sealed-4x8": {"vcpu": 4, "memory_gib": 8, "disk_gib": 10},
    "sealed-8x16": {"vcpu": 8, "memory_gib": 16, "disk_gib": 10},
}
# A one-shot room lives for the timeout plus this margin, so a caller can write the recipe's create.ttl_seconds
# without asking (broker/oneshot_create_keys.json, room_margin_seconds).
ONESHOT_ROOM_MARGIN_SECONDS = 600
ROOM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FILE_MODE_RE = re.compile(r"^[0-7]{3,4}$")
CONTEXT_PATH = "/work/in/.context.json"
END_MARKER_PATH = "/work/.cathedral-end"
# Spec G4 5.1: these must be present, with the right type, in the recipe and in the file's request. The others
# (cwd, user, image_id) may be absent in both; absent in one only is a difference.
REQUIRED_REQUEST_FIELDS = ("image", "command", "env", "size", "timeout_seconds", "network", "outputs", "inputs",
                           "max_spend_usd")
BUNDLE_MEMBERS = ("schema", "oneshot_id", "request", "attestation", "amd_certs", "receipts", "create_request_b64",
                  "exec_request_b64", "exec_response_b64", "inline_outputs", "not_proven")
ATTESTATION_MEMBERS = ("binding", "binding_sha256", "report_b64")
RECEIPT_MEMBERS = ("statement", "signature_b64", "receipt_sha256")
REQUEST_FIELDS = ("image", "image_id", "command", "env", "cwd", "user", "size", "timeout_seconds", "network",
                  "outputs", "inputs", "context", "max_spend_usd")
RUN_SHOWS = [
    "A machine with this measurement started this image, with nothing added at create.",
    ("These input files and this context were written. This command ran with this environment on top of the "
     "image's own."),
    ("These output files were then read, and the room was still there after the last read. Between its start and "
     "the end marker, no other request that can run something in the room, write to it or change its limit "
     "reached it through the machine's front."),
]
RUN_DOES_NOT_SHOW = [
    "That a second run gives the same output.",
    "The exit code, unless the exec answer in the file hashes to the signed result (see exit_code).",
    "That the room is gone: the delete is clean-up.",
    "Which build the measurement stands for: it is checked against the measurements you allowed.",
    "The request headers of file calls: they are in neither the signed target nor any hash.",
    "Reads (logs, for one): they leave no receipt.",
    "That the machine's disk was left unaltered by its host: the receipts do not show it either way.",
    "That the approved build is the same as the published source: the allowed measurements are your own list.",
]
RUN_CHECKED = "run mode: checks 1 to 8 of the one-shot file"



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


# Report versions with a layout here: 2 has no CPUID fields, 3 and later have them.
SUPPORTED_REPORT_VERSIONS = (2, 3, 4, 5)


def product(rep: dict, override: str | None) -> str:
    """The product the report names. A report with CPUID fields (version 3 on) names its own: a family with no
    layout here fails whatever --product says, and a different --product fails. Only a version 2 report, which
    has no CPUID fields, takes the product from --product; no other version reads the flag."""
    version, fam, mod = rep["version"], rep["cpuid_fam"], rep["cpuid_mod"]
    if version not in SUPPORTED_REPORT_VERSIONS:
        raise Fail(f"the report is version {version}, which has no layout here")
    if version == 2:
        if override is not None:
            return override
        raise Fail(f"cannot tell the product from cpuid family {fam} model {mod}; pass --product")
    if fam != 0x19:
        raise Fail(f"the report names cpuid family {fam} model {mod}, which has no layout here")
    shown = "Genoa" if mod is not None and mod >= 0x10 else "Milan"
    if override is not None and override != shown:
        raise Fail(f"--product {override}: the report names the product {shown}")
    return shown


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


def load_bundle_certs(certs: dict) -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    """VCEK, ASK and ARK from base64 DER, as a one-shot's file carries them."""
    try:
        return tuple(x509.load_der_x509_certificate(base64.b64decode(certs[k], validate=True))
                     for k in ("vcek", "ask", "ark"))
    except (KeyError, TypeError, ValueError) as exc:
        raise Fail("the AMD certificates are not base64 DER certificates (vcek, ask, ark)") from exc


def verify_amd(report: bytes, rep: dict, prod: str, cache: str, ark_sha256: str | list[str] | None,
               certs: dict | None = None) -> dict:
    """The AMD chain. certs (base64 DER vcek, ask, ark) replace the KDS fetch; every other check is the same."""
    tcb = rep["reported_tcb"]
    need(prod in ("Genoa", "Milan"), "only Milan and Genoa TCB layouts are handled")
    bl, tee, snp, ucode = tcb[0], tcb[1], tcb[6], tcb[7]
    if certs is None:
        chain_pem = fetch(f"{KDS}/{prod}/cert_chain", cache, f"{prod}-cert_chain.pem")
        loaded = x509.load_pem_x509_certificates(chain_pem)
        need(len(loaded) == 2, "KDS cert_chain should hold ASK and ARK")
        ask, ark = loaded
        vcek = None
    else:
        vcek, ask, ark = load_bundle_certs(certs)
    pss_verify(ark, ark)
    pss_verify(ark, ask)
    ark_fp = sha(ark.public_bytes(serialization.Encoding.DER))
    if ark_sha256:
        # Any pin may match: each product has its own ARK, and the chain
        # fetched is the report's product, so one run serves a mixed fleet.
        pins = [ark_sha256] if isinstance(ark_sha256, str) else ark_sha256
        need(ark_fp in {p.lower() for p in pins}, f"ARK sha256 {ark_fp} differs from the pinned value")
    chip = rep["chip_id"].hex()
    if vcek is None:
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


def verify_attestation(att: dict, expected_measurement: str | list[str] | None, prod: str | None, cache: str,
                       ark_sha256: str | list[str] | None, skip_amd: bool, certs: dict | None = None) -> dict:
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
        allowed = [expected_measurement] if isinstance(expected_measurement, str) else list(expected_measurement)
        allowed = [m.lower() for m in allowed]
        if len(allowed) == 1:
            need(rep["measurement"] == allowed[0], "measurement differs from the expected build")
        else:
            need(rep["measurement"] in allowed, "measurement is not one of the allowed measurements")
    out = {"binding_sha256": bsha, "measurement": rep["measurement"], "chip_id": rep["chip_id"].hex()[:16] + "...",
           "policy": hex(rep["policy"]), "host_data": rep["host_data"], "report_version": rep["version"],
           "kernel_cmdline": cmdline}
    if not skip_amd:
        out["amd"] = verify_amd(report, rep, product(rep, prod), cache, ark_sha256, certs)
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


POOL_CLAIM_SHOWS = (
    "Nothing ran in this room before the claim except the machine's own main process, and no request reached it "
    "through the front. This rests on the rules of the measured front, so it holds only for the measurements you "
    "allowed.")
POOL_CHECKED = "pool rooms: each claim is receipt 2 of its room and names the create it was made from"


def _check_pool_rooms(receipts: list[dict]) -> dict[str, dict]:
    """Pre-made rooms: receipt 1 is a pool create, receipt 2 is the claim made from it.

    The claim's sandbox id is the room's link, so every part of the pair is checked here, by the code
    that hands the link out. Entries keep the room and link under underscore keys for room_links."""
    groups = room_groups(receipts)
    out: dict[str, dict] = {}
    for (bsha, room), rcs in groups.items():
        for rc in rcs:
            st = rc["statement"]
            where = f"room {room}: receipt {st.get('sequence')}"
            if "pool" in st:
                need(isinstance(st["pool"], bool), f"{where}: pool is not a boolean")
                if st["pool"]:
                    need(st.get("action") == "create" and _succeeded(st),
                         f"{where}: pool is set on a receipt that is not a successful create")
                    need(st.get("serial") is not True, f"{where}: a pool create cannot also be serial")
                    need("cathedral_sandbox_id" not in st, f"{where}: a pool create names a sandbox link")
        pool_creates = [rc for rc in rcs if rc["statement"].get("pool") is True]
        claims = [rc for rc in rcs if rc["statement"].get("action") == "claim"]
        for rc in claims:
            need(pool_creates, f"room {room}: receipt {rc['statement'].get('sequence')}: "
                               "a claim in a room that was not made as a pool room")
        if not pool_creates:
            continue
        need(len(pool_creates) == 1, f"room {room}: a pool room has one create")
        create = pool_creates[0]
        numbered = all(_has_complete_numbering(rc["statement"]) for rc in rcs)
        if claims:
            first = claims[0]["statement"]
            need(numbered, f"room {room}: receipt {first.get('sequence')}: a claim needs numbered receipts: "
                           "cannot show nothing sits between create and claim")
            ordered = check_room_chain(room, rcs)
        else:
            ordered = sorted(rcs, key=lambda rc: rc["statement"].get("sequence"))
        need(ordered[0] is create, f"room {room}: a pool create must be receipt 1 of its room")
        entry = {"state": "unclaimed", "pooled_from": create["receipt_sha256"], "_room": room}
        if claims:
            for rc in claims:
                need(rc is ordered[1] if len(ordered) > 1 else False,
                     f"room {room}: receipt {rc['statement'].get('sequence')}: a claim must be receipt 2 of a pool room")
            st = ordered[1]["statement"]
            where = f"room {room}: receipt {st.get('sequence')}"
            need(st.get("target") == f"POST /v1/sandboxes/{room}/claim",
                 f"{where}: the claim's target is not POST /v1/sandboxes/{room}/claim")
            need(st.get("pooled_from") == create["receipt_sha256"],
                 f"{where}: pooled_from is not the pool create's receipt hash")
            if _succeeded(st):
                linked = st.get("cathedral_sandbox_id")
                need(isinstance(linked, str) and SANDBOX_LINK_RE.fullmatch(linked) is not None,
                     f"{where}: cathedral_sandbox_id is not a lower-case UUID")
                need(_is_int(st.get("lifetime_seconds")) and st["lifetime_seconds"] > 0,
                     f"{where}: lifetime_seconds is not a positive integer")
                entry.update(state="claimed", shows=[POOL_CLAIM_SHOWS], _link=linked)
            else:
                entry["state"] = "closed"
        elif len(ordered) > 1:
            # A room deleted before any claim is retired. Anything else at receipt 2 is a request that
            # reached the room with no claim.
            second = ordered[1]["statement"]
            need(second.get("action") == "delete",
                 f"room {room}: receipt {second.get('sequence')}: receipt 2 of a pool room is not a claim")
            entry["state"] = "retired"
        out[room_key(groups, bsha, room)] = entry
    return out


def pool_rooms(receipts: list[dict]) -> dict[str, dict]:
    """Room id -> {state, pooled_from} for each pre-made room: claimed, closed, unclaimed or retired."""
    return {key: {k: v for k, v in entry.items() if not k.startswith("_")}
            for key, entry in _check_pool_rooms(receipts).items()}


def room_links(receipts: list[dict]) -> dict:
    """Room id -> the Cathedral sandbox id its signed successful create receipt names (AB#389).

    Receipts from guests before AB#389 carry no cathedral_sandbox_id: their rooms are not listed.
    A pre-made room is linked by its claim, after the pair is checked (_check_pool_rooms)."""
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
    for entry in _check_pool_rooms(receipts).values():
        if entry.get("_link"):
            out[entry["_room"]] = entry["_link"]
    return out


ORDINARY_ROOM_SHOWS = "No receipt of this room is missing from this list, between its first receipt and its last."
ORDINARY_ROOM_DOES_NOT_SHOW = (
    "That nothing was still running in the room when the list was read, or that no receipt was signed after it. "
    "There is no closed verdict for an ordinary room.")
SERIAL_ROOM_SHOWS = (
    "Every request on a signed route that named the room and reached it through the front before the last receipt "
    "was signed is in this list, in the order it ran, and none was still running.")
SERIAL_ROOM_DOES_NOT_SHOW = [
    ("Reads leave no receipt. A plain heartbeat sent just before the room was marked serial leaves none."),
    ("A bulk delete, the reaper and an API restart can remove the room without a receipt. A last action that is a "
     "successful exec, file put or file get shows the room was alive when it ran."),
    ("Programs left running inside the room: its main process, a program an earlier exec left behind, a process "
     "started by process_start."),
    ("A front restart loses the serial mark and the key; a run that spans one fails."),
]
NUMBERED_CHECKED = "each numbered room: its receipts run 1 to n with no gap and every link right"
LIVE_ACTIONS = ("exec", "file_put", "file_get")


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _succeeded(st: dict) -> bool:
    status = st.get("status")
    return _is_int(status) and 200 <= status < 300


def _has_numbering(st: dict) -> bool:
    return "room_sequence" in st or "room_previous_receipt_sha256" in st


def _has_complete_numbering(st: dict) -> bool:
    return "room_sequence" in st and "room_previous_receipt_sha256" in st


def check_room_chain(room: str, rcs: list[dict], in_order: bool = False) -> list[dict]:
    """One room's numbered receipts: 1 to n, no gap, no repeat, each linked to the one before.

    Returns the receipts in room order. Every receipt must carry the numbering fields."""
    for rc in rcs:
        st = rc["statement"]
        where = f"room {room}: receipt {st.get('sequence')}"
        need(_is_int(st.get("room_sequence")), f"{where}: room_sequence is not an integer")
        prev = st.get("room_previous_receipt_sha256")
        need(prev is None or (isinstance(prev, str) and HEX64.fullmatch(prev) is not None),
             f"{where}: room_previous_receipt_sha256 is neither null nor 64 lower-case hex")
    if in_order:  # a one-shot's file lists the receipts by their room numbers: check the order as given
        given = [rc["statement"]["room_sequence"] for rc in rcs]
        need(given == sorted(given), f"room {room}: the receipts are not in the order of their room numbers")
    ordered = sorted(rcs, key=lambda rc: rc["statement"]["room_sequence"])
    seqs = [rc["statement"]["room_sequence"] for rc in ordered]
    for n in seqs:
        need(seqs.count(n) == 1, f"room {room}: room_sequence {n} appears more than once")
    need(seqs[0] == 1, f"room {room}: room_sequence does not start at 1 (first is {seqs[0]})")
    for before, after in itertools.pairwise(seqs):
        need(after == before + 1, f"room {room}: room_sequence jumps from {before} to {after}: a receipt is missing")
    for i, rc in enumerate(ordered):
        prev = rc["statement"]["room_previous_receipt_sha256"]
        if i == 0:
            need(prev is None, f"room {room}: room receipt 1 must have a null room_previous_receipt_sha256")
        else:
            need(prev == ordered[i - 1]["receipt_sha256"],
                 f"room {room}: room receipt {i + 1} does not link to room receipt {i}")
    return ordered


def check_serial_room(room: str, ordered: list[dict]) -> None:
    """A serial room: its one create is receipt 1, and no receipt is for a lost answer (502)."""
    for rc in ordered:
        st = rc["statement"]
        if st.get("serial") is True:
            need(st["room_sequence"] == 1, f"room {room}: receipt {st['sequence']}: "
                                           "a serial create must be receipt 1 of its room")
    for rc in ordered:
        st = rc["statement"]
        where = f"room {room}: receipt {st['sequence']}"
        need(st.get("serial") is True or st.get("action") != "create", f"{where}: a second create in a serial room")
        need(st.get("status") != 502, f"{where}: a lost answer (status 502) in a serial room")


def room_groups(receipts: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Receipts by (binding, room id). A room id can come back under another key, with its own numbers."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for rc in receipts:
        st = rc["statement"]
        room = st.get("sandbox_id")
        if isinstance(room, str) and room:
            groups.setdefault((str(st.get("binding_sha256")), room), []).append(rc)
    return groups


def room_key(groups: dict, bsha: str, room: str) -> str:
    """The room id, or the room id and its binding when two bindings both name it."""
    return room if sum(1 for _, r in groups if r == room) == 1 else f"{room}@{bsha[:12]}"


def room_numbering(receipts: list[dict], list_doc: dict | None = None) -> dict:
    """Per-room numbering and serial rooms (the receipts' room_sequence, serial and room_end fields).

    A room whose receipts all carry the numbering fields is checked in full. A room with some of them
    gets a warning and no claim; a room with none is left as it was. Returns the rooms that were
    checked and the warnings. list_doc is a per-room list answer: its room_head and count are checked."""
    groups = room_groups(receipts)
    rooms: dict[str, dict] = {}
    warnings: list[str] = []
    for (bsha, room), rcs in groups.items():
        serial_seen = False
        for rc in rcs:
            st = rc["statement"]
            where = f"room {room}: receipt {st.get('sequence')}"
            if "serial" in st:
                need(isinstance(st["serial"], bool), f"{where}: serial is not a boolean")
                if st["serial"]:
                    need(st.get("action") == "create" and _succeeded(st),
                         f"{where}: serial is set on a receipt that is not a successful create")
                    serial_seen = True
            if st.get("action") == "room_end":
                reason = st.get("reason")
                need(isinstance(reason, str) and reason != "", f"{where}: room_end has no reason")
        flags = [_has_numbering(rc["statement"]) for rc in rcs]
        complete = [_has_complete_numbering(rc["statement"]) for rc in rcs]
        if serial_seen:
            for rc in rcs:
                if rc["statement"].get("serial") is True:
                    need(all(complete), f"room {room}: receipt {rc['statement']['sequence']}: "
                                     "a serial create needs numbered receipts")
        if not any(flags):
            continue
        if not all(complete):
            kind = "with and without numbering" if not all(flags) else "with incomplete numbering"
            warnings.append(f"room {room} has receipts {kind}: no numbering claim for it")
            continue
        ordered = check_room_chain(room, rcs)
        if serial_seen:
            check_serial_room(room, ordered)
        last = ordered[-1]["statement"]
        entry = {"receipts": len(ordered), "first": ordered[0]["statement"]["sequence"], "last": last["sequence"],
                 "head": ordered[-1]["receipt_sha256"]}
        if serial_seen:
            entry["serial"] = True
            entry["closed_to"] = last.get("action")
            entry["alive_at_last_action"] = True if last.get("action") in LIVE_ACTIONS and _succeeded(last) else None
        ends = [rc["statement"] for rc in ordered if rc["statement"].get("action") == "room_end"]
        if ends:
            entry["ended"] = {"reason": ends[-1]["reason"]}
        # The same room id under two bindings has two chains: name them apart.
        rooms[room_key(groups, bsha, room)] = entry
    if list_doc is not None and "count" in list_doc:
        # An integer as written: in Python a boolean equals 0 or 1 and 0.0 equals 0, which other tools do not mirror.
        need(_is_int(list_doc["count"]), "the list's count is not an integer")
    if list_doc is not None and "room_head" in list_doc:
        need(len(groups) <= 1, f"the list names a room_head but holds receipts of {len(groups)} rooms")
        if not groups:
            need(list_doc["room_head"] is None, "an empty room list names a nonempty room_head")
            if "count" in list_doc:
                need(list_doc["count"] == 0, "an empty room list names a nonzero count")
        if groups:
            (_, room), rcs = next(iter(groups.items()))
            order_key = "room_sequence" if all(_has_complete_numbering(rc["statement"]) for rc in rcs) else "sequence"
            last_rc = max(rcs, key=lambda rc: rc["statement"][order_key])
            need(last_rc["receipt_sha256"] == list_doc["room_head"],
                 f"room {room}: the last receipt is not the room_head the list names")
            if "count" in list_doc:
                need(list_doc["count"] == len(rcs), f"room {room}: the list names {list_doc['count']} receipts "
                                                    f"but holds {len(rcs)}")
    return {"rooms": rooms, "warnings": warnings}


def numbering_words(rooms: dict[str, dict]) -> dict:
    """What a numbered list shows, and what it does not, in the words the output carries."""
    serial = [e for e in rooms.values() if e.get("serial")]
    ordinary = [e for e in rooms.values() if not e.get("serial")]
    shows = ([ORDINARY_ROOM_SHOWS] if ordinary else []) + ([SERIAL_ROOM_SHOWS] if serial else [])
    does_not = ([ORDINARY_ROOM_DOES_NOT_SHOW] if ordinary else []) + (SERIAL_ROOM_DOES_NOT_SHOW if serial else [])
    return {"rooms": rooms, "shows": shows, "does_not_show": does_not}



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


def check_receipt_shapes(receipts) -> None:
    """Every receipt of a list is an object with a statement of the shape the list-mode checks read, so a signed
    but malformed statement ends in a reason and not in an uncaught error."""
    need(isinstance(receipts, list), "the receipts are not a list")
    for i, rc in enumerate(receipts, start=1):
        need(isinstance(rc, dict) and isinstance(rc.get("statement"), dict),
             f"receipt {i} of the list is not an object with a statement")
        for key in ("signature_b64", "receipt_sha256"):
            need(isinstance(rc.get(key), str), f"receipt {i} of the list has no string {key}")
        try:
            base64.b64decode(rc["signature_b64"])
        except ValueError as exc:
            raise Fail(f"receipt {i} of the list: signature_b64 is not base64") from exc
        st, where = rc["statement"], f"receipt {i} of the list"
        need(_is_int(st.get("sequence")), f"{where}: sequence is not an integer")
        need(isinstance(st.get("binding_sha256"), str), f"{where}: binding_sha256 is not a string")
        need(isinstance(st.get("action"), str), f"{where}: action is not a string")
        need("previous_receipt_sha256" in st, f"{where} has no previous_receipt_sha256")
        need(st.get("status") is None or _is_int(st["status"]), f"{where}: status is not an integer")
        need(st.get("sandbox_id") is None or isinstance(st["sandbox_id"], str), f"{where}: sandbox_id is not a string")


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
        if policy is not None or (room in out and st["action"] == "delete"):
            where = f"receipt {st['sequence']}"
            need(_is_int(st.get("issued_at")), f"{where}: issued_at is not an integer")
            need(_is_int(st.get("status")), f"{where}: status is not an integer")
        if policy is not None:
            need(isinstance(policy, dict), f"{where}: network_policy is not an object")
            need("mode" in policy, f"{where}: network_policy has no mode")
            need("allow" in policy, f"{where}: network_policy has no allow")
            need(isinstance(policy["mode"], str), f"{where}: network_policy mode is not a string")
            need(isinstance(policy["allow"], list), f"{where}: network_policy allow is not a list")
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


# How deep a JSON document may nest before run mode refuses to read it. The depth is counted on the raw text,
# before any parse, so the answer is the same on every Python version (the parsers give up at different depths).
# The documents run mode reads are a few levels deep and the context rule is 32, so 64 leaves room.
JSON_MAX_DEPTH = 64


# The longest number literal a read document may hold, counted on the raw text over the whole token: sign, digits,
# point and exponent. Python 3.11 and later refuse an integer of more than 4,300 digits and earlier versions do
# not, so a fixed bound keeps the answer the same on every version. No number run mode reads comes near it.
JSON_MAX_NUMBER_CHARS = 100
NUMBER_CHARS = frozenset("0123456789+-.eE")


class Unreadable(Fail):
    """A document run mode refuses to read because of its nesting or a number's length."""


HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
SURROGATE_CODE_POINT_RE = re.compile("[\ud800-\udfff]")


def _hex4(text: str, at: int) -> int | None:
    digits = text[at:at + 4]
    return int(digits, 16) if len(digits) == 4 and set(digits) <= HEX_DIGITS else None


def json_shape(text: str) -> tuple[int, int, bool]:
    """(the deepest nesting of [ and {, the longest number token, whether an unpaired surrogate is in the text),
    all decided on the raw text before any parse.

    A number token is a run of digits, signs, points and the letters e and E (the e of true and false counts as a
    run of one). An unpaired surrogate is a surrogate code point in the decoded text, or a \\uXXXX escape of a high
    surrogate not followed at once by an escape of a low one, or of a low one not preceded by a high one; a
    backslash followed by ud800 (an escaped backslash, then text) is not an escape. Characters inside strings are
    skipped for nesting and numbers; the walk is a loop, not a recursion."""
    depth = deepest = run = longest = 0
    unpaired = SURROGATE_CODE_POINT_RE.search(text) is not None
    in_string = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            if ch == "\\":
                code = _hex4(text, i + 2) if text[i + 1:i + 2] == "u" else None
                if code is None:
                    i += 2  # any other escape, an escaped quote and an escaped backslash among them
                    continue
                if 0xD800 <= code <= 0xDBFF:
                    low = _hex4(text, i + 8) if text[i + 6:i + 8] == "\\u" else None
                    if low is not None and 0xDC00 <= low <= 0xDFFF:
                        i += 12  # a proper pair
                        continue
                    unpaired = True
                elif 0xDC00 <= code <= 0xDFFF:
                    unpaired = True
                i += 6
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        i += 1
        if ch in NUMBER_CHARS:
            run += 1
            longest = max(longest, run)
            continue
        run = 0
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest, longest, unpaired


def json_depth(text: str) -> int:
    """The deepest nesting of [ and { in a JSON text, counted on the raw text."""
    return json_shape(text)[0]


def strict_json(raw: bytes, prefix: str, what: str, plural: bool = False, floats: bool = False):
    """Parse JSON the way the Go checker does: a repeated key, at any level, and a non-integer number are refused.

    floats=True lets numbers with a fraction through (a receipt can hold one); repeated keys are still refused."""
    def pairs(items):
        out: dict = {}
        for key, value in items:
            need(key not in out, f"{prefix}: {what} {'repeat' if plural else 'repeats'} the key {key!r}")
            out[key] = value
        return out

    def refuse(text):
        raise Fail(f"{prefix}: {what} {'hold' if plural else 'holds'} the number {text}, which is not an integer")

    try:
        text = raw.decode(json.detect_encoding(raw), "surrogatepass")
    except (UnicodeDecodeError, LookupError):
        text = None  # not decodable: the parse below says so
    if text is not None:
        deepest, longest, unpaired = json_shape(text)
        if deepest > JSON_MAX_DEPTH:
            raise Unreadable(f"{prefix}: {what} {'nest' if plural else 'nests'} too deeply to read")
        if longest > JSON_MAX_NUMBER_CHARS:
            raise Unreadable(f"{prefix}: {what} {'hold' if plural else 'holds'} a number literal of more than "
                             f"{JSON_MAX_NUMBER_CHARS} characters")
        if unpaired:
            raise Unreadable(f"{prefix}: {what} {'hold' if plural else 'holds'} an unpaired surrogate")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=float if floats else refuse, parse_constant=refuse)
    except RecursionError as exc:
        raise Unreadable(f"{prefix}: {what} {'nest' if plural else 'nests'} too deeply to read") from exc
    except ValueError as exc:
        raise Fail(f"{prefix}: {what} {'are' if plural else 'is'} not JSON") from exc


def file_query(pairs: dict[str, str]) -> str:
    """A query as the machine's front signs it: keys sorted, values quote_plus encoded (Go's url.Values.Encode)."""
    return urlencode(sorted(pairs.items()), quote_via=quote_plus)


def put_target(room: str, mode: str, path: str) -> str:
    return f"PUT /v1/sandboxes/{room}/files?{file_query({'mode': mode, 'path': path})}"


def get_target(room: str, max_bytes: int, path: str) -> str:
    return f"GET /v1/sandboxes/{room}/files?{file_query({'max_bytes': str(max_bytes), 'path': path})}"


NETWORK_MODES = ("deny_all", "internet", "allowlist")
MISSING = object()


def same_json(a, b) -> bool:
    """Equal with exact types: true is not 1, and a list is not a tuple of its parts."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same_json(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_json(x, y) for x, y in zip(a, b))
    return a == b


_NON_PUBLIC_V4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"))
_HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _allow_entry(entry) -> str:
    """One allowlist entry in the machine API's canonical form (a copy of its rule; a test compares the two).

    A hostname (lower case, no trailing dot), optional :80 or :443, a leading wildcard, an IPv4 address or an IPv4
    CIDR in network form. IPv6, URLs, paths, other hostname ports and non-public ranges are refused."""
    def bad():
        raise Fail(f"recipe: network allow entry {entry!r} is not a valid allowlist entry")

    if not (isinstance(entry, str) and 1 <= len(entry) <= 255):
        bad()
    value = entry.strip().lower().rstrip(".")
    if not value:
        bad()
    port = None
    if value.count(":") == 1 and not value.startswith("[") and "/" not in value:
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            port = int(port_part)
            if not 1 <= port <= 65535:
                bad()
            try:
                ipaddress.ip_address(host_part)
            except ValueError:
                if port not in (80, 443):
                    bad()
                value = host_part
            else:
                bad()
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            bad()
        if net.version != 4 or any(net.overlaps(n) for n in _NON_PUBLIC_V4):
            bad()
        return str(net)
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        addr = None
    if addr is not None:
        if addr.version != 4 or any(addr in n for n in _NON_PUBLIC_V4):
            bad()
        return str(addr)
    if ":" in value or "[" in value:
        bad()
    name = value.removeprefix("*.")
    labels = name.split(".")
    if not (len(name) <= 253 and len(labels) >= 2 and all(_HOST_LABEL_RE.fullmatch(lb) for lb in labels)):
        bad()
    if labels[-1].isdigit():
        bad()
    return value if port is None else f"{value}:{port}"


def _merge_allow_ports(entries) -> list[str]:
    """Collapse host and host:port rows: a bare host means ports 80 and 443; the sorted, unique result."""
    hosts: dict[str, set[int]] = {}
    wilds: dict[str, set[int]] = {}
    others: list[str] = []
    for raw in entries:
        e = _allow_entry(raw)
        port = None
        value = e
        if e.count(":") == 1 and not e.startswith("[") and "/" not in e:
            host_part, port_part = e.rsplit(":", 1)
            if port_part.isdigit():
                value, port = host_part, int(port_part)
        try:
            ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            others.append(e)
            continue
        bucket = wilds if value.startswith("*.") else hosts
        ports = bucket.setdefault(value.removeprefix("*."), set())
        if port is None:
            ports.update((80, 443))
        else:
            ports.add(port)
    out = list(others)
    for name, ports in hosts.items():
        out.extend([name] if ports >= {80, 443} else [f"{name}:{p}" for p in sorted(ports)])
    for name, ports in wilds.items():
        out.extend([f"*.{name}"] if ports >= {80, 443} else [f"*.{name}:{p}" for p in sorted(ports)])
    return sorted(set(out))


def canonical_policy(mode: str, allow) -> dict:
    """The policy document the machine API signs: the mode name and, for an allowlist only, the canonical names."""
    mode = {"public": "internet"}.get(mode, mode)
    return {"mode": mode, "allow": _merge_allow_ports(allow) if mode == "allowlist" else []}


def network_policy(value, default_ok: bool = False) -> dict:
    """The canonical policy of a network setting (the recipe's, or the one in the create bytes).

    default_ok lets absent-like values mean deny_all, as the broker reads a create (nativeNetwork). A mode name,
    or an object with a mode and names, is mapped; a form that maps to no policy is refused."""
    if default_ok and (value is None or value == ""):
        return canonical_policy("deny_all", [])
    if isinstance(value, str):
        need(value in NETWORK_MODES, f"recipe: network mode {value} is not deny_all, internet or allowlist")
        mode, allow = value, []
    else:
        need(isinstance(value, dict), "recipe: network is not an object or a mode name")
        for key in value:
            need(key in ("mode", "allow"), f"recipe: unknown member {key}")
        allow = value.get("allow")
        need(allow is None or (isinstance(allow, list) and all(isinstance(n, str) for n in allow)),
             "recipe: network allow is not a list of names")
        allow = [] if allow is None else allow
        mode = value.get("mode")
        if mode is None or mode == "":
            mode = "deny_all"
        need(isinstance(mode, str) and mode in NETWORK_MODES,
             f"recipe: network mode {mode} is not deny_all, internet or allowlist")
    if mode == "allowlist":
        need(bool(allow), "recipe: an allowlist network needs at least one name")
    return canonical_policy(mode, allow)


IMAGE_PIN_RE = re.compile(r".+@sha256:[0-9a-f]{64}")
CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
COMMAND_MAX, ENV_MAX, INPUTS_MAX = 128, 64, 8
OUTPUT_MAX_BYTES = 64 * 1024  # outputs are kept inline in this version
CONTEXT_MAX_BYTES = 4 * 1024
INLINE_OUTPUT_MAX_BYTES = 64 * 1024
IMAGE_MAX, PATH_MAX, ENV_VALUE_MAX, CWD_MAX, USER_MAX = 512, 1024, 8192, 1024, 64
PATH_SEGMENT_RE = re.compile(r"[A-Za-z0-9._-]+")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
USER_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_-]*[$]?|[0-9]+")
MODE_RE = re.compile(r"[0-7]{3,4}")
# max_spend_usd as a string: digits, an optional point and 1 to 6 more digits (a run costs cents, so a fraction is
# sent as text, never as a float); the value must also be greater than zero.
MAX_SPEND_RE = re.compile(r"(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?")
MAX_SPEND_INTEGER_MAX = 999_999_999_999
INPUT_PREFIX, OUTPUT_PREFIX = "/work/in/", "/work/out/"


CONTEXT_MAX_DEPTH = 32


def _depth(value) -> int:
    """How many levels of objects and lists nest in value (a plain value is 0). Walks with a stack: a deep
    document must be measured, not recursed into."""
    deepest, stack = 0, [(value, 0)]
    while stack:
        node, level = stack.pop()
        if isinstance(node, dict):
            level += 1
            deepest = max(deepest, level)
            stack.extend((v, level) for v in node.values())
        elif isinstance(node, list):
            level += 1
            deepest = max(deepest, level)
            stack.extend((v, level) for v in node)
    return deepest


def _has_float(value) -> bool:
    """Whether a float is anywhere inside value (call only after the depth is bounded or with a stack)."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, float):
            return True
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def _path_form(path: str, kind: str, prefix: str, prefix_error: str) -> None:
    """One path: under its prefix, at most 1,024 characters, and every segment after the prefix is one or more
    of A-Z a-z 0-9 . _ - and is not . or .. (so no empty segment and no trailing slash)."""
    noun = f"an {kind} path"
    need(path.startswith(prefix) and len(path) > len(prefix), f"{prefix_error}{noun} must be under {prefix}")
    need(len(path) <= PATH_MAX, f"{prefix_error}{noun} must be at most {PATH_MAX} characters")
    for segment in path[len(prefix):].split("/"):
        need(segment != "", f"{prefix_error}{noun} must not hold an empty segment")
        need(segment not in (".", ".."), f"{prefix_error}{noun} must not hold a . or .. segment")
        need(PATH_SEGMENT_RE.fullmatch(segment) is not None,
             f"{prefix_error}{noun} may hold only letters, digits, . _ and - in a segment")


def request_limits(req: dict, prefix: str) -> None:
    """The rules spec G4 5.1 states for a one-shot request (and its Forms block), for the recipe and for the
    file's request alike.

    One function serves both, so they cannot drift. Wrong types are not this function's business (the recipe
    loader refuses them, and the file's request must equal the recipe in check 8); a member of the wrong type is
    skipped here. Bounds that are settings (the timeout cap, the output count, the total input size) are the
    API's to enforce: none is invented here."""
    image, command, env = req.get("image"), req.get("command"), req.get("env")
    if isinstance(image, str):
        need(CONTROL_CHARACTER_RE.search(image) is None, f"{prefix}image must hold no control character")
        need(len(image) <= IMAGE_MAX, f"{prefix}image must be at most {IMAGE_MAX} characters")
        need(IMAGE_PIN_RE.fullmatch(image) is not None, f"{prefix}image must end in @sha256: and 64 lower-case hex")
    if isinstance(command, list):
        need(1 <= len(command) <= COMMAND_MAX, f"{prefix}command must hold 1 to {COMMAND_MAX} strings")
    if isinstance(env, dict):
        need(len(env) <= ENV_MAX, f"{prefix}env must hold at most {ENV_MAX} entries")
        for name in env:
            need(ENV_NAME_RE.fullmatch(name) is not None,
                 f"{prefix}an env name must be a letter or _, then up to 127 letters, digits or _")
        for value in env.values():
            if isinstance(value, str):
                need(len(value) <= ENV_VALUE_MAX, f"{prefix}an env value must be at most {ENV_VALUE_MAX} characters")
    cwd, user = req.get("cwd"), req.get("user")
    if isinstance(cwd, str):
        need(1 <= len(cwd) <= CWD_MAX, f"{prefix}cwd must be 1 to {CWD_MAX} characters")
    if isinstance(user, str):
        need(len(user) <= USER_MAX, f"{prefix}user must be at most {USER_MAX} characters")
        need(USER_RE.fullmatch(user) is not None, f"{prefix}user must be digits only, or a name of letters, digits, "
                                                  "_ and - that starts with a letter or _ and may end in $")
    if "timeout_seconds" in req:
        need(_is_int(req["timeout_seconds"]), f"{prefix}timeout_seconds must be an integer")
    if "max_spend_usd" in req:
        spend = req["max_spend_usd"]
        ok = (1 <= spend <= MAX_SPEND_INTEGER_MAX if _is_int(spend) else
              isinstance(spend, str) and MAX_SPEND_RE.fullmatch(spend) is not None and spend.strip("0.") != "")
        need(ok, f"{prefix}max_spend_usd must be an integer from 1 to 999999999999, or a decimal string of 1 to 12 digits "
              "and up to 6 decimals, greater than zero")
    if "image_id" in req:
        need(isinstance(req["image_id"], str) and IMAGE_DIGEST_RE.fullmatch(req["image_id"]) is not None,
             f"{prefix}image_id must be sha256: and 64 lower-case hex")
    timeout = req.get("timeout_seconds")
    if _is_int(timeout):
        need(timeout >= 1, f"{prefix}timeout_seconds must be at least 1")
    inputs, outputs = req.get("inputs"), req.get("outputs")
    if isinstance(inputs, list):
        need(len(inputs) <= INPUTS_MAX, f"{prefix}inputs must hold at most {INPUTS_MAX} entries")
        seen = set()
        for entry in inputs:
            if not isinstance(entry, dict):
                continue
            path = entry.get("path")
            if isinstance(path, str):
                _path_form(path, "input", INPUT_PREFIX, prefix)
                need(path != CONTEXT_PATH, f"{prefix}an input path must not be {CONTEXT_PATH}")
                need(path not in seen, f"{prefix}an input path is given twice")
                seen.add(path)
            if "mode" in entry:
                need(isinstance(entry["mode"], str) and MODE_RE.fullmatch(entry["mode"]) is not None,
                     f"{prefix}an input mode must be 3 or 4 octal digits")
            if "sha256" in entry:
                need(isinstance(entry["sha256"], str) and HEX64.fullmatch(entry["sha256"]) is not None,
                     f"{prefix}an input sha256 must be 64 lower-case hex")
    if isinstance(outputs, list):
        seen = set()
        for entry in outputs:
            if not isinstance(entry, dict):
                continue
            path, limit = entry.get("path"), entry.get("max_bytes")
            if isinstance(path, str):
                _path_form(path, "output", OUTPUT_PREFIX, prefix)
                need(path not in seen, f"{prefix}an output path is given twice")
                seen.add(path)
            if "max_bytes" in entry:
                need(_is_int(limit), f"{prefix}an output max_bytes must be an integer")
            if _is_int(limit):
                need(limit >= 1, f"{prefix}an output max_bytes must be at least 1")
                need(limit <= OUTPUT_MAX_BYTES, f"{prefix}an output max_bytes must be at most {OUTPUT_MAX_BYTES}")
    if "context" in req:
        need(_depth(req["context"]) <= CONTEXT_MAX_DEPTH,
             f"{prefix}context nests deeper than {CONTEXT_MAX_DEPTH} levels")
        need(not _has_float(req["context"]), f"{prefix}context must hold no floating point number")


def _members(doc: dict, allowed: tuple[str, ...]) -> None:
    for key in doc:
        need(key in allowed, f"recipe: unknown member {key}")


def _typed(doc: dict, key: str, kind: str, ok) -> None:
    need(ok(doc[key]), f"recipe: {key} is not {kind}")


def load_recipe(doc) -> dict:
    """The expected run, as the caller wrote it. The recipe is strict: a member the checker does not know, at any
    level, is a refusal, so a misplaced field can never be dropped without notice."""
    need(isinstance(doc, dict) and doc.get("schema") == ONESHOT_RECIPE_SCHEMA,
         f"recipe: the document is not a {ONESHOT_RECIPE_SCHEMA}")
    _members(doc, ("schema", "request", "create", "file_modes"))
    req, create = doc.get("request"), doc.get("create")
    need(isinstance(req, dict) and isinstance(create, dict), "recipe: request and create must be objects")
    _members(req, ("image", "image_id", "command", "env", "cwd", "user", "size", "timeout_seconds", "network",
                   "outputs", "inputs", "max_spend_usd"))
    _members(create, ("ttl_seconds", "broker_guest"))
    for key in REQUIRED_REQUEST_FIELDS:
        need(key in req, f"recipe: the request has no {key}")
    need("ttl_seconds" in create, "recipe: create has no ttl_seconds")
    is_text = isinstance
    _typed(req, "image", "a string", lambda v: is_text(v, str))
    _typed(req, "command", "a list of strings",
           lambda v: isinstance(v, list) and v and all(isinstance(x, str) for x in v))
    _typed(req, "env", "an object of strings",
           lambda v: isinstance(v, dict) and all(isinstance(x, str) for x in v.values()))
    _typed(req, "size", "a string", lambda v: isinstance(v, str))
    _typed(req, "timeout_seconds", "an integer", _is_int)
    for key in ("cwd", "user"):
        if key in req:
            _typed(req, key, "a string", lambda v: isinstance(v, str))
    if "image_id" in req:
        _typed(req, "image_id", "sha256: and 64 lower-case hex",
               lambda v: isinstance(v, str) and IMAGE_DIGEST_RE.fullmatch(v) is not None)
    _typed(req, "outputs", "a list", lambda v: isinstance(v, list))
    _typed(req, "inputs", "a list", lambda v: isinstance(v, list))
    for out in req["outputs"]:
        need(isinstance(out, dict), "recipe: an output is not an object")
        _members(out, ("path", "max_bytes", "optional"))
    for inp in req["inputs"]:
        need(isinstance(inp, dict), "recipe: an input is not an object")
        _members(inp, ("path", "mode"))
    request_limits(req, "recipe: ")
    _typed(create, "ttl_seconds", "an integer", _is_int)
    if "broker_guest" in create:
        _typed(create, "broker_guest", "a string", lambda v: isinstance(v, str))
    modes = doc.get("file_modes", {})
    need(isinstance(modes, dict), "recipe: file_modes is not an object")
    _members(modes, ("context", "end_marker"))
    outputs = []
    for out in req["outputs"]:
        need(isinstance(out, dict), "recipe: an output is not an object")
        _members(out, ("path", "max_bytes", "optional"))
        need(isinstance(out.get("path"), str) and _is_int(out.get("max_bytes")),
             "recipe: each output needs a path and an integer max_bytes")
        need(isinstance(out.get("optional", False), bool), "recipe: optional is not a boolean")
        outputs.append({"path": out["path"], "max_bytes": out["max_bytes"], "optional": out.get("optional", False)})
    inputs = []
    for inp in req["inputs"]:
        need(isinstance(inp, dict), "recipe: an input is not an object")
        _members(inp, ("path", "mode"))
        need(isinstance(inp.get("path"), str), "recipe: each input needs a path")
        inputs.append({"path": inp["path"], "mode": inp.get("mode", "644")})
    for kind, items in (("output", outputs), ("input", inputs)):
        need(len({i["path"] for i in items}) == len(items), f"recipe: a {kind} path is given twice")
    for mode in [i["mode"] for i in inputs] + [modes.get("context", "644"), modes.get("end_marker", "644")]:
        need(isinstance(mode, str) and FILE_MODE_RE.fullmatch(mode) is not None,
             "recipe: a file mode is not an octal string")
    need(_is_int(create["ttl_seconds"]) and _is_int(req["timeout_seconds"])
         and create["ttl_seconds"] == req["timeout_seconds"] + ONESHOT_ROOM_MARGIN_SECONDS,
         f"recipe: create.ttl_seconds must be timeout_seconds + {ONESHOT_ROOM_MARGIN_SECONDS}")
    policy = network_policy(req["network"])
    return {"request": req, "create": create, "outputs": outputs, "inputs": inputs, "network_policy": policy, "context_mode": modes.get("context", "644"),
            "end_mode": modes.get("end_marker", "644")}


def expected_steps(room: str, recipe: dict) -> list[tuple[str, str]]:
    """The room's actions and signed targets, in order, from the recipe alone."""
    steps = [("create", "POST /v1/sandboxes"), ("file_put", put_target(room, recipe["context_mode"], CONTEXT_PATH))]
    steps += [("file_put", put_target(room, i["mode"], i["path"])) for i in recipe["inputs"]]
    steps.append(("exec", f"POST /v1/sandboxes/{room}/exec"))
    steps += [("file_get", get_target(room, o["max_bytes"], o["path"])) for o in recipe["outputs"]]
    steps.append(("file_put", put_target(room, recipe["end_mode"], END_MARKER_PATH)))
    return steps


def _bytes_member(bundle: dict, name: str, missing: str) -> bytes:
    raw = bundle.get(name)
    need(isinstance(raw, str), missing)
    try:
        return base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise Fail(f"{missing.split(':')[0]}: {name} is not base64") from exc


def _normal_inputs(items) -> list[dict]:
    return [{"path": i.get("path"), "mode": i.get("mode", "644"), "sha256": i.get("sha256")}
            for i in items if isinstance(i, dict)]


def verify_oneshot(bundle, recipe: dict, trust: dict, caller: dict) -> dict:
    """The eight checks of a one-shot's file (spec: one run, one receipt).

    bundle is the file; recipe comes from load_recipe; trust holds the AMD root pins ("ark_sha256") and the
    allowed measurements; caller holds what the caller knows: "context", "run_id" (or None), "input_hashes" and
    "output_bytes" (path -> bytes). Nothing is believed because the file says so: each part is checked against
    a signature, a hash or the recipe. Returns the PASS output; raises Fail("check N: ...") otherwise."""
    need(isinstance(bundle, dict) and bundle.get("schema") == ONESHOT_BUNDLE_SCHEMA,
         f"check 1: the file is not a {ONESHOT_BUNDLE_SCHEMA}")
    req, create = recipe["request"], recipe["create"]
    # The shapes of the file are exact (spec G4 5.5): the members it names, no others.
    for key in sorted(bundle):
        need(key in BUNDLE_MEMBERS, f"check 1: the file has an unknown member {key}")
    need("not_proven" in bundle, "check 1: the file has no not_proven")
    need(isinstance(bundle["not_proven"], list) and all(isinstance(r, str) for r in bundle["not_proven"]),
         "check 1: not_proven is not a list of strings")
    need("inline_outputs" in bundle, "check 1: the file has no inline_outputs")
    if "exec_response_b64" in bundle:  # decided before any hash is compared
        try:
            ok = isinstance(bundle["exec_response_b64"], str) and base64.b64decode(bundle["exec_response_b64"],
                                                                                    validate=True) is not None
        except ValueError:
            ok = False
        need(ok, "check 1: exec_response_b64 is not a string of valid base64")

    # 1. attestation, AMD chain, measurement, every receipt's signature, one binding
    att, certs, receipts = bundle.get("attestation"), bundle.get("amd_certs"), bundle.get("receipts")
    need(isinstance(att, dict) and isinstance(att.get("binding"), dict), "check 1: the file holds no attestation")
    need(isinstance(receipts, list) and receipts and all(isinstance(r, dict) for r in receipts),
         "check 1: the file holds no receipts")
    for key in sorted(att):
        need(key in ATTESTATION_MEMBERS, f"check 1: attestation has an unknown member {key}")
    for key in ATTESTATION_MEMBERS:
        need(key in att, f"check 1: attestation has no {key}")
    if isinstance(certs, dict):
        for key in sorted(certs):
            need(key in ("vcek", "ask", "ark"), f"check 1: amd_certs has an unknown member {key}")
    for receipt in receipts:
        for key in sorted(receipt):
            need(key in RECEIPT_MEMBERS, f"check 1: a receipt has an unknown member {key}")
        for key in RECEIPT_MEMBERS:
            need(key in receipt, f"check 1: a receipt has no {key}")
    need(all(isinstance(r["statement"], dict) for r in receipts), "check 1: the file holds no receipts")
    need(not is_hotel_level(att), "check 1: an SEV-SNP attestation is required")
    need(isinstance(certs, dict) and all(isinstance(certs.get(k), str) for k in ("vcek", "ask", "ark")),
         "check 1: the file holds no AMD certificates (amd_certs)")
    try:
        attestation_out = verify_attestation(att, trust["measurements"], trust.get("product"), "", trust["ark_sha256"],
                                             False, certs)
        chain_out = verify_receipts(att, receipts, None)
    except Fail as exc:
        raise Fail(f"check 1: {exc}") from exc
    except InvalidSignature as exc:
        raise Fail("check 1: an AMD certificate is not signed by the one above it in the chain") from exc
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise Fail("check 1: the attestation or a receipt is malformed") from exc

    # 2. the room's own numbers, a serial create first, no lost answer
    first = min(receipts, key=lambda r: r["statement"]["sequence"])
    room = first["statement"].get("sandbox_id")
    need(isinstance(room, str) and ROOM_ID_RE.fullmatch(room) is not None, "check 2: the room id is not a safe id")
    for rc in receipts:
        st = rc["statement"]
        need(st.get("sandbox_id") == room, f"check 2: receipt {st['sequence']} names room {st.get('sandbox_id')}, "
                                           f"not {room}")
    need(all(_has_complete_numbering(rc["statement"]) for rc in receipts),
         f"check 2: room {room}: the receipts are not numbered (room_sequence)")
    try:
        ordered = check_room_chain(room, receipts, in_order=True)
    except Fail as exc:
        raise Fail(f"check 2: {exc}") from exc
    created = ordered[0]["statement"]
    need(created.get("action") == "create", "check 2: receipt 1 is not a create")
    need(created.get("serial") is True, "check 2: receipt 1 does not say serial: true")
    for rc in ordered:
        need(rc["statement"].get("status") != 502,
             f"check 2: receipt {rc['statement']['sequence']} is a lost answer (status 502)")

    # 3. exactly the actions the recipe gives, with the exact signed target of each
    want = expected_steps(room, recipe)
    for i, (action, target) in enumerate(want):
        if i < len(ordered):
            st = ordered[i]["statement"]
            need(st.get("action") == action and st.get("target") == target,
                 f"check 3: receipt {i + 1} is {st.get('action')} {st.get('target')}, the recipe needs {action} {target}")
    need(len(ordered) == len(want), f"check 3: the list has {len(ordered)} receipts, the recipe needs {len(want)}")
    n_in = len(recipe["inputs"])
    ctx_rc, in_rcs = ordered[1]["statement"], [r["statement"] for r in ordered[2:2 + n_in]]
    exec_rc = ordered[2 + n_in]["statement"]
    get_rcs = [r["statement"] for r in ordered[3 + n_in:3 + n_in + len(recipe["outputs"])]]
    end_rc = ordered[-1]["statement"]

    # 4. the create: it succeeded, names this run, and its bytes are the recipe's
    run_id = bundle.get("oneshot_id")
    need(isinstance(run_id, str) and SANDBOX_LINK_RE.fullmatch(run_id) is not None,
         "check 4: the file's oneshot_id is not a lower-case UUID")
    need(_succeeded(created), f"check 4: the create did not succeed (status {created.get('status')})")
    digest = created.get("image_digest")
    need(digest is not None, "check 4: the create receipt has no image_digest")
    need(isinstance(digest, str) and IMAGE_DIGEST_RE.fullmatch(digest) is not None,
         "check 4: image_digest is not sha256: and 64 lower-case hex")
    need(not created.get("pool"), "check 4: the create is a pool create")
    need(same_json(created.get("network_policy"), recipe["network_policy"]),
         "check 4: the signed network rule is not the recipe's")
    need(created.get("cathedral_sandbox_id") == run_id,
         f"check 4: the create names sandbox {created.get('cathedral_sandbox_id')}, not the file's oneshot_id {run_id}")
    need(caller["run_id"] is None or caller["run_id"] == run_id,
         "check 4: the run id you gave is not the file's oneshot_id")
    create_bytes = _bytes_member(bundle, "create_request_b64",
                                 "check 4: the file holds no create bytes (create_request_b64): the broker that "
                                 "made this run does not hand them back")
    need(sha(create_bytes) == created.get("customer_request_sha256"),
         "check 4: the create bytes do not hash to the receipt's customer_request_sha256")
    body = strict_json(create_bytes, "check 4", "the create bytes", plural=True)
    need(isinstance(body, dict), "check 4: the create bytes are not a JSON object")
    extra = sorted(set(body) - set(ONESHOT_CREATE_KEYS))
    need(not extra, f"check 4: the create has a key it should not have: {extra[0] if extra else ''}")
    missing = [k for k in ONESHOT_CREATE_KEYS if k not in body]
    need(not missing, f"check 4: the create lacks the key {missing[0] if missing else ''}")
    need(same_json(body["image"], req["image"]), "check 4: the create's image is not the recipe's")
    need(req["size"] in ONESHOT_SIZES, f"check 4: the size {req['size']} is not a sealed size")
    need(same_json(body["resources"], ONESHOT_SIZES[req["size"]]),
         "check 4: the create's resources are not those of the recipe's size")
    need(same_json(body["ttl_seconds"], create["ttl_seconds"]), "check 4: the create's ttl_seconds is not the recipe's")
    try:
        in_bytes = network_policy(body["network"], default_ok=True)
    except Fail:
        in_bytes = None
    need(same_json(in_bytes, recipe["network_policy"]),
         "check 4: the create's network is not the broker's form of the recipe's")
    labels = body["labels"]
    need(isinstance(labels, dict), "check 4: the create's labels are not an object")
    extra, missing = sorted(set(labels) - set(ONESHOT_LABEL_KEYS)), [k for k in ONESHOT_LABEL_KEYS if k not in labels]
    need(not extra and not missing, "check 4: the labels are not exactly the four expected ("
                                    + (f"extra: {', '.join(extra)}" if extra else f"missing: {', '.join(missing)}") + ")")
    need(labels["cathedral_sandbox_id"] == run_id, "check 4: the label cathedral_sandbox_id is not the run id")
    need(labels["cathedral_serial"] == "1", "check 4: the label cathedral_serial is not 1")
    guest = labels["broker_guest"]
    if "broker_guest" in create:
        need(guest == create["broker_guest"], "check 4: the label broker_guest is not the recipe's")
    else:
        need(isinstance(guest, str) and ROOM_ID_RE.fullmatch(guest) is not None,
             "check 4: the label broker_guest is not an id-safe string")
    need(isinstance(labels["broker_batch"], str) and SANDBOX_LINK_RE.fullmatch(labels["broker_batch"]) is not None,
         "check 4: the label broker_batch is not a lower-case UUID")
    image_compared = "image_id" in req
    if image_compared:
        need(digest == req["image_id"], "check 4: the create's image_digest is not the recipe's image_id")

    # 5. the context and each input were written, and are the ones the caller holds
    need(_succeeded(ctx_rc), f"check 5: the put of the context did not succeed (status {ctx_rc.get('status')})")
    need(ctx_rc.get("customer_request_sha256") == sha(canonical(caller["context"])),
         "check 5: the context put does not carry the expected context (its hash differs)")
    for inp, st in zip(recipe["inputs"], in_rcs):
        path = inp["path"]
        need(_succeeded(st), f"check 5: the put of input {path} did not succeed (status {st.get('status')})")
        given = caller["input_hashes"].get(path)
        need(given is not None, f"check 5: no hash or file was given for input {path}")
        need(st.get("customer_request_sha256") == given,
             f"check 5: the put of input {path} does not carry the bytes whose hash you gave")

    # 6. the exec: this command, this environment
    need(exec_rc.get("status") == 200, f"check 6: the exec did not return 200 (status {exec_rc.get('status')})")
    exec_bytes = _bytes_member(bundle, "exec_request_b64", "check 6: the file holds no exec bytes (exec_request_b64)")
    need(sha(exec_bytes) == exec_rc.get("customer_request_sha256"),
         "check 6: the exec bytes do not hash to the receipt's customer_request_sha256")
    ebody = strict_json(exec_bytes, "check 6", "the exec bytes", plural=True)
    need(isinstance(ebody, dict), "check 6: the exec bytes are not a JSON object")
    values = {"cmd": req["command"], "timeout_seconds": req["timeout_seconds"], "env": req["env"]}
    values.update({k: req[k] for k in ("cwd", "user") if k in req})
    extra = sorted(set(ebody) - set(values))
    need(not extra, f"check 6: the exec has a key it should not have: {extra[0] if extra else ''}")
    missing = [k for k in values if k not in ebody]
    need(not missing, f"check 6: the exec lacks the key {missing[0] if missing else ''}")
    for key, value in values.items():
        need(same_json(ebody[key], value), f"check 6: the exec's {key} is not the recipe's")

    # 7. each output was read whole (exactly 200); every copy of it in the file is checked; the end marker
    #    came after the last read
    inline = bundle.get("inline_outputs", {})
    need(isinstance(inline, dict), "check 7: inline_outputs is not an object")
    declared = {o["path"] for o in recipe["outputs"]}
    for path in inline:
        need(path in declared, f"check 7: inline_outputs names {path}, which is not an output of the recipe")

    def check_copy(lead: str, size_lead: str, path: str, data: bytes, result_sha: str, limit: int) -> None:
        need(sha(data) == result_sha, f"check 7: {lead} {path} do not hash to the receipt's result_sha256")
        need(len(data) <= limit, f"check 7: {size_lead.format(path=path)} is {len(data)} bytes, over its max_bytes "
                                 f"{limit}")

    outputs_out = []
    for out, st in zip(recipe["outputs"], get_rcs):
        path, status = out["path"], st.get("status")
        held = caller["output_bytes"].get(path)
        if status == 404 and out["optional"]:
            need(held is None, f"check 7: bytes are held for {path}, but the receipt says it was absent")
            need(path not in inline, f"check 7: the inline bytes of {path} are given, but the receipt says it "
                                     "was absent")
            outputs_out.append({"path": path, "state": "absent", "sha256": None, "bytes": None})
            continue
        need(status != 404, f"check 7: the required output {path} was not found (404)")
        need(status == 200, f"check 7: the get of {path} answered {status}, not 200")
        copies = 0
        if path in inline:
            need(isinstance(inline[path], str), f"check 7: the inline bytes of {path} are not a base64 string")
            try:
                data = base64.b64decode(inline[path], validate=True)
            except ValueError as exc:
                raise Fail(f"check 7: the inline bytes of {path} are not base64") from exc
            need(len(data) <= INLINE_OUTPUT_MAX_BYTES, f"check 7: the inline bytes of {path} are {len(data)} bytes, "
                 f"over the {INLINE_OUTPUT_MAX_BYTES // 1024} KiB an inline output may have")
            check_copy("the inline bytes of", "the inline copy of {path}", path, data, st.get("result_sha256"),
                       out["max_bytes"])
            copies += 1
        if held is not None:
            check_copy("the bytes held for", "{path}", path, held, st.get("result_sha256"), out["max_bytes"])
            copies += 1
        outputs_out.append({"path": path, "state": "present", "sha256": st.get("result_sha256"),
                            "bytes": "held" if copies else "receipt_only"})
    need(_succeeded(end_rc), f"check 7: the end marker put did not succeed (status {end_rc.get('status')})")
    need(end_rc.get("customer_request_sha256") == sha(b""), "check 7: the end marker put does not carry empty bytes")

    # 8. the request the file shows is the recipe's request, member for member, with exact types
    shown = bundle.get("request")
    need(isinstance(shown, dict), "check 8: the file holds no request")
    for key in sorted(shown):
        need(key in REQUEST_FIELDS, f"check 8: the request holds a key that is not a request field: {key}")
    for entry in shown.get("inputs") if isinstance(shown.get("inputs"), list) else []:
        need(not (isinstance(entry, dict) and "content_b64" in entry),
             "check 8: the request holds content_b64, which a file must not carry")
    for entry in shown.get("inputs") if isinstance(shown.get("inputs"), list) else []:
        need(isinstance(entry, dict) and set(entry) == {"path", "sha256", "mode"},
             "check 8: the file's request: an input must hold exactly path, sha256 and mode")
    request_limits(shown, "check 8: the file's request: ")

    def entries(items, keys, defaults):
        """Entries as objects with exactly the allowed members, defaults filled; None for anything else."""
        if not isinstance(items, list):
            return None
        out = []
        for item in items:
            if not isinstance(item, dict) or not set(item) <= set(keys):
                return None
            out.append({**defaults, **item})
        return out

    wanted = {k: v for k, v in req.items() if k not in ("inputs", "outputs")}
    wanted["outputs"] = recipe["outputs"]
    wanted["inputs"] = [{"path": i["path"], "mode": i["mode"], "sha256": caller["input_hashes"][i["path"]]}
                        for i in recipe["inputs"]]
    got = {k: v for k, v in shown.items() if k not in ("inputs", "outputs")}
    got["outputs"] = entries(shown.get("outputs"), ("path", "max_bytes", "optional"), {"optional": False})
    got["inputs"] = entries(shown.get("inputs"), ("path", "mode", "sha256"), {"mode": "644"})
    for field in REQUEST_FIELDS:
        if field == "context":
            continue  # compared below, against the caller's expected context
        need(same_json(got.get(field, MISSING), wanted.get(field, MISSING)),
             f"check 8: the request in the file differs from the recipe in {field}")
    # The signed context put (check 5) is the binding. A context member in the file's request, when there is one,
    # is one more copy, so it must be the expected context too.
    if "context" in shown:
        need(same_json(shown["context"], caller["context"]),
             "check 8: the file's request.context is not the expected context")

    # The exit code is confirmed only by an answer whose hash the exec receipt signed. It never changes the verdict.
    exit_code: dict = {"status": "not confirmed"}
    raw = bundle.get("exec_response_b64")
    if isinstance(raw, str):
        try:
            answer = base64.b64decode(raw, validate=True)
        except ValueError:
            answer = None
        # The hash comes first: an answer that is not the signed one is not read at all.
        if answer is not None and sha(answer) == exec_rc.get("result_sha256"):
            try:
                doc = strict_json(answer, "check 6", "the exec answer", floats=True)
            except Unreadable:
                raise
            except Fail:
                doc = None
            if isinstance(doc, dict) and _is_int(doc.get("exit_code")):
                exit_code = {"status": "confirmed", "value": doc["exit_code"]}

    context_check = ("the signed context file and the request in the file" if "context" in shown
                     else "the signed context file only")
    numbering = room_numbering(receipts)
    if numbering["rooms"]:
        chain_out["room_numbering"] = numbering_words(numbering["rooms"])
    image = {"image_digest": digest, "compared_with_recipe": image_compared}
    if not image_compared:
        image["note"] = "The signed image_digest is the image's own id; the recipe gave no image_id, so it was not compared."
    does_not = list(RUN_DOES_NOT_SHOW)
    if any(o["bytes"] == "receipt_only" for o in outputs_out):
        does_not.append("The length of an output whose bytes were not given to the checker (receipt only).")
    return {"attestation": attestation_out, "chain": chain_out, "policy_timeline": policy_timeline(receipts),
            "room_tunables": room_tunables(receipts), "room_links": room_links(receipts), "verdict": "PASS",
            "checked": RUN_CHECKED,
            "run": {"oneshot_id": run_id, "room": room, "image": image, "context_check": context_check, "outputs": outputs_out,
                    "exit_code": exit_code, "shows": RUN_SHOWS, "does_not_show": does_not}}


def split_known(entry: str, known: list[str], flag: str, kind: str) -> tuple[str, str]:
    """PATH=VALUE where PATH is one of the recipe's paths (a path may hold '=', so match by prefix)."""
    for path in sorted(known, key=len, reverse=True):
        if entry.startswith(path + "="):
            return path, entry[len(path) + 1:]
    raise Fail(f"inputs: {flag} names {entry.split('=', 1)[0]}, which is not an {kind} of the recipe")


def read_file(path: str, what: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as exc:
        raise Fail(f"inputs: cannot read {what} {path}") from exc


def run_mode(a) -> int:
    """--oneshot: check one file against what the caller expects. Missing caller input is a FAIL, never a guess."""
    try:
        need(not a.skip_amd, "check 1: --skip-amd is not allowed in run mode")
        need(a.ark_sha256, "inputs: run mode needs --ark-sha256")
        need(a.recipe, "inputs: run mode needs --recipe")
        need(bool(a.context) != bool(a.no_context), "inputs: run mode needs --context FILE or --no-context")
        measurements = list(a.expected_measurement or [])
        if a.allowed_measurements:
            listed = strict_json(read_file(a.allowed_measurements, "the allowed measurements file"), "inputs",
                                 "the allowed measurements file")
            need(isinstance(listed, list) and all(isinstance(m, str) for m in listed),
                 "inputs: the allowed measurements file is not a JSON list of strings")
            measurements += listed
        need(measurements, "inputs: run mode needs --expected-measurement or --allowed-measurements")
        bundle = strict_json(read_file(a.oneshot, "the one-shot file"), "inputs", "the one-shot file", floats=True)
        recipe = load_recipe(strict_json(read_file(a.recipe, "the recipe"), "inputs", "the recipe"))
        context = {} if a.no_context else strict_json(read_file(a.context, "the context file"), "inputs",
                                                      "the context file")
        need(_depth(context) <= CONTEXT_MAX_DEPTH, f"inputs: context nests deeper than {CONTEXT_MAX_DEPTH} levels")
        need(isinstance(context, dict), "inputs: the context is not a JSON object")
        need(len(canonical(context)) <= CONTEXT_MAX_BYTES,
             f"inputs: the context is larger than 4 KiB ({CONTEXT_MAX_BYTES} canonical bytes)")
        in_paths = [i["path"] for i in recipe["inputs"]]
        hashes: dict[str, str] = {}
        for entry in a.input_sha256:
            path, value = split_known(entry, in_paths, "--input-sha256", "input")
            need(HEX64.fullmatch(value) is not None, f"inputs: the hash for {path} is not 64 lower-case hex")
            need(path not in hashes, f"inputs: {path} is given twice")
            hashes[path] = value
        for entry in a.input_file:
            path, value = split_known(entry, in_paths, "--input-file", "input")
            need(path not in hashes, f"inputs: {path} is given twice")
            hashes[path] = sha(read_file(value, "the input file"))
        out_paths = [o["path"] for o in recipe["outputs"]]
        held: dict[str, bytes] = {}
        for entry in a.output_file:
            path, value = split_known(entry, out_paths, "--output-file", "output")
            need(path not in held, f"inputs: {path} is given twice")
            held[path] = read_file(value, "the output file")
        caller = {"context": context, "run_id": a.run_id, "input_hashes": hashes, "output_bytes": held}
        out = verify_oneshot(bundle, recipe, {"measurements": list(dict.fromkeys(measurements)),
                                              "ark_sha256": a.ark_sha256, "product": a.product}, caller)
        print(json.dumps(out, indent=1))
        return 0
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, OverflowError, RecursionError):
        # A member of the wrong type that no check named: a refusal, never a traceback.
        print(json.dumps({"verdict": "FAIL", "reason": "inputs: the file or the recipe has a member of the wrong "
                                                         "type or shape"}))
        return 1
    except Fail as exc:
        print(json.dumps({"verdict": "FAIL", "reason": str(exc)}))
        return 1


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
    ap.add_argument("--expected-measurement", action="append",
                    help="the measurement to accept; repeat it to accept any of several")
    ap.add_argument("--allowed-measurements", help="run mode: a JSON list of measurements to accept")
    ap.add_argument("--oneshot", help="run mode: a one-shot's file (cathedral_oneshot_bundle_v1) to check")
    ap.add_argument("--recipe", help="run mode: the expected run (cathedral_oneshot_recipe_v1)")
    ap.add_argument("--run-id", help="run mode: the run id you were sent; it must be the file's oneshot_id")
    ap.add_argument("--context", help="run mode: the context you submitted (a JSON file)")
    ap.add_argument("--no-context", action="store_true", help="run mode: you submitted no context")
    ap.add_argument("--input-sha256", action="append", default=[], metavar="PATH=HEX",
                    help="run mode: the sha256 of an input file you submitted; repeat per input")
    ap.add_argument("--input-file", action="append", default=[], metavar="PATH=FILE",
                    help="run mode: an input file you submitted; repeat per input")
    ap.add_argument("--output-file", action="append", default=[], metavar="PATH=FILE",
                    help="run mode: an output file you hold, to check against the receipts; repeat per output")
    ap.add_argument("--ark-sha256", action="append",
                    help="pin the AMD ARK certificate (sha256 of its DER); repeat to accept any of several")
    ap.add_argument("--product", help="Milan or Genoa (default: from the report)")
    ap.add_argument("--kds-cache", help="list mode: where fetched AMD certificates are cached "
                                        "(default ~/.cache/amd-kds)")
    ap.add_argument("--skip-amd", action="store_true", help="skip the AMD chain (offline smoke test only)")
    ap.add_argument("--require-sealed", action="store_true",
                    help="fail unless the hotel answers an SEV-SNP binding (run mode accepts it: it always asks for one)")
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
    if a.oneshot:
        # Every flag run mode does not act on is refused, so no caller believes a check ran that did not.
        # --require-sealed is accepted: run mode always requires an SEV-SNP attestation.
        # A flag counts as given when it differs from the parser's own default (None, False or an empty list), so
        # an empty string, or a value equal to an old default, is still a flag the caller passed.
        clash = [flag for flag, value in (
            ("--receipts", a.receipts), ("--attestation", a.attestation), ("--broker", a.broker),
            ("--origin", a.origin), ("--owner-pubkey", a.owner_pubkey), ("--tls-spki-sha256", a.tls_spki_sha256),
            ("--require-tls", a.require_tls), ("--kds-cache", a.kds_cache), ("--sandbox", a.sandbox),
            ("--hotel", a.hotel), ("--operator-key-file", a.operator_key_file), ("--save", a.save),
            ("--receipt-header", a.receipt_header), ("--cathedral-sandbox", a.cathedral_sandbox),
            ("--key-file", a.key_file)) if value is not None and value is not False and value != []]
        if clash:
            ap.error(f"--oneshot checks one file; it takes no {', '.join(clash)}")
        return run_mode(a)
    if a.kds_cache is None:
        a.kds_cache = os.path.expanduser("~/.cache/amd-kds")
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
        whole = isinstance(doc, dict) and not doc.get("filtered") and not a.sandbox and not a.receipt_header
        head = doc.get("head") if whole else None
        need(isinstance(receipts, list), "the receipts are not a list")
        for h in a.receipt_header:
            try:
                receipts.append(json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4))))
            except ValueError as exc:
                raise Fail("--receipt-header is not base64url JSON") from exc
        check_receipt_shapes(receipts)
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
        numbering = room_numbering(receipts, doc if isinstance(doc, dict) else None)
        if numbering["rooms"]:
            chain_out["room_numbering"] = numbering_words(numbering["rooms"])
            checked += "; " + NUMBERED_CHECKED
        for warning in numbering["warnings"]:
            checked += "; " + warning
        pools = pool_rooms(receipts)
        if pools:
            checked += "; " + POOL_CHECKED
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
        out = {"attestation": attestation_out,
               "chain": chain_out,
               "policy_timeline": policy_timeline(receipts), "room_tunables": room_tunables(receipts),
               "room_links": room_links(receipts), "verdict": verdict,
               "checked": checked}
        if sealed_archive:
            out["not_proven"] = [
                "archived sealed bindings have no SNP report; receipt signatures checked, attestation not proven"
            ]
        if pools:
            out["pool_rooms"] = pools
        if a.cathedral_sandbox:
            rooms = sorted(room for room, linked in out["room_links"].items() if linked == a.cathedral_sandbox)
            need(rooms, f"no successful create receipt names Cathedral sandbox {a.cathedral_sandbox}")
            out["sandbox_link"] = {"cathedral_sandbox_id": a.cathedral_sandbox, "rooms": rooms}
        print(json.dumps(out, indent=1))
        return 3 if verdict == "NOT PROVEN" else 0
    except Fail as exc:
        print(json.dumps({"verdict": "FAIL", "reason": str(exc)}))
        return 1
    except (KeyError, TypeError, AttributeError, IndexError):
        # A member of the wrong type that no check named: a refusal, never a traceback.
        print(json.dumps({"verdict": "FAIL", "reason": "a receipt or the attestation has a member of the wrong "
                                                         "type or shape"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
