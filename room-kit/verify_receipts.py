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
     Optional --ark-sha256 pins the ARK certificate.
  4. receipts: each statement names this binding, receipt_sha256 =
     sha256(canonical(statement)), the Ed25519 signature verifies with the
     binding's receipt key, and the chain links (sequence 1 links to the
     binding; each next receipt links to the one before).
  5. network policy: each create and network_set receipt that carries
     network_policy has network_policy_sha256 = sha256(canonical(policy)).
     The output has the policy timeline of each room, in chain order.

Not checked here (by design, today): that the measurement is an approved image.
Image approval is a signed policy release; that is a later step.

Usage:
  verify_receipts.py --attestation att.json --receipts chain.json [--receipt-header B64 ...]
  verify_receipts.py --broker https://<broker> --key-file KEY --hotel <hotel id> [--sandbox ID]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request

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


def verify_amd(report: bytes, rep: dict, prod: str, cache: str, ark_sha256: str | None) -> dict:
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
        need(ark_fp == ark_sha256.lower(), f"ARK sha256 {ark_fp} differs from the pinned value")
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
                       ark_sha256: str | None, skip_amd: bool) -> dict:
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


def verify_receipts(att: dict, receipts: list[dict], head: str | None = None) -> dict:
    binding = att["binding"]
    bsha = att["binding_sha256"]
    hotel = is_hotel_level(att)
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(binding["receipt_key_ed25519_b64"]))
    by_seq = {}
    for rc in receipts:
        st = rc["statement"]
        if hotel:
            need(st.get("schema") == HOTEL_RECEIPT_SCHEMA, f"receipt {st.get('sequence')}: not a hotel receipt")
        need(st["binding_sha256"] == bsha, f"receipt {st.get('sequence')} names another binding")
        need(rc["receipt_sha256"] == sha(canonical(st)), f"receipt {st['sequence']}: receipt_sha256 mismatch")
        try:
            key.verify(base64.b64decode(rc["signature_b64"]), canonical(st))
        except InvalidSignature as exc:
            raise Fail(f"receipt {st['sequence']}: signature does not verify") from exc
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
    actions = {}
    for rc in receipts:
        actions[rc["statement"]["action"]] = actions.get(rc["statement"]["action"], 0) + 1
    return {"receipts": len(receipts), "signatures_ok": len(receipts), "links_checked": links,
            "contiguous": contiguous, "first": seqs[0] if seqs else None, "last": seqs[-1] if seqs else None,
            "actions": actions}


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
    ap.add_argument("--hotel", required=False, default="sealed-1")
    ap.add_argument("--sandbox", help="with --broker: one room's receipts instead of the whole chain")
    ap.add_argument("--expected-measurement")
    ap.add_argument("--ark-sha256", help="pin the AMD ARK certificate (sha256 of its DER)")
    ap.add_argument("--product", help="Milan or Genoa (default: from the report)")
    ap.add_argument("--kds-cache", default=os.path.expanduser("~/.cache/amd-kds"))
    ap.add_argument("--skip-amd", action="store_true", help="skip the AMD chain (offline smoke test only)")
    ap.add_argument("--require-sealed", action="store_true", help="fail unless the hotel answers an SEV-SNP binding")
    ap.add_argument("--save", help="with --broker: write the fetched attestation and receipts here")
    a = ap.parse_args()
    try:
        if a.broker:
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
        for h in a.receipt_header:
            receipts.append(json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4))))
        sealed_asked = a.require_sealed or a.expected_measurement or a.ark_sha256 or a.product
        if is_hotel_level(att) and sealed_asked:
            # A sealed guest whose TSM is missing runs level 1 under the same
            # hotel name. Asking for a measurement means asking for SNP.
            raise Fail("the hotel answered a level 1 (unsealed) binding; an SEV-SNP attestation was asked for")
        if is_hotel_level(att):
            attestation_out = verify_hotel_attestation(att)
        else:
            attestation_out = verify_attestation(att, a.expected_measurement, a.product, a.kds_cache,
                                                 a.ark_sha256, a.skip_amd)
        out = {"attestation": attestation_out,
               "chain": verify_receipts(att, receipts, head),
               "policy_timeline": policy_timeline(receipts), "verdict": "PASS",
               # head is named by the server, not signed: even a whole chain does
               # not prove that nothing was cut from its end.
               "checked": ("whole chain to the head the server named" if head is not None
                           else "each receipt; not that none are missing")}
        print(json.dumps(out, indent=1))
        return 0
    except Fail as exc:
        print(json.dumps({"verdict": "FAIL", "reason": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
