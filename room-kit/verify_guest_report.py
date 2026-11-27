#!/usr/bin/env python3
"""Verify a direct SNP guest report against caller-owned launch expectations (AB#1004).

Uses the existing AMD verifier. HOST_DATA proves the host supplied those bytes at
launch, not that arbitrary guest code consumed or enforced that bootstrap.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys

from cryptography.exceptions import InvalidSignature

import verify_receipts as vr


def cpuid_tuple(value: str) -> tuple[int, int, int]:
    """One independently approved CPU tuple, in hexadecimal (family:model:stepping)."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}", value):
        raise ValueError("expected CPUID must be three hex bytes: family:model:stepping")
    return tuple(int(part, 16) for part in value.split(":"))


def verify(answer: dict, *, report_data_hex: str, expected_measurement: str,
           expected_host_data: str, ark_sha256: str, cache: str,
           product: str | None = None, min_tcb: dict | None = None,
           expected_chip_id: str | None = None, expected_cpuid: str | None = None,
           ark_crl: bytes | None = None) -> dict:
    for label, value, width in (("REPORT_DATA", report_data_hex, 128),
                                ("expected measurement", expected_measurement, 96),
                                ("expected HOST_DATA", expected_host_data, 64)):
        vr.need(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{%d}" % width, value) is not None,
                f"{label} must be {width} hex characters")
    vr.need(isinstance(answer, dict) and isinstance(answer.get("report_b64"), str), "missing report_b64")
    vr.need(len(answer["report_b64"]) <= 2048, "report_b64 is too large")
    try:
        report = base64.b64decode(answer["report_b64"], validate=True)
    except ValueError as exc:
        raise vr.Fail("report_b64 is not base64") from exc
    vr.need(len(report) == 1184, "direct SNP report must be exactly 1184 bytes")
    rep = vr.parse_report(report)
    vr.need(rep["version"] in (3, 4, 5), "direct guest requires report version 3, 4 or 5")
    vr.need(vr.product(rep, product) == "Turin", "direct guest contract requires Turin")
    vr.need(bool(expected_chip_id), "direct guest requires --expected-chip-id")
    # This floor is approved for exactly one tuple. Never apply it to a different
    # stepping merely because both CPUs share the Turin TCB byte layout.
    approved_cpu = cpuid_tuple(expected_cpuid)
    cpu = (rep["cpuid_fam"], rep["cpuid_mod"], rep["cpuid_step"])
    vr.need(cpu == approved_cpu, "no approved firmware floor for this CPUID family/model/stepping")
    vr.need(isinstance(min_tcb, dict) and set(min_tcb) == {"turin"},
            "direct guest requires one complete --min-tcb turin floor for --expected-cpuid")
    floor = min_tcb["turin"]
    vr.need(isinstance(floor, dict) and set(floor) == {"fmc", "bl", "tee", "snp", "ucode"}
            and all(type(v) is int and 0 <= v <= 255 for v in floor.values()),
            "direct guest requires a complete uint8 Turin firmware floor")
    platform_smt = int.from_bytes(report[0x40:0x48], "little") & 1
    vr.need(not platform_smt or rep["policy"] & (1 << 16), "platform SMT is enabled without guest permission")
    vr.need(rep["policy"] == 0x30000, "direct guest requires exact policy 0x30000 (no debug or migration)")
    signer = int.from_bytes(report[0x48:0x4C], "little")
    vr.need((signer >> 2) & 7 == 0, "direct guest report must be signed by VCEK")
    vr.need(not signer & 2, "direct guest report must not mask the chip key")
    vr.need(signer & ~1 == 0, "direct guest report has reserved signer bits")
    # These are signed report fields. Ignore unsigned answer metadata and certificate pins.
    vr.need(rep["measurement"] == expected_measurement.lower(), "launch measurement differs from expectation")
    vr.need(rep["host_data"] == expected_host_data.lower(), "HOST_DATA differs from expected bootstrap binding")
    vr.need(int.from_bytes(report[0x30:0x34], "little") == 0, "direct guest report must be VMPL 0")
    result = vr.verify_fresh_report({"report_b64": answer["report_b64"]}, report_data_hex,
                                    product, cache, ark_sha256, min_tcb, expected_chip_id,
                                    current_certificates=True, ark_crl=ark_crl)
    result["tcb_floor"]["cpuid"] = expected_cpuid.lower()
    result["fresh_report"].update(host_data=rep["host_data"], vmpl=0)
    return {"verdict": "report_verified", "ssh_channel_binding": "not_checked", **result,
            "does_not_prove": ["the SSH connection terminates in this guest",
                               "the guest consumed or enforced the bootstrap", "application correctness",
                               "disk freshness or continuous availability"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("answer", help="JSON containing report_b64")
    parser.add_argument("--report-data-hex", required=True)
    parser.add_argument("--expected-measurement", required=True)
    parser.add_argument("--expected-host-data", required=True)
    parser.add_argument("--ark-sha256", required=True, help="independently trusted AMD root fingerprint")
    parser.add_argument("--kds-cache", default=os.path.expanduser("~/.cache/amd-kds"))
    parser.add_argument("--product", choices=("Turin",))
    parser.add_argument("--min-tcb", action="append", required=True, help=vr.MIN_TCB_HELP)
    parser.add_argument("--expected-chip-id", required=True)
    parser.add_argument("--expected-cpuid", required=True, help="approved floor's family:model:stepping, three hex bytes")
    parser.add_argument("--ark-crl", help="current AMD KDS DER CRL for offline verification; otherwise fetch live")
    args = parser.parse_args()
    try:
        with open(args.answer, "rb") as source:
            raw = source.read(65537)
        vr.need(len(raw) <= 65536, "answer exceeds 64 KiB")
        answer = json.loads(raw)
        crl = None
        if args.ark_crl:
            with open(args.ark_crl, "rb") as source:
                crl = source.read(1024 * 1024 + 1)
        result = verify(answer, report_data_hex=args.report_data_hex,
                        expected_measurement=args.expected_measurement, expected_host_data=args.expected_host_data,
                        ark_sha256=args.ark_sha256, cache=args.kds_cache, product=args.product,
                        min_tcb=vr.parse_min_tcb(args.min_tcb), expected_chip_id=args.expected_chip_id,
                        expected_cpuid=args.expected_cpuid, ark_crl=crl)
    except (vr.Fail, OSError, ValueError, InvalidSignature) as exc:
        print(json.dumps({"verdict": "FAIL", "reason": str(exc) or type(exc).__name__}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
