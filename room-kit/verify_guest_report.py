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


def verify(answer: dict, *, report_data_hex: str, expected_measurement: str,
           expected_host_data: str, ark_sha256: str, cache: str,
           product: str | None = None, min_tcb: dict | None = None,
           expected_chip_id: str | None = None) -> dict:
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
    # These are signed report fields. Ignore unsigned answer metadata and certificate pins.
    vr.need(rep["measurement"] == expected_measurement.lower(), "launch measurement differs from expectation")
    vr.need(rep["host_data"] == expected_host_data.lower(), "HOST_DATA differs from expected bootstrap binding")
    vr.need(int.from_bytes(report[0x30:0x34], "little") == 0, "direct guest report must be VMPL 0")
    result = vr.verify_fresh_report({"report_b64": answer["report_b64"]}, report_data_hex,
                                    product, cache, ark_sha256, min_tcb, expected_chip_id)
    result["fresh_report"].update(host_data=rep["host_data"], vmpl=0)
    return {"verdict": "PASS", **result,
            "does_not_prove": ["the guest consumed or enforced the bootstrap", "application correctness",
                               "disk freshness or continuous availability"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("answer", help="JSON containing report_b64")
    parser.add_argument("--report-data-hex", required=True)
    parser.add_argument("--expected-measurement", required=True)
    parser.add_argument("--expected-host-data", required=True)
    parser.add_argument("--ark-sha256", required=True, help="independently trusted AMD root fingerprint")
    parser.add_argument("--kds-cache", default=os.path.expanduser("~/.cache/amd-kds"))
    parser.add_argument("--product", choices=("Milan", "Genoa", "Turin"))
    parser.add_argument("--min-tcb", action="append", default=[], help=vr.MIN_TCB_HELP)
    parser.add_argument("--expected-chip-id")
    args = parser.parse_args()
    try:
        with open(args.answer, "rb") as source:
            raw = source.read(65537)
        vr.need(len(raw) <= 65536, "answer exceeds 64 KiB")
        answer = json.loads(raw)
        result = verify(answer, report_data_hex=args.report_data_hex,
                        expected_measurement=args.expected_measurement, expected_host_data=args.expected_host_data,
                        ark_sha256=args.ark_sha256, cache=args.kds_cache, product=args.product,
                        min_tcb=vr.parse_min_tcb(args.min_tcb), expected_chip_id=args.expected_chip_id)
    except (vr.Fail, OSError, ValueError, InvalidSignature) as exc:
        print(json.dumps({"verdict": "FAIL", "reason": str(exc) or type(exc).__name__}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
