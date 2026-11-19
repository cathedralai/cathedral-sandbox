#!/usr/bin/env python3
"""Run room-kit/verify_receipts.py over the cases the Go parity tests write.

    mkdir /tmp/diff && CATHEDRAL_DIFF_OUT=/tmp/diff go test -count=1 ./snpverify
    python3 -I scripts/differential_receipts.py /tmp/diff/cases.json ../../room-kit/verify_receipts.py

Exit 1 when Go says PASS on a case Python rejects (the one thing that must never happen),
or when the harness cannot run. Cases where Go rejects and Python passes are listed; they
are the documented "stricter here" differences. The AMD part is not part of the cases.
"""
import importlib.util
import json
import sys


def load(path):
    spec = importlib.util.spec_from_file_location("verify_receipts", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def python_verdict(vr, kind, doc):
    try:
        if kind == "attestation":
            vr.check_attestation_shape({"binding": doc["binding"], "binding_sha256": doc["binding_sha256"],
                                        "report_b64": doc["report_b64"]})
            return "PASS", ""
        att = {"binding": doc["binding"], "binding_sha256": doc["binding_sha256"]}
        receipts = doc["receipts"]
        list_doc = doc.get("list")
        head = doc.get("head") or None
        vr.check_receipt_shapes(receipts)
        vr.verify_guest_tls(att)
        vr.verify_guest_ingress(att)
        vr.verify_receipts(att, receipts, head)
        vr.check_snapshot_edges(receipts)
        vr.room_numbering(receipts, list_doc)
        vr.pool_rooms(receipts)
        vr.policy_timeline(receipts)
        vr.room_tunables(receipts)
        vr.room_links(receipts)
        return "PASS", ""
    except vr.Fail as exc:
        return "FAIL", str(exc)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        return "FAIL", f"internal error: {type(exc).__name__}"


def json_limit_mismatches(vr):
    """The raw-text limits the Go parser mirrors: the same strings, the same verdicts."""
    cases = {  # text -> Python must read it
        "[" * 64 + "]" * 64: True, "[" * 65 + "]" * 65: False,
        "[" + "7" * 100 + "]": True, "[" + "7" * 101 + "]": False,
        "[-" + "7" * 99 + "]": True, "[-" + "7" * 100 + "]": False,
        "[1e" + "0" * 98 + "]": True, "[1e" + "0" * 99 + "]": False,
    }
    wrong = []
    for text, readable in cases.items():
        try:
            vr.load_json_bounded(text.encode(), "inputs", "the test document")
            got = True
        except vr.Fail:
            got = False
        if got != readable:
            wrong.append(f"{text[:12]}...{len(text)} chars: Python readable={got}, the Go tests assume {readable}")
    return wrong


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    cases = json.load(open(sys.argv[1]))
    vr = load(sys.argv[2])
    bad, stricter, same = [], [], 0
    for case in cases:
        py, why = python_verdict(vr, case["kind"], case["payload"])
        if case["go"] == "PASS" and py != "PASS":
            bad.append((case["name"], why))
        elif case["go"] != py:
            stricter.append((case["name"], why))
        else:
            same += 1
    print(f"{len(cases)} cases: {same} agree, {len(stricter)} Go stricter, {len(bad)} Go PASS where Python FAIL")
    for name, why in stricter:
        print(f"  stricter: {name}")
    for name, why in bad:
        print(f"  MISMATCH: {name}: python said: {why}")
    wrong = json_limit_mismatches(vr)
    for line in wrong:
        print("  JSON LIMIT:", line)
    return 1 if bad or wrong or not cases else 0


if __name__ == "__main__":
    sys.exit(main())
