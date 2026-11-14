#!/usr/bin/env python3
"""Build snapshot_fork_v1.json: the shared test for a snapshot and a fork (AB#604, CS-3).

One file: the attestation and four receipts, made by driving the real receipts front (room-kit/room_receipts.py)
with a fixed key, clock and ids in front of a fake room API:
  1. A create   2. A snapshot   3. B fork create (names the snapshot)   4. A snapshot_delete

It follows the contract of tests/fixtures/receipt_lists_v2/generate.py: the attestation, trust values and receipt
key are that pack's (source/), the JSON is indent 1 with sorted keys and one trailing newline, signatures are
standard base64, the receipts part is {"receipts", "head"}, and the case part holds description, args (with
{dir} for the folder a checker writes attestation_doc.json and receipts.json into) and expect (exit_code, verdict).
The keys are derived from public labels: test data that signs nothing real.

Usage:
  generate.py            write snapshot_fork_v1.json
  generate.py --check    rebuild in memory and fail if the file differs or is missing; run the checker on the
                         receipts and fail unless it gives the expected verdict
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import itertools
import json
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PACK = HERE.parent / "receipt_lists_v2"
OUT = HERE / "snapshot_fork_v1.json"
BASE_TIME = 1_700_000_000
ROOM_A = "0f1e2d3c-4b5a-4968-8776-655443322110"
ROOM_B = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
SNAPSHOT_ID = "snap_0123456789ab"
IMAGE_ID = "sha256:" + hashlib.sha256(b"snapshot_fork_v1 committed image").hexdigest()
ARCHIVE = hashlib.sha256(b"snapshot_fork_v1 tar of /work").hexdigest()


def pretty(doc) -> bytes:
    return (json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def build(front_patch=None) -> bytes:
    """The file's bytes. *front_patch* (tests only) gets the front's module to change before it runs."""
    sys.path.insert(0, str(ROOT / "tests"))
    support = load("snapshot_fork_v1_support", ROOT / "tests" / "room_front_support.py")
    pack = load("snapshot_fork_v1_pack", PACK / "generate.py")
    rr = support.rr
    if front_patch is not None:
        front_patch(rr)
    attestation = json.loads((PACK / "source" / "attestation_doc.json").read_text())
    trust = json.loads((PACK / "source" / "trust.json").read_text())

    clock = {"now": BASE_TIME}
    counter = itertools.count(1)
    saved = (time.time, uuid.uuid4, rr.tsm_provider)
    time.time = lambda: clock["now"]
    uuid.uuid4 = lambda: uuid.UUID(int=next(counter))
    rr.tsm_provider = lambda: None
    api = support.FakeApi()
    api.start()
    server = None
    try:
        with tempfile.TemporaryDirectory() as store:
            ledger = rr.Ledger("pack-hotel", store)
            ledger.key = pack.signing_key()
            ledger.hotel = attestation["binding"]["hotel"]
            ledger.receipt_schema = rr.RECEIPT_SCHEMA
            ledger.binding, ledger.binding_sha256 = attestation["binding"], attestation["binding_sha256"]
            ledger.head = ledger.binding_sha256
            server = rr.Server(("127.0.0.1", 0), ledger, api.server.server_address[1], 1, support.KEY,
                               "/nonexistent.sock")
            server.image_digest = lambda ref: None
            threading.Thread(target=server.serve_forever, daemon=True).start()
            api.expires_at = "2023-11-14T22:13:20+00:00"
            api.new_ids = [ROOM_A, ROOM_B]
            port = server.server_address[1]

            delivered: list[dict] = []

            def call(method, path, body=None):
                import http.client
                clock["now"] += 1
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                c.request(method, path, body=json.dumps(body).encode() if body is not None else None,
                          headers={**support.AUTH, "Content-Type": "application/json"})
                r = c.getresponse()
                out = r.read()
                c.close()
                assert 200 <= r.status < 300, (method, path, r.status, out)
                header = r.getheader("X-Room-Receipt")
                if header is None:
                    raise SystemExit(f"{method} {path}: the answer carried no X-Room-Receipt header")
                delivered.append(json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))))

            call("POST", "/v1/sandboxes", {"image": "repo/app:1"})
            api.reply(rf"POST /v1/sandboxes/{ROOM_A}/snapshot", 202, {
                "operation_id": "op_1", "status": "done",
                "result": {"snapshot_id": SNAPSHOT_ID, "size_bytes": 4096, "committed_image_id": IMAGE_ID,
                          "work_archive_sha256": ARCHIVE}})
            call("POST", f"/v1/sandboxes/{ROOM_A}/snapshot", {})
            call("POST", "/v1/sandboxes", {"snapshot_id": SNAPSHOT_ID})
            api.reply(r"DELETE /v1/snapshots/[^/]+", 200, {"deleted": True})
            call("DELETE", f"/v1/snapshots/{SNAPSHOT_ID}")
            receipts = list(ledger.chain)
            if delivered != receipts:
                raise SystemExit("the receipt headers the callers received (decoded X-Room-Receipt) differ from "
                                 "the front's chain")
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        api.stop()
        time.time, uuid.uuid4, rr.tsm_provider = saved
    doc = {
        "description": "A is created, A is snapshotted, B is forked from the snapshot, the snapshot is deleted. "
                       "B's create receipt names the snapshot receipt; the delete receipt has no room.",
        "args": ["--attestation", "{dir}/attestation_doc.json", "--receipts", "{dir}/receipts.json", "--skip-amd",
                 "--expected-measurement", trust["measurements"][0]],
        "expect": {"exit_code": 0, "verdict": "PASS"},
        "trust": trust,
        "attestation": attestation,
        "receipts": receipts,
        "head": receipts[-1]["receipt_sha256"],
    }
    return pretty(doc)


def run_checker(data: bytes) -> None:
    doc = json.loads(data)
    with tempfile.TemporaryDirectory() as d:
        Path(d, "attestation_doc.json").write_bytes(pretty(doc["attestation"]))
        Path(d, "receipts.json").write_bytes(pretty({"receipts": doc["receipts"], "head": doc["head"]}))
        args = [a.replace("{dir}", d) for a in doc["args"]]
        run = subprocess.run([sys.executable, str(ROOT / "room-kit" / "verify_receipts.py"), *args],
                             capture_output=True, text=True, timeout=120)
    verdict = None
    try:
        verdict = json.loads(run.stdout).get("verdict")
    except ValueError:
        pass
    if run.returncode != doc["expect"]["exit_code"] or verdict != doc["expect"]["verdict"]:
        raise SystemExit(f"the checker gave exit {run.returncode}, verdict {verdict}\n{run.stdout}\n{run.stderr}")


def check(front_patch=None) -> int:
    """Rebuild and compare: the file, the receipt headers the callers got, and the checker's verdict."""
    data = build(front_patch)
    if not OUT.exists() or OUT.read_bytes() != data:
        print(f"{OUT.name} differs from a rebuild (or is missing): run generate.py", file=sys.stderr)
        return 1
    run_checker(data)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if not args.check:
        data = build()
        OUT.write_bytes(data)
        print(f"wrote {OUT.name} sha256 {hashlib.sha256(data).hexdigest()}")
        return 0
    status = check()
    if status == 0:
        print(f"{OUT.name} is current, the receipt headers match it and the checker gives the expected verdict")
    return status


if __name__ == "__main__":
    sys.exit(main())
