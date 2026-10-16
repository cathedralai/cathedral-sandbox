"""Phase A launch-bind check for #274 — real HOST_DATA, no inject.

Exit codes:
  0  PASS — live HOST_DATA matches root file; gate STARTED; wrong key REFUSED
  2  BLOCKED / FAIL — missing device, inject env set, mismatch, or gate wrong

Does not claim full #274 PASS (tee-box B–F, measured image, receipts).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cathedral.tee_box import measured_root

OFFICIAL_DIGEST = (
    "551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e"
)


def _die(msg: str, code: int = 2) -> int:
    print(f"FAIL: {msg}", file=sys.stderr)
    return code


def _ensure_no_inject() -> str | None:
    for key in ("E2E_HOST_DATA_HEX", "CATHEDRAL_E2E_HOST_DATA_HEX"):
        if os.environ.get(key):
            return f"inject env {key} is set — not a launch-bound PASS"
    return None


def _wrong_root_bytes(key_id: str = "cathedral-root-1") -> bytes:
    # Well-formed throwaway: same schema as official {key_id: b64(raw32)}.
    raw = hashlib.sha256(b"cathedral-snp-phase-a-wrong-root").digest()
    doc = {key_id: base64.b64encode(raw).decode()}
    return json.dumps(doc, separators=(",", ":")).encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root-keys",
        default="/usr/share/cathedral/central-root-keys.json",
        help="guest path of the official central root keys file",
    )
    parser.add_argument(
        "--expect-digest",
        default=OFFICIAL_DIGEST,
        help="expected sha256 hex of the root keys file (no sha256: prefix)",
    )
    parser.add_argument(
        "--skip-wrong-key",
        action="store_true",
        help="do not swap in a throwaway root to prove REFUSED",
    )
    args = parser.parse_args(argv)

    inject = _ensure_no_inject()
    if inject:
        return _die(inject)

    root_path = Path(args.root_keys)
    if not root_path.is_file():
        return _die(f"root keys missing: {root_path}")

    device = Path(os.environ.get("CATHEDRAL_SEV_GUEST_DEV", measured_root.SEV_GUEST_DEVICE))
    print(f"sev_guest_device={device} present={device.exists()}")
    if not device.exists():
        return _die("no /dev/sev-guest — cannot read live HOST_DATA")

    raw = root_path.read_bytes()
    file_digest = hashlib.sha256(raw).hexdigest()
    expect = args.expect_digest.removeprefix("sha256:")
    print(f"root_keys={root_path}")
    print(f"file_sha256={file_digest}")
    print(f"expect_sha256={expect}")
    if file_digest != expect:
        return _die("root file digest does not match --expect-digest")

    live = measured_root.read_snp_host_data()
    print(f"live_host_data={live.hex()}")
    if live.hex() != file_digest:
        return _die("live HOST_DATA does not match sha256(root file) — Inject?")

    # Official gate
    try:
        keys, pinned = measured_root.load_measured_root_keys("snp")
    except measured_root.MeasuredRootError as exc:
        return _die(f"official gate REFUSED unexpectedly: {exc}")
    print(f"official_gate=STARTED pinned={pinned} key_ids={sorted(keys)}")
    if pinned != f"sha256:{file_digest}":
        return _die(f"pinned digest mismatch: {pinned}")

    if not args.skip_wrong_key:
        backup = raw
        wrong = _wrong_root_bytes()
        wrong_digest = hashlib.sha256(wrong).hexdigest()
        root_path.write_bytes(wrong)
        print(f"wrong_file_sha256={wrong_digest}")
        try:
            measured_root.load_measured_root_keys("snp")
            root_path.write_bytes(backup)
            return _die("wrong key STARTED — gate did not bind to HOST_DATA")
        except measured_root.MeasuredRootError as exc:
            msg = str(exc)
            print(f"wrong_key_gate=REFUSED detail={msg}")
            if "HOST_DATA" not in msg and "does not match" not in msg.lower():
                root_path.write_bytes(backup)
                return _die(f"REFUSED but message missing HOST_DATA bind: {msg}")
        finally:
            root_path.write_bytes(backup)
        # Restore + STARTED again
        keys2, pinned2 = measured_root.load_measured_root_keys("snp")
        print(f"restored_gate=STARTED pinned={pinned2} key_ids={sorted(keys2)}")

    # Optional snpguest AMD verify if binary present
    snpguest = shutil.which("snpguest")
    print(f"snpguest={snpguest or 'absent'}")
    if snpguest:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            req = tdp / "request.bin"
            att = tdp / "attestation.bin"
            certs = tdp / "certs"
            certs.mkdir()
            req.write_bytes(b"\x00" * 64)
            subprocess.run(
                [snpguest, "report", str(att), str(req)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [snpguest, "fetch", "ca", "pem", str(certs), "genoa"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                [
                    snpguest,
                    "fetch",
                    "vcek",
                    "pem",
                    str(certs),
                    str(att),
                    "--processor-model",
                    "genoa",
                ],
                check=False,
                capture_output=True,
            )
            v1 = subprocess.run(
                [snpguest, "verify", "certs", str(certs)],
                capture_output=True,
                text=True,
            )
            v2 = subprocess.run(
                [snpguest, "verify", "attestation", str(certs), str(att)],
                capture_output=True,
                text=True,
            )
            print("amd_certs_verify:")
            print(v1.stdout.strip() or v1.stderr.strip())
            print("amd_attestation_verify:")
            print(v2.stdout.strip() or v2.stderr.strip())
            if v1.returncode != 0 or v2.returncode != 0:
                return _die("snpguest AMD verify failed")

    print("phase_a_launch_bind=PASS")
    print("label=launch_bound_no_inject")
    print("not_claimed=full_274_B_through_F_measured_tee_box_image")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
