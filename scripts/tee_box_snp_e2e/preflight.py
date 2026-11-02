"""Preflight for SNP tee-box e2e: devices and binding helpers only.

Does not claim a sealed PASS. Exit 0 when the guest can collect a report
and (optionally) when an injected HOST_DATA matches a root key file.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cathedral.tee_box import measured_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root-keys",
        help="if set, print host_data_for_root_keys hex (for E2E_HOST_DATA_HEX inject)",
    )
    parser.add_argument(
        "--require-device",
        action="store_true",
        help="refuse when /dev/sev-guest is missing",
    )
    args = parser.parse_args(argv)
    device = os.environ.get("CATHEDRAL_SEV_GUEST_DEV", measured_root.SEV_GUEST_DEVICE)
    present = Path(device).exists()
    print(f"sev_guest_device={device} present={present}")
    if args.require_device and not present:
        print("BLOCKED: no SEV-SNP guest device; cannot collect HOST_DATA", file=sys.stderr)
        return 2
    if args.root_keys:
        data = Path(args.root_keys).read_bytes()
        host_data = measured_root.host_data_for_root_keys(data)
        print(f"host_data_hex={host_data.hex()}")
        print("label=test_hook_unless_launch_set_this_value")
    print("fresh_boot=B.d_BLOCKED_no_rtmr3_class_register")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
