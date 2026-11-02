"""Compute the SNP HOST_DATA bytes a launch must set for a root key file.

Usage::

    python -m cathedral.tee_box.host_data_cli --root-keys PATH

Prints 64 hex characters (sha256 of the file bytes) and exits 0. Refuses an
empty or missing file. See docs/SNP_HOST_DATA_LAUNCH.md.
"""

from __future__ import annotations

import argparse
import sys

from cathedral.tee_box import measured_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root-keys",
        required=True,
        help="path to the central-root-keys.json file the guest image will install",
    )
    args = parser.parse_args(argv)
    try:
        with open(args.root_keys, "rb") as handle:
            data = handle.read()
        host_data = measured_root.host_data_for_root_keys(data)
    except OSError as exc:
        print(f"cannot read root keys: {exc}", file=sys.stderr)
        return 2
    except measured_root.MeasuredRootError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(host_data.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
