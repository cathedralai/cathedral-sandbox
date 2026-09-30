#!/usr/bin/env python3
"""Run the real ``cathedral worker serve`` with the TEE box API, one hook changed.

On the TD the only change is the measured-root binding reader: Polaris launches
with MRCONFIGID all zero, so ``build_tee_box_api`` gets ``read_binding`` (its
test hook, cathedral/tee_box/configure.py) returning the MRCONFIGID the
harness computed with ``mrconfigid_for_root_keys`` for the root key file it
installed at ``CENTRAL_ROOT_KEYS_PATH``. Everything else is the production
path: the CLI's flag checks, TLS, the worker HTTP server, central access, the
storage probes, SysfsRtmr3, runsc, nft/tc.

Environment:
  E2E_MRCONFIGID_HEX  96 hex characters the injected reader returns, or
  E2E_BINDING=real    keep the real TDREPORT reader (for the refusal check).
  E2E_LOCAL=1         local development only: see local_fakes.py.

Arguments are the worker's own (``worker serve ...``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    src = os.environ.get("E2E_SRC", str(HERE / "src" / "sandbox"))
    sys.path.insert(0, src)
    from cathedral import cli
    from cathedral.tee_box import configure, measured_root

    local = os.environ.get("E2E_LOCAL") == "1"
    real = os.environ.get("E2E_BINDING") == "real"
    binding = None if real else bytes.fromhex(os.environ["E2E_MRCONFIGID_HEX"])
    if binding is not None and len(binding) != measured_root.MRCONFIGID_LEN:
        raise SystemExit("E2E_MRCONFIGID_HEX must be 48 bytes")

    real_build = configure.build_tee_box_api

    def build(config, **kwargs):  # noqa: ANN001, ANN202
        if binding is not None:
            kwargs["read_binding"] = lambda: binding
        if local:
            sys.path.insert(0, str(HERE))
            import local_fakes

            kwargs = local_fakes.local_build_kwargs(config, kwargs)
        return real_build(config, **kwargs)

    cli.build_tee_box_api = build
    if local:
        # The image path is root-owned on a real box; locally the harness keeps
        # the root key file in its work directory.
        measured_root.CENTRAL_ROOT_KEYS_PATH = os.environ["E2E_ROOT_KEYS_PATH"]
    return cli.main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
