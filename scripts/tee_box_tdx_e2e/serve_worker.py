#!/usr/bin/env python3
"""TEST HARNESS ONLY: NOT A PRODUCTION LAUNCHER.

It injects the MRCONFIGID binding and overwrites
/usr/share/cathedral/central-root-keys.json (via harness.py). It refuses to run
unless setup.sh has marked this boot as a disposable test box
(``/run/cathedral-tee-e2e/TEST_BOX``, on tmpfs), and with ``E2E_LOCAL=1`` it
refuses on any machine that has ``/dev/tdx_guest``.

Run the real ``cathedral worker serve`` with the TEE box API, one hook changed.

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
# Written by setup.sh prepare; keep the path in step with it.
TEST_BOX_MARKER = Path("/run/cathedral-tee-e2e/TEST_BOX")
TDX_GUEST_DEVICE = Path("/dev/tdx_guest")


def require_test_box(local: bool) -> None:
    """Refuse unless this is a marked test TD, or (``local``) not a TD at all."""

    if local:
        if TDX_GUEST_DEVICE.exists():
            raise SystemExit(
                "refusing: local mode (E2E_LOCAL=1 / --local) must not run on a TDX guest"
            )
        return
    try:
        marker = TEST_BOX_MARKER.read_text()
        owner = TEST_BOX_MARKER.stat().st_uid
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        marker, owner, boot_id = "", -1, "?"
    if owner != 0 or not boot_id or f"boot_id {boot_id}" not in marker:
        raise SystemExit(
            f"refusing: TEST HARNESS ONLY. {TEST_BOX_MARKER} (root-owned, this boot) is "
            "missing; run setup.sh prepare on a disposable test TD first"
        )


def main() -> int:
    local = os.environ.get("E2E_LOCAL") == "1"
    require_test_box(local)
    src = os.environ.get("E2E_SRC", str(HERE / "src" / "sandbox"))
    sys.path.insert(0, src)
    from cathedral import cli
    from cathedral.tee_box import configure, measured_root

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
