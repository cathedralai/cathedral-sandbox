"""The TEE box's central-access root keys, bound to measured state.

The sandbox API trusts one set of Cathedral central-access root keys. They are
read from a fixed path inside the image, ``CENTRAL_ROOT_KEYS_PATH``, and the
box refuses to start unless the sha256 of that file's bytes is the value the
launch measured:

- TDX: the first 32 bytes of MRCONFIGID are ``sha256(root key file)`` and the
  last 16 are zero. The Cathedral TDX value covers MRCONFIGID
  (docs/MRTD.md), so a box launched with any other root key file cannot match
  a published measurement. The box reads its own MRCONFIGID from a TDREPORT
  it asks the TDX module for through ``/dev/tdx_guest``. A TDREPORT never
  leaves the guest, so the host cannot substitute one. A configfs-tsm quote
  would not do: the host's quoting service writes those bytes, and the guest
  does not verify them.
- SEV-SNP: HOST_DATA is the closest launch field, but the repository's SNP
  code does not read it, so an SNP box refuses to start.

Nothing here reads a flag, an environment variable or a writable config file,
so a miner cannot choose the root. The binding reader is injectable only for
tests, and every failure refuses startup.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import secrets
from collections.abc import Callable

from cathedral.central_access import CentralAccessError, load_central_root_keys

# Inside the image. The TEE box image build installs the Cathedral root key
# file here (the key file the offline root tool's ``keygen --keys-out``
# writes, PR #239), owned by root and read-only.
CENTRAL_ROOT_KEYS_PATH = "/usr/share/cathedral/central-root-keys.json"

TDX_GUEST_DEVICE = "/dev/tdx_guest"
# linux/include/uapi/linux/tdx-guest.h: struct tdx_report_req is 64 bytes of
# REPORTDATA then the 1024-byte TDREPORT_STRUCT; TDX_CMD_GET_REPORT0 is
# _IOWR('T', 1, struct tdx_report_req).
TDX_REPORTDATA_LEN = 64
TDX_REPORT_LEN = 1024
TDX_CMD_GET_REPORT0 = (
    (3 << 30) | ((TDX_REPORTDATA_LEN + TDX_REPORT_LEN) << 16) | (ord("T") << 8) | 1
)
# TDREPORT_STRUCT: REPORTMACSTRUCT (256 bytes, REPORTTYPE.TYPE at 0 and
# REPORTDATA at 128), TEE_TCB_INFO and padding to 512, then TDINFO_STRUCT:
# ATTRIBUTES (8), XFAM (8), MRTD (48), MRCONFIGID (48), ...
TDX_REPORT_TYPE_TDX = 0x81
_REPORTDATA_OFFSET = 128
_MRCONFIGID_OFFSET = 512 + 8 + 8 + 48
MRCONFIGID_LEN = 48

MeasuredBindingReader = Callable[[], bytes]


class MeasuredRootError(ValueError):
    """The measured root binding is unavailable or does not match."""


def read_tdx_mrconfigid(device: str = TDX_GUEST_DEVICE) -> bytes:
    """Return this TD's MRCONFIGID from a fresh TDREPORT (TDG.MR.REPORT).

    The report carries a random REPORTDATA, which must come back in place,
    and the TDX report type; anything else refuses.
    """

    report_data = secrets.token_bytes(TDX_REPORTDATA_LEN)
    request = bytearray(report_data + bytes(TDX_REPORT_LEN))
    try:
        descriptor = os.open(device, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise MeasuredRootError(
            f"the TD report device {device} is unavailable; the TEE box reads its "
            "MRCONFIGID from it"
        ) from exc
    try:
        fcntl.ioctl(descriptor, TDX_CMD_GET_REPORT0, request, True)
    except OSError as exc:
        raise MeasuredRootError("the TDX module refused a TD report") from exc
    finally:
        os.close(descriptor)
    report = bytes(request[TDX_REPORTDATA_LEN:])
    if report[0] != TDX_REPORT_TYPE_TDX:
        raise MeasuredRootError("the TD report is not a TDX report")
    echoed = report[_REPORTDATA_OFFSET : _REPORTDATA_OFFSET + TDX_REPORTDATA_LEN]
    if not hmac.compare_digest(echoed, report_data):
        raise MeasuredRootError("the TD report does not carry the requested REPORTDATA")
    return report[_MRCONFIGID_OFFSET : _MRCONFIGID_OFFSET + MRCONFIGID_LEN]


def read_snp_host_data() -> bytes:
    """SEV-SNP has no supported binding yet: always refuse."""

    raise MeasuredRootError(
        "the TEE box on AMD SEV-SNP needs the central root bound in HOST_DATA, which "
        "the SNP report code does not read yet; refusing to start"
    )


def default_binding_reader(tee: str) -> MeasuredBindingReader:
    if tee == "tdx":
        return read_tdx_mrconfigid
    if tee == "snp":
        return read_snp_host_data
    raise MeasuredRootError(f"the TEE box has no measured root binding for TEE {tee!r}")


def root_digest_from_mrconfigid(mrconfigid: object) -> str:
    """The pinned root key digest an MRCONFIGID carries, or a refusal."""

    if not isinstance(mrconfigid, bytes) or len(mrconfigid) != MRCONFIGID_LEN:
        raise MeasuredRootError("MRCONFIGID must be 48 bytes")
    digest, padding = mrconfigid[:32], mrconfigid[32:]
    if any(padding):
        raise MeasuredRootError(
            "MRCONFIGID must hold sha256(root key file) followed by 16 zero bytes"
        )
    if not any(digest):
        raise MeasuredRootError("MRCONFIGID is zero: the launch bound no central root")
    return "sha256:" + digest.hex()


def load_measured_root_keys(
    tee: str,
    *,
    read_binding: MeasuredBindingReader | None = None,
) -> tuple[dict[str, bytes], str]:
    """Load the root keys whose file digest the launch measured.

    Returns the keys and their ``sha256:`` digest. The file is always
    ``CENTRAL_ROOT_KEYS_PATH``. ``read_binding`` exists for tests; the worker
    never passes it.
    """

    path = CENTRAL_ROOT_KEYS_PATH
    reader = default_binding_reader(tee) if read_binding is None else read_binding
    try:
        binding = reader()
    except MeasuredRootError:
        raise
    except Exception as exc:  # noqa: BLE001 - any reader failure refuses startup
        raise MeasuredRootError(f"the measured root binding is unreadable: {exc}") from exc
    if tee != "tdx":
        # Only TDX has a binding format today.
        raise MeasuredRootError(f"the TEE box has no measured root binding for TEE {tee!r}")
    pinned = root_digest_from_mrconfigid(binding)
    try:
        keys = load_central_root_keys(path, pinned_digest=pinned)
    except CentralAccessError as exc:
        raise MeasuredRootError(
            f"the central root key file {path} is unusable or does not match MRCONFIGID: {exc}"
        ) from exc
    return keys, pinned


def mrconfigid_for_root_keys(data: bytes) -> bytes:
    """The MRCONFIGID a TDX launch sets for this exact root key file."""

    if not isinstance(data, bytes) or not data:
        raise MeasuredRootError("the root key file must be non-empty bytes")
    return hashlib.sha256(data).digest() + bytes(MRCONFIGID_LEN - 32)
