"""attest.report: a fresh SEV-SNP report from the TEE box guest over caller REPORT_DATA.

The caller sends 64 bytes. They go to the kernel's configfs-tsm ``inblob`` verbatim
(``cathedral.attest.read_configfs_tsm_report``, the same path the room kit's sealed
hotel uses), so the caller must put a digest of what it binds there and check
REPORT_DATA against the same digest. The guest does not hash them again.

Only the ``sev_guest`` provider answers. The report is checked before it leaves: its
size, a nonempty signature, and REPORT_DATA equal to the 64 bytes asked for. The
signature is not verified here; the caller verifies it against AMD KDS (or the
certificate table returned with it). Reports are rate limited per guest, and one is
asked for at a time.
"""

from __future__ import annotations

import base64
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from cathedral.attest import TsmReport, read_configfs_tsm_report
from cathedral.verify.snp import SNP_REPORT_SIZE, parse_snp_report

DEFAULT_ATTEST_PER_MINUTE = 30
SNP_PROVIDER = "sev_guest"
# GHCB certificate table GUIDs (AMD SEV-SNP firmware ABI / GHCB spec), as in the room kit.
_CERT_GUIDS = {
    "vcek": "63da758d-e664-4564-adc5-f4b93be8accd",
    "ask": "4ab7b379-bbac-4fe4-a02f-05aef327c782",
    "ark": "c0b406a4-a803-4952-9743-3fb6014cd0ae",
}


class AttestUnavailable(RuntimeError):
    """This guest cannot produce an SEV-SNP report now."""


class AttestRateLimited(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("attestation rate limit")
        self.retry_after = retry_after


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def cert_chain(aux: bytes) -> dict[str, str] | None:
    """VCEK, ASK and ARK (base64 DER) from an SNP certificate table, or None.

    Entries are GUID (16 bytes), offset (u32 LE) and length (u32 LE), ended by an
    all-zero entry; offsets count from the table start. The GUID is matched in both byte
    orders. None unless all three are present and in range.
    """

    names: dict[bytes, str] = {}
    for name, text in _CERT_GUIDS.items():
        guid = uuid.UUID(text)
        names[guid.bytes] = names[guid.bytes_le] = name
    found: dict[str, str] = {}
    position = 0
    while position + 24 <= len(aux):
        guid = aux[position : position + 16]
        if guid == bytes(16):
            break
        offset = int.from_bytes(aux[position + 16 : position + 20], "little")
        length = int.from_bytes(aux[position + 20 : position + 24], "little")
        name = names.get(guid)
        if name and length and offset + length <= len(aux):
            found[name] = _b64(aux[offset : offset + length])
        position += 24
    return found if set(found) == set(_CERT_GUIDS) else None


class GuestAttestor:
    def __init__(
        self,
        *,
        reader: Callable[[bytes], TsmReport] | None = None,
        root: Path | None = None,
        per_minute: int = DEFAULT_ATTEST_PER_MINUTE,
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if isinstance(per_minute, bool) or not isinstance(per_minute, int) or per_minute < 1:
            raise ValueError("the attestation rate must be at least one report a minute")
        if reader is None:
            if root is None:
                reader = read_configfs_tsm_report
            else:
                reader = lambda data: read_configfs_tsm_report(data, root=root)
        self._reader = reader
        self.per_minute = per_minute
        self._monotonic = monotonic
        self._clock = clock
        self._times: list[float] = []
        self._slots = threading.Lock()
        self._one = threading.Lock()

    def _take_slot(self) -> None:
        now = self._monotonic()
        with self._slots:
            self._times = [t for t in self._times if now - t < 60]
            if len(self._times) >= self.per_minute:
                raise AttestRateLimited(int(60 - (now - self._times[0])) + 1)
            self._times.append(now)

    def report(self, report_data: bytes) -> dict[str, object]:
        if len(report_data) != 64:
            raise ValueError("REPORT_DATA must be exactly 64 bytes")
        self._take_slot()
        with self._one:
            try:
                tsm = self._reader(report_data)
            except (OSError, ValueError) as exc:
                raise AttestUnavailable(
                    f"configfs-tsm report failed: {type(exc).__name__}"
                ) from exc
        if tsm.provider != SNP_PROVIDER:
            raise AttestUnavailable(f"TSM provider is {tsm.provider or 'none'}, not {SNP_PROVIDER}")
        try:
            parsed = parse_snp_report(tsm.outblob[:SNP_REPORT_SIZE])
        except ValueError as exc:
            raise AttestUnavailable(f"the SNP report is malformed: {exc}") from exc
        if parsed.report_data != report_data:
            raise AttestUnavailable("the SNP report does not carry the REPORT_DATA asked for")
        return {
            "report_b64": _b64(tsm.outblob),
            "cert_chain_b64": cert_chain(tsm.auxblob),
            "measurement": parsed.measurement,
            "chip_id": parsed.chip_id,
            "reported_tcb": parsed.tcb.reported.to_bytes(8, "little").hex(),
            "generated_at": int(self._clock()),
        }
