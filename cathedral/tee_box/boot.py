"""One customer per boot: the TEE box VM is relaunched between customers.

Owner decision 1, amended 2026-09-29: the confidential VM is relaunched and
re-attested between customer allocations, so a gVisor escape by one customer
cannot persist into the next. The box enforces its half of that here. Once a
lease has been granted in this boot, no other caller is leased the box until
the kernel's boot id changes, that is, until the VM has booted again. The
caller that consumed the boot may lease it again: the relaunch is between
customers, not between one customer's leases.

The record is kept in memory and in a small file next to the central state,
on the same tmpfs (``<central state>.boot``), so a worker restart within one
boot keeps it and a relaunch empties it. The file names the boot id it was
written in, and a file for any other boot id is ignored, so one that somehow
survived a relaunch does not carry over. A file that cannot be read or parsed
refuses every caller until the next boot.

This protects against a box that is not relaunched while the guest kernel is
intact. A tenant that escapes gVisor into the guest kernel controls this code,
the file and the boot id, so it proves nothing after an escape; see
docs/TEE_BOX_SERVICE.md, "Relaunch between customers".
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass

BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
PROC_STAT_PATH = "/proc/stat"
MARKER_SUFFIX = ".boot"
MARKER_SCHEMA = "cathedral_tee_box_boot_v1"
MAX_MARKER_BYTES = 4096
# Stands for "consumed by a caller this process cannot name" (a marker it could
# not read, or a boot id it could not read). No central caller is named this.
UNKNOWN_CONSUMER = "(unknown)"
_BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_MARKER_KEYS = frozenset({"schema", "boot_id", "consumed_by", "consumed_at", "released_at"})


class BootError(Exception):
    """The boot identity or the boot record cannot be read or written."""


class RelaunchRequired(Exception):
    """Another customer consumed this boot; the VM must be relaunched first."""


def read_boot_id(path: str = BOOT_ID_PATH) -> str:
    """The kernel's random per-boot UUID, lower-case."""

    try:
        with open(path, encoding="ascii") as handle:
            text = handle.read(64).strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise BootError(f"cannot read the boot id from {path}: {exc}") from exc
    if _BOOT_ID_RE.fullmatch(text) is None:
        raise BootError(f"{path} does not hold a boot id")
    return text


def read_booted_at(path: str = PROC_STAT_PATH) -> int:
    """Boot time in epoch seconds (``btime`` in /proc/stat), by the guest clock."""

    try:
        with open(path, encoding="ascii") as handle:
            for line in handle:
                name, _, value = line.partition(" ")
                if name == "btime":
                    value = value.strip()
                    if value.isascii() and value.isdigit() and len(value) <= 12:
                        return int(value)
                    break
    except (OSError, UnicodeDecodeError) as exc:
        raise BootError(f"cannot read the boot time from {path}: {exc}") from exc
    raise BootError(f"{path} has no btime line")


@dataclass(frozen=True)
class BootRecord:
    boot_id: str
    consumed_by: str | None
    consumed_at: float | None
    released_at: float | None


def marker_path_for(central_state: str) -> str:
    """The boot record's file for the central state at ``central_state``."""

    return central_state + MARKER_SUFFIX


def _number(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("not a number")
    if not math.isfinite(value) or value < 0:
        raise ValueError("not a time")
    return float(value)


def _parse_marker(raw: bytes) -> BootRecord:
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict) or frozenset(document) != _MARKER_KEYS:
        raise ValueError("unexpected fields")
    if document["schema"] != MARKER_SCHEMA:
        raise ValueError("unknown schema")
    boot_id = document["boot_id"]
    consumed_by = document["consumed_by"]
    if not isinstance(boot_id, str) or _BOOT_ID_RE.fullmatch(boot_id) is None:
        raise ValueError("bad boot id")
    if consumed_by is not None and (not isinstance(consumed_by, str) or not consumed_by):
        raise ValueError("bad consumer")
    return BootRecord(
        boot_id,
        consumed_by,
        _number(document["consumed_at"]),
        _number(document["released_at"]),
    )


class BootGuard:
    """Refuse a second customer in one boot; report the boot for re-attestation.

    ``marker_path`` is the record's file (``marker_path_for(central state)``),
    or None to keep it in memory only (tests; a worker restart then forgets
    it). ``read_boot_id`` and ``read_booted_at`` are the kernel readers,
    replaced in tests. Construction reads both and raises :class:`BootError`
    when either is unavailable, so the worker refuses to start.

    The boot id is read again on every check. In a real box it cannot change
    while the process lives (a relaunch ends the process); if it does, the
    record for the old boot is dropped, as a new process would drop it.
    """

    def __init__(
        self,
        marker_path: str | None,
        *,
        read_boot_id: Callable[[], str] = read_boot_id,
        read_booted_at: Callable[[], int] = read_booted_at,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(read_boot_id) or not callable(read_booted_at) or not callable(clock):
            raise ValueError("boot readers and clock must be callable")
        self._read_boot_id = read_boot_id
        self._read_booted_at = read_booted_at
        self._clock = clock
        self.marker_path = marker_path
        boot_id = self._checked_boot_id()
        self._booted_at = self._checked_booted_at()
        self._record = self._load(boot_id)
        if self._record.consumed_by is not None and self._record.released_at is None:
            # An earlier worker in this boot held a lease; whatever it was, it
            # ended no later than now.
            self._record = BootRecord(
                boot_id, self._record.consumed_by, self._record.consumed_at, self._clock()
            )
            self._store_or_close()

    # -- readers -----------------------------------------------------------

    def _checked_boot_id(self) -> str:
        boot_id = self._read_boot_id()
        if not isinstance(boot_id, str) or _BOOT_ID_RE.fullmatch(boot_id) is None:
            raise BootError("the boot id reader returned no boot id")
        return boot_id

    def _checked_booted_at(self) -> int:
        booted_at = self._read_booted_at()
        if isinstance(booted_at, bool) or not isinstance(booted_at, int) or booted_at < 0:
            raise BootError("the boot time reader returned no time")
        return booted_at

    def _load(self, boot_id: str) -> BootRecord:
        fresh = BootRecord(boot_id, None, None, None)
        if self.marker_path is None:
            return fresh
        try:
            fd = os.open(self.marker_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return fresh
        except OSError:
            # Unreadable (a symlink, a permission problem): fail closed.
            return BootRecord(boot_id, UNKNOWN_CONSUMER, None, self._clock())
        try:
            raw = os.read(fd, MAX_MARKER_BYTES + 1)
        except OSError:
            raw = b""
        finally:
            os.close(fd)
        try:
            if len(raw) > MAX_MARKER_BYTES:
                raise ValueError("too large")
            record = _parse_marker(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return BootRecord(boot_id, UNKNOWN_CONSUMER, None, self._clock())
        if record.boot_id != boot_id:
            # Written in another boot: that boot's customer is not this one's.
            return fresh
        return record

    def _store(self) -> None:
        if self.marker_path is None:
            return
        record = self._record
        body = json.dumps(
            {
                "schema": MARKER_SCHEMA,
                "boot_id": record.boot_id,
                "consumed_by": record.consumed_by,
                "consumed_at": record.consumed_at,
                "released_at": record.released_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        temporary = f"{self.marker_path}.tmp-{os.getpid()}"
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(fd, body)
        finally:
            os.close(fd)
        os.replace(temporary, self.marker_path)

    def _store_or_close(self) -> None:
        """Store the record; if that fails, refuse every caller until the next boot.

        A record on tmpfs that disagrees with memory would mislead the next
        worker of this boot (a stale release time, or a live lease it cannot
        see), so a failed write closes the box instead.
        """

        try:
            self._store()
        except OSError:
            record = self._record
            self._record = BootRecord(
                record.boot_id, UNKNOWN_CONSUMER, record.consumed_at, record.released_at
            )

    def _current(self) -> BootRecord | None:
        """The record for the running boot, or None when the boot id is unreadable."""

        try:
            boot_id = self._checked_boot_id()
        except Exception:
            return None
        if boot_id != self._record.boot_id:
            try:
                self._booted_at = self._checked_booted_at()
            except Exception:
                return None
            self._record = BootRecord(boot_id, None, None, None)
        return self._record

    # -- the lease's hooks (called under the lease lock) ---------------------

    def check(self, caller: str) -> None:
        """Raise :class:`RelaunchRequired` unless ``caller`` may take a new lease."""

        record = self._current()
        if record is None:
            raise RelaunchRequired("the boot id cannot be read")
        if record.consumed_by is not None and record.consumed_by != caller:
            raise RelaunchRequired("another customer used this boot")

    def consume(self, caller: str, now: float) -> None:
        """Record ``caller`` as this boot's customer before its first lease.

        The record is written before the lease is granted; if the write
        fails, :class:`BootError` is raised and the lease must not be granted.
        The same customer leasing again clears the last release time, so a
        worker restarted during that lease does not report the earlier one.
        """

        self.check(caller)
        previous = self._record
        if previous.consumed_by is not None:
            if previous.released_at is None:
                return
            self._record = BootRecord(previous.boot_id, caller, previous.consumed_at, None)
        else:
            self._record = BootRecord(previous.boot_id, caller, now, None)
        try:
            self._store()
        except OSError as exc:
            self._record = previous
            raise BootError(f"cannot record this boot's customer: {exc}") from exc

    def released(self, now: float) -> None:
        """The consuming customer's lease ended at ``now``."""

        record = self._current()
        if record is None or record.consumed_by is None:
            return
        self._record = BootRecord(record.boot_id, record.consumed_by, record.consumed_at, now)
        self._store_or_close()

    # -- reporting -----------------------------------------------------------

    def view(self, caller: str, *, leased: bool) -> dict[str, object]:
        """The ``boot`` object of ``GET /v1/box``.

        ``needs_relaunch`` is true once a customer consumed this boot and its
        lease has ended (or the boot cannot be identified): no other customer
        is leased the box until it boots again. ``last_released_at`` is rounded
        up to the whole second, so evidence verified after it is after the
        release.
        """

        record = self._current()
        if record is None:
            return {
                "boot_id": None,
                "booted_at": None,
                "consumed": True,
                "consumed_by_caller": False,
                "needs_relaunch": True,
                "last_released_at": None,
            }
        consumed = record.consumed_by is not None
        return {
            "boot_id": record.boot_id,
            "booted_at": self._booted_at,
            "consumed": consumed,
            "consumed_by_caller": consumed and record.consumed_by == caller,
            "needs_relaunch": consumed and not leased,
            "last_released_at": (
                None if record.released_at is None else math.ceil(record.released_at)
            ),
        }

    @property
    def record(self) -> BootRecord:
        return self._record

    @property
    def booted_at(self) -> int:
        return self._booted_at
