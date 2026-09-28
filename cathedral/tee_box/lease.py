"""One customer at a time on a TEE box (owner decision 1, v1).

A customer is one control-plane caller key. It takes the box with an explicit
lease that has an expiry. While the lease is live every other caller is
refused with a busy error. Releasing the lease, or letting it expire, drains
every sandbox the customer still holds before the next customer can take the
box. This mirrors the Reliquary grant rules: an expiring grant, no
overlapping owners, and a drain before the executor changes hands
(deploy/reliquary-workers/admission.py).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_MAX_LEASE_SECONDS = 24 * 3600
MIN_LEASE_SECONDS = 60


class LeaseBusy(Exception):
    """Another customer holds the box."""


class LeaseRequired(Exception):
    """The caller does not hold the box."""


@dataclass(frozen=True)
class Lease:
    holder: str
    acquired_at: float
    expires_at: float

    def view(self) -> dict[str, object]:
        return {
            "holder": self.holder,
            "acquired_at": int(self.acquired_at),
            "expires_at": int(self.expires_at),
        }


class CustomerLease:
    """Exclusive, expiring box lease with a drain on every hand-over.

    ``drain(holder)`` is called with the lock held, so a new customer cannot
    take the box, and the old one cannot create, while the drain runs.
    """

    def __init__(
        self,
        drain: Callable[[str], object],
        *,
        max_seconds: int = DEFAULT_MAX_LEASE_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(drain) or not callable(clock):
            raise ValueError("lease drain and clock must be callable")
        if (
            isinstance(max_seconds, bool)
            or not isinstance(max_seconds, int)
            or not MIN_LEASE_SECONDS <= max_seconds <= DEFAULT_MAX_LEASE_SECONDS
        ):
            raise ValueError("maximum lease must be 60 s to 24 h")
        self._drain = drain
        self._clock = clock
        self.max_seconds = max_seconds
        self._lock = threading.RLock()
        self._lease: Lease | None = None

    def _expire_locked(self, now: float) -> None:
        lease = self._lease
        if lease is not None and now >= lease.expires_at:
            self._drain(lease.holder)
            self._lease = None

    def current(self) -> Lease | None:
        with self._lock:
            self._expire_locked(self._clock())
            return self._lease

    def acquire(self, caller: str, ttl_seconds: int) -> Lease:
        """Take or renew the box for ``caller``; refuse while another holds it."""

        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not MIN_LEASE_SECONDS <= ttl_seconds <= self.max_seconds
        ):
            raise ValueError("lease ttl_seconds is out of range")
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            lease = self._lease
            if lease is not None and lease.holder != caller:
                raise LeaseBusy
            acquired_at = now if lease is None else lease.acquired_at
            self._lease = Lease(caller, acquired_at, now + ttl_seconds)
            return self._lease

    def release(self, caller: str) -> bool:
        """Drain and release ``caller``'s lease. False when it holds none."""

        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            lease = self._lease
            if lease is None:
                return False
            if lease.holder != caller:
                raise LeaseBusy
            self._drain(caller)
            self._lease = None
            return True

    def require(self, caller: str) -> Lease:
        """Return the caller's live lease, or raise busy or lease-required."""

        with self._lock:
            self._expire_locked(self._clock())
            lease = self._lease
            if lease is None:
                raise LeaseRequired
            if lease.holder != caller:
                raise LeaseBusy
            return lease

    def locked(self):  # noqa: ANN201 - context manager
        """Hold the lease lock so a call cannot race a hand-over."""

        return self._lock
