"""One customer at a time on a TEE box (owner decision 1, v1).

A customer is one control-plane caller key. It takes the box with an explicit
lease that has an expiry. While the lease is live every other caller is
refused with a busy error. Releasing the lease, or letting it expire, drains
every sandbox the customer still holds before the next customer can take the
box. The hand-over waits until the drain confirms every sandbox is gone: until
then the box is "draining" and refuses every lease, and later calls (and the
worker's reaper) retry the drain. A new process starts draining too. This mirrors the Reliquary grant rules: an expiring grant, no
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
# Ordinary calls retry a failed drain at most this often; the reaper retries
# every tick regardless.
DRAIN_RETRY_SECONDS = 2.0
# The drain target at process start: no customer owns it, so the drain is
# the sweep alone (every box-labelled container, whoever it belonged to).
BOX_START = "(box start)"


class LeaseBusy(Exception):
    """Another customer holds the box."""


class LeaseRequired(Exception):
    """The caller does not hold the box."""


class LeaseDraining(Exception):
    """The previous customer's sandboxes are not confirmed gone yet."""


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

    ``drain(holder)`` returns true only when every sandbox of ``holder`` is
    confirmed gone and no untracked box container remains. The box is marked
    draining before it runs, so a new customer cannot take the box, and the
    old one cannot create, while it runs. A false return leaves the box
    draining; the drain is retried by later calls and by the reaper. The box
    also starts draining, so a restart cannot skip the check.
    """

    def __init__(
        self,
        drain: Callable[[str], bool],
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
        # A new process knows nothing of what an earlier one left running, so
        # the box starts draining: no customer is leased it until a drain
        # (whose sweep covers every box-labelled container) comes back clean.
        self._draining: str | None = BOX_START
        self._drain_running = False
        self._retry_at = 0.0

    def _expire_locked(self, now: float) -> None:
        lease = self._lease
        if lease is not None and now >= lease.expires_at:
            self._lease = None
            self._draining = lease.holder
            self._retry_at = 0.0

    def _settle(self, *, force: bool = False) -> None:
        """End an expired lease and run an unfinished drain.

        The drain runs without the lock: the box is already marked draining,
        so no lease or create can proceed while it runs, and a slow container
        daemon holds up only this call. Retries from ordinary calls are spaced
        by DRAIN_RETRY_SECONDS; the reaper forces one each tick.
        """

        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            target = self._draining
            if target is None or self._drain_running or not (force or now >= self._retry_at):
                return
            self._drain_running = True
        drained = False
        try:
            drained = self._drain(target) is True
        finally:
            with self._lock:
                self._drain_running = False
                if drained and self._draining == target:
                    self._draining = None
                elif not drained:
                    self._retry_at = self._clock() + DRAIN_RETRY_SECONDS

    def retry_drain(self) -> None:
        """Force a drain attempt now (the reaper's entry point)."""

        self._settle(force=True)

    @property
    def draining(self) -> bool:
        with self._lock:
            return self._draining is not None

    def current(self) -> Lease | None:
        self._settle()
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
        self._settle()
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            if self._draining is not None:
                raise LeaseDraining
            lease = self._lease
            if lease is not None and lease.holder != caller:
                raise LeaseBusy
            acquired_at = now if lease is None else lease.acquired_at
            self._lease = Lease(caller, acquired_at, now + ttl_seconds)
            return self._lease

    def release(self, caller: str) -> bool:
        """End ``caller``'s lease and drain it. False when it holds none.

        The lease ends at once; the box stays draining until the drain
        confirms every sandbox of ``caller`` is gone.
        """

        self._settle()
        with self._lock:
            self._expire_locked(self._clock())
            lease = self._lease
            if lease is None:
                return False
            if lease.holder != caller:
                raise LeaseBusy
            self._lease = None
            self._draining = caller
            self._retry_at = 0.0
        self._settle(force=True)
        return True

    def require(self, caller: str) -> Lease:
        """Return the caller's live lease, or raise draining, busy or lease-required."""

        self._settle()
        with self._lock:
            self._expire_locked(self._clock())
            if self._draining is not None:
                raise LeaseDraining
            lease = self._lease
            if lease is None:
                raise LeaseRequired
            if lease.holder != caller:
                raise LeaseBusy
            return lease

    def require_locked(self, caller: str) -> Lease:
        """``require`` for a caller already holding ``locked()``: it never runs a
        drain. An expiry found here marks the box draining and refuses; the
        drain then runs on a later call, outside the lock, so a slow container
        daemon cannot block every other caller behind this one."""

        now = self._clock()
        self._expire_locked(now)
        if self._draining is not None:
            raise LeaseDraining
        lease = self._lease
        if lease is None:
            raise LeaseRequired
        if lease.holder != caller:
            raise LeaseBusy
        return lease

    def locked(self):  # noqa: ANN201 - context manager
        """Hold the lease lock so a call cannot race a hand-over."""

        return self._lock
