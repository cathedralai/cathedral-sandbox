"""Bounded worker for evidence collection and canonical SAT work.

``WorkerServer`` listens on loopback behind an HTTPS terminator unless an
explicit development-only override is supplied; tests may also install a TLS
context directly. Production v2 evidence is accepted only for the configured
in-guest channel-key digest. The corresponding client requires HTTPS by
default.
"""
from __future__ import annotations

import hmac
import io
import ipaddress
import json
import math
import multiprocessing
import re
import socket
import ssl
import sys
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from cathedral.attest import collect_tdx
from cathedral.central_access import (
    CENTRAL_REQUEST_HEADER,
    CENTRAL_ROUTES,
    MAX_CENTRAL_CONCURRENT,
    CentralAccessAuthorizer,
    CentralAccessError,
    CentralRequestLimiter,
)
from cathedral.common import (
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
    MAX_COMPOSITE_JWT_BYTES,
    MAX_EVIDENCE_CERTIFICATE_BYTES,
    MAX_EVIDENCE_CERTIFICATES,
    MAX_EVIDENCE_COMPONENTS,
    MAX_EVIDENCE_QUOTE_BYTES,
    MAX_EVIDENCE_RESPONSE_BODY,
)
from cathedral.lanes.sat import (
    MAX_SEED,
    MIN_SEED,
    _canonical_instance,
    _compute_challenge_id,
    derived_work_units_for,
    solve_sat,
    validate_sat_instance,
)
from cathedral.lanes.sat_types import SatInstance
from cathedral.validator_access import (
    PreauthorizedValidatorRequest,
    VALIDATOR_REQUEST_HEADER,
    FleetManifest,
    ValidatorRequestAuthorizer,
    ValidatorRequestLimiter,
    fleet_response,
)

MAX_REQUEST_BODY: int = 64 * 1024
MAX_RESPONSE_BODY: int = MAX_EVIDENCE_RESPONSE_BODY
# Sized for the 4 vCPU guest the worker ships in. Authenticated work gets one
# slot per vCPU because canonical SAT is CPU bound and customer SAT runs in a
# child process, so the slots map onto real parallelism. Explicit migration
# and development-no-auth challenge paths get their own smaller pool: a
# migration validator needs one quote and one canonical audit per miner per
# epoch plus room for a retry. A POST that carries the configured bearer uses
# the authenticated pool instead. Public migration SAT gets a third pool of
# its own: it must parse an attacker-chosen instance before it can decide
# whether the request is the canonical audit, so it must not be able to occupy
# the slots a validator needs for quote collection.
MAX_CONCURRENT: int = 4
MAX_CHALLENGE_CONCURRENT: int = 2
MAX_SAT_CHALLENGE_CONCURRENT: int = 2
MAX_VALIDATOR_CHALLENGE_CONCURRENT: int = 2
# Connections allowed beyond the request-class slots while a handshake or the
# headers are still arriving. Such a connection costs an idle thread, and the
# oldest is evicted when a new one needs its permit, so a few idle sockets can
# no longer lock validators out (review finding W1). Permits stay strict;
# evicted threads exit on their next read.
PREAUTH_CONNECTION_HEADROOM: int = 22
# A signed validator body is at most MAX_REQUEST_BODY and arrives within one
# round trip. A request still reading its body after this long is stalled, and
# a new validator may take its slot (review finding W2).
VALIDATOR_BODY_STALL_SECONDS: float = 1.0
# The stall grace grows with the declared body at this rate, so a distant
# validator's large upload is not mistaken for a stall.
VALIDATOR_BODY_MIN_RATE_BYTES: int = 32 * 1024
# A validator whose signed request leaves its slot without a complete body
# (displaced, closed or timed out), or is refused for a client fault (a body
# its signature does not cover, a replayed nonce, a request that expired in
# flight), is kept out of the signed class this long, so stalling and
# reconnecting just inside the grace no longer holds slots.
VALIDATOR_ABANDON_PENALTY_SECONDS: float = 20.0
# The bench does not stop a validator that sends valid requests with each
# body just inside its grace: such a request holds a slot for almost the grace
# and is never displaced or benched, and the rate limit allows about two a
# second, so two hotkeys doing it used to lock a third out of a class of two.
# Each hotkey therefore has a budget of slow slot time. The time a request
# holds its slot before its body arrives, beyond the first tenth of its grace,
# is charged to a per-hotkey bucket that holds VALIDATOR_SLOW_SLOT_BUDGET_SECONDS
# and drains at that much per VALIDATOR_SLOW_SLOT_WINDOW_SECONDS. While its
# bucket is over the budget, a hotkey's request that is still waiting for its
# body is displaced at once by another validator arriving at a full class,
# without a bench. A validator that sends its body within a tenth of its
# grace (about 0.1 s for a small body, 0.3 s for a 64 KiB one) is never
# charged, so it is never displaced before its grace.
#
# What remains is the uncharged tenth and the budget itself. Under the default
# rate limit a hotkey can hold a slot undisplaceably before its body for about
# 5 / 60 + 2 * 0.1 * G of the time, where G is its grace: about 0.31 on the
# small signed routes (G <= 1.125 s) and 0.68 on a 64 KiB sat-work request
# (G = 3 s). Keeping both slots of the class full that way takes about seven
# colluding permit holders on the small routes and three on sat-work, where
# two used to be enough. A request whose body has arrived is served, not
# displaced: that is rate-limited work, one in flight per hotkey.
VALIDATOR_SLOW_SLOT_BUDGET_SECONDS: float = 5.0
VALIDATOR_SLOW_SLOT_WINDOW_SECONDS: float = 60.0
VALIDATOR_PROMPT_GRACE_FRACTION: float = 0.1
# Signed evidence, fleet and capabilities bodies are a few hundred bytes; only
# sat-work may declare up to the body cap and so earn a longer grace.
SMALL_SIGNED_BODY_BYTES: int = 4096
MAX_HOTKEY_LENGTH: int = 256
MAX_BEARER_TOKEN_LENGTH: int = 4096
MAX_CUSTOMER_SAT_SOLVE_SECONDS: float = 30.0
MAX_CUSTOMER_SAT_MEMORY_BYTES: int = 256 * 1024 * 1024

_EVIDENCE_REQUEST_KEYS = frozenset({"nonce_hex", "assigned_hotkey"})
_EVIDENCE_V2_REQUEST_KEYS = _EVIDENCE_REQUEST_KEYS | frozenset(
    {"report_data_version", "channel_binding_type", "channel_binding_digest_hex"}
)
_SAT_REQUEST_KEYS = frozenset({"challenge_id", "assigned_hotkey", "instance", "seed"})
_POST_PATHS = frozenset(
    {"/v1/evidence", "/v1/capabilities", "/v1/sat-work", "/v1/fleet",
     "/v1/gpu-evidence", "/v1/gpu-work", "/v1/gpu-capabilities"}
)
_GPU_PATHS = frozenset({"/v1/gpu-evidence", "/v1/gpu-work", "/v1/gpu-capabilities"})
_Semaphore = threading.Semaphore
_CAPABILITIES_REQUEST_KEYS: frozenset[str] = frozenset()
_INSTANCE_KEYS = frozenset({"n_vars", "clauses"})
_DECIMAL_RE = re.compile(r"[0-9]+")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


def _customer_sat_solve_child(connection, instance: SatInstance, cpu_seconds: int) -> None:
    """Solve one untrusted instance inside a resource-capped child process."""

    try:
        if sys.platform.startswith("linux"):
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            resource.setrlimit(
                resource.RLIMIT_AS,
                (MAX_CUSTOMER_SAT_MEMORY_BYTES, MAX_CUSTOMER_SAT_MEMORY_BYTES),
            )
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        connection.send(("ok", solve_sat(instance)))
    except BaseException:
        try:
            connection.send(("error", None))
        except BaseException:
            pass
    finally:
        connection.close()


def _solve_customer_sat_bounded(
    instance: SatInstance,
    timeout_seconds: float,
) -> tuple[bool, list[int] | None]:
    """Return ``(completed, assignment)`` and kill work that exceeds its budget."""

    budget = min(float(timeout_seconds), MAX_CUSTOMER_SAT_SOLVE_SECONDS)
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_customer_sat_solve_child,
        args=(child, instance, max(1, math.ceil(budget))),
        daemon=True,
    )
    started = False
    try:
        process.start()
        started = True
        child.close()
        process.join(budget)
        if process.is_alive():
            process.terminate()
            process.join(1.0)
        if process.is_alive():
            process.kill()
            process.join(1.0)
        if process.exitcode != 0 or not parent.poll():
            return False, None
        status, assignment = parent.recv()
        if status != "ok" or (
            assignment is not None
            and (
                not isinstance(assignment, list)
                or len(assignment) != instance.n_vars
                or any(isinstance(item, bool) or not isinstance(item, int) for item in assignment)
            )
        ):
            return False, None
        return True, assignment
    except (OSError, EOFError, RuntimeError):
        return False, None
    finally:
        try:
            child.close()
        except OSError:
            pass
        try:
            parent.close()
        except OSError:
            pass
        if started and process.is_alive():
            process.kill()
            process.join(1.0)


def _evidence_fits_transport(evidence: Evidence) -> bool:
    jwt = evidence.composite_jwt
    return (
        isinstance(evidence.quote, bytes)
        and 0 < len(evidence.quote) <= MAX_EVIDENCE_QUOTE_BYTES
        and isinstance(evidence.cert_chain, list)
        and len(evidence.cert_chain) <= MAX_EVIDENCE_CERTIFICATES
        and all(
            isinstance(certificate, bytes)
            and 0 < len(certificate) <= MAX_EVIDENCE_CERTIFICATE_BYTES
            for certificate in evidence.cert_chain
        )
        and (
            jwt is None
            or (
                isinstance(jwt, str)
                and bool(jwt)
                and jwt.isascii()
                and len(jwt) <= MAX_COMPOSITE_JWT_BYTES
                and all(ord(character) >= 0x20 for character in jwt)
            )
        )
    )


def _arm_remaining_budget(connection: socket.socket, deadline: float) -> None:
    """Set the socket timeout to whatever is left before ``deadline``."""

    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise TimeoutError("request deadline exceeded")
    connection.settimeout(remaining)


class _DeadlineReader(io.RawIOBase):
    """Bound a request by total wall clock rather than by each recv.

    ``socket.settimeout`` limits one recv, not one request, so a caller that
    dribbles a byte per timeout window keeps its connection alive forever.
    Every read here is a single underlying ``read1``, so the remaining budget
    is rechecked between recvs and the socket timeout is trimmed to what is
    left. Reads past the deadline raise ``TimeoutError``, which the header
    parser and ``_read_body`` already treat as a dead request.
    """

    def __init__(
        self,
        source: io.BufferedReader,
        connection: socket.socket,
        deadline: float,
    ) -> None:
        self._source = source
        self._connection = connection
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # noqa: ANN001 - writable buffer protocol
        wanted = len(buffer)
        if wanted == 0:
            return 0
        _arm_remaining_budget(self._connection, self._deadline)
        chunk = self._source.read1(wanted)
        buffer[: len(chunk)] = chunk
        return len(chunk)

    def close(self) -> None:
        try:
            self._source.close()
        finally:
            super().close()


class _DeadlineWriter(io.BufferedIOBase):
    """Give the response its own budget, starting at its first byte.

    Replaces the unbuffered ``_SocketWriter`` the base handler installs. A
    caller that stops reading its response would otherwise keep a worker slot
    for as long as it likes, because ``sendall`` restarts the socket timeout
    on every partial send. The budget starts here rather than being shared
    with the request deadline so that a request which ran out of read budget
    can still be told why.
    """

    def __init__(self, connection: socket.socket, budget: float) -> None:
        self._connection = connection
        self._budget = budget
        self._deadline: float | None = None

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:  # noqa: ANN001 - readable buffer protocol
        if self._deadline is None:
            self._deadline = time.monotonic() + self._budget
        view = memoryview(data)
        total = len(view)
        sent = 0
        while sent < total:
            _arm_remaining_budget(self._connection, self._deadline)
            sent += self._connection.send(view[sent:])
        return total


class _ValidatorSlot:
    """One signed request's place in the validator class.

    Its life has three marks. ``mark_body_received`` records a complete,
    full-length body: the stall clock stops and the slot can no longer be
    displaced, so a slow ``finalize`` (a synchronous replay-store write) never
    costs an honest validator its slot. ``mark_client_fault`` records a
    refusal that is the validator's fault: a body its signature does not
    cover, a replayed nonce or a request that expired in flight.
    ``mark_verified`` records that ``finalize`` accepted the body. On release
    the validator is benched only for a client fault: no complete body, or a
    refusal marked as one. A refusal on the worker's side (replay store full
    or failing, snapshot unavailable) does not bench an honest validator.
    """

    __slots__ = (
        "pool",
        "connection",
        "hotkey",
        "admitted_at",
        "grace",
        "body_received",
        "client_refused",
        "verified",
        "charged",
        "owned",
    )

    def __init__(
        self,
        pool: "_ValidatorPool",
        connection: socket.socket,
        hotkey: str,
        admitted_at: float,
        grace: float,
    ) -> None:
        self.pool = pool
        self.connection = connection
        self.hotkey = hotkey
        self.admitted_at = admitted_at
        self.grace = grace
        self.body_received = False
        self.client_refused = False
        self.verified = False
        self.charged = False
        self.owned = True

    def mark_body_received(self) -> bool:
        """Record a complete body; False when the slot was already taken over,
        in which case the request must stop rather than run over capacity."""
        with self.pool._lock:
            if self.owned:
                self.body_received = True
                self.pool._charge_locked(self, self.pool._clock())
            return self.owned

    def mark_client_fault(self) -> None:
        with self.pool._lock:
            self.client_refused = True

    def mark_verified(self) -> None:
        with self.pool._lock:
            self.verified = True

    @property
    def client_fault(self) -> bool:
        return not self.verified and (not self.body_received or self.client_refused)

    def release(self) -> None:
        self.pool._release(self)


class _ValidatorPool:
    """The signed-validator request class, fair across validators.

    Each validator is already limited to one request in flight, but the class
    itself is small and shared, so a few permitted validators stalling their
    bodies used to hold every slot until the request deadline and turn all
    other validators away (review finding W2). Three rules close that:

    - when the class is full, a new validator takes the slot of the request
      that has spent longest reading its body past its grace (one second plus
      the declared body at VALIDATOR_BODY_MIN_RATE_BYTES per second); a
      request whose body has been read is never displaced;
    - a validator whose request leaves its slot without a complete body
      (stalled, closed, displaced past its grace) or is refused for a client
      fault is kept out of the class for VALIDATOR_ABANDON_PENALTY_SECONDS, so
      stalling and reconnecting just inside the grace does not hold slots;
    - a hotkey over its slow-slot budget (VALIDATOR_SLOW_SLOT_BUDGET_SECONDS)
      loses the grace: its request still waiting for a body may be displaced
      at once, without a bench, so valid bodies sent just inside the grace
      cannot hold the class either.
    """

    def __init__(
        self,
        capacity: int,
        *,
        stall_seconds: float = VALIDATOR_BODY_STALL_SECONDS,
        min_rate_bytes: int = VALIDATOR_BODY_MIN_RATE_BYTES,
        penalty_seconds: float = VALIDATOR_ABANDON_PENALTY_SECONDS,
        slow_budget_seconds: float = VALIDATOR_SLOW_SLOT_BUDGET_SECONDS,
        slow_window_seconds: float = VALIDATOR_SLOW_SLOT_WINDOW_SECONDS,
        prompt_fraction: float = VALIDATOR_PROMPT_GRACE_FRACTION,
        max_penalized: int = 256,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._capacity = capacity
        self._stall_seconds = stall_seconds
        self._min_rate_bytes = min_rate_bytes
        self._penalty_seconds = penalty_seconds
        self._slow_budget = slow_budget_seconds
        self._slow_drain = slow_budget_seconds / slow_window_seconds
        self._prompt_fraction = prompt_fraction
        self._max_penalized = max_penalized
        self._clock = clock
        self._lock = threading.Lock()
        self._slots: list[_ValidatorSlot] = []
        self._penalized_until: dict[str, float] = {}
        # hotkey -> (charged slow seconds, as of this clock reading)
        self._slow_usage: dict[str, tuple[float, float]] = {}
        self.displaced_count = 0

    def penalized(self, hotkey: str) -> bool:
        with self._lock:
            return self._penalized_until.get(hotkey, 0.0) > self._clock()

    def slow_usage(self, hotkey: str) -> float:
        with self._lock:
            return self._slow_usage_locked(hotkey, self._clock())

    def _slow_usage_locked(self, hotkey: str, now: float) -> float:
        level, at = self._slow_usage.get(hotkey, (0.0, now))
        return max(0.0, level - max(0.0, now - at) * self._slow_drain)

    def _slow_seconds(self, slot: _ValidatorSlot, now: float) -> float:
        """Pre-body slot time beyond the prompt part of the grace."""
        return max(0.0, now - slot.admitted_at - slot.grace * self._prompt_fraction)

    def _charge_locked(self, slot: _ValidatorSlot, now: float) -> None:
        if slot.charged:
            return
        slot.charged = True
        slow = self._slow_seconds(slot, now)
        if slow <= 0.0:
            return
        hotkey = slot.hotkey
        if hotkey not in self._slow_usage and len(self._slow_usage) >= self._max_penalized:
            drained = [key for key in self._slow_usage if self._slow_usage_locked(key, now) <= 0.0]
            for key in drained:
                del self._slow_usage[key]
            if len(self._slow_usage) >= self._max_penalized:
                lowest = min(self._slow_usage, key=lambda key: self._slow_usage_locked(key, now))
                del self._slow_usage[lowest]
        self._slow_usage[hotkey] = (self._slow_usage_locked(hotkey, now) + slow, now)

    def _displaceable_locked(self, held: _ValidatorSlot, now: float) -> bool:
        if held.body_received:
            return False
        if now - held.admitted_at >= held.grace:
            return True
        return (
            self._slow_usage_locked(held.hotkey, now) + self._slow_seconds(held, now)
            > self._slow_budget
        )

    def admit(
        self, connection: socket.socket, hotkey: str, declared_length: int = 0
    ) -> _ValidatorSlot | None:
        now = self._clock()
        grace = self._stall_seconds + max(0, declared_length) / self._min_rate_bytes
        slot = _ValidatorSlot(self, connection, hotkey, now, grace)
        with self._lock:
            if self._penalized_until.get(hotkey, 0.0) > now:
                return None
            if len(self._slots) < self._capacity:
                self._slots.append(slot)
                return slot
            candidates = [held for held in self._slots if self._displaceable_locked(held, now)]
            if not candidates:
                return None
            victim = min(candidates, key=lambda held: held.admitted_at)
            victim.owned = False
            self._slots[self._slots.index(victim)] = slot
            self._charge_locked(victim, now)
            if now - victim.admitted_at >= victim.grace:
                # Stalled past its grace. A victim displaced only for being
                # over its slow-slot budget is not benched.
                self._penalize_locked(victim.hotkey, now)
            self.displaced_count += 1
            # Still under the lock: the victim cannot have released and closed
            # its socket, so its descriptor cannot have been reused. The raw TCP
            # shutdown wakes its body read with EOF. This is the same call as
            # _BoundedThreadingHTTPServer's _shutdown_transport helper where
            # that exists; swap this block for it when both are present.
            try:
                socket.socket.shutdown(victim.connection, socket.SHUT_RDWR)
            except OSError:
                pass
        return slot

    def _penalize_locked(self, hotkey: str, now: float) -> None:
        if hotkey not in self._penalized_until and len(self._penalized_until) >= self._max_penalized:
            expired = [key for key, until in self._penalized_until.items() if until <= now]
            for key in expired:
                del self._penalized_until[key]
            if len(self._penalized_until) >= self._max_penalized:
                oldest = min(self._penalized_until, key=self._penalized_until.__getitem__)
                del self._penalized_until[oldest]
        self._penalized_until[hotkey] = now + self._penalty_seconds

    def _release(self, slot: _ValidatorSlot) -> None:
        with self._lock:
            if slot.owned:
                slot.owned = False
                self._slots.remove(slot)
                now = self._clock()
                self._charge_locked(slot, now)
                if slot.client_fault:
                    # Closed or timed out before its body, or refused for a
                    # client fault after it.
                    self._penalize_locked(slot.hotkey, now)

    @property
    def in_use(self) -> int:
        with self._lock:
            return len(self._slots)


def _make_handler(
    semaphore: threading.Semaphore,
    challenge_semaphore: threading.Semaphore,
    sat_challenge_semaphore: threading.Semaphore,
    validator_pool: _ValidatorPool,
    configured_hotkey: str,
    bearer_token: str | None,
    evidence_collector: Callable[..., Evidence | tuple[Evidence, ...] | list[Evidence]],
    configured_channel_binding: ChannelBinding | None,
    max_body: int,
    max_response_body: int,
    request_timeout: float,
    allow_noncanonical_sat: bool,
    validator_authorizer: ValidatorRequestAuthorizer | None,
    fleet_endpoints: Callable[[], tuple[str, ...]] | None,
    allow_public_bootstrap_evidence: bool,
    allow_public_legacy_audit: bool,
    validator_request_limiter: ValidatorRequestLimiter | None,
    gpu_executor,
    gpu_evidence_collector,
    central_authorizer: CentralAccessAuthorizer | None = None,
    central_request_limiter: CentralRequestLimiter | None = None,
    central_semaphore: threading.Semaphore | None = None,
) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(request_timeout)
            # One deadline covers headers and body, so the budget a caller
            # spends stalling on headers is not also available for stalling on
            # the body; the response then gets a budget of its own.
            self.rfile = io.BufferedReader(
                _DeadlineReader(
                    self.rfile, self.connection, time.monotonic() + request_timeout
                )
            )
            self.wfile = _DeadlineWriter(self.connection, request_timeout)

        def log_message(self, fmt: str, *args: object) -> None:
            pass

        def parse_request(self) -> bool:
            parsed = super().parse_request()
            if parsed:
                protect = getattr(self.server, "protect_connection", None)
                if protect is not None:
                    protect(self.request)
            return parsed

        def _send_json(self, code: int, obj: dict[str, object]) -> None:
            body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            if len(body) > max_response_body:
                code = 500
                body = b'{"error":"response too large"}'
                if len(body) > max_response_body:
                    body = b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _check_auth(self) -> bool:
            if bearer_token is None:
                return True
            header = self.headers.get("Authorization", "")
            expected = f"Bearer {bearer_token}"
            # compare_digest raises TypeError on non-ASCII strings. A junk
            # Authorization header is unauthenticated, not a crash.
            if not isinstance(header, str) or not header.isascii():
                return False
            return hmac.compare_digest(header, expected)

        def _validator_request_header(self) -> str | None:
            values = self.headers.get_all(VALIDATOR_REQUEST_HEADER, failobj=[])
            if len(values) != 1:
                return None
            return values[0]

        def _serve_central(self, path: str) -> None:
            # A central caller never shares the validator header, limiter,
            # replay state, or pool. Every refusal is the same 401, before any
            # body is read, and only granted routes are served.
            headers = self.headers.get_all(CENTRAL_REQUEST_HEADER, failobj=[])
            if (
                len(headers) != 1
                or self.headers.get_all(VALIDATOR_REQUEST_HEADER, failobj=[])
                or path not in CENTRAL_ROUTES
            ):
                self._send_json(401, {"error": "unauthorized"})
                return
            assert central_authorizer is not None
            assert central_request_limiter is not None
            assert central_semaphore is not None
            try:
                request = central_authorizer.preauthorize(
                    headers[0], method="POST", path=path, now=datetime.now(UTC)
                )
            except CentralAccessError:
                self._send_json(401, {"error": "unauthorized"})
                return
            lease = central_request_limiter.acquire(request.caller)
            if lease is None:
                self._send_json(429, {"error": "central rate limit exceeded"})
                return
            try:
                if not central_semaphore.acquire(blocking=False):
                    self._send_json(503, {"error": "busy"})
                    return
                try:
                    raw, error_code, error_message = self._read_body()
                    if raw is None:
                        self._send_json(error_code, {"error": error_message})
                        return
                    try:
                        central_authorizer.finalize(request, body=raw, now=datetime.now(UTC))
                    except CentralAccessError:
                        self._send_json(401, {"error": "unauthorized"})
                        return
                    self._handle_post(raw)
                finally:
                    central_semaphore.release()
            finally:
                lease.release()

        def _preauthorize_validator(self, path: str) -> PreauthorizedValidatorRequest | None:
            if validator_authorizer is None:
                return None
            header = self._validator_request_header()
            if header is None:
                return None
            return validator_authorizer.preauthorize(
                header,
                method="POST",
                path=path,
            )

        def _read_body(self) -> tuple[bytes | None, int, str]:
            if self.headers.get("Transfer-Encoding") is not None:
                return None, 400, "invalid request framing"
            lengths = self.headers.get_all("Content-Length", failobj=[])
            if len(lengths) != 1:
                return None, 411, "content length required"
            length_text = lengths[0]
            if _DECIMAL_RE.fullmatch(length_text) is None:
                return None, 400, "invalid content length"
            length = int(length_text)
            if length > max_body:
                return None, 413, "request too large"
            try:
                body = self.rfile.read(length)
            except (socket.timeout, TimeoutError, OSError):
                return None, 400, "incomplete request body"
            if len(body) != length:
                return None, 400, "incomplete request body"
            return body, 200, ""

        def do_POST(self) -> None:
            path = self.path.partition("?")[0]
            # Header presence is not authentication. Reject unknown routes
            # before it can influence pool selection or trigger a body read,
            # otherwise a fake validator header could occupy the small signed
            # challenge pool while withholding an irrelevant request body.
            if path not in _POST_PATHS:
                self._send_json(404, {"error": "not found"})
                return
            if path in _GPU_PATHS and gpu_executor is None:
                self._send_json(404, {"error": "GPU capability unavailable"})
                return
            if path == "/v1/fleet" and validator_authorizer is None:
                self._send_json(404, {"error": "fleet discovery unavailable"})
                return
            if central_authorizer is not None and self.headers.get_all(
                CENTRAL_REQUEST_HEADER, failobj=[]
            ):
                try:
                    self._serve_central(path)
                except (socket.timeout, TimeoutError, OSError):
                    try:
                        self._send_json(400, {"error": "request failed"})
                    except OSError:
                        pass
                except Exception:
                    try:
                        self._send_json(500, {"error": "internal error"})
                    except OSError:
                        pass
                return
            # Public evidence and canonical SAT exist only for an explicit
            # migration bridge or a development worker with authentication
            # disabled. Normal bearer-only production authenticates every
            # POST. Signed-access production requires a validator envelope for
            # evidence even when a fallback bearer is configured.
            public_bootstrap = (
                path == "/v1/evidence"
                and validator_authorizer is not None
                and (allow_public_bootstrap_evidence or allow_public_legacy_audit)
            )
            public_legacy_sat = (
                path == "/v1/sat-work"
                and validator_authorizer is not None
                and allow_public_legacy_audit
            )
            credential_free = public_bootstrap or public_legacy_sat
            if path == "/v1/fleet":
                auth_ok = False
            elif path == "/v1/evidence" and validator_authorizer is not None:
                # Do not let a bearer bypass signed evidence access. Migration
                # modes are handled by credential_free above.
                auth_ok = False
            elif validator_authorizer is not None and bearer_token is None:
                # In signed-access mode, an intentionally absent migration
                # bearer means "signature required", not "authentication
                # disabled". Development no-auth has no authorizer and still
                # follows _check_auth below.
                auth_ok = False
            else:
                auth_ok = self._check_auth()
            signed_candidate = (
                validator_authorizer is not None and self._validator_request_header() is not None
            )
            signed_only = path == "/v1/fleet" or path in _GPU_PATHS
            if signed_only and not signed_candidate:
                self._send_json(401, {"error": "unauthorized"})
                return
            if not signed_only and not credential_free and not auth_ok and not signed_candidate:
                self._send_json(401, {"error": "unauthorized"})
                return
            signed_required = validator_authorizer is not None and (
                signed_candidate
                or path == "/v1/fleet"
                or (
                    path in {"/v1/sat-work", "/v1/capabilities"}
                    and not auth_ok
                    and not public_legacy_sat
                )
                or (
                    path == "/v1/evidence"
                    and not allow_public_bootstrap_evidence
                    and not allow_public_legacy_audit
                )
            )
            validator_lease = None
            try:
                preauthorized_validator = None
                if signed_required:
                    preauthorized_validator = self._preauthorize_validator(path)
                    if preauthorized_validator is None:
                        self._send_json(401, {"error": "unauthorized"})
                        return
                    if validator_request_limiter is None:
                        self._send_json(503, {"error": "validator limiter unavailable"})
                        return
                    validator_lease = validator_request_limiter.acquire(
                        preauthorized_validator.validator_hotkey
                    )
                    if validator_lease is None:
                        self._send_json(429, {"error": "validator rate limit exceeded"})
                        return
                # A SAT POST with a configured, valid bearer is customer work
                # (or a validator that already holds the credential). It uses
                # the authenticated pool so public migration traffic cannot
                # 503 it.
                #
                # Explicit public-migration SAT gets its own pool, not the
                # evidence pool. Canonical classification needs the parsed
                # instance. Sharing the evidence pool would let migration SAT
                # traffic 503 a validator's quote collection.
                validator_slot = None
                if preauthorized_validator is not None:
                    # Signed validator control traffic has reserved
                    # request-class capacity after headers are parsed and the
                    # envelope is authenticated. A validator stalling its body
                    # can be displaced by another (see _ValidatorPool).
                    pool = None
                elif path == "/v1/sat-work" and bearer_token is not None and auth_ok:
                    pool = semaphore
                elif path == "/v1/sat-work":
                    pool = sat_challenge_semaphore
                elif path == "/v1/evidence":
                    # Evidence collection stays isolated from work even when a
                    # production bearer authenticated the request.
                    pool = challenge_semaphore
                elif credential_free or signed_candidate or path == "/v1/fleet":
                    pool = challenge_semaphore
                else:
                    pool = semaphore
                if pool is None:
                    assert preauthorized_validator is not None
                    hotkey = preauthorized_validator.validator_hotkey
                    if validator_pool.penalized(hotkey):
                        self._send_json(429, {"error": "validator recently abandoned a request"})
                        return
                    # A header whose nonce an accepted request already used
                    # gets no slot at all. finalize still decides every nonce.
                    assert validator_authorizer is not None
                    if validator_authorizer.is_replay(preauthorized_validator):
                        self._send_json(401, {"error": "unauthorized"})
                        return
                    declared = self.headers.get("Content-Length", "")
                    route_cap = max_body if path == "/v1/sat-work" else SMALL_SIGNED_BODY_BYTES
                    declared_length = (
                        min(int(declared), route_cap)
                        if _DECIMAL_RE.fullmatch(declared or "")
                        else 0
                    )
                    validator_slot = validator_pool.admit(self.connection, hotkey, declared_length)
                    admitted = validator_slot is not None
                else:
                    admitted = pool.acquire(blocking=False)
                if not admitted:
                    self._send_json(503, {"error": "busy"})
                    return
                try:
                    # Admission precedes every untrusted body read. A caller
                    # that declares a body and then stalls therefore consumes
                    # one bounded class slot, never an unbounded handler
                    # thread. The server-level connection gate also covers
                    # clients that stall before their headers identify a path.
                    raw, error_code, error_message = self._read_body()
                    if raw is None:
                        self._send_json(error_code, {"error": error_message})
                        return
                    # A full-length body stops the stall clock before finalize
                    # writes the replay store, so a slow write cannot get an
                    # honest validator displaced. A request displaced just
                    # before its body arrived must stop (see _ValidatorPool).
                    if validator_slot is not None and not validator_slot.mark_body_received():
                        return
                    if preauthorized_validator is not None:
                        assert validator_authorizer is not None
                        finalized = validator_authorizer.finalize_result(
                            preauthorized_validator, body=raw
                        )
                        if not isinstance(finalized, str):
                            # A mismatched body, a replay or an expiry is the
                            # client's fault and benches; a replay-store or
                            # snapshot refusal is the worker's and does not.
                            if validator_slot is not None and finalized.client_fault:
                                validator_slot.mark_client_fault()
                            self._send_json(401, {"error": "unauthorized"})
                            return
                        if validator_slot is not None:
                            validator_slot.mark_verified()
                    self._handle_post(raw)
                finally:
                    if validator_slot is not None:
                        validator_slot.release()
                    elif pool is not None:
                        pool.release()
            except (socket.timeout, TimeoutError, OSError):
                try:
                    self._send_json(400, {"error": "request failed"})
                except OSError:
                    pass
            except Exception:
                try:
                    self._send_json(500, {"error": "internal error"})
                except OSError:
                    pass
            finally:
                if validator_lease is not None:
                    validator_lease.release()

        def _handle_post(self, raw: bytes) -> None:
            try:
                body = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid JSON"})
                return
            if not isinstance(body, dict):
                self._send_json(400, {"error": "expected JSON object"})
                return

            path = self.path.partition("?")[0]
            if path == "/v1/evidence":
                self._handle_evidence(body)
            elif path == "/v1/gpu-evidence":
                self._handle_evidence(body, gpu=True)
            elif path == "/v1/gpu-work":
                self._handle_gpu_work(body)
            elif path == "/v1/gpu-capabilities":
                if body:
                    self._send_json(400, {"error": "invalid GPU capabilities schema"})
                else:
                    self._send_json(200, gpu_executor.capabilities())
            elif path == "/v1/capabilities":
                if set(body) != _CAPABILITIES_REQUEST_KEYS:
                    self._send_json(400, {"error": "invalid capabilities schema"})
                else:
                    self._send_json(200, {"customer_sat": allow_noncanonical_sat})
            elif path == "/v1/sat-work":
                self._handle_sat_work(body)
            elif path == "/v1/fleet":
                if set(body):
                    self._send_json(400, {"error": "invalid fleet schema"})
                elif fleet_endpoints is None:
                    self._send_json(404, {"error": "fleet discovery unavailable"})
                else:
                    # Read the manifest per request so a changed fleet.json is
                    # served without a restart.
                    self._send_json(200, fleet_response(configured_hotkey, fleet_endpoints()))
            else:
                self._send_json(404, {"error": "not found"})

        def _handle_evidence(self, body: dict[str, object], *, gpu: bool = False) -> None:
            keys = frozenset(body)
            if (keys not in {_EVIDENCE_REQUEST_KEYS, _EVIDENCE_V2_REQUEST_KEYS}
                    or (gpu and keys != _EVIDENCE_V2_REQUEST_KEYS)):
                self._send_json(400, {"error": "invalid evidence schema"})
                return
            nonce_hex = body["nonce_hex"]
            hotkey = body["assigned_hotkey"]
            if not isinstance(hotkey, str) or not hotkey or len(hotkey) > MAX_HOTKEY_LENGTH:
                self._send_json(400, {"error": "invalid assigned_hotkey"})
                return
            if hotkey != configured_hotkey:
                self._send_json(403, {"error": "assigned_hotkey mismatch"})
                return
            if not isinstance(nonce_hex, str) or _SHA256_RE.fullmatch(nonce_hex) is None:
                self._send_json(400, {"error": "nonce must be exactly 32 bytes of hex"})
                return
            nonce = bytes.fromhex(nonce_hex)

            report_data_version = body.get("report_data_version", 1)
            if isinstance(report_data_version, bool) or not isinstance(
                report_data_version, int
            ):
                self._send_json(400, {"error": "invalid report data version"})
                return
            requested_binding: ChannelBinding | None = None
            if report_data_version == 2:
                try:
                    binding_type = ChannelBindingType(body["channel_binding_type"])
                    digest_hex = body["channel_binding_digest_hex"]
                    if (
                        not isinstance(digest_hex, str)
                        or _SHA256_RE.fullmatch(digest_hex) is None
                    ):
                        raise ValueError
                    requested_binding = ChannelBinding(
                        binding_type, bytes.fromhex(digest_hex)
                    )
                except (KeyError, TypeError, ValueError):
                    self._send_json(400, {"error": "invalid channel binding"})
                    return
                if configured_channel_binding is None:
                    self._send_json(503, {"error": "channel binding unavailable"})
                    return
                if requested_binding != configured_channel_binding:
                    self._send_json(403, {"error": "channel binding mismatch"})
                    return
            elif report_data_version != 1:
                self._send_json(400, {"error": "unsupported report data version"})
                return

            try:
                if report_data_version == 2:
                    collector = gpu_evidence_collector if gpu else evidence_collector
                    collected = collector(
                        nonce,
                        configured_hotkey,
                        channel_binding=configured_channel_binding,
                        report_data_version=2,
                    )
                else:
                    collected = evidence_collector(nonce, configured_hotkey)
            except Exception:
                self._send_json(500, {"error": "evidence collection failed"})
                return
            if gpu:
                from cathedral.gpu_provider import G4ProviderCollector, PROVIDER_EVIDENCE_SCHEMA
                if isinstance(gpu_evidence_collector, G4ProviderCollector):
                    self._send_json(200, {"schema": PROVIDER_EVIDENCE_SCHEMA, "evidence": collected})
                    return
            if isinstance(collected, Evidence):
                evidences = (collected,)
            elif isinstance(collected, (tuple, list)) and all(
                isinstance(item, Evidence) for item in collected
            ):
                evidences = tuple(collected)
            else:
                self._send_json(500, {"error": "evidence collection failed"})
                return
            if (
                not 1 <= len(evidences) <= MAX_EVIDENCE_COMPONENTS
                or any(
                    evidence.nonce != nonce
                    or evidence.miner_hotkey != configured_hotkey
                    or not _evidence_fits_transport(evidence)
                    for evidence in evidences
                )
                or (
                    len(evidences) == 2
                    and {evidence.kind for evidence in evidences}
                    != {EvidenceKind.TDX, EvidenceKind.GPU_CC}
                )
            ):
                self._send_json(500, {"error": "evidence collection failed"})
                return

            response_items: list[dict[str, object]] = []
            for evidence in evidences:
                item: dict[str, object] = {
                    "kind": evidence.kind.value,
                    "quote_hex": evidence.quote.hex(),
                    "nonce_hex": nonce.hex(),
                    "assigned_hotkey": configured_hotkey,
                    "cert_chain_hex": [cert.hex() for cert in evidence.cert_chain],
                }
                response_items.append(item)
            if report_data_version == 2:
                if any(
                    evidence.report_data_version != 2
                    or evidence.channel_binding != configured_channel_binding
                    for evidence in evidences
                ):
                    self._send_json(500, {"error": "evidence collection failed"})
                    return
                assert configured_channel_binding is not None
                for evidence, item in zip(evidences, response_items, strict=True):
                    item.update({
                        "report_data_version": 2,
                        "channel_binding_type": configured_channel_binding.binding_type.value,
                        "channel_binding_digest_hex": configured_channel_binding.digest.hex(),
                    })
                    if len(evidences) > 1:
                        item["composite_jwt"] = evidence.composite_jwt
            if gpu:
                from cathedral.gpu_work import EVIDENCE_SCHEMA, serialize_composite
                try:
                    response_items = serialize_composite(
                        evidences, nonce, configured_hotkey, configured_channel_binding
                    )
                except ValueError:
                    self._send_json(503, {"error": "GPU composite evidence unavailable"})
                    return
                self._send_json(200, {"schema": EVIDENCE_SCHEMA, "evidence": response_items})
            elif len(response_items) == 1:
                self._send_json(200, response_items[0])
            else:
                self._send_json(200, {"evidence": response_items})

        def _handle_gpu_work(self, body: dict[str, object]) -> None:
            from cathedral.gpu_work import (
                RESULT_SCHEMA, completion_nonce, request_digest, serialize_composite,
                validate_request,
            )
            try:
                validate_request(body)
            except ValueError:
                self._send_json(400, {"error": "invalid GPU work request"})
                return
            if body["assigned_hotkey"] != configured_hotkey:
                self._send_json(403, {"error": "assigned_hotkey mismatch"})
                return
            try:
                from cathedral.gpu_provider import G4ProviderCollector
                if isinstance(gpu_evidence_collector, G4ProviderCollector):
                    output_digest, completion = gpu_evidence_collector.execute(gpu_executor, body)
                else:
                    output_digest = gpu_executor.execute(body)
                    nonce = completion_nonce(body, output_digest)
                    evidence = gpu_evidence_collector(
                        nonce, configured_hotkey, channel_binding=configured_channel_binding,
                        report_data_version=2,
                    )
                    completion = serialize_composite(
                        evidence, nonce, configured_hotkey, configured_channel_binding
                    )
            except Exception:
                self._send_json(503, {"error": "GPU execution or completion unavailable"})
                return
            self._send_json(200, {"schema": RESULT_SCHEMA,
                                 "request_digest": request_digest(body),
                                 "output_digest": output_digest,
                                 "device_identity_digests": body["device_identity_digests"],
                                 "completion_evidence": completion})

        def _handle_sat_work(self, body: dict[str, object]) -> None:
            if set(body) != _SAT_REQUEST_KEYS:
                self._send_json(400, {"error": "invalid SAT schema"})
                return
            challenge_id = body["challenge_id"]
            hotkey = body["assigned_hotkey"]
            instance_raw = body["instance"]
            seed = body["seed"]

            if not isinstance(hotkey, str) or not hotkey or len(hotkey) > MAX_HOTKEY_LENGTH:
                self._send_json(400, {"error": "invalid assigned_hotkey"})
                return
            if hotkey != configured_hotkey:
                self._send_json(403, {"error": "assigned_hotkey mismatch"})
                return
            if not isinstance(challenge_id, str) or _SHA256_RE.fullmatch(challenge_id) is None:
                self._send_json(400, {"error": "invalid challenge_id"})
                return
            if (
                isinstance(seed, bool)
                or not isinstance(seed, int)
                or not MIN_SEED <= seed <= MAX_SEED
            ):
                self._send_json(400, {"error": "invalid seed"})
                return
            instance = _parse_instance(instance_raw)
            if instance is None:
                self._send_json(400, {"error": "invalid instance"})
                return
            canonical = instance == _canonical_instance(seed)
            # Explicit migration may let canonical SAT through without
            # credentials. Anything else is customer work and must present the
            # bearer before a solver is entered.
            if not canonical and (
                (validator_authorizer is not None and bearer_token is None)
                or not self._check_auth()
            ):
                self._send_json(401, {"error": "unauthorized"})
                return
            if not allow_noncanonical_sat and not canonical:
                self._send_json(400, {"error": "noncanonical SAT instance"})
                return
            if _compute_challenge_id(instance, seed) != challenge_id:
                self._send_json(400, {"error": "challenge_id mismatch"})
                return

            if canonical:
                assignment = solve_sat(instance)
            else:
                completed, assignment = _solve_customer_sat_bounded(
                    instance,
                    request_timeout,
                )
                if not completed:
                    self._send_json(503, {"error": "customer SAT solve exceeded resource limits"})
                    return
            self._send_json(
                200,
                {
                    "satisfiable": assignment is not None,
                    "assignment": assignment,
                    "work_units": derived_work_units_for(instance, seed),
                    "challenge_id": challenge_id,
                    "assigned_hotkey": configured_hotkey,
                },
            )

    return _Handler


def _parse_instance(raw: object) -> SatInstance | None:
    if not isinstance(raw, dict) or set(raw) != _INSTANCE_KEYS:
        return None
    n_vars = raw["n_vars"]
    clauses = raw["clauses"]
    instance = SatInstance(n_vars=n_vars, clauses=clauses)
    try:
        validate_sat_instance(instance)
    except ValueError:
        return None
    return instance


def _shutdown_transport(request: socket.socket) -> None:
    """Shut the underlying TCP socket down from another thread.

    ``SSLSocket.shutdown`` also drops its TLS object, which races a handler
    thread mid-read and makes it raise instead of seeing EOF; the plain socket
    call wakes that read with EOF and leaves the TLS object to its owner.
    """
    try:
        socket.socket.shutdown(request, socket.SHUT_RDWR)
    except OSError:
        pass


class _Connection:
    """One accepted connection's place at the server-level gate."""

    __slots__ = ("request", "accepted_at", "protected", "owns_permit", "closed")

    def __init__(self, request: socket.socket, accepted_at: float) -> None:
        self.request = request
        self.accepted_at = accepted_at
        # Set once the handler has parsed a request line and headers. Until then
        # the connection has shown nothing, and it may be evicted.
        self.protected = False
        self.owns_permit = True
        # Set under the server's _active_lock just before the socket is closed.
        # Another thread may shut the socket down only while holding that lock
        # and seeing this False, so it never touches a descriptor that has been
        # closed and possibly reused.
        self.closed = False


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Hand out at most ``max_connection_concurrent`` connection permits, and
    never let idle connections lock out real requests.

    The handler's semaphores reserve execution capacity by request class. This
    earlier gate covers the part before a handler knows the path: the TLS
    handshake and the headers. When every permit is taken, a new connection
    evicts the oldest connection that has not yet produced a parsed request,
    and takes over its permit. Permits stay strict; evicted threads exit on
    their next read, so until then live handler threads and
    ``active_connection_count`` can briefly exceed the permit count. A connection
    becomes protected as soon as its headers parse, so an honest client, which
    sends its headers within one round trip, is not evicted by idle sockets,
    while an attacker's idle sockets are the first to go (review finding W1).
    Only when every permit belongs to a protected connection is a new one
    closed, without a thread or an HTTP response: the server has not parsed
    HTTP, and a nonblocking write is not portable while the peer is still
    sending or a TLS handshake is pending.
    """

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[BaseHTTPRequestHandler],
        *,
        max_connection_concurrent: int,
    ) -> None:
        self._connection_slots = threading.BoundedSemaphore(max_connection_concurrent)
        self._active_lock = threading.Lock()
        self._active_requests: dict[socket.socket, _Connection] = {}
        self.evicted_connection_count = 0
        super().__init__(server_address, request_handler)

    @property
    def active_connection_count(self) -> int:
        with self._active_lock:
            return len(self._active_requests)

    def protect_connection(self, request: socket.socket) -> None:
        """Called by the handler once a request line and headers have parsed."""

        with self._active_lock:
            record = self._active_requests.get(request)
            if record is not None:
                record.protected = True

    def _evict_oldest_unprotected(self, newcomer: _Connection) -> bool:
        """Hand the oldest unprotected connection's permit to ``newcomer``."""

        with self._active_lock:
            idle = [
                record
                for record in self._active_requests.values()
                if not record.protected and record.owns_permit
            ]
            if not idle:
                return False
            victim = min(idle, key=lambda record: record.accepted_at)
            victim.owns_permit = False
            newcomer.owns_permit = True
            self._active_requests[newcomer.request] = newcomer
            self.evicted_connection_count += 1
            # The victim's thread fails its next read and exits without
            # releasing the permit it no longer owns. Under the lock, and only
            # while its record is open: its thread marks the record closed under
            # this lock before closing the socket (shutdown_request), so the
            # descriptor cannot have been closed and reused by now.
            if not victim.closed:
                _shutdown_transport(victim.request)
        return True

    def process_request(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        record = _Connection(request, time.monotonic())
        if self._connection_slots.acquire(blocking=False):
            with self._active_lock:
                self._active_requests[request] = record
        elif not self._evict_oldest_unprotected(record):
            # Every permit belongs to a connection that has shown a request.
            # Keep the accept loop nonblocking and the permits strict.
            self.shutdown_request(request)
            return

        try:
            super().process_request(request, client_address)
        except BaseException:
            self._forget(record)
            raise

    def process_request_thread(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        with self._active_lock:
            record = self._active_requests.get(request)
        try:
            super().process_request_thread(request, client_address)
        finally:
            if record is not None:
                self._forget(record)

    def shutdown_request(self, request: socket.socket) -> None:
        with self._active_lock:
            record = self._active_requests.get(request)
            if record is not None:
                record.closed = True
        super().shutdown_request(request)

    def _forget(self, record: _Connection) -> None:
        with self._active_lock:
            if self._active_requests.get(record.request) is record:
                del self._active_requests[record.request]
            release = record.owns_permit
            record.owns_permit = False
        if release:
            self._connection_slots.release()

    def server_close(self) -> None:
        # ThreadingHTTPServer uses daemon handler threads, so its default close
        # leaves a partial-body read alive until the request timeout. Closing
        # each tracked socket makes shutdown a cancellation boundary and frees
        # every connection permit promptly.
        with self._active_lock:
            for record in self._active_requests.values():
                if not record.closed:
                    _shutdown_transport(record.request)
        super().server_close()


def _install_tls_accept(server: ThreadingHTTPServer, tls_context: "ssl.SSLContext",
                        handshake_timeout: float) -> None:
    """Do the TLS handshake in the WORKER thread, never in the accept loop.

    Wrapping the LISTENING socket (`server.socket = ctx.wrap_socket(...)`) makes
    `socket.accept()` perform the handshake, because `do_handshake_on_connect`
    defaults to True. `serve_forever` is single-threaded up to that point, and the
    listening socket has no timeout, so the accepted socket inherits None: one peer
    that completes the TCP handshake and then sends nothing blocks every subsequent
    request indefinitely, and ThreadingHTTPServer never gets to spawn a thread.

    Measured trigger (#86): zero bytes, or a truncated ClientHello followed by
    silence. A connect-then-close scan and a plaintext GET to the TLS port do NOT
    wedge it -- the peer has to hold the connection open. So a network partition or
    a client killed between connect() and ClientHello does it, no attacker needed.

    Every bound the worker advertises -- MAX_CONCURRENT, the body cap, the deadline
    reader/writer, connection.settimeout -- lives in the handler and was never
    reached. This is the accept-path twin of #65, whose fix hardened the handler
    path only.

    So: accept plain, set a deadline on the accepted socket, and wrap with
    do_handshake_on_connect=False. The handshake then happens on the first read,
    which is inside the per-connection worker thread and under that deadline.
    """
    plain_accept = server.get_request

    def get_request():  # type: ignore[no-untyped-def]
        conn, addr = plain_accept()
        try:
            # Bounds the handshake itself. Without this the wrapped socket
            # inherits the listener's None timeout and can block forever.
            conn.settimeout(handshake_timeout)
            tls_conn = tls_context.wrap_socket(
                conn, server_side=True, do_handshake_on_connect=False
            )
        except OSError:
            try:
                conn.close()
            finally:
                raise
        return tls_conn, addr

    server.get_request = get_request  # type: ignore[method-assign]


class WorkerServer:
    """Expose one miner identity over bounded HTTP or native TLS.

    Plain HTTP production deployments must keep this server on loopback behind
    an HTTPS terminator. Native TLS may bind a non-loopback address. SAT work is
    restricted to deterministic ``SatLane`` canonical backfill by default.
    Customer-submitted SAT is an explicit authenticated deployment mode.

    Public migration and development-no-auth ``/v1/evidence`` and canonical
    ``/v1/sat-work`` run on their own pools. Verified validator requests have
    another reserved pool after headers are parsed and authenticated, so the
    explicit public migration bridge cannot consume signed request-class
    capacity. A POST carrying the configured bearer uses the work pool.
    Noncanonical SAT still requires that bearer before any solver runs. A
    shared final gate caps every connection before a request handler thread
    starts, and each request-class gate is acquired before its body is read.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        configured_hotkey: str,
        bearer_token: str | None = None,
        evidence_collector: Callable[
            ..., Evidence | tuple[Evidence, ...] | list[Evidence]
        ]
        | None = None,
        channel_binding: ChannelBinding | None = None,
        tls_context: ssl.SSLContext | None = None,
        max_body: int = MAX_REQUEST_BODY,
        max_concurrent: int = MAX_CONCURRENT,
        max_challenge_concurrent: int = MAX_CHALLENGE_CONCURRENT,
        max_sat_challenge_concurrent: int = MAX_SAT_CHALLENGE_CONCURRENT,
        max_connection_concurrent: int | None = None,
        max_response_body: int = MAX_RESPONSE_BODY,
        timeout: float = 10.0,
        allow_noncanonical_sat: bool = False,
        allow_non_loopback_for_development: bool = False,
        validator_authorizer: ValidatorRequestAuthorizer | None = None,
        fleet_endpoints: tuple[str, ...] | FleetManifest | None = None,
        allow_public_bootstrap_evidence: bool = False,
        allow_public_legacy_audit: bool = False,
        validator_max_concurrent: int = 1,
        validator_requests_per_window: int = 120,
        validator_rate_window_seconds: float = 60.0,
        max_validator_challenge_concurrent: int = MAX_VALIDATOR_CHALLENGE_CONCURRENT,
        gpu_executor=None,
        gpu_evidence_collector=None,
        central_authorizer: CentralAccessAuthorizer | None = None,
        max_central_concurrent: int = MAX_CENTRAL_CONCURRENT,
        central_requests_per_window: int = 60,
        central_rate_window_seconds: float = 60.0,
    ) -> None:
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not isinstance(allow_non_loopback_for_development, bool):
            raise ValueError("allow_non_loopback_for_development must be a boolean")
        if (
            not loopback
            and tls_context is None
            and not allow_non_loopback_for_development
        ):
            raise ValueError("plain worker HTTP must bind a loopback address")
        if (
            not isinstance(configured_hotkey, str)
            or not configured_hotkey
            or len(configured_hotkey) > MAX_HOTKEY_LENGTH
        ):
            raise ValueError("configured_hotkey must be a non-empty bounded string")
        if bearer_token is not None and (
            not isinstance(bearer_token, str)
            or not bearer_token
            or len(bearer_token) > MAX_BEARER_TOKEN_LENGTH
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in bearer_token)
        ):
            raise ValueError("bearer_token must be a nonempty bounded ASCII string")
        for name, value in (
            ("max_body", max_body),
            ("max_concurrent", max_concurrent),
            ("max_challenge_concurrent", max_challenge_concurrent),
            ("max_sat_challenge_concurrent", max_sat_challenge_concurrent),
            (
                "max_validator_challenge_concurrent",
                max_validator_challenge_concurrent,
            ),
            ("max_response_body", max_response_body),
            ("max_central_concurrent", max_central_concurrent),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        validator_class_capacity = (
            max_validator_challenge_concurrent
            if validator_authorizer is not None
            else 0
        ) + (max_central_concurrent if central_authorizer is not None else 0)
        if max_connection_concurrent is None:
            max_connection_concurrent = (
                max_concurrent
                + max_challenge_concurrent
                + max_sat_challenge_concurrent
                + validator_class_capacity
                + PREAUTH_CONNECTION_HEADROOM
            )
        if (
            isinstance(max_connection_concurrent, bool)
            or not isinstance(max_connection_concurrent, int)
            or max_connection_concurrent <= 0
        ):
            raise ValueError("max_connection_concurrent must be a positive integer")
        class_capacity = (
            max_concurrent
            + max_challenge_concurrent
            + max_sat_challenge_concurrent
            + validator_class_capacity
        )
        if max_connection_concurrent < class_capacity:
            raise ValueError("max_connection_concurrent must cover all request-class capacity")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number")
        if not isinstance(allow_noncanonical_sat, bool):
            raise ValueError("allow_noncanonical_sat must be a boolean")
        if channel_binding is not None and not isinstance(
            channel_binding, ChannelBinding
        ):
            raise ValueError("channel_binding must be a ChannelBinding")
        if allow_noncanonical_sat and (bearer_token is None or channel_binding is None):
            raise ValueError(
                "customer SAT requires bearer authentication and a configured channel binding"
            )
        if allow_noncanonical_sat and allow_non_loopback_for_development:
            raise ValueError("customer SAT cannot use the development non-loopback HTTP bind")
        if tls_context is not None and not isinstance(tls_context, ssl.SSLContext):
            raise ValueError("tls_context must be an SSLContext")
        if tls_context is not None and channel_binding is None:
            raise ValueError("TLS worker requires its configured channel binding")
        if not isinstance(allow_public_bootstrap_evidence, bool):
            raise ValueError("allow_public_bootstrap_evidence must be a boolean")
        if not isinstance(allow_public_legacy_audit, bool):
            raise ValueError("allow_public_legacy_audit must be a boolean")
        if validator_authorizer is None:
            if gpu_executor is not None or gpu_evidence_collector is not None:
                raise ValueError("GPU service requires signed validator access and native TLS")
            if fleet_endpoints is not None:
                raise ValueError("fleet discovery requires signed validator access")
            if allow_public_bootstrap_evidence:
                raise ValueError("public bootstrap compatibility requires signed validator access")
            if allow_public_legacy_audit:
                raise ValueError(
                    "public legacy audit compatibility requires signed validator access"
                )
        else:
            if not isinstance(validator_authorizer, ValidatorRequestAuthorizer):
                raise ValueError("validator_authorizer must be a ValidatorRequestAuthorizer")
            if tls_context is None:
                raise ValueError("signed validator access requires native worker TLS")
            if channel_binding is None or validator_authorizer.channel_binding != channel_binding:
                raise ValueError("validator access must bind the worker TLS key")
            if validator_authorizer.worker_hotkey != configured_hotkey:
                raise ValueError("validator access must bind the configured worker hotkey")
            if isinstance(fleet_endpoints, FleetManifest):
                if fleet_endpoints.worker_hotkey != configured_hotkey:
                    raise ValueError("fleet manifest must bind the configured worker hotkey")
            elif (
                not isinstance(fleet_endpoints, tuple)
                or not fleet_endpoints
                or any(not isinstance(endpoint, str) for endpoint in fleet_endpoints)
            ):
                raise ValueError("signed validator access requires bounded fleet candidates")
        if central_authorizer is not None:
            if not isinstance(central_authorizer, CentralAccessAuthorizer):
                raise ValueError("central_authorizer must be a CentralAccessAuthorizer")
            if validator_authorizer is None or tls_context is None:
                raise ValueError("central access requires signed validator access and native TLS")
            if central_authorizer.channel_binding != channel_binding:
                raise ValueError("central access must bind the worker TLS key")
            if central_authorizer.worker_hotkey != configured_hotkey:
                raise ValueError("central access must bind the configured worker hotkey")
        if (gpu_executor is None) != (gpu_evidence_collector is None):
            raise ValueError("GPU execution and composite collector are required together")
        if gpu_executor is not None:
            from cathedral.gpu_work import CudaWorkExecutor, G4_WORKER_PROFILE_ID
            from cathedral.gpu_provider import G4ProviderCollector
            if not isinstance(gpu_executor, CudaWorkExecutor) or not callable(gpu_evidence_collector):
                raise ValueError("GPU service requires the fixed CUDA executor and collector")
            if ((gpu_executor.profile_id == G4_WORKER_PROFILE_ID)
                    != isinstance(gpu_evidence_collector, G4ProviderCollector)):
                raise ValueError("G4 requires its distinct provider collector")

        semaphore = _Semaphore(max_concurrent)
        challenge_semaphore = _Semaphore(max_challenge_concurrent)
        sat_challenge_semaphore = _Semaphore(max_sat_challenge_concurrent)
        validator_pool = _ValidatorPool(max_validator_challenge_concurrent)
        self._validator_pool = validator_pool
        if isinstance(fleet_endpoints, FleetManifest):
            fleet_source = fleet_endpoints.endpoints
        elif fleet_endpoints is not None:
            static_fleet = fleet_endpoints
            fleet_source = lambda: static_fleet  # noqa: E731
        else:
            fleet_source = None
        validator_request_limiter = (
            None
            if validator_authorizer is None
            else ValidatorRequestLimiter(
                max_concurrent=validator_max_concurrent,
                requests_per_window=validator_requests_per_window,
                window_seconds=validator_rate_window_seconds,
            )
        )
        handler = _make_handler(
            semaphore,
            challenge_semaphore,
            sat_challenge_semaphore,
            validator_pool,
            configured_hotkey,
            bearer_token,
            evidence_collector or collect_tdx,
            channel_binding,
            max_body,
            max_response_body,
            float(timeout),
            allow_noncanonical_sat,
            validator_authorizer,
            fleet_source,
            allow_public_bootstrap_evidence,
            allow_public_legacy_audit,
            validator_request_limiter,
            gpu_executor,
            gpu_evidence_collector,
            central_authorizer,
            None
            if central_authorizer is None
            else CentralRequestLimiter(
                requests_per_window=central_requests_per_window,
                window_seconds=central_rate_window_seconds,
            ),
            None if central_authorizer is None else _Semaphore(max_central_concurrent),
        )
        self._server = _BoundedThreadingHTTPServer(
            (host, port),
            handler,
            max_connection_concurrent=max_connection_concurrent,
        )
        self._tls_enabled = tls_context is not None
        if tls_context is not None:
            _install_tls_accept(self._server, tls_context, float(timeout))

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def base_url(self) -> str:
        scheme = "https" if self._tls_enabled else "http"
        return f"{scheme}://{self.host}:{self.port}"

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "WorkerServer":
        return self

    def __exit__(self, *_: object) -> None:
        self.shutdown()
