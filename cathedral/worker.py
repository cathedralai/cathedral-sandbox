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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from cathedral.attest import collect_tdx
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
    solve_sat,
    validate_sat_instance,
)
from cathedral.lanes.sat_types import SatInstance
from cathedral.validator_access import (
    PreauthorizedValidatorRequest,
    VALIDATOR_REQUEST_HEADER,
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
    {"/v1/evidence", "/v1/capabilities", "/v1/sat-work", "/v1/fleet"}
)
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


def _make_handler(
    semaphore: threading.Semaphore,
    challenge_semaphore: threading.Semaphore,
    sat_challenge_semaphore: threading.Semaphore,
    validator_challenge_semaphore: threading.Semaphore,
    configured_hotkey: str,
    bearer_token: str | None,
    evidence_collector: Callable[..., Evidence | tuple[Evidence, ...] | list[Evidence]],
    configured_channel_binding: ChannelBinding | None,
    max_body: int,
    max_response_body: int,
    request_timeout: float,
    allow_noncanonical_sat: bool,
    validator_authorizer: ValidatorRequestAuthorizer | None,
    fleet_endpoints: tuple[str, ...] | None,
    allow_public_bootstrap_evidence: bool,
    allow_public_legacy_audit: bool,
    validator_request_limiter: ValidatorRequestLimiter | None,
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
            if path == "/v1/fleet" and validator_authorizer is None:
                self._send_json(404, {"error": "fleet discovery unavailable"})
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
            signed_only = path == "/v1/fleet"
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
                if preauthorized_validator is not None:
                    # Signed validator control traffic has reserved
                    # request-class capacity after headers are parsed and the
                    # envelope is authenticated. The earlier connection gate
                    # is shared by every TLS client and must be protected at
                    # the network edge in a production deployment.
                    pool = validator_challenge_semaphore
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
                if not pool.acquire(blocking=False):
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
                    if preauthorized_validator is not None:
                        assert validator_authorizer is not None
                        if (
                            validator_authorizer.finalize(
                                preauthorized_validator,
                                body=raw,
                            )
                            is None
                        ):
                            self._send_json(401, {"error": "unauthorized"})
                            return
                    self._handle_post(raw)
                finally:
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
                    self._send_json(200, fleet_response(configured_hotkey, fleet_endpoints))
            else:
                self._send_json(404, {"error": "not found"})

        def _handle_evidence(self, body: dict[str, object]) -> None:
            keys = frozenset(body)
            if keys not in {_EVIDENCE_REQUEST_KEYS, _EVIDENCE_V2_REQUEST_KEYS}:
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
                    collected = evidence_collector(
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
            if len(response_items) == 1:
                self._send_json(200, response_items[0])
            else:
                self._send_json(200, {"evidence": response_items})

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
                    "work_units": float(len(instance.clauses)),
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


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Start at most ``max_connection_concurrent`` request threads.

    The handler's three semaphores reserve execution capacity by request
    class. This earlier gate covers the part before a handler knows the path,
    including a client that never finishes its headers. A refused connection
    is closed without starting a thread or attempting an HTTP response. At
    this point the server has not parsed HTTP, and a nonblocking write is not
    portable when the peer is still sending or a TLS handshake is pending.
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
        self._active_requests: set[socket.socket] = set()
        super().__init__(server_address, request_handler)

    @property
    def active_connection_count(self) -> int:
        with self._active_lock:
            return len(self._active_requests)

    def process_request(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        if not self._connection_slots.acquire(blocking=False):
            # Keep the accept loop nonblocking and the thread ceiling strict.
            # HTTP status belongs to the later class-pool gates, after a
            # handler has parsed enough of the request to send one reliably.
            self.shutdown_request(request)
            return

        with self._active_lock:
            self._active_requests.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._active_lock:
                self._active_requests.discard(request)
            self._connection_slots.release()
            raise

    def process_request_thread(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active_requests.discard(request)
            self._connection_slots.release()

    def server_close(self) -> None:
        # ThreadingHTTPServer uses daemon handler threads, so its default close
        # leaves a partial-body read alive until the request timeout. Closing
        # each tracked socket makes shutdown a cancellation boundary and frees
        # every connection permit promptly.
        with self._active_lock:
            active_requests = tuple(self._active_requests)
        for request in active_requests:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
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
        fleet_endpoints: tuple[str, ...] | None = None,
        allow_public_bootstrap_evidence: bool = False,
        allow_public_legacy_audit: bool = False,
        validator_max_concurrent: int = 1,
        validator_requests_per_window: int = 120,
        validator_rate_window_seconds: float = 60.0,
        max_validator_challenge_concurrent: int = MAX_VALIDATOR_CHALLENGE_CONCURRENT,
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
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        validator_class_capacity = (
            max_validator_challenge_concurrent
            if validator_authorizer is not None
            else 0
        )
        if max_connection_concurrent is None:
            max_connection_concurrent = (
                max_concurrent
                + max_challenge_concurrent
                + max_sat_challenge_concurrent
                + validator_class_capacity
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
            if (
                not isinstance(fleet_endpoints, tuple)
                or not fleet_endpoints
                or any(not isinstance(endpoint, str) for endpoint in fleet_endpoints)
            ):
                raise ValueError("signed validator access requires bounded fleet candidates")

        semaphore = _Semaphore(max_concurrent)
        challenge_semaphore = _Semaphore(max_challenge_concurrent)
        sat_challenge_semaphore = _Semaphore(max_sat_challenge_concurrent)
        validator_challenge_semaphore = _Semaphore(
            max_validator_challenge_concurrent
        )
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
            validator_challenge_semaphore,
            configured_hotkey,
            bearer_token,
            evidence_collector or collect_tdx,
            channel_binding,
            max_body,
            max_response_body,
            float(timeout),
            allow_noncanonical_sat,
            validator_authorizer,
            fleet_endpoints,
            allow_public_bootstrap_evidence,
            allow_public_legacy_audit,
            validator_request_limiter,
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
