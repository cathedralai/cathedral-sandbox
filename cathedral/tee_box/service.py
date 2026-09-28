"""The v1 TEE box sandbox API, served on the worker's attested TLS listener.

The worker authenticates each call with a control-plane caller key before
``TeeBoxSandboxApi.handle`` runs. Caller keys arrive as a signed snapshot in
the validator-access format, under the network label ``TEE_BOX_CALLER_NETWORK``
so that neither kind of snapshot can stand in for the other. Requests use the
validator request envelope, restricted to the routes below.

v1 serves create, exec (sync and background), files, list, get, lifetime,
delete and image import by digest. It has no snapshots, fork, ports or
Docker-in-Docker (owner decision 5).
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import parse_qsl

from cathedral.common import ChannelBinding
from cathedral.tee_box.egress import EgressPolicy
from cathedral.tee_box.executor import (
    MAX_FILE_BYTES,
    MAX_OUTPUT_BYTES,
    ExecRequest,
    ExecResult,
    ExecStatus,
    Executor,
    ExecutorError,
    ExecutorRefused,
    NotFound,
    SandboxInfo,
    SandboxSpec,
    Shape,
    TooLarge,
)
from cathedral.tee_box.lease import (
    DEFAULT_MAX_LEASE_SECONDS,
    CustomerLease,
    LeaseBusy,
    LeaseDraining,
    LeaseRequired,
)
from cathedral.validator_access import (
    SignatureVerifier,
    SignedValidatorSnapshotProvider,
    ValidatorAccessState,
    ValidatorRequestAuthorizer,
)

TEE_BOX_API_SCHEMA = "cathedral_tee_box_v1"
TEE_BOX_CALLER_NETWORK = "cathedral-control-plane"
HARDWARE_CLASS = "standard"
ISOLATION = "gvisor-runsc-systrap"
MAX_EXEC_TIMEOUT_SECONDS = 14_400
MAX_SYNC_EXEC_SECONDS = 45
MAX_POLL_WAIT_SECONDS = 25
MIN_LIFETIME_SECONDS = 60
MAX_LIFETIME_SECONDS = 24 * 3600
MAX_SANDBOXES = 64
MAX_TARGET_LENGTH = 4096 + 256
MAX_REQUEST_BODY = MAX_FILE_BYTES
MAX_RESPONSE_BODY = 2 * MAX_FILE_BYTES
MAX_COMMAND_BYTES = 64 * 1024
MAX_ENV_ENTRIES = 128
MAX_LABELS = 32
MAX_EXCLUDES = 64

_SANDBOX_ID = r"sbx-[0-9a-f]{24}"
_EXEC_ID = r"exec-[0-9a-f]{16}"
_DIGEST = r"sha256:[0-9a-f]{64}"
_ROUTES: tuple[tuple[str, re.Pattern[str], str], ...] = tuple(
    (method, re.compile(pattern), name)
    for method, pattern, name in (
        ("GET", r"/v1/box", "box"),
        ("GET", r"/v1/lease", "lease_get"),
        ("POST", r"/v1/lease", "lease_acquire"),
        ("DELETE", r"/v1/lease", "lease_release"),
        ("POST", r"/v1/images/import", "image_import"),
        ("GET", rf"/v1/images/(?P<digest>{_DIGEST})", "image_get"),
        ("GET", r"/v1/sandboxes", "list"),
        ("POST", r"/v1/sandboxes", "create"),
        ("GET", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})", "get"),
        ("DELETE", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})", "delete"),
        ("POST", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/lifetime", "lifetime"),
        ("POST", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/exec", "exec"),
        ("POST", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/(?:execs|processes)", "exec_start"),
        (
            "GET",
            rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/(?:execs|processes)/(?P<eid>{_EXEC_ID})",
            "exec_poll",
        ),
        (
            "DELETE",
            rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/(?:execs|processes)/(?P<eid>{_EXEC_ID})",
            "exec_stop",
        ),
        ("GET", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/files", "file_get"),
        ("PUT", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/files", "file_put"),
        ("GET", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/tar", "tar_get"),
        ("PUT", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/tar", "tar_put"),
        ("GET", rf"/v1/sandboxes/(?P<sid>{_SANDBOX_ID})/stat", "stat"),
    )
)
_PREFIXES = ("/v1/box", "/v1/lease", "/v1/images", "/v1/sandboxes")
_NO_LEASE_ROUTES = frozenset({"box", "lease_get", "lease_acquire", "lease_release"})
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_LABEL_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,31})?$")
_REFERENCE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(?::[0-9]{1,5})?(?:/[a-z0-9][a-z0-9._-]*)+$")
_DIGEST_RE = re.compile(rf"^{_DIGEST}$")


def owns_path(path: str) -> bool:
    """True for every path in the sandbox API namespace, known route or not."""

    return any(path == prefix or path.startswith(prefix + "/") for prefix in _PREFIXES)


def _match(method: str, path: str) -> tuple[str, dict[str, str]] | None:
    for route_method, pattern, name in _ROUTES:
        found = pattern.fullmatch(path)
        if found is not None and route_method == method:
            return name, found.groupdict()
    return None


def sandbox_target_allowed(method: str, target: str) -> bool:
    """The request targets a signed envelope may name for the sandbox API.

    ``target`` is the full request target, path and query, so the caller's
    signature covers the file path and every other query parameter.
    """

    if (
        not isinstance(method, str)
        or not isinstance(target, str)
        or not 0 < len(target) <= MAX_TARGET_LENGTH
        or not target.isascii()
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in target)
        or "#" in target
    ):
        return False
    return _match(method, target.partition("?")[0]) is not None


def caller_snapshot_provider(
    path: str,
    trusted_keys: Mapping[str, bytes],
    *,
    netuid: int,
    state: ValidatorAccessState,
    max_age_seconds: int = 3600,
) -> SignedValidatorSnapshotProvider:
    """Load the signed control-plane caller snapshot with the validator machinery.

    The document is a ``cathedral_validator_access_snapshot_v1`` whose rows
    are the control-plane hotkeys (permit true, stake 0) under the network
    label ``cathedral-control-plane`` and a zero stake floor.
    """

    return SignedValidatorSnapshotProvider(
        path,
        trusted_keys,
        network=TEE_BOX_CALLER_NETWORK,
        netuid=netuid,
        minimum_stake_rao=0,
        state=state,
        max_age_seconds=max_age_seconds,
    )


def caller_authorizer(
    snapshot_provider,  # noqa: ANN001 - a validator snapshot provider or snapshot
    *,
    worker_hotkey: str,
    channel_binding: ChannelBinding,
    state: ValidatorAccessState,
    signature_verifier: SignatureVerifier | None = None,
) -> ValidatorRequestAuthorizer:
    """A request authorizer that accepts only sandbox API targets."""

    authorizer = ValidatorRequestAuthorizer(
        snapshot_provider,
        worker_hotkey=worker_hotkey,
        channel_binding=channel_binding,
        state=state,
        signature_verifier=signature_verifier,
        target_allowed=sandbox_target_allowed,
    )
    if authorizer.snapshot_provider.network != TEE_BOX_CALLER_NETWORK:
        raise ValueError("the caller snapshot must use the control-plane network label")
    return authorizer


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str = "application/json"


class _Refusal(Exception):
    def __init__(self, status: int, message: str, reason: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.reason = reason


def _json(status: int, document: Mapping[str, object]) -> Response:
    return Response(status, json.dumps(document, separators=(",", ":")).encode())


def _bad(message: str) -> _Refusal:
    return _Refusal(400, message)


def _int(value: object, low: int, high: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise _bad(f"{label} must be an integer from {low} to {high}")
    return value


def _decimal(value: str, label: str) -> int:
    """Parse a short ASCII decimal query value; anything else is a 400."""

    if not value.isascii() or not value.isdigit() or len(value) > 6:
        raise _bad(f"{label} must be a small decimal number")
    return int(value)


def _text(value: object, limit: int, label: str) -> str:
    if not isinstance(value, str) or len(value.encode()) > limit or "\x00" in value:
        raise _bad(f"{label} is invalid")
    return value


def _abs_path(value: object, label: str = "path") -> str:
    text = _text(value, 4096, label)
    if not text.startswith("/") or "\n" in text:
        raise _bad(f"{label} must be an absolute path")
    return text


def _env(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_ENV_ENTRIES:
        raise _bad("env must be an object of at most 128 entries")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or _ENV_KEY_RE.fullmatch(key) is None:
            raise _bad("env key is invalid")
        result[key] = _text(item, 16 * 1024, "env value")
    return result


def _labels(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_LABELS:
        raise _bad("labels must be an object of at most 32 entries")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or _LABEL_KEY_RE.fullmatch(key) is None:
            raise _bad("label key is invalid")
        result[key] = _text(item, 256, "label value")
    return result


def _body(raw: bytes, allowed: frozenset[str], required: frozenset[str]) -> dict[str, object]:
    try:
        document = json.loads(raw or b"{}")
    except (UnicodeDecodeError, ValueError) as exc:
        raise _bad("invalid JSON") from exc
    if not isinstance(document, dict):
        raise _bad("expected JSON object")
    keys = frozenset(document)
    if not keys <= allowed or not required <= keys:
        raise _bad("unexpected or missing fields")
    return document


def _exec_view(result: ExecResult) -> dict[str, object]:
    return {
        "exit_code": result.exit_code,
        "stdout": result.stdout.decode("utf-8", "replace"),
        "stderr": result.stderr.decode("utf-8", "replace"),
        "timed_out": result.timed_out,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
    }


def _status_view(status: ExecStatus) -> dict[str, object]:
    view: dict[str, object] = {"exec_id": status.exec_id, "state": status.state}
    if status.result is not None:
        view.update(_exec_view(status.result))
    return view


class TeeBoxSandboxApi:
    """Map the v1 sandbox routes onto one ``Executor`` for one customer at a time."""

    def __init__(
        self,
        *,
        executor: Executor,
        authorizer: ValidatorRequestAuthorizer,
        egress: EgressPolicy,
        capacity: Shape,
        default_shape: Shape,
        max_lease_seconds: int = DEFAULT_MAX_LEASE_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(authorizer, ValidatorRequestAuthorizer):
            raise ValueError("the sandbox API requires a caller authorizer")
        if authorizer.target_allowed is not sandbox_target_allowed:
            raise ValueError("the caller authorizer must accept only sandbox API targets")
        if authorizer.snapshot_provider.network != TEE_BOX_CALLER_NETWORK:
            raise ValueError("the caller snapshot must use the control-plane network label")
        if not isinstance(egress, EgressPolicy):
            raise ValueError("the sandbox API requires an egress policy")
        if not default_shape.fits_within(capacity):
            raise ValueError("the default shape must fit the box capacity")
        self.executor = executor
        self.authorizer = authorizer
        self.egress = egress
        self.capacity = capacity
        self.default_shape = default_shape
        self._clock = clock
        self.lease = CustomerLease(self._drain_owner, max_seconds=max_lease_seconds, clock=clock)

    # -- lifecycle helpers -----------------------------------------------

    def _drain_owner(self, owner: str) -> bool:
        """Delete ``owner``'s sandboxes; true only when none is left anywhere.

        Deletes that fail leave the sandbox listed, so the drain reports false
        and the lease stays draining. The executor sweep then removes any
        labelled container the table does not know (a create that timed out,
        or one left by an earlier worker process); a leftover of unknown
        owner also blocks the hand-over.
        """

        for info in self.executor.list():
            if info.spec.owner == owner:
                try:
                    self.executor.delete(info.sandbox_id)
                except ExecutorError:
                    pass
        if any(info.spec.owner == owner for info in self.executor.list()):
            return False
        try:
            return self.executor.sweep() == 0
        except ExecutorError:
            return False

    def sweep(self) -> None:
        """Remove labelled containers the executor does not track (reaper thread)."""

        try:
            self.executor.sweep()
        except ExecutorError:
            pass

    def reap(self) -> None:
        """Expire the lease, retry an unfinished drain, and end expired sandboxes."""

        self.lease.current()
        now = self._clock()
        for info in self.executor.list():
            if now >= info.spec.expires_at:
                try:
                    self.executor.delete(info.sandbox_id)
                except ExecutorError:
                    pass

    def _allocated(self) -> Shape:
        total = Shape(0, 0, 0)
        for info in self.executor.list():
            total = total.plus(info.spec.shape)
        return total

    def _owned(self, caller: str, sandbox_id: str) -> SandboxInfo:
        info = self.executor.get(sandbox_id)
        if info is None or info.spec.owner != caller:
            raise _Refusal(404, "sandbox not found")
        return info

    def _sandbox_view(self, info: SandboxInfo) -> dict[str, object]:
        spec = info.spec
        return {
            "id": spec.sandbox_id,
            "state": info.state,
            "hardware": HARDWARE_CLASS,
            "image_id": spec.image.digest,
            "network": spec.network,
            "shape": spec.shape.view(),
            "labels": dict(spec.labels),
            "created_at": int(info.created_at),
            "expires_at": int(spec.expires_at),
        }

    # -- dispatch --------------------------------------------------------

    def handle(self, method: str, target: str, caller: str, body: bytes) -> Response:
        """Answer one authenticated call. ``caller`` is the verified signer."""

        path, _, query = target.partition("?")
        matched = _match(method, path)
        if matched is None:
            return _json(404, {"error": "not found"})
        name, params = matched
        try:
            fields = parse_qsl(
                query,
                keep_blank_values=True,
                strict_parsing=bool(query),
                max_num_fields=MAX_EXCLUDES + 4,
            )
        except ValueError:
            return _json(400, {"error": "invalid query"})
        try:
            self.reap()
            if name not in _NO_LEASE_ROUTES:
                self.lease.require(caller)
            return getattr(self, "_" + name)(caller, body, fields, **params)
        except _Refusal as refusal:
            document: dict[str, object] = {"error": refusal.message}
            if refusal.reason is not None:
                document["reason"] = refusal.reason
            return _json(refusal.status, document)
        except LeaseBusy:
            return _json(
                409, {"error": "the box is leased to another customer", "reason": "box_busy"}
            )
        except LeaseRequired:
            return _json(409, {"error": "take the box lease first", "reason": "lease_required"})
        except LeaseDraining:
            return _json(
                409,
                {
                    "error": "the previous customer's sandboxes are still being removed",
                    "reason": "box_draining",
                },
            )
        except NotFound:
            return _json(404, {"error": "not found"})
        except TooLarge:
            return _json(413, {"error": "transfer exceeds the box limit"})
        except ExecutorRefused as exc:
            return _json(409, {"error": str(exc) or "refused", "reason": "executor_refused"})
        except ExecutorError as exc:
            if str(exc) == "tar_extract_failed":
                return _json(422, {"error": "tar extract failed", "code": "tar_extract_failed"})
            return _json(502, {"error": "executor failed"})

    @staticmethod
    def _query(fields: list[tuple[str, str]], allowed: frozenset[str]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for key, value in fields:
            if key not in allowed:
                raise _bad("unexpected query parameter")
            result.setdefault(key, []).append(value)
        return result

    @classmethod
    def _one(
        cls, fields: list[tuple[str, str]], key: str, allowed: frozenset[str] | None = None
    ) -> str:
        values = cls._query(fields, allowed or frozenset({key})).get(key, [])
        if len(values) != 1:
            raise _bad(f"exactly one {key} is required")
        return values[0]

    # -- box and lease ---------------------------------------------------

    def _box(self, caller, body, fields) -> Response:  # noqa: ANN001
        lease = self.lease.current()
        return _json(
            200,
            {
                "schema": TEE_BOX_API_SCHEMA,
                "hardware": HARDWARE_CLASS,
                "isolation": ISOLATION,
                "network_modes": list(self.executor.network_modes),
                "max_exec_timeout_seconds": MAX_EXEC_TIMEOUT_SECONDS,
                "max_sync_exec_seconds": MAX_SYNC_EXEC_SECONDS,
                "exec_output_limit_bytes": MAX_OUTPUT_BYTES,
                "max_file_bytes": MAX_FILE_BYTES,
                "max_lifetime_seconds": MAX_LIFETIME_SECONDS,
                "exec_options": ["env", "user", "cwd", "timeout_seconds"],
                "capacity": self.capacity.view(),
                "allocated": self._allocated().view(),
                "default_shape": self.default_shape.view(),
                "egress": self.egress.describe(),
                "lease": {
                    "held": lease is not None,
                    "held_by_caller": lease is not None and lease.holder == caller,
                    "expires_at": None if lease is None else int(lease.expires_at),
                    "draining": self.lease.draining,
                },
            },
        )

    def _lease_get(self, caller, body, fields) -> Response:  # noqa: ANN001
        lease = self.lease.current()
        if lease is None or lease.holder != caller:
            return _json(200, {"lease": None, "held": lease is not None})
        return _json(200, {"lease": lease.view(), "held": True})

    def _lease_acquire(self, caller, body, fields) -> Response:  # noqa: ANN001
        document = _body(body, frozenset({"ttl_seconds"}), frozenset({"ttl_seconds"}))
        ttl = _int(document["ttl_seconds"], 60, self.lease.max_seconds, "ttl_seconds")
        return _json(200, {"lease": self.lease.acquire(caller, ttl).view()})

    def _lease_release(self, caller, body, fields) -> Response:  # noqa: ANN001
        released = self.lease.release(caller)
        return _json(200, {"released": released, "draining": self.lease.draining})

    # -- images ----------------------------------------------------------

    def _image_import(self, caller, body, fields) -> Response:  # noqa: ANN001
        document = _body(
            body, frozenset({"digest", "reference"}), frozenset({"digest", "reference"})
        )
        digest = document["digest"]
        reference = document["reference"]
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise _bad("digest must be sha256:<64 hex>")
        if (
            not isinstance(reference, str)
            or len(reference) > 255
            or _REFERENCE_RE.fullmatch(reference) is None
        ):
            raise _bad("reference must be a registry repository without tag or digest")
        return _json(200, self.executor.import_image(digest, reference).view())

    def _image_get(self, caller, body, fields, digest: str) -> Response:  # noqa: ANN001
        image = self.executor.get_image(digest)
        if image is None:
            raise _Refusal(404, "image not imported")
        return _json(200, image.view())

    # -- sandboxes -------------------------------------------------------

    def _list(self, caller, body, fields) -> Response:  # noqa: ANN001
        wanted = []
        for value in self._query(fields, frozenset({"label"})).get("label", []):
            key, sep, item = value.partition("=")
            if not sep:
                raise _bad("label filter must be key=value")
            wanted.append((key, item))
        rows = [
            self._sandbox_view(info)
            for info in self.executor.list()
            if info.spec.owner == caller
            and all(info.spec.labels.get(key) == item for key, item in wanted)
        ]
        return _json(200, {"sandboxes": rows})

    def _create(self, caller, body, fields) -> Response:  # noqa: ANN001
        document = _body(
            body,
            frozenset({"image_id", "network", "lifetime_seconds", "shape", "labels", "env"}),
            frozenset({"image_id", "network", "lifetime_seconds"}),
        )
        network = document["network"]
        if network not in ("internet", "deny_all"):
            raise _bad("network must be internet or deny_all")
        if network not in self.executor.network_modes:
            raise _Refusal(409, "this box does not offer that network mode", "network_unavailable")
        lifetime = _int(
            document["lifetime_seconds"],
            MIN_LIFETIME_SECONDS,
            MAX_LIFETIME_SECONDS,
            "lifetime_seconds",
        )
        shape = self.default_shape
        if "shape" in document:
            raw = document["shape"]
            if not isinstance(raw, dict) or frozenset(raw) != {"vcpus", "memory_mib", "disk_mib"}:
                raise _bad("shape needs vcpus, memory_mib and disk_mib")
            shape = Shape(
                _int(raw["vcpus"], 1, 1024, "vcpus"),
                _int(raw["memory_mib"], 256, 4 * 1024 * 1024, "memory_mib"),
                _int(raw["disk_mib"], 256, 64 * 1024 * 1024, "disk_mib"),
            )
        image_id = document["image_id"]
        if not isinstance(image_id, str) or _DIGEST_RE.fullmatch(image_id) is None:
            raise _bad("image_id must be an imported sha256 digest")
        image = self.executor.get_image(image_id)
        if image is None:
            raise _Refusal(404, "image not imported")
        labels = _labels(document.get("labels"))
        env = _env(document.get("env"))
        # Hold the lease lock so a drain cannot miss this sandbox.
        with self.lease.locked():
            self.lease.require(caller)
            sandboxes = self.executor.list()
            if len(sandboxes) >= MAX_SANDBOXES or not self._allocated().plus(shape).fits_within(
                self.capacity
            ):
                raise _Refusal(409, "the box has no room for this shape", "box_capacity_full")
            spec = SandboxSpec(
                sandbox_id="sbx-" + secrets.token_hex(12),
                owner=caller,
                image=image,
                shape=shape,
                network=network,
                expires_at=self._clock() + lifetime,
                env=env,
                labels=labels,
            )
            info = self.executor.create(spec)
        return _json(201, self._sandbox_view(info))

    def _get(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        return _json(200, self._sandbox_view(self._owned(caller, sid)))

    def _delete(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        self.executor.delete(sid)
        return _json(200, {"id": sid, "deleted": True})

    def _lifetime(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        info = self._owned(caller, sid)
        document = _body(body, frozenset({"extend_by_seconds", "lifetime_seconds"}), frozenset())
        now = self._clock()
        if len(document) != 1:
            raise _bad("send exactly one of extend_by_seconds or lifetime_seconds")
        if "extend_by_seconds" in document:
            extend = _int(
                document["extend_by_seconds"], 1, MAX_LIFETIME_SECONDS, "extend_by_seconds"
            )
            expires_at = info.spec.expires_at + extend
        else:
            expires_at = now + _int(
                document["lifetime_seconds"],
                MIN_LIFETIME_SECONDS,
                MAX_LIFETIME_SECONDS,
                "lifetime_seconds",
            )
        if expires_at - now > MAX_LIFETIME_SECONDS:
            raise _bad("a sandbox lives at most 24 hours from now")
        return _json(200, self._sandbox_view(self.executor.set_expiry(sid, expires_at)))

    # -- exec ------------------------------------------------------------

    @staticmethod
    def _exec_request(
        document: dict[str, object], *, command_key: str, max_timeout: int, default_timeout: int
    ) -> ExecRequest:
        command = document[command_key]
        if isinstance(command, str):
            argv = ("/bin/sh", "-c", _text(command, MAX_COMMAND_BYTES, "command"))
        elif (
            isinstance(command, list)
            and 0 < len(command) <= 256
            and all(isinstance(item, str) for item in command)
        ):
            argv = tuple(_text(item, MAX_COMMAND_BYTES, "command") for item in command)
            if sum(len(item.encode()) for item in argv) > MAX_COMMAND_BYTES:
                raise _bad("command is too long")
        else:
            raise _bad("command must be a string or a list of strings")
        timeout = document.get("timeout_seconds", default_timeout)
        user = document.get("user")
        if user is not None and (not isinstance(user, str) or _USER_RE.fullmatch(user) is None):
            raise _bad("user is invalid")
        cwd = document.get("cwd")
        return ExecRequest(
            argv=argv,
            timeout_seconds=_int(timeout, 1, max_timeout, "timeout_seconds"),
            env=_env(document.get("env")),
            user=user,
            cwd=None if cwd is None else _abs_path(cwd, "cwd"),
        )

    def _exec(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        document = _body(
            body,
            frozenset({"command", "timeout_seconds", "env", "cwd", "user"}),
            frozenset({"command"}),
        )
        request = self._exec_request(
            document,
            command_key="command",
            max_timeout=MAX_SYNC_EXEC_SECONDS,
            default_timeout=MAX_SYNC_EXEC_SECONDS,
        )
        return _json(200, _exec_view(self.executor.exec(sid, request)))

    def _exec_start(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        try:
            document = _body(
                body,
                frozenset({"command", "timeout_seconds", "env", "cwd", "user"}),
                frozenset({"command"}),
            )
            key = "command"
        except _Refusal:
            # The verifiers adapter's background process form.
            document = _body(body, frozenset({"cmd", "env", "cwd", "user"}), frozenset({"cmd"}))
            key = "cmd"
        request = self._exec_request(
            document,
            command_key=key,
            max_timeout=MAX_EXEC_TIMEOUT_SECONDS,
            default_timeout=MAX_EXEC_TIMEOUT_SECONDS,
        )
        exec_id = self.executor.start_exec(sid, request)
        return _json(200, {"exec_id": exec_id, "state": "running"})

    def _exec_poll(self, caller, body, fields, sid: str, eid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        wait = 0
        values = self._query(fields, frozenset({"wait"})).get("wait", [])
        if len(values) > 1:
            raise _bad("wait may appear once")
        if values:
            wait = _int(_decimal(values[0], "wait"), 0, MAX_POLL_WAIT_SECONDS, "wait")
        return _json(200, _status_view(self.executor.poll_exec(sid, eid, wait)))

    def _exec_stop(self, caller, body, fields, sid: str, eid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        return _json(200, _status_view(self.executor.stop_exec(sid, eid)))

    # -- files -----------------------------------------------------------

    def _file_get(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        path = _abs_path(self._one(fields, "path"))
        return Response(200, self.executor.read_file(sid, path), "application/octet-stream")

    def _file_put(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        query = self._query(fields, frozenset({"path", "mode"}))
        paths, modes = query.get("path", []), query.get("mode", ["420"])
        if len(paths) != 1 or len(modes) != 1:
            raise _bad("send one path and at most one decimal mode")
        path = _abs_path(paths[0])
        mode = _int(_decimal(modes[0], "mode"), 0, 0o7777, "mode")
        self.executor.write_file(sid, path, body, mode)
        return _json(200, {"path": path, "size": len(body)})

    def _tar_get(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        query = self._query(fields, frozenset({"path", "exclude"}))
        paths, excludes = query.get("path", []), query.get("exclude", [])
        if len(paths) != 1 or len(excludes) > MAX_EXCLUDES:
            raise _bad("send one path and at most 64 excludes")
        for pattern in excludes:
            _text(pattern, 1024, "exclude")
            if not pattern or "\n" in pattern:
                raise _bad("exclude is invalid")
        data = self.executor.get_tar(sid, _abs_path(paths[0]), excludes)
        return Response(200, data, "application/gzip")

    def _tar_put(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        path = _abs_path(self._one(fields, "path"))
        if path.rstrip("/") == "":
            raise _bad("the tar route refuses /")
        self.executor.put_tar(sid, path, body)
        return _json(200, {"path": path})

    def _stat(self, caller, body, fields, sid: str) -> Response:  # noqa: ANN001
        self._owned(caller, sid)
        path = _abs_path(self._one(fields, "path"))
        found = self.executor.stat(sid, path)
        if found is None:
            raise _Refusal(404, "path not found")
        return _json(
            200,
            {
                "path": path,
                "is_dir": found.is_dir,
                "is_file": found.is_file,
                "size": found.size,
                "mode": found.mode,
            },
        )
