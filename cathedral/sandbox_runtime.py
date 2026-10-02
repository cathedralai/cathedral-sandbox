"""Production sandbox runtime selection for customer guests behind /v1.

Runtimes:

* ``memory`` — real in-process reference provider (subprocess FS). Contract tests.
* ``docker`` — real Linux containers via the Docker daemon. Fails closed if Docker
  is down. ``kernel_isolation=false`` (honest).
* ``kata`` — real Docker guests with ``--runtime=kata-runtime``. Fails closed if
  Kata is not registered. No stub mode.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Any, Mapping

from cathedral.sandbox_api import CreateSandboxRequest, QuotaLimits, StatusReport
from cathedral.sandbox_fleet import (
    FleetRegistry,
    assert_quota_fits_fleet,
    fleet_from_env_lines,
    require_fleet_admission,
)
from cathedral.sandbox_guest import DockerGuestProvider, docker_daemon_ready
from cathedral.sandbox_provider import (
    InMemorySandboxProvider,
    SandboxOpError,
    SandboxProvider,
    provider_from_environment,
)


RUNTIME_MEMORY = "memory"
RUNTIME_DOCKER = "docker"
RUNTIME_KATA = "kata"
RUNTIME_CHOICES = frozenset({RUNTIME_MEMORY, RUNTIME_DOCKER, RUNTIME_KATA})


@dataclass(frozen=True)
class RuntimeCapabilities:
    runtime: str
    kernel_isolation: bool
    dind: bool
    disk_enforced: bool

    def to_document(self) -> dict[str, object]:
        return {
            "runtime": self.runtime,
            "kernel_isolation": self.kernel_isolation,
            "dind": self.dind,
            "disk_enforced": self.disk_enforced,
        }


def kata_host_ready() -> bool:
    if os.name != "posix":
        return False
    if not any(
        shutil.which(name)
        for name in ("kata-runtime", "containerd-shim-kata-v2", "kata-containers")
    ):
        return False
    return docker_daemon_ready()


def detect_runtime(explicit: str | None = None) -> str:
    raw = (explicit or os.environ.get("CATHEDRAL_SANDBOX_RUNTIME") or RUNTIME_MEMORY).strip().lower()
    if raw not in RUNTIME_CHOICES:
        raise ValueError(f"unknown sandbox runtime {raw!r}; choose from {sorted(RUNTIME_CHOICES)}")
    return raw


class FleetGuardedProvider:
    def __init__(self, inner: SandboxProvider, fleet: FleetRegistry) -> None:
        self._inner = inner
        self._fleet = fleet

    @property
    def fleet(self) -> FleetRegistry:
        return self._fleet

    def authorize(self, api_key: str | None) -> None:
        self._inner.authorize(api_key)

    def create(
        self,
        request: CreateSandboxRequest,
        *,
        api_key: str | None,
        idempotency: str | None,
        body_digest: str,
    ) -> dict[str, Any]:
        require_fleet_admission(request, self._fleet)
        return self._inner.create(
            request, api_key=api_key, idempotency=idempotency, body_digest=body_digest
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def status(self) -> StatusReport:
        return self._inner.status()

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()


def build_sandbox_provider(
    *,
    runtime: str | None = None,
    allow_insecure_dev: bool = False,
    base_url: str | None = None,
    require_fleet: bool | None = None,
) -> SandboxProvider:
    """Construct the provider ``sandbox serve`` mounts. No stub runtimes."""
    kind = detect_runtime(RUNTIME_MEMORY if allow_insecure_dev else runtime)

    fleet_raw = os.environ.get("CATHEDRAL_SANDBOX_FLEET", "").strip()
    use_fleet = require_fleet if require_fleet is not None else bool(fleet_raw)
    fleet: FleetRegistry | None = None
    if use_fleet:
        if not fleet_raw:
            raise SandboxOpError(
                "fleet_empty",
                503,
                "CATHEDRAL_SANDBOX_FLEET is required when fleet admission is on",
                retry_after=30,
            )
        fleet = fleet_from_env_lines(fleet_raw.split(","))
        raw_quota = os.environ.get("CATHEDRAL_SANDBOX_QUOTA", "").strip()
        parts = [p.strip() for p in raw_quota.split(":") if p.strip()]
        if len(parts) == 3:
            limits = QuotaLimits(
                running_sandboxes=int(parts[0]),
                vcpu=int(parts[1]),
                memory_gib=int(parts[2]),
            )
            assert_quota_fits_fleet(limits, fleet)

    if allow_insecure_dev:
        provider: SandboxProvider = InMemorySandboxProvider(
            enforce_disk=True,
            runtime_label=RUNTIME_MEMORY,
        )
    elif kind == RUNTIME_MEMORY:
        provider = provider_from_environment(
            base_url=base_url,
            enforce_disk=True,
            runtime_label=RUNTIME_MEMORY,
        )
    elif kind == RUNTIME_DOCKER:
        provider = DockerGuestProvider(
            use_kata=False,
            inner=provider_from_environment(
                base_url=base_url,
                enforce_disk=True,
                runtime_label=RUNTIME_DOCKER,
            )
            if os.environ.get("CATHEDRAL_SANDBOX_KEYS", "").strip()
            else None,
        )
    else:
        if not kata_host_ready():
            raise SandboxOpError(
                "runtime_unavailable",
                503,
                "kata runtime not available; install kata-runtime + Docker on Linux, "
                "or use --runtime docker / --runtime memory",
                retry_after=60,
            )
        provider = DockerGuestProvider(
            use_kata=True,
            inner=provider_from_environment(
                base_url=base_url,
                enforce_disk=True,
                runtime_label=RUNTIME_KATA,
            )
            if os.environ.get("CATHEDRAL_SANDBOX_KEYS", "").strip()
            else None,
        )

    if fleet is not None:
        provider = FleetGuardedProvider(provider, fleet)
    return provider


def capabilities_document(provider: SandboxProvider) -> Mapping[str, object]:
    status = getattr(provider, "status", None)
    if callable(status):
        report = status()
        if isinstance(report, StatusReport):
            return RuntimeCapabilities(
                runtime=report.runtime,
                kernel_isolation=report.kernel_isolation,
                dind=report.dind,
                disk_enforced=report.disk_enforced,
            ).to_document()
    return RuntimeCapabilities(
        runtime=RUNTIME_MEMORY,
        kernel_isolation=False,
        dind=False,
        disk_enforced=bool(getattr(provider, "_enforce_disk", False)),
    ).to_document()


__all__ = [
    "FleetGuardedProvider",
    "RUNTIME_CHOICES",
    "RUNTIME_DOCKER",
    "RUNTIME_KATA",
    "RUNTIME_MEMORY",
    "RuntimeCapabilities",
    "build_sandbox_provider",
    "capabilities_document",
    "detect_runtime",
    "kata_host_ready",
]
