"""Fleet capacity for the customer-facing sandbox control plane.

The purchase bar (§3.8) is a project quota of 500 running sandboxes /
1,000 vCPU / 3,000 GiB sustained.  This module records what Linux miner nodes
have actually registered and refuses to *advertise* or *admit* more than that
registered capacity.  A laptop cannot claim 500 running sandboxes.

The HTTP surface stays :mod:`cathedral.sandbox_server`.  Placement decides
whether a :class:`~cathedral.sandbox_api.CreateSandboxRequest` fits; the
runtime on the chosen node starts the guest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from cathedral import sandbox_api as api
from cathedral.sandbox_api import CreateSandboxRequest, QuotaLimits, QuotaUsage
from cathedral.sandbox_provider import SandboxOpError


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class NodeCapacity:
    """What one miner node can still hold (customer checklist §3.6 resource dimensions)."""

    node_id: str
    running_sandboxes: int
    vcpu: int
    memory_gib: int
    disk_gib: int

    def __post_init__(self) -> None:
        for name, value in (
            ("running_sandboxes", self.running_sandboxes),
            ("vcpu", self.vcpu),
            ("memory_gib", self.memory_gib),
            ("disk_gib", self.disk_gib),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative int")
        if not self.node_id.strip():
            raise ValueError("node_id must be non-empty")

    def fits(self, request: CreateSandboxRequest) -> bool:
        need_n = request.count
        need_vcpu = request.total_vcpu
        need_mem = request.total_memory_gib
        need_disk = request.resources.disk_gib * need_n
        return (
            self.running_sandboxes >= need_n
            and self.vcpu >= need_vcpu
            and self.memory_gib >= need_mem
            and self.disk_gib >= need_disk
        )


@dataclass
class FleetRegistry:
    """Registered miner capacity.  Thread-hostile by design — wrap under a lock."""

    nodes: dict[str, NodeCapacity] = field(default_factory=dict)
    updated_at: datetime | None = None

    def register(self, node: NodeCapacity) -> None:
        self.nodes[node.node_id] = node
        self.updated_at = _now()

    def unregister(self, node_id: str) -> None:
        self.nodes.pop(node_id, None)
        self.updated_at = _now()

    def total(self) -> NodeCapacity:
        """Sum free capacity across every registered node."""
        if not self.nodes:
            return NodeCapacity(
                node_id="fleet",
                running_sandboxes=0,
                vcpu=0,
                memory_gib=0,
                disk_gib=0,
            )
        return NodeCapacity(
            node_id="fleet",
            running_sandboxes=sum(n.running_sandboxes for n in self.nodes.values()),
            vcpu=sum(n.vcpu for n in self.nodes.values()),
            memory_gib=sum(n.memory_gib for n in self.nodes.values()),
            disk_gib=sum(n.disk_gib for n in self.nodes.values()),
        )

    def pick(self, request: CreateSandboxRequest) -> NodeCapacity | None:
        """Return one node that can hold *request*, or None."""
        for node in self.nodes.values():
            if node.fits(request):
                return node
        return None

    def document(self) -> dict[str, object]:
        total = self.total()
        return {
            "nodes": len(self.nodes),
            "capacity": {
                "running_sandboxes": total.running_sandboxes,
                "vcpu": total.vcpu,
                "memory_gib": total.memory_gib,
                "disk_gib": total.disk_gib,
            },
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z") if self.updated_at else None,
        }


def customer_mvp_quota() -> QuotaLimits:
    """The sustained project quota from customer-sandbox-requirements.txt §3.8."""
    return QuotaLimits(
        running_sandboxes=api.MIN_RUNNING_SANDBOXES,
        vcpu=api.MIN_VCPU,
        memory_gib=api.MIN_MEMORY_GIB,
    )


def assert_quota_fits_fleet(limits: QuotaLimits, fleet: FleetRegistry) -> None:
    """Refuse to configure a project quota larger than registered miner capacity.

    The sale gate is a real 500/1000/3000 project.  Advertising that number
    without the machines is the Daytona failure mode customers asked us not to copy.
    """
    total = fleet.total()
    gaps: list[str] = []
    if limits.running_sandboxes > total.running_sandboxes:
        gaps.append(
            f"running_sandboxes quota {limits.running_sandboxes} > fleet {total.running_sandboxes}"
        )
    if limits.vcpu > total.vcpu:
        gaps.append(f"vcpu quota {limits.vcpu} > fleet {total.vcpu}")
    if limits.memory_gib > total.memory_gib:
        gaps.append(f"memory_gib quota {limits.memory_gib} > fleet {total.memory_gib}")
    if gaps:
        raise SandboxOpError(
            "fleet_capacity_insufficient",
            503,
            "project quota exceeds registered miner capacity: " + "; ".join(gaps),
            retry_after=30,
        )


def require_fleet_admission(request: CreateSandboxRequest, fleet: FleetRegistry) -> NodeCapacity:
    """Place *request* on a registered node or raise a synchronous 429/503."""
    if not fleet.nodes:
        raise SandboxOpError(
            "fleet_empty",
            503,
            "no miner nodes registered; cannot start sandboxes",
            retry_after=30,
        )
    node = fleet.pick(request)
    if node is None:
        raise SandboxOpError(
            "fleet_capacity_exhausted",
            429,
            "no registered miner has free capacity for this create",
            retry_after=1,
        )
    return node


def fleet_from_env_lines(lines: Iterable[str]) -> FleetRegistry:
    """Parse ``node_id:running:vcpu:memory_gib:disk_gib`` lines into a registry.

    Used by ``CATHEDRAL_SANDBOX_FLEET`` (comma-separated) so operators can pin a
    known capacity without standing up the node agent yet.
    """
    fleet = FleetRegistry()
    for raw in lines:
        entry = raw.strip()
        if not entry:
            continue
        parts = [p.strip() for p in entry.split(":")]
        if len(parts) != 5:
            raise ValueError(
                f"fleet entry must be node_id:running:vcpu:memory_gib:disk_gib, got {entry!r}"
            )
        node_id, running, vcpu, memory_gib, disk_gib = parts
        fleet.register(
            NodeCapacity(
                node_id=node_id,
                running_sandboxes=int(running),
                vcpu=int(vcpu),
                memory_gib=int(memory_gib),
                disk_gib=int(disk_gib),
            )
        )
    return fleet


def usage_fits_remaining(usage: QuotaUsage, limits: QuotaLimits, request: CreateSandboxRequest) -> bool:
    """True when project usage + request still fits *limits* (no fleet involved)."""
    return (
        usage.running_sandboxes + request.count <= limits.running_sandboxes
        and usage.vcpu + request.total_vcpu <= limits.vcpu
        and usage.memory_gib + request.total_memory_gib <= limits.memory_gib
    )


__all__ = [
    "FleetRegistry",
    "NodeCapacity",
    "customer_mvp_quota",
    "assert_quota_fits_fleet",
    "fleet_from_env_lines",
    "require_fleet_admission",
    "usage_fits_remaining",
]
