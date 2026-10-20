"""Fleet capacity admission for customer checklist §3.8."""

from __future__ import annotations

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, QuotaLimits, Resources
from cathedral.sandbox_fleet import (
    FleetRegistry,
    NodeCapacity,
    assert_quota_fits_fleet,
    customer_mvp_quota,
    fleet_from_env_lines,
    require_fleet_admission,
)
from cathedral.sandbox_provider import SandboxOpError


def _req(**over) -> CreateSandboxRequest:
    values = {
        "image": ImageSource(image="repo/tool:latest"),
        "resources": Resources(vcpu=1, memory_gib=4, disk_gib=10),
    }
    values.update(over)
    return CreateSandboxRequest(**values)


def test_customer_mvp_quota_matches_spec() -> None:
    q = customer_mvp_quota()
    assert q.running_sandboxes == 500
    assert q.vcpu == 1000
    assert q.memory_gib == 3000


def test_assert_quota_fits_fleet_refuses_oversell() -> None:
    fleet = FleetRegistry()
    fleet.register(
        NodeCapacity(node_id="n1", running_sandboxes=10, vcpu=40, memory_gib=160, disk_gib=200)
    )
    with pytest.raises(SandboxOpError) as exc:
        assert_quota_fits_fleet(customer_mvp_quota(), fleet)
    assert exc.value.code == "fleet_capacity_insufficient"
    assert exc.value.http_status == 503


def test_assert_quota_fits_when_fleet_covers_mvp() -> None:
    fleet = FleetRegistry()
    fleet.register(
        NodeCapacity(
            node_id="big",
            running_sandboxes=500,
            vcpu=1000,
            memory_gib=3000,
            disk_gib=10_000,
        )
    )
    assert_quota_fits_fleet(customer_mvp_quota(), fleet)


def test_require_fleet_admission_picks_a_node() -> None:
    fleet = FleetRegistry()
    fleet.register(NodeCapacity(node_id="a", running_sandboxes=2, vcpu=4, memory_gib=16, disk_gib=40))
    fleet.register(NodeCapacity(node_id="b", running_sandboxes=0, vcpu=0, memory_gib=0, disk_gib=0))
    node = require_fleet_admission(_req(), fleet)
    assert node.node_id == "a"


def test_require_fleet_admission_429_when_full() -> None:
    fleet = FleetRegistry()
    fleet.register(NodeCapacity(node_id="tiny", running_sandboxes=0, vcpu=0, memory_gib=0, disk_gib=0))
    with pytest.raises(SandboxOpError) as exc:
        require_fleet_admission(_req(), fleet)
    assert exc.value.code == "fleet_capacity_exhausted"
    assert exc.value.http_status == 429


def test_fleet_from_env_lines() -> None:
    fleet = fleet_from_env_lines(["node-a:5:10:40:100", "node-b:5:10:40:100"])
    total = fleet.total()
    assert total.running_sandboxes == 10
    assert total.vcpu == 20


def test_fleet_empty_is_503() -> None:
    with pytest.raises(SandboxOpError) as exc:
        require_fleet_admission(_req(), FleetRegistry())
    assert exc.value.code == "fleet_empty"


def test_quota_limits_type_still_used() -> None:
    # smoke: QuotaLimits remains the project document shape
    limits = QuotaLimits(running_sandboxes=2, vcpu=4, memory_gib=8)
    fleet = FleetRegistry()
    fleet.register(NodeCapacity(node_id="n", running_sandboxes=2, vcpu=4, memory_gib=8, disk_gib=20))
    assert_quota_fits_fleet(limits, fleet)
