"""In-guest TEE box sandbox service (queue items T6a and T6b1), off by default.

See docs/TEE_BOX_SERVICE.md. The worker serves these routes only when it is
given a ``TeeBoxSandboxApi``; nothing here runs otherwise.
"""

from cathedral.tee_box.boot import BootError, BootGuard, RelaunchRequired
from cathedral.tee_box.egress import EgressPolicy, EgressPolicyError, build_egress_policy
from cathedral.tee_box.enforce import EgressEnforcementError, EgressEnforcer
from cathedral.tee_box.executor import (
    ExecRequest,
    ExecResult,
    Executor,
    ExecutorError,
    FakeExecutor,
    RunscExecutor,
    Shape,
)
from cathedral.tee_box.lease import CustomerLease, LeaseBusy, LeaseRequired
from cathedral.tee_box.service import (
    ROUTE_SCOPES,
    TeeBoxSandboxApi,
    route_scope,
    sandbox_target_allowed,
)

__all__ = [
    "ROUTE_SCOPES",
    "BootError",
    "BootGuard",
    "CustomerLease",
    "EgressEnforcementError",
    "EgressEnforcer",
    "EgressPolicy",
    "EgressPolicyError",
    "ExecRequest",
    "ExecResult",
    "Executor",
    "ExecutorError",
    "FakeExecutor",
    "LeaseBusy",
    "LeaseRequired",
    "RelaunchRequired",
    "RunscExecutor",
    "Shape",
    "TeeBoxSandboxApi",
    "build_egress_policy",
    "route_scope",
    "sandbox_target_allowed",
]
