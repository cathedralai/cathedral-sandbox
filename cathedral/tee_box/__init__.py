"""In-guest TEE box sandbox service (queue item T6a), off by default.

See docs/TEE_BOX_SERVICE.md. The worker serves these routes only when it is
given a ``TeeBoxSandboxApi``; nothing here runs otherwise.
"""

from cathedral.tee_box.egress import EgressPolicy, EgressPolicyError, build_egress_policy
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
    TEE_BOX_CALLER_NETWORK,
    TeeBoxSandboxApi,
    caller_authorizer,
    caller_snapshot_provider,
    sandbox_target_allowed,
)

__all__ = [
    "TEE_BOX_CALLER_NETWORK",
    "CustomerLease",
    "EgressPolicy",
    "EgressPolicyError",
    "ExecRequest",
    "ExecResult",
    "Executor",
    "ExecutorError",
    "FakeExecutor",
    "LeaseBusy",
    "LeaseRequired",
    "RunscExecutor",
    "Shape",
    "TeeBoxSandboxApi",
    "build_egress_policy",
    "caller_authorizer",
    "caller_snapshot_provider",
    "sandbox_target_allowed",
]
