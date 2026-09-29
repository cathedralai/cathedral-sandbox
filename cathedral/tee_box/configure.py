"""Worker flags that enable the TEE box sandbox API (T6b1), off by default.

``cathedral worker serve`` and ``serve-snp`` accept these flags. With none of
them, the worker has no sandbox routes. Any one of them requires the whole
required set, or the worker refuses to start, as the signed validator-access
flags do. The API also requires the worker's attested TLS listener.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import subprocess
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from cathedral.common import ChannelBinding
from cathedral.tee_box.egress import (
    DEFAULT_BANDWIDTH_MBIT,
    EgressPolicy,
    EgressPolicyError,
    build_egress_policy,
)
from cathedral.tee_box.enforce import (
    EgressEnforcementError,
    EgressEnforcer,
    detect_box_addresses,
)
from cathedral.tee_box.executor import DEFAULT_RUNTIME_PATH, RunscExecutor, Shape

EXECUTORS = ("runsc",)
DEFAULT_DOCKER_PATH = "/usr/bin/docker"
DEFAULT_CALLER_MAX_AGE_SECONDS = 3600

# Flags with no default: giving any TEE box flag requires all of these, plus
# exactly one address source (--tee-box-address or --tee-box-detect-addresses).
REQUIRED = {
    "tee_box_caller_snapshot": "--tee-box-caller-snapshot",
    "tee_box_caller_keys": "--tee-box-caller-keys",
    "tee_box_caller_keys_digest": "--tee-box-caller-keys-digest",
    "tee_box_caller_state": "--tee-box-caller-state",
    "tee_box_executor": "--tee-box-executor",
    "tee_box_capacity": "--tee-box-capacity",
    "tee_box_default_shape": "--tee-box-default-shape",
}
# Flags that have a default once the box is enabled. Giving one alone is
# still a partial configuration and refuses to start.
OPTIONAL = (
    "tee_box_address",
    "tee_box_detect_addresses",
    "tee_box_caller_max_age_seconds",
    "tee_box_docker_path",
    "tee_box_runtime",
    "tee_box_runtime_path",
    "tee_box_bandwidth_mbit",
    "tee_box_id",
    "tee_box_no_disk_quota",
)


def _shape(text: str) -> Shape:
    parts = text.split(",")
    if len(parts) != 3 or not all(part.isascii() and part.isdigit() for part in parts):
        raise argparse.ArgumentTypeError("expected VCPUS,MEMORY_MIB,DISK_MIB")
    vcpus, memory, disk = (int(part) for part in parts)
    if not (1 <= vcpus <= 4096 and 256 <= memory <= 64 * 1024 * 1024 and 256 <= disk):
        raise argparse.ArgumentTypeError("shape values are out of range")
    return Shape(vcpus, memory, disk)


def _address(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected one IP address") from exc


def add_tee_box_arguments(command: argparse.ArgumentParser) -> None:
    group = command.add_argument_group(
        "TEE box sandbox API (off by default; docs/TEE_BOX_SERVICE.md)"
    )
    group.add_argument(
        "--tee-box-caller-snapshot",
        help="signed control-plane caller snapshot (network label cathedral-control-plane)",
    )
    group.add_argument("--tee-box-caller-keys", help="trusted Ed25519 keys for the caller snapshot")
    group.add_argument(
        "--tee-box-caller-keys-digest",
        help="required sha256 pin for the caller key file",
    )
    group.add_argument(
        "--tee-box-caller-state",
        help="owner-only SQLite replay state for callers, apart from validator access",
    )
    group.add_argument(
        "--tee-box-caller-max-age-seconds",
        type=int,
        help=f"caller snapshot freshness (default {DEFAULT_CALLER_MAX_AGE_SECONDS})",
    )
    group.add_argument("--tee-box-executor", choices=EXECUTORS, help="sandbox executor")
    group.add_argument(
        "--tee-box-docker-path", help=f"docker CLI in the guest (default {DEFAULT_DOCKER_PATH})"
    )
    group.add_argument("--tee-box-runtime", help="docker runtime name (default runsc)")
    group.add_argument(
        "--tee-box-runtime-path",
        help=f"runsc binary the daemon registers (default {DEFAULT_RUNTIME_PATH})",
    )
    group.add_argument(
        "--tee-box-address",
        action="append",
        type=_address,
        help="one of the box's own addresses, denied to sandboxes; repeatable",
    )
    group.add_argument(
        "--tee-box-detect-addresses",
        action="store_true",
        default=None,
        help="deny every interface address, and the public endpoint if it is an IP",
    )
    group.add_argument(
        "--tee-box-capacity",
        type=_shape,
        help="admission capacity VCPUS,MEMORY_MIB,DISK_MIB for all sandboxes together",
    )
    group.add_argument(
        "--tee-box-default-shape",
        type=_shape,
        help="shape VCPUS,MEMORY_MIB,DISK_MIB of a sandbox created without one",
    )
    group.add_argument(
        "--tee-box-bandwidth-mbit",
        type=int,
        help=f"per-sandbox bandwidth cap (default {DEFAULT_BANDWIDTH_MBIT})",
    )
    group.add_argument("--tee-box-id", help="container label for this box (default: default)")
    group.add_argument(
        "--tee-box-no-disk-quota",
        action="store_true",
        default=None,
        help="run without per-sandbox disk quotas when the storage driver has none",
    )


@dataclass(frozen=True)
class TeeBoxConfig:
    caller_snapshot: str
    caller_keys: str
    caller_keys_digest: str
    caller_state: str
    caller_max_age_seconds: int
    executor: str
    docker_path: str
    runtime: str
    runtime_path: str
    addresses: tuple[str, ...]
    detect_addresses: bool
    capacity: Shape
    default_shape: Shape
    bandwidth_mbit: int
    box_id: str
    disk_quota: bool


def tee_box_config(args: argparse.Namespace) -> TeeBoxConfig | None:
    """Validate the TEE box flags: none (off), or the whole required set."""

    given = [name for name in (*REQUIRED, *OPTIONAL) if getattr(args, name, None) is not None]
    if not given:
        return None
    missing = [flag for name, flag in REQUIRED.items() if getattr(args, name, None) is None]
    addresses = tuple(getattr(args, "tee_box_address", None) or ())
    detect = bool(getattr(args, "tee_box_detect_addresses", None))
    if missing:
        raise ValueError("the TEE box API requires all of its flags; missing " + ", ".join(missing))
    if bool(addresses) == detect:
        raise ValueError(
            "the TEE box API requires exactly one of --tee-box-address or "
            "--tee-box-detect-addresses"
        )
    capacity, default_shape = args.tee_box_capacity, args.tee_box_default_shape
    if not default_shape.fits_within(capacity):
        raise ValueError("the TEE box default shape must fit its capacity")
    if args.tee_box_caller_state == getattr(args, "validator_access_state", None):
        raise ValueError("the TEE box caller state must be separate from validator access state")

    def pick(name: str, default):  # noqa: ANN001, ANN202
        value = getattr(args, name, None)
        return default if value is None else value

    return TeeBoxConfig(
        caller_snapshot=args.tee_box_caller_snapshot,
        caller_keys=args.tee_box_caller_keys,
        caller_keys_digest=args.tee_box_caller_keys_digest,
        caller_state=args.tee_box_caller_state,
        caller_max_age_seconds=pick(
            "tee_box_caller_max_age_seconds", DEFAULT_CALLER_MAX_AGE_SECONDS
        ),
        executor=args.tee_box_executor,
        docker_path=pick("tee_box_docker_path", DEFAULT_DOCKER_PATH),
        runtime=pick("tee_box_runtime", "runsc"),
        runtime_path=pick("tee_box_runtime_path", DEFAULT_RUNTIME_PATH),
        addresses=addresses,
        detect_addresses=detect,
        capacity=capacity,
        default_shape=default_shape,
        bandwidth_mbit=pick("tee_box_bandwidth_mbit", DEFAULT_BANDWIDTH_MBIT),
        box_id=pick("tee_box_id", "default"),
        disk_quota=not bool(getattr(args, "tee_box_no_disk_quota", None)),
    )


def _endpoint_address(public_endpoint: str | None) -> tuple[str, ...]:
    if not public_endpoint:
        return ()
    host = urllib.parse.urlsplit(public_endpoint).hostname or ""
    try:
        return (str(ipaddress.ip_address(host)),)
    except ValueError:
        return ()


def box_policy(
    config: TeeBoxConfig,
    *,
    public_endpoint: str | None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> EgressPolicy:
    """The egress policy, with box addresses parsed into ``ipaddress`` objects only."""

    if config.detect_addresses:
        found = detect_box_addresses(extra=_endpoint_address(public_endpoint), runner=runner)
    else:
        found = tuple(ipaddress.ip_address(text) for text in config.addresses)
    try:
        return build_egress_policy(
            [str(address) for address in found], bandwidth_mbit=config.bandwidth_mbit
        )
    except EgressPolicyError as exc:
        raise ValueError(f"TEE box egress policy: {exc}") from exc


def build_tee_box_api(
    config: TeeBoxConfig,
    *,
    hotkey: str,
    channel_binding: ChannelBinding,
    netuid: int,
    public_endpoint: str | None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    now: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(datetime.UTC),
):  # noqa: ANN201 - returns (TeeBoxSandboxApi, startup facts)
    """Build the sandbox API or refuse to start.

    Refuses when the caller snapshot is absent or stale, the runsc runtime is
    not registered, or disk quotas are unsupported without the opt-out. An
    egress table that fails to apply does not refuse: the box starts with
    ``deny_all`` only and reports the error, and the reaper retries.
    """

    from cathedral.admission_policy import load_policy_keys
    from cathedral.tee_box.service import (
        TeeBoxSandboxApi,
        caller_authorizer,
        caller_snapshot_provider,
    )
    from cathedral.validator_access import (
        ValidatorAccessState,
        load_sr25519_verifier,
        preflight_sr25519_verifier,
    )

    if config.executor != "runsc":
        raise ValueError("the TEE box executor must be runsc")
    keys = load_policy_keys(
        config.caller_keys, production_mode=True, pinned_digest=config.caller_keys_digest
    )
    state = ValidatorAccessState(config.caller_state)
    provider = caller_snapshot_provider(
        config.caller_snapshot,
        keys,
        netuid=netuid,
        state=state,
        max_age_seconds=config.caller_max_age_seconds,
    )
    if provider.load(now=now()) is None:
        raise ValueError("TEE box caller snapshot is absent, stale, or invalid")
    verifier = load_sr25519_verifier()
    preflight_sr25519_verifier(verifier)
    authorizer = caller_authorizer(
        provider,
        worker_hotkey=hotkey,
        channel_binding=channel_binding,
        state=state,
        signature_verifier=verifier,
    )
    policy = box_policy(config, public_endpoint=public_endpoint, runner=runner)
    try:
        enforcer = EgressEnforcer(policy, docker=config.docker_path, runner=runner)
    except (EgressEnforcementError, ValueError) as exc:
        raise ValueError(f"TEE box egress enforcer: {exc}") from exc
    executor = RunscExecutor(
        policy,
        docker=config.docker_path,
        runtime=config.runtime,
        runtime_path=config.runtime_path,
        egress_enforcer=enforcer,
        storage_quota=config.disk_quota,
        runner=runner,
        box_id=config.box_id,
    )
    registered, runtime_detail = executor.runtime_check()
    if not registered:
        raise ValueError(f"TEE box runtime: {runtime_detail}")
    if config.disk_quota:
        supported, quota_detail = executor.storage_quota_support()
        if not supported:
            raise ValueError(
                f"TEE box disk quota: {quota_detail}; fix the storage driver or pass "
                "--tee-box-no-disk-quota"
            )
    else:
        quota_detail = "disabled by --tee-box-no-disk-quota"
    enforcer.apply()
    api = TeeBoxSandboxApi(
        executor=executor,
        authorizer=authorizer,
        egress=policy,
        capacity=config.capacity,
        default_shape=config.default_shape,
    )
    facts = {
        "executor": config.executor,
        "runtime": runtime_detail,
        "network_modes": list(executor.network_modes),
        "egress": enforcer.status(),
        "box_addresses": [str(net) for net in policy.box_addresses],
        "bandwidth_mbit": policy.bandwidth_mbit,
        "disk_quota": quota_detail,
        "capacity": config.capacity.view(),
        "default_shape": config.default_shape.view(),
    }
    return api, facts
