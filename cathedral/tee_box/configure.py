"""Worker flags that enable the TEE box sandbox API (T6b1), off by default.

``cathedral worker serve`` and ``serve-snp`` accept these flags. With none of
them, the worker has no sandbox routes. Any one of them requires the whole
required set, or the worker refuses to start, as the signed validator-access
flags do. The API also requires the worker's attested TLS listener.

No flag names the callers. They use central access under the Cathedral root
keys the launch measured (cathedral/tee_box/measured_root.py); the worker
refuses to start when those are unavailable or do not match.

The TEE box runs only in TEE mode, so its storage rules always apply
(cathedral/tee_box/storage.py): the central state on tmpfs or ramfs, no
swap, and Docker's data root in memory or on dm-crypt with integrity.
No flag relaxes them.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import subprocess
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from cathedral.common import ChannelBinding
from cathedral.tee_box import measured_root
from cathedral.tee_box.boot import BootError, BootGuard, SysfsRtmr3, marker_path_for
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
from cathedral.tee_box.executor import (
    DEFAULT_RUNTIME_PATH,
    ExecutorError,
    RunscExecutor,
    Shape,
)
from cathedral.tee_box.storage import (
    StorageError,
    StorageProbe,
    default_storage_probe,
    require_memory_backed,
    require_no_swap,
    require_protected_scratch,
)

EXECUTORS = ("runsc",)
DEFAULT_DOCKER_PATH = "/usr/bin/docker"

# Flags with no default: giving any TEE box flag requires all of these, plus
# exactly one address source (--tee-box-address or --tee-box-detect-addresses).
REQUIRED = {
    "tee_box_central_state": "--tee-box-central-state",
    "tee_box_executor": "--tee-box-executor",
    "tee_box_capacity": "--tee-box-capacity",
    "tee_box_default_shape": "--tee-box-default-shape",
}
# Flags that have a default once the box is enabled. Giving one alone is
# still a partial configuration and refuses to start.
OPTIONAL = (
    "tee_box_address",
    "tee_box_detect_addresses",
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
        "--tee-box-central-state",
        help=(
            "owner-only SQLite replay state for central callers, apart from validator "
            "and --central-access state, in a directory on tmpfs or ramfs (the root "
            "keys are measured, not a flag)"
        ),
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
    central_state: str
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
    for other in ("validator_access_state", "central_access_state"):
        if _same_file(args.tee_box_central_state, getattr(args, other, None)):
            raise ValueError(
                "the TEE box central state must be separate from validator and central access state"
            )

    def pick(name: str, default):  # noqa: ANN001, ANN202
        value = getattr(args, name, None)
        return default if value is None else value

    return TeeBoxConfig(
        central_state=args.tee_box_central_state,
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


def _same_file(first: str, second: str | None) -> bool:
    if second is None:
        return False
    if os.path.abspath(first) == os.path.abspath(second):
        return True
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


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
    tee: str,
    hotkey: str,
    channel_binding: ChannelBinding,
    network: str,
    netuid: int,
    public_endpoint: str | None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    read_binding: measured_root.MeasuredBindingReader | None = None,
    storage_probe: StorageProbe | None = None,
    boot_options: dict | None = None,
):  # noqa: ANN201 - returns (TeeBoxSandboxApi, startup facts)
    """Build the sandbox API or refuse to start.

    Refuses first when the central root keys at the fixed image path do not
    hash to the launch's measured binding (MRCONFIGID on TDX; SNP has none
    yet), then when the central state is not on tmpfs or ramfs, any swap is
    on, the central state is unusable, the runsc
    runtime is not registered, Docker's data root is neither in memory nor
    on dm-crypt with integrity, or disk quotas are unsupported without the
    opt-out. An egress table that fails to apply does not refuse: the box
    starts with ``deny_all`` only and reports the error, and the reaper
    retries.

    It also refuses when the kernel's boot id, boot time or RTMR3 cannot be
    read, and on any TEE but TDX, which has no RTMR3 to extend: the box
    records the one customer each boot may serve next to the central state,
    and extends RTMR3 before the first lease (cathedral/tee_box/boot.py).

    ``read_binding``, ``storage_probe`` and ``boot_options`` (``rtmr``,
    ``read_boot_id`` and ``read_booted_at`` keyword arguments for
    ``BootGuard``) replace the TD report reader, the storage probes, RTMR3
    and the boot readers in tests only.
    """

    from cathedral.central_access import (
        CentralAccessAuthorizer,
        CentralAccessError,
        open_central_access_state,
    )
    from cathedral.tee_box.service import TeeBoxSandboxApi

    if config.executor != "runsc":
        raise ValueError("the TEE box executor must be runsc")
    try:
        root_keys, root_digest = measured_root.load_measured_root_keys(
            tee, read_binding=read_binding
        )
    except measured_root.MeasuredRootError as exc:
        raise ValueError(f"TEE box central root: {exc}") from exc
    probe = default_storage_probe(runner) if storage_probe is None else storage_probe
    # Checked before the state is opened, which would create it.
    try:
        state_storage = require_memory_backed(config.central_state, fs_type=probe.fs_type)
        swap = require_no_swap(probe)
    except (StorageError, OSError) as exc:
        raise ValueError(f"TEE box storage: {exc}") from exc
    if tee != "tdx":
        # SEV-SNP has no RTMR; its equivalent (a vTPM PCR) is not built.
        raise ValueError(f"TEE box boot identity: TEE {tee!r} has no RTMR3 for the lease extend")
    options = {"rtmr": SysfsRtmr3(), **(boot_options or {})}
    try:
        boot = BootGuard(marker_path_for(config.central_state), **options)
    except BootError as exc:
        raise ValueError(f"TEE box boot identity: {exc}") from exc
    try:
        authorizer = CentralAccessAuthorizer(
            root_keys,
            worker_hotkey=hotkey,
            network=network,
            netuid=netuid,
            channel_binding=channel_binding,
            state=open_central_access_state(config.central_state),
        )
    except CentralAccessError as exc:
        raise ValueError(f"TEE box central access: {exc}") from exc
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
    try:
        docker_root, _driver, driver_status = executor.storage_root()
        scratch = require_protected_scratch(docker_root, probe, driver_status=driver_status)
    except (ExecutorError, StorageError, OSError) as exc:
        raise ValueError(f"TEE box storage: {exc}") from exc
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
        boot=boot,
    )
    facts = {
        "central_root_keys": measured_root.CENTRAL_ROOT_KEYS_PATH,
        "central_root_digest": root_digest,
        "central_root_key_ids": sorted(root_keys),
        "executor": config.executor,
        "runtime": runtime_detail,
        "network_modes": list(executor.network_modes),
        "egress": enforcer.status(),
        "box_addresses": [str(net) for net in policy.box_addresses],
        "bandwidth_mbit": policy.bandwidth_mbit,
        "disk_quota": quota_detail,
        "storage": {
            "central_state": state_storage,
            "swap": swap,
            "docker_root": docker_root,
            "scratch": scratch,
        },
        "capacity": config.capacity.view(),
        "default_shape": config.default_shape.view(),
        "boot": {
            "boot_id": boot.record.boot_id,
            "booted_at": boot.booted_at,
            "consumed": boot.record.consumed_by is not None,
            "rtmr3_extended": boot.rtmr3_extended,
            "record": boot.marker_path,
        },
    }
    return api, facts
