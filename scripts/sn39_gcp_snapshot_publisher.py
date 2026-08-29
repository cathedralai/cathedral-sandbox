#!/usr/bin/env python3
"""Provision and refresh the bounded two-guest UID124 signed-access view.

Cloud-changing modes require an exact acknowledgement. The policy has no flags
for project, zone, VM shape, subnet, miner, stake floor, validity, interval, or
runtime. The dedicated Ed25519 snapshot seed stays on this control host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Sequence

PROJECT_ID = "polaris-tdx-attest"
REGION = "us-central1"
ZONE = "us-central1-b"
NETWORK = "cathedral-sn39-e2e-f6d91c2a"
SUBNET = "cathedral-sn39-e2e-f6d91c2a"
FIREWALL_RULE = "cathedral-sn39-e2e-tls-f6d91c2a"
NETWORK_TAG = "cathedral-sn39-e2e-f6d91c2a"
BASE_IMAGE = "polaris-attest-base"
BASE_IMAGE_ID = "3355993504309639309"
BASE_IMAGE_LICENSE = "ubuntu-2404-lts"
MACHINE_TYPE = "c3-standard-4"
BOOT_DISK_GB = 20
MAX_RUN_SECONDS = 4 * 60 * 60
MAX_RUN_DURATION = "4h"
SNAPSHOT_VALID_SECONDS = 900
SNAPSHOT_REFRESH_SECONDS = 300
SNAPSHOT_REFRESH_CYCLES = 48
WINDOW_DISCOVERY_ATTEMPTS = 3
WINDOW_DISCOVERY_RETRY_SECONDS = 15
GUEST_READY_TIMEOUT_SECONDS = 8 * 60
GUEST_READY_POLL_SECONDS = 5
METADATA_VALUE_LIMIT_BYTES = 256 * 1024
METADATA_TOTAL_LIMIT_BYTES = 512 * 1024
NETWORK_NAME = "finney"
NETUID = 39
MINIMUM_STAKE_RAO = 0
UID30 = 30
UID30_HOTKEY = "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"
MINER_UID = 124
MINER_HOTKEY = "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"

PRIMARY_NAME = "cathedral-sn39-uid124-fleet-primary-20260829"
SECONDARY_NAME = "cathedral-sn39-uid124-fleet-secondary-20260829"
PRIMARY_ADDRESS = "cathedral-sn39-uid124-static-20260828"
SECONDARY_ADDRESS = "cathedral-sn39-uid8-static-20260828"
PRIMARY_IP = "35.222.166.235"
SECONDARY_IP = "34.46.19.69"

IMAGE_REPOSITORY = "ghcr.io/cathedralai/cathedral-sn39-audit-miner"
ACTIVATION_IMAGE = (
    IMAGE_REPOSITORY
    + "@sha256:61a1806fce13d987323e7c418f1260ba1cd8c9ace8e5b9f9be3c193bdba7228a"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PROVISION_ACK = "CREATE_TWO_UID124_TDX_GUESTS_FOR_FOUR_HOURS"
PUBLISH_ACK = "PUBLISH_PUBLIC_UID30_PERMIT_SNAPSHOT_TO_TWO_GUESTS"

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCER = REPOSITORY_ROOT / "scripts" / "cathedral_validator_access.py"
BOOTSTRAP = REPOSITORY_ROOT / "scripts" / "sn39_gcp_guest_bootstrap.sh"
POLLER = REPOSITORY_ROOT / "scripts" / "sn39_gcp_guest_poller.py"
LAUNCHER = REPOSITORY_ROOT / "scripts" / "run_sn39_signed_fleet_miner.sh"

ATTR_IMAGE = "cathedral-sn39-image"
ATTR_MINER_HOTKEY = "cathedral-sn39-miner-hotkey"
ATTR_PUBLIC_ENDPOINT = "cathedral-sn39-public-endpoint"
ATTR_KEYS = "cathedral-sn39-snapshot-keys"
ATTR_KEYS_DIGEST = "cathedral-sn39-snapshot-keys-digest"
ATTR_FLEET = "cathedral-sn39-fleet"
ATTR_FLEET_DIGEST = "cathedral-sn39-fleet-digest"
ATTR_LAUNCHER = "cathedral-sn39-launcher"
ATTR_LAUNCHER_DIGEST = "cathedral-sn39-launcher-digest"
ATTR_POLLER = "cathedral-sn39-poller"
ATTR_POLLER_DIGEST = "cathedral-sn39-poller-digest"
ATTR_SNAPSHOT = "cathedral-sn39-validator-access-snapshot"
ATTR_BLOCK_PROJECT_SSH_KEYS = "block-project-ssh-keys"


class PublisherError(RuntimeError):
    """The fixed control-host policy refused before or between cloud writes."""

    def __init__(
        self,
        message: str,
        *,
        completed_cloud_writes: Sequence[str] = (),
        ambiguous_cloud_write: str | None = None,
    ) -> None:
        super().__init__(message)
        self.completed_cloud_writes = tuple(completed_cloud_writes)
        self.ambiguous_cloud_write = ambiguous_cloud_write


@dataclass(frozen=True)
class VMPolicy:
    name: str
    address_name: str
    public_ip: str
    fleet_endpoints: tuple[str, ...]

    @property
    def public_endpoint(self) -> str:
        return f"https://{self.public_ip}:8081"


VMS = (
    VMPolicy(
        name=PRIMARY_NAME,
        address_name=PRIMARY_ADDRESS,
        public_ip=PRIMARY_IP,
        fleet_endpoints=(f"https://{SECONDARY_IP}:8081",),
    ),
    VMPolicy(
        name=SECONDARY_NAME,
        address_name=SECONDARY_ADDRESS,
        public_ip=SECONDARY_IP,
        fleet_endpoints=(),
    ),
)


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_json(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def fleet_bytes(vm: VMPolicy) -> bytes:
    return _canonical_json(
        {
            "schema": "cathedral_worker_fleet_v1",
            "worker_hotkey": MINER_HOTKEY,
            "endpoints": list(vm.fleet_endpoints),
        }
    )


def _require_regular_file(path: Path, *, private: bool = False) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PublisherError(f"required artifact is not a regular file: {path}")
    if private and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
        raise PublisherError("snapshot signing seed must be owner-only")
    payload = path.read_bytes()
    if not payload:
        raise PublisherError(f"required artifact is empty: {path}")
    return payload


def validate_inputs(*, signing_key: Path, keys_file: Path, image: str) -> dict[str, str]:
    if image != ACTIVATION_IMAGE:
        raise PublisherError("image must be the reviewed immutable activation digest")
    _require_regular_file(signing_key, private=True)
    keys = _require_regular_file(keys_file)
    launcher = _require_regular_file(LAUNCHER)
    poller = _require_regular_file(POLLER)
    _require_regular_file(BOOTSTRAP)
    return {
        "keys_digest": _sha256(keys),
        "launcher_digest": _sha256(launcher),
        "poller_digest": _sha256(poller),
    }


def capture_command(
    *, signing_key: Path, signing_key_id: str, output: Path
) -> list[str]:
    return [
        sys.executable,
        str(PRODUCER),
        "capture",
        "--network",
        NETWORK_NAME,
        "--netuid",
        str(NETUID),
        "--minimum-stake-rao",
        str(MINIMUM_STAKE_RAO),
        "--signing-key-id",
        signing_key_id,
        "--signing-key-file",
        str(signing_key),
        "--out",
        str(output),
        "--valid-seconds",
        str(SNAPSHOT_VALID_SECONDS),
        "--max-age-seconds",
        str(SNAPSHOT_VALID_SECONDS),
        "--require-hotkey",
        UID30_HOTKEY,
        "--require-uid-hotkey",
        f"{UID30}={UID30_HOTKEY}",
        "--require-uid-hotkey",
        f"{MINER_UID}={MINER_HOTKEY}",
    ]


def verify_command(
    *, snapshot: Path, keys_file: Path, keys_digest: str
) -> list[str]:
    return [
        sys.executable,
        str(PRODUCER),
        "verify",
        "--snapshot",
        str(snapshot),
        "--keys",
        str(keys_file),
        "--keys-digest",
        keys_digest,
        "--network",
        NETWORK_NAME,
        "--netuid",
        str(NETUID),
        "--minimum-stake-rao",
        str(MINIMUM_STAKE_RAO),
        "--max-age-seconds",
        str(SNAPSHOT_VALID_SECONDS),
        "--require-hotkey",
        UID30_HOTKEY,
    ]


def capture_snapshot(
    *, signing_key: Path, signing_key_id: str, keys_file: Path, output: Path
) -> None:
    keys_digest = _sha256(_require_regular_file(keys_file))
    try:
        subprocess.run(
            capture_command(
                signing_key=signing_key,
                signing_key_id=signing_key_id,
                output=output,
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
        )
        subprocess.run(
            verify_command(
                snapshot=output, keys_file=keys_file, keys_digest=keys_digest
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PublisherError("finalized permit snapshot capture or verification failed") from exc


def _gcloud_json(arguments: Sequence[str], *, timeout: int = 60) -> Any:
    try:
        completed = subprocess.run(
            ["gcloud", *arguments, "--format=json"],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return json.loads(completed.stdout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PublisherError(f"gcloud read failed: {' '.join(arguments[:4])}") from exc
    except json.JSONDecodeError as exc:
        raise PublisherError("gcloud returned malformed JSON") from exc


def _require_suffix(value: Any, suffix: str, *, label: str) -> None:
    if not isinstance(value, str) or not value.endswith("/" + suffix):
        raise PublisherError(f"{label} differs from the fixed policy")


def verify_shared_infrastructure(*, addresses_must_be_reserved: bool) -> None:
    image = _gcloud_json(
        ["compute", "images", "describe", BASE_IMAGE, "--project", PROJECT_ID]
    )
    licenses = image.get("licenses") or []
    if (
        str(image.get("id")) != BASE_IMAGE_ID
        or image.get("status") != "READY"
        or image.get("architecture") != "X86_64"
        or str(image.get("diskSizeGb")) != str(BOOT_DISK_GB)
        or len(licenses) != 1
        or not str(licenses[0]).endswith("/" + BASE_IMAGE_LICENSE)
    ):
        raise PublisherError("launch base image differs from the fixed image ID")
    network = _gcloud_json(
        ["compute", "networks", "describe", NETWORK, "--project", PROJECT_ID]
    )
    if network.get("autoCreateSubnetworks") is not False:
        raise PublisherError("launch network is not the fixed custom VPC")
    subnet = _gcloud_json(
        [
            "compute",
            "networks",
            "subnets",
            "describe",
            SUBNET,
            "--region",
            REGION,
            "--project",
            PROJECT_ID,
        ]
    )
    if subnet.get("ipCidrRange") != "10.239.31.0/28" or subnet.get("stackType") not in {
        None,
        "IPV4_ONLY",
    }:
        raise PublisherError("launch subnet differs from its fixed IPv4 range")
    rules = _gcloud_json(
        [
            "compute",
            "firewall-rules",
            "list",
            "--project",
            PROJECT_ID,
            "--filter",
            f"network:{NETWORK}",
        ]
    )
    if not isinstance(rules, list) or len(rules) != 1:
        raise PublisherError("launch VPC must contain exactly one ingress rule")
    rule = rules[0]
    allowed = rule.get("allowed")
    if (
        rule.get("name") != FIREWALL_RULE
        or rule.get("direction") != "INGRESS"
        or rule.get("disabled", False) is not False
        or rule.get("sourceRanges") != ["0.0.0.0/0"]
        or rule.get("targetTags") != [NETWORK_TAG]
        or allowed != [{"IPProtocol": "tcp", "ports": ["8081"]}]
    ):
        raise PublisherError("launch VPC ingress is not exact TCP 8081 only")
    for vm in VMS:
        address = _gcloud_json(
            [
                "compute",
                "addresses",
                "describe",
                vm.address_name,
                "--region",
                REGION,
                "--project",
                PROJECT_ID,
            ]
        )
        if address.get("address") != vm.public_ip:
            raise PublisherError(f"reserved address {vm.address_name} changed")
        if addresses_must_be_reserved and address.get("status") != "RESERVED":
            raise PublisherError(f"reserved address {vm.address_name} is still in use")


def verify_instance(document: Any, vm: VMPolicy, *, image: str) -> None:
    if not isinstance(document, dict) or document.get("name") != vm.name:
        raise PublisherError(f"instance {vm.name} describe result is invalid")
    _require_suffix(document.get("machineType"), MACHINE_TYPE, label="machine type")
    confidential = document.get("confidentialInstanceConfig") or {}
    scheduling = document.get("scheduling") or {}
    services = document.get("serviceAccounts") or []
    disks = document.get("disks") or []
    interfaces = document.get("networkInterfaces") or []
    tags = (document.get("tags") or {}).get("items") or []
    metadata_values = {
        row.get("key"): row.get("value")
        for row in (document.get("metadata") or {}).get("items", [])
    }
    metadata_names = set(metadata_values)
    if document.get("status") != "RUNNING":
        raise PublisherError(f"instance {vm.name} is not running")
    if confidential.get("confidentialInstanceType") != "TDX":
        raise PublisherError(f"instance {vm.name} is not Intel TDX")
    if services:
        raise PublisherError(f"instance {vm.name} unexpectedly has a service account")
    if (
        scheduling.get("automaticRestart") is not False
        or scheduling.get("onHostMaintenance") != "TERMINATE"
        or scheduling.get("instanceTerminationAction") != "DELETE"
        or int((scheduling.get("maxRunDuration") or {}).get("seconds", -1))
        != MAX_RUN_SECONDS
    ):
        raise PublisherError(f"instance {vm.name} lost its four-hour delete bound")
    if (
        len(disks) != 1
        or disks[0].get("autoDelete") is not True
        or disks[0].get("interface") != "NVME"
        or int(disks[0].get("diskSizeGb", -1)) != BOOT_DISK_GB
    ):
        raise PublisherError(f"instance {vm.name} disk policy changed")
    if len(interfaces) != 1:
        raise PublisherError(f"instance {vm.name} must have one network interface")
    interface = interfaces[0]
    _require_suffix(interface.get("network"), NETWORK, label="instance network")
    _require_suffix(interface.get("subnetwork"), SUBNET, label="instance subnet")
    access = interface.get("accessConfigs") or []
    if len(access) != 1 or access[0].get("natIP") != vm.public_ip:
        raise PublisherError(f"instance {vm.name} public IP changed")
    if tags != [NETWORK_TAG]:
        raise PublisherError(f"instance {vm.name} network tags changed")
    if any(name in {"ssh-keys", "enable-oslogin"} for name in metadata_names):
        raise PublisherError(f"instance {vm.name} contains an SSH access override")
    if (
        metadata_values.get(ATTR_IMAGE) != image
        or metadata_values.get(ATTR_MINER_HOTKEY) != MINER_HOTKEY
        or metadata_values.get(ATTR_PUBLIC_ENDPOINT) != vm.public_endpoint
        or metadata_values.get(ATTR_BLOCK_PROJECT_SSH_KEYS) != "true"
    ):
        raise PublisherError(f"instance {vm.name} public runtime metadata changed")
    if document.get("deletionProtection", False) is not False:
        raise PublisherError(f"instance {vm.name} has deletion protection")


def verify_running_instances(*, image: str) -> dict[str, Any]:
    verify_shared_infrastructure(addresses_must_be_reserved=False)
    documents: dict[str, Any] = {}
    for vm in VMS:
        document = _gcloud_json(
            [
                "compute",
                "instances",
                "describe",
                vm.name,
                "--zone",
                ZONE,
                "--project",
                PROJECT_ID,
            ]
        )
        verify_instance(document, vm, image=image)
        documents[vm.name] = document
    return documents


def _parse_creation_timestamp(value: Any, *, vm_name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PublisherError(f"instance {vm_name} has no creation timestamp")
    try:
        created = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PublisherError(
            f"instance {vm_name} has a malformed creation timestamp"
        ) from exc
    if created.tzinfo is None:
        raise PublisherError(f"instance {vm_name} creation timestamp lacks a timezone")
    return created.astimezone(UTC)


def instance_window_deadline(instances: dict[str, Any]) -> datetime:
    """Return the earliest fixed four-hour deletion deadline."""

    if set(instances) != {vm.name for vm in VMS}:
        raise PublisherError("running instance set differs from the fixed two-guest fleet")
    return min(
        _parse_creation_timestamp(
            instances[vm.name].get("creationTimestamp"), vm_name=vm.name
        )
        + timedelta(seconds=MAX_RUN_SECONDS)
        for vm in VMS
    )


def discover_instance_window_deadline(*, image: str) -> datetime:
    """Tolerate one short read outage before entering the bounded publish loop."""

    for attempt in range(1, WINDOW_DISCOVERY_ATTEMPTS + 1):
        try:
            return instance_window_deadline(verify_running_instances(image=image))
        except PublisherError as exc:
            will_retry = attempt < WINDOW_DISCOVERY_ATTEMPTS
            print(
                json.dumps(
                    {
                        "status": "REFUSED_WINDOW_DISCOVERY",
                        "attempt": attempt,
                        "of": WINDOW_DISCOVERY_ATTEMPTS,
                        "error": str(exc),
                        "cloud_write_state": "NONE_CONFIRMED",
                        "next_retry_seconds": (
                            WINDOW_DISCOVERY_RETRY_SECONDS if will_retry else None
                        ),
                        "will_retry": will_retry,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
            if not will_retry:
                raise PublisherError(
                    "could not establish the fixed instance deletion window after "
                    f"{WINDOW_DISCOVERY_ATTEMPTS} bounded reads"
                ) from exc
            time.sleep(WINDOW_DISCOVERY_RETRY_SECONDS)
    raise AssertionError("unreachable instance-window discovery state")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _publisher_refusal_document(
    exc: PublisherError,
    *,
    cycle: int,
    consecutive_failures: int,
    deadline: datetime,
    next_refresh_seconds: int | None,
) -> dict[str, Any]:
    completed = list(exc.completed_cloud_writes)
    return {
        "status": "REFUSED_CYCLE",
        "cycle": cycle,
        "consecutive_failures": consecutive_failures,
        "error": str(exc),
        "cloud_write_state": (
            "AMBIGUOUS"
            if exc.ambiguous_cloud_write is not None
            else "PARTIAL_CONFIRMED"
            if completed
            else "NONE_CONFIRMED"
        ),
        "completed_cloud_writes": completed,
        "ambiguous_cloud_write": exc.ambiguous_cloud_write,
        "instance_window_deadline": deadline.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "next_refresh_seconds": next_refresh_seconds,
        "will_retry": next_refresh_seconds is not None,
    }


def _window_complete_document(
    *, deadline: datetime, cycles_attempted: int, reason: str
) -> dict[str, Any]:
    return {
        "status": "INSTANCE_WINDOW_COMPLETE",
        "cycles_attempted": cycles_attempted,
        "instance_window_deadline": deadline.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reason": reason,
        "next_refresh_seconds": None,
    }


def _metadata_scalars(
    vm: VMPolicy,
    *,
    image: str,
    keys_digest: str,
    fleet_digest: str,
    launcher_digest: str,
    poller_digest: str,
) -> str:
    values = {
        ATTR_BLOCK_PROJECT_SSH_KEYS: "true",
        ATTR_IMAGE: image,
        ATTR_MINER_HOTKEY: MINER_HOTKEY,
        ATTR_PUBLIC_ENDPOINT: vm.public_endpoint,
        ATTR_KEYS_DIGEST: keys_digest,
        ATTR_FLEET_DIGEST: fleet_digest,
        ATTR_LAUNCHER_DIGEST: launcher_digest,
        ATTR_POLLER_DIGEST: poller_digest,
    }
    if any("," in value or "=" in value for value in values.values()):
        raise PublisherError("metadata scalar contains a gcloud delimiter")
    return ",".join(f"{key}={value}" for key, value in values.items())


def _metadata_payloads(
    vm: VMPolicy,
    *,
    image: str,
    keys_file: Path,
    snapshot: Path,
    fleet_file: Path,
    pins: dict[str, str],
) -> dict[str, bytes]:
    scalars = _metadata_scalars(
        vm,
        image=image,
        keys_digest=pins["keys_digest"],
        fleet_digest=_sha256(fleet_file.read_bytes()),
        launcher_digest=pins["launcher_digest"],
        poller_digest=pins["poller_digest"],
    )
    payloads = {
        row.split("=", 1)[0]: row.split("=", 1)[1].encode("utf-8")
        for row in scalars.split(",")
    }
    payloads.update(
        {
            "startup-script": _require_regular_file(BOOTSTRAP),
            ATTR_POLLER: _require_regular_file(POLLER),
            ATTR_LAUNCHER: _require_regular_file(LAUNCHER),
            ATTR_KEYS: _require_regular_file(keys_file),
            ATTR_FLEET: _require_regular_file(fleet_file),
            ATTR_SNAPSHOT: _require_regular_file(snapshot),
        }
    )
    _validate_metadata_sizes(payloads)
    return payloads


def _validate_metadata_sizes(payloads: dict[str, bytes]) -> None:
    for key, value in payloads.items():
        if len(value) > METADATA_VALUE_LIMIT_BYTES:
            raise PublisherError(f"metadata value {key} exceeds the GCP 256 KiB limit")
    total = sum(len(key.encode("utf-8")) + len(value) for key, value in payloads.items())
    if total > METADATA_TOTAL_LIMIT_BYTES:
        raise PublisherError("combined instance metadata exceeds the GCP 512 KiB limit")


def _existing_metadata_payloads(document: Any) -> dict[str, bytes]:
    rows = (document.get("metadata") or {}).get("items", []) if isinstance(document, dict) else []
    if not isinstance(rows, list):
        raise PublisherError("instance metadata is malformed")
    payloads: dict[str, bytes] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise PublisherError("instance metadata is malformed")
        key = row.get("key")
        value = row.get("value")
        if not isinstance(key, str) or not isinstance(value, str) or key in payloads:
            raise PublisherError("instance metadata is malformed or duplicated")
        payloads[key] = value.encode("utf-8")
    return payloads


def create_instance_command(
    vm: VMPolicy,
    *,
    image: str,
    keys_file: Path,
    snapshot: Path,
    fleet_file: Path,
    pins: dict[str, str],
) -> list[str]:
    _metadata_payloads(
        vm,
        image=image,
        keys_file=keys_file,
        snapshot=snapshot,
        fleet_file=fleet_file,
        pins=pins,
    )
    metadata_files = {
        "startup-script": BOOTSTRAP,
        ATTR_POLLER: POLLER,
        ATTR_LAUNCHER: LAUNCHER,
        ATTR_KEYS: keys_file,
        ATTR_FLEET: fleet_file,
        ATTR_SNAPSHOT: snapshot,
    }
    if any("," in str(path) or "=" in str(path) for path in metadata_files.values()):
        raise PublisherError("metadata file path contains a gcloud delimiter")
    return [
        "gcloud",
        "compute",
        "instances",
        "create",
        vm.name,
        "--project",
        PROJECT_ID,
        "--zone",
        ZONE,
        "--machine-type",
        MACHINE_TYPE,
        "--confidential-compute-type",
        "TDX",
        "--maintenance-policy",
        "TERMINATE",
        "--no-restart-on-failure",
        "--provisioning-model",
        "STANDARD",
        "--max-run-duration",
        MAX_RUN_DURATION,
        "--instance-termination-action",
        "DELETE",
        "--image",
        BASE_IMAGE,
        "--image-project",
        PROJECT_ID,
        "--boot-disk-size",
        f"{BOOT_DISK_GB}GB",
        "--boot-disk-type",
        "pd-balanced",
        "--boot-disk-interface",
        "NVME",
        "--boot-disk-auto-delete",
        "--no-service-account",
        "--no-scopes",
        "--network-interface",
        (
            f"network={NETWORK},subnet={SUBNET},address={vm.address_name},"
            "network-tier=PREMIUM,stack-type=IPV4_ONLY"
        ),
        "--tags",
        NETWORK_TAG,
        "--shielded-vtpm",
        "--shielded-integrity-monitoring",
        "--no-shielded-secure-boot",
        "--metadata",
        _metadata_scalars(
            vm,
            image=image,
            keys_digest=pins["keys_digest"],
            fleet_digest=_sha256(fleet_file.read_bytes()),
            launcher_digest=pins["launcher_digest"],
            poller_digest=pins["poller_digest"],
        ),
        "--metadata-from-file",
        ",".join(f"{key}={path}" for key, path in metadata_files.items()),
        "--quiet",
    ]


def _guest_tls_ready(vm: VMPolicy, context: ssl.SSLContext) -> bool:
    try:
        with socket.create_connection((vm.public_ip, 8081), timeout=3) as connection:
            with context.wrap_socket(connection) as tls:
                certificate = tls.getpeercert(binary_form=True)
                version = tls.version()
        return bool(certificate) and version in {"TLSv1.2", "TLSv1.3"}
    except (OSError, ssl.SSLError):
        return False


def wait_for_guest_tls() -> None:
    """Require both newly created guests to expose their signed-fleet TLS worker."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    pending = {vm.name: vm for vm in VMS}
    deadline = time.monotonic() + GUEST_READY_TIMEOUT_SECONDS
    while pending and time.monotonic() < deadline:
        for name, vm in list(pending.items()):
            if _guest_tls_ready(vm, context):
                del pending[name]
        if pending:
            time.sleep(GUEST_READY_POLL_SECONDS)
    if pending:
        raise PublisherError(
            "new guests did not expose TLS before the readiness deadline: "
            + ", ".join(sorted(pending))
        )


def _desired_instances_absent() -> None:
    rows = _gcloud_json(
        [
            "compute",
            "instances",
            "list",
            "--project",
            PROJECT_ID,
            "--filter",
            f"name=({PRIMARY_NAME} {SECONDARY_NAME})",
        ]
    )
    if rows:
        raise PublisherError("one or both bounded fleet VM names already exist")


def provision(
    *, signing_key: Path, signing_key_id: str, keys_file: Path, image: str
) -> None:
    pins = validate_inputs(signing_key=signing_key, keys_file=keys_file, image=image)
    verify_shared_infrastructure(addresses_must_be_reserved=True)
    _desired_instances_absent()
    with tempfile.TemporaryDirectory(prefix="cathedral-sn39-provision-") as temporary:
        root = Path(temporary)
        snapshot = root / "validator-access.json"
        capture_snapshot(
            signing_key=signing_key,
            signing_key_id=signing_key_id,
            keys_file=keys_file,
            output=snapshot,
        )
        completed: list[str] = []
        for vm in VMS:
            fleet = root / f"{vm.name}-fleet.json"
            fleet.write_bytes(fleet_bytes(vm))
            command = create_instance_command(
                vm,
                image=image,
                keys_file=keys_file,
                snapshot=snapshot,
                fleet_file=fleet,
                pins=pins,
            )
            try:
                subprocess.run(command, check=True, timeout=300)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise PublisherError(
                    f"instance creation stopped after a failure at {vm.name}; no rollback was attempted",
                    completed_cloud_writes=completed,
                    ambiguous_cloud_write=f"create instance {vm.name}",
                ) from exc
            completed.append(f"created instance {vm.name}")
    try:
        verify_running_instances(image=image)
        wait_for_guest_tls()
    except PublisherError as exc:
        raise PublisherError(
            str(exc), completed_cloud_writes=completed
        ) from exc


def snapshot_update_command(vm: VMPolicy, snapshot: Path, *, instance: Any) -> list[str]:
    payload = _require_regular_file(snapshot)
    metadata_payloads = _existing_metadata_payloads(instance)
    metadata_payloads[ATTR_SNAPSHOT] = payload
    _validate_metadata_sizes(metadata_payloads)
    return [
        "gcloud",
        "compute",
        "instances",
        "add-metadata",
        vm.name,
        "--project",
        PROJECT_ID,
        "--zone",
        ZONE,
        "--metadata-from-file",
        f"{ATTR_SNAPSHOT}={snapshot}",
        "--quiet",
    ]


def publish_once(
    *,
    signing_key: Path,
    signing_key_id: str,
    keys_file: Path,
    snapshot: Path,
    image: str,
) -> None:
    instances = verify_running_instances(image=image)
    capture_snapshot(
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        keys_file=keys_file,
        output=snapshot,
    )
    completed: list[str] = []
    for vm in VMS:
        try:
            command = snapshot_update_command(
                vm, snapshot, instance=instances[vm.name]
            )
        except PublisherError as exc:
            raise PublisherError(
                str(exc), completed_cloud_writes=completed
            ) from exc
        try:
            subprocess.run(command, check=True, timeout=60)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise PublisherError(
                f"snapshot update failed at {vm.name}; the guest retains its prior short-lived view",
                completed_cloud_writes=completed,
                ambiguous_cloud_write=f"update snapshot metadata on {vm.name}",
            ) from exc
        completed.append(f"updated snapshot metadata on {vm.name}")


def publish_loop(
    *, signing_key: Path, signing_key_id: str, keys_file: Path, image: str
) -> None:
    validate_inputs(signing_key=signing_key, keys_file=keys_file, image=image)
    deadline = discover_instance_window_deadline(image=image)
    consecutive_failures = 0
    with tempfile.TemporaryDirectory(prefix="cathedral-sn39-snapshot-") as temporary:
        snapshot = Path(temporary) / "validator-access.json"
        for cycle in range(SNAPSHOT_REFRESH_CYCLES):
            now = _utc_now()
            if now >= deadline:
                print(
                    json.dumps(
                        _window_complete_document(
                            deadline=deadline,
                            cycles_attempted=cycle,
                            reason="instance_window_elapsed",
                        ),
                        sort_keys=True,
                    ),
                    flush=True,
                )
                return

            refusal: PublisherError | None = None
            try:
                publish_once(
                    signing_key=signing_key,
                    signing_key_id=signing_key_id,
                    keys_file=keys_file,
                    snapshot=snapshot,
                    image=image,
                )
            except PublisherError as exc:
                consecutive_failures += 1
                refusal = exc
            else:
                consecutive_failures = 0

            after_attempt = _utc_now()
            retry_seconds = (
                SNAPSHOT_REFRESH_SECONDS
                if cycle + 1 < SNAPSHOT_REFRESH_CYCLES
                and after_attempt + timedelta(seconds=SNAPSHOT_REFRESH_SECONDS)
                < deadline
                else None
            )
            if refusal is not None:
                print(
                    json.dumps(
                        _publisher_refusal_document(
                            refusal,
                            cycle=cycle + 1,
                            consecutive_failures=consecutive_failures,
                            deadline=deadline,
                            next_refresh_seconds=retry_seconds,
                        ),
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                    flush=True,
                )
            else:
                print(
                    json.dumps(
                        {
                            "status": "PUBLISHED",
                            "cycle": cycle + 1,
                            "of": SNAPSHOT_REFRESH_CYCLES,
                            "published_to": [vm.name for vm in VMS],
                            "valid_seconds": SNAPSHOT_VALID_SECONDS,
                            "instance_window_deadline": deadline.strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            "next_refresh_seconds": retry_seconds,
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )

            if retry_seconds is None:
                reason = (
                    "maximum_cycles_reached"
                    if cycle + 1 >= SNAPSHOT_REFRESH_CYCLES
                    else "next_refresh_reaches_instance_deadline"
                )
                print(
                    json.dumps(
                        _window_complete_document(
                            deadline=deadline,
                            cycles_attempted=cycle + 1,
                            reason=reason,
                        ),
                        sort_keys=True,
                    ),
                    flush=True,
                )
                return
            time.sleep(retry_seconds)


def plan_document() -> dict[str, Any]:
    return {
        "cloud_writes": False,
        "project": PROJECT_ID,
        "zone": ZONE,
        "network": NETWORK,
        "subnet": SUBNET,
        "firewall": {"ingress": "tcp:8081", "ssh": False},
        "machine": {
            "type": MACHINE_TYPE,
            "confidential_compute": "TDX",
            "base_image": BASE_IMAGE,
            "base_image_id": BASE_IMAGE_ID,
            "boot_disk_gb": BOOT_DISK_GB,
            "service_account": None,
            "max_run_seconds": MAX_RUN_SECONDS,
            "termination_action": "DELETE",
        },
        "activation_image": ACTIVATION_IMAGE,
        "miner": {"uid": MINER_UID, "hotkey": MINER_HOTKEY},
        "validator_access": {
            "network": NETWORK_NAME,
            "netuid": NETUID,
            "minimum_stake_rao": MINIMUM_STAKE_RAO,
            "required_uid": UID30,
            "required_hotkey": UID30_HOTKEY,
            "valid_seconds": SNAPSHOT_VALID_SECONDS,
            "refresh_seconds": SNAPSHOT_REFRESH_SECONDS,
            "maximum_cycles": SNAPSHOT_REFRESH_CYCLES,
        },
        "vms": [
            {
                "name": vm.name,
                "static_ip": vm.public_ip,
                "public_endpoint": vm.public_endpoint,
                "fleet_candidates_beyond_self": list(vm.fleet_endpoints),
            }
            for vm in VMS
        ],
        "guest_secrets": [],
        "guest_wallet": False,
        "guest_chain_rpc": False,
    }


def _add_artifact_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--signing-key-file", required=True, type=Path)
    parser.add_argument("--keys-file", required=True, type=Path)
    parser.add_argument("--signing-key-id", default="cathedral-validator-access-1")
    parser.add_argument("--image", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sn39-gcp-snapshot-publisher", allow_abbrev=False
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan", help="print the fixed no-write policy")
    provision_parser = commands.add_parser(
        "provision", help="create exactly two bounded TDX guests"
    )
    _add_artifact_arguments(provision_parser)
    provision_parser.add_argument("--acknowledge", required=True)
    publish_parser = commands.add_parser(
        "publish-loop", help="refresh public signed snapshots every five minutes"
    )
    _add_artifact_arguments(publish_parser)
    publish_parser.add_argument("--acknowledge", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if options.command == "plan":
            print(json.dumps(plan_document(), indent=2, sort_keys=True))
            return 0
        if options.command == "provision":
            if options.acknowledge != PROVISION_ACK:
                raise PublisherError("provision acknowledgement does not match")
            provision(
                signing_key=options.signing_key_file,
                signing_key_id=options.signing_key_id,
                keys_file=options.keys_file,
                image=options.image,
            )
            return 0
        if options.acknowledge != PUBLISH_ACK:
            raise PublisherError("publisher acknowledgement does not match")
        publish_loop(
            signing_key=options.signing_key_file,
            signing_key_id=options.signing_key_id,
            keys_file=options.keys_file,
            image=options.image,
        )
        return 0
    except PublisherError as exc:
        completed = list(exc.completed_cloud_writes)
        print(
            json.dumps(
                {
                    "status": "REFUSED",
                    "error": str(exc),
                    "cloud_write_state": (
                        "AMBIGUOUS"
                        if exc.ambiguous_cloud_write is not None
                        else "PARTIAL_CONFIRMED"
                        if completed
                        else "NONE_CONFIRMED"
                    ),
                    "completed_cloud_writes": completed,
                    "ambiguous_cloud_write": exc.ambiguous_cloud_write,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
