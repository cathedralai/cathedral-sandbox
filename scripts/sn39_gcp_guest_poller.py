#!/usr/bin/env python3
"""Fail-closed GCP metadata delivery for the bounded UID124 signed fleet.

This process runs as root on one or two reviewed Intel TDX guests. It accepts
only public deployment material from instance metadata. Snapshot signatures
are verified inside the immutable audit-miner image before atomic installation.
No wallet, chain client, RPC endpoint, bearer, or private artifact seed enters
the guest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Sequence

PROJECT_ID = "polaris-tdx-attest"
ZONE = "us-central1-b"
MACHINE_TYPE = "c3-standard-4"
NETWORK = "finney"
NETUID = 39
MINIMUM_STAKE_RAO = 0
UID30 = 30
UID30_HOTKEY = "5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw"
MINER_UID = 124
MINER_HOTKEY = "5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G"

PRIMARY_NAME = "cathedral-sn39-uid124-fleet-primary-20260829"
SECONDARY_NAME = "cathedral-sn39-uid124-fleet-secondary-20260829"
PRIMARY_IP = "35.222.166.235"
SECONDARY_IP = "34.46.19.69"
VM_PUBLIC_IPS = {PRIMARY_NAME: PRIMARY_IP, SECONDARY_NAME: SECONDARY_IP}

IMAGE_REPOSITORY = "ghcr.io/cathedralai/cathedral-sn39-audit-miner"
ACTIVATION_IMAGE = (
    IMAGE_REPOSITORY
    + "@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RUNTIME_CONTRACT = "signed-validator-fleet-v1"

METADATA_ROOT = "http://metadata.google.internal/computeMetadata/v1"
METADATA_HEADER = {"Metadata-Flavor": "Google"}
METADATA_TIMEOUT_SECONDS = 5.0
MAX_METADATA_BYTES = 512 * 1024
POLL_SECONDS = 15
SNAPSHOT_MAX_AGE_SECONDS = 900
SNAPSHOT_MAX_VALIDITY_SECONDS = 900
VALIDATOR_TIMEOUT_SECONDS = 60
IMAGE_PULL_TIMEOUT_SECONDS = 300
CHILD_STOP_TIMEOUT_SECONDS = 30
CHILD_KILL_TIMEOUT_SECONDS = 10
CONTAINER_REMOVE_TIMEOUT_SECONDS = 15
CONTAINER_NAME = "cathedral-sn39-audit-miner"

CONFIG_DIRECTORY = Path("/etc/cathedral/validator-access")
STATE_DIRECTORY = Path("/var/lib/cathedral/validator-access")
RUNTIME_DIRECTORY = Path("/run/cathedral-sn39")
SNAPSHOT_PATH = CONFIG_DIRECTORY / "validator-access.json"
KEYS_PATH = CONFIG_DIRECTORY / "snapshot-keys.json"
FLEET_PATH = CONFIG_DIRECTORY / "fleet.json"
LAUNCHER_PATH = Path("/usr/local/libexec/cathedral-sn39-signed-fleet-launcher")
HIGH_WATER_PATH = STATE_DIRECTORY / "metadata-snapshot-high-water.json"

ATTR_IMAGE = "cathedral-sn39-image"
ATTR_MINER_HOTKEY = "cathedral-sn39-miner-hotkey"
ATTR_PUBLIC_ENDPOINT = "cathedral-sn39-public-endpoint"
ATTR_KEYS = "cathedral-sn39-snapshot-keys"
ATTR_KEYS_DIGEST = "cathedral-sn39-snapshot-keys-digest"
ATTR_FLEET = "cathedral-sn39-fleet"
ATTR_FLEET_DIGEST = "cathedral-sn39-fleet-digest"
ATTR_LAUNCHER = "cathedral-sn39-launcher"
ATTR_LAUNCHER_DIGEST = "cathedral-sn39-launcher-digest"
ATTR_SNAPSHOT = "cathedral-sn39-validator-access-snapshot"

SNAPSHOT_VALIDATOR_CODE = r"""
import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path

from cathedral.admission_policy import load_policy_keys
from cathedral.validator_access import verify_validator_access_snapshot

keys_digest = sys.argv[1]
expected_hotkey = sys.argv[2]
expected_uid = int(sys.argv[3])
keys = load_policy_keys(
    "/input/snapshot-keys.json",
    production_mode=True,
    pinned_digest=keys_digest,
)
snapshot = verify_validator_access_snapshot(
    Path("/input/validator-access.json").read_bytes(),
    keys,
    network="finney",
    netuid=39,
    required_minimum_stake_rao=0,
    max_age_seconds=900,
)
if snapshot.expires_at - snapshot.generated_at > timedelta(seconds=900):
    raise SystemExit("snapshot validity exceeds 900 seconds")
qualified = snapshot.validators.get(expected_hotkey)
if qualified is None or qualified.uid != expected_uid:
    raise SystemExit("pinned UID30 validator is not qualified")
authorization = {
    "network": snapshot.network,
    "netuid": snapshot.netuid,
    "block": snapshot.block,
    "block_hash": snapshot.block_hash,
    "minimum_stake_rao": snapshot.minimum_stake_rao,
    "signing_key_id": snapshot.signing_key_id,
    "validators": [
        {
            "hotkey": row.hotkey,
            "uid": row.uid,
            "stake_rao": row.stake_rao,
        }
        for row in sorted(snapshot.validators.values(), key=lambda row: row.hotkey)
    ],
}
authorization_bytes = json.dumps(
    authorization, sort_keys=True, separators=(",", ":")
).encode("ascii")
print(json.dumps({
    "block": snapshot.block,
    "block_hash": snapshot.block_hash,
    "digest": snapshot.digest,
    "authorization_digest": "sha256:" + hashlib.sha256(authorization_bytes).hexdigest(),
    "generated_at": snapshot.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "expires_at": snapshot.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
}, sort_keys=True, separators=(",", ":")))
""".strip()


class GuestDeliveryError(RuntimeError):
    """The guest delivery contract refused an input or runtime transition."""


@dataclass(frozen=True)
class VMPolicy:
    name: str
    public_ip: str

    @property
    def public_endpoint(self) -> str:
        return f"https://{self.public_ip}:8081"


@dataclass(frozen=True)
class Deployment:
    vm: VMPolicy
    image: str
    keys_digest: str
    fleet_digest: str
    launcher_digest: str


@dataclass(frozen=True)
class SnapshotStatus:
    block: int
    block_hash: str
    digest: str
    authorization_digest: str
    generated_at: datetime
    expires_at: datetime

    def fresh(self, now: datetime) -> bool:
        return (
            self.generated_at <= now < self.expires_at
            and now - self.generated_at <= timedelta(seconds=SNAPSHOT_MAX_AGE_SECONDS)
            and self.expires_at - self.generated_at
            <= timedelta(seconds=SNAPSHOT_MAX_VALIDITY_SECONDS)
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class MetadataClient:
    """Small, proxy-free, no-redirect GCP metadata client."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def get(self, path: str, *, maximum: int = MAX_METADATA_BYTES) -> bytes:
        if not path or path.startswith("/") or ".." in path:
            raise GuestDeliveryError("metadata path is not fixed and relative")
        request = urllib.request.Request(
            f"{METADATA_ROOT}/{path}", headers=METADATA_HEADER, method="GET"
        )
        try:
            with self._opener.open(request, timeout=METADATA_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise GuestDeliveryError(f"metadata {path} answered {response.status}")
                if response.headers.get("Metadata-Flavor") != "Google":
                    raise GuestDeliveryError("metadata response lacks the Google binding")
                payload = response.read(maximum + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise GuestDeliveryError(f"metadata {path} is unavailable") from exc
        if not payload or len(payload) > maximum:
            raise GuestDeliveryError(f"metadata {path} is empty or over its bound")
        return payload

    def text(self, path: str, *, maximum: int = 4096) -> str:
        raw = self.get(path, maximum=maximum)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GuestDeliveryError(f"metadata {path} is not UTF-8") from exc
        if value != value.strip() or "\x00" in value:
            raise GuestDeliveryError(f"metadata {path} is not a canonical scalar")
        return value

    def attribute(self, name: str, *, maximum: int = MAX_METADATA_BYTES) -> bytes:
        if not re.fullmatch(r"[a-z0-9-]+", name):
            raise GuestDeliveryError("metadata attribute name is invalid")
        return self.get(f"instance/attributes/{name}", maximum=maximum)

    def attribute_text(self, name: str) -> str:
        raw = self.attribute(name, maximum=4096)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GuestDeliveryError(f"metadata attribute {name} is not UTF-8") from exc
        if value != value.strip() or "\x00" in value:
            raise GuestDeliveryError(f"metadata attribute {name} is not canonical")
        return value


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _require_digest(value: str, *, label: str) -> str:
    if DIGEST_RE.fullmatch(value) is None:
        raise GuestDeliveryError(f"{label} is not a lowercase sha256 digest")
    return value


def _require_pinned(payload: bytes, expected: str, *, label: str) -> None:
    pin = _require_digest(expected, label=f"{label} digest")
    if _sha256(payload) != pin:
        raise GuestDeliveryError(f"{label} does not match its pinned digest")


def _parse_utc(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ) is None:
        raise GuestDeliveryError(f"{label} is not canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise GuestDeliveryError(f"{label} is invalid") from exc


def _require_root_directory(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.chmod(0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise GuestDeliveryError(f"{path} must be a root-owned mode-0700 directory")


def atomic_write(path: Path, payload: bytes, mode: int) -> None:
    """Replace one fixed file without following links or exposing partial bytes."""

    _require_root_directory(path.parent)
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if current is not None and (
        not stat.S_ISREG(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or current.st_uid != 0
    ):
        raise GuestDeliveryError(f"refusing unsafe replacement target {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            os.fchmod(handle.fileno(), mode)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _basename_metadata(value: str, *, label: str) -> str:
    if "/" not in value:
        raise GuestDeliveryError(f"{label} metadata is malformed")
    return value.rsplit("/", 1)[-1]


def load_deployment(metadata: MetadataClient) -> Deployment:
    if metadata.text("project/project-id") != PROJECT_ID:
        raise GuestDeliveryError("guest is outside the pinned GCP project")
    name = metadata.text("instance/name")
    public_ip = VM_PUBLIC_IPS.get(name)
    if public_ip is None:
        raise GuestDeliveryError("guest name is outside the two-machine launch")
    if _basename_metadata(metadata.text("instance/zone"), label="zone") != ZONE:
        raise GuestDeliveryError("guest is outside the pinned GCP zone")
    if (
        _basename_metadata(metadata.text("instance/machine-type"), label="machine type")
        != MACHINE_TYPE
    ):
        raise GuestDeliveryError("guest is not the pinned machine type")
    observed_ip = metadata.text(
        "instance/network-interfaces/0/access-configs/0/external-ip"
    )
    if observed_ip != public_ip:
        raise GuestDeliveryError("guest external IP differs from its pinned static IP")
    vm = VMPolicy(name=name, public_ip=public_ip)
    image = metadata.attribute_text(ATTR_IMAGE)
    if image != ACTIVATION_IMAGE:
        raise GuestDeliveryError("audit-miner image is not the reviewed activation digest")
    if metadata.attribute_text(ATTR_MINER_HOTKEY) != MINER_HOTKEY:
        raise GuestDeliveryError("guest miner hotkey is not the pinned UID124 owner")
    if metadata.attribute_text(ATTR_PUBLIC_ENDPOINT) != vm.public_endpoint:
        raise GuestDeliveryError("guest public endpoint does not match its fixed identity")
    return Deployment(
        vm=vm,
        image=image,
        keys_digest=_require_digest(
            metadata.attribute_text(ATTR_KEYS_DIGEST), label="snapshot keys digest"
        ),
        fleet_digest=_require_digest(
            metadata.attribute_text(ATTR_FLEET_DIGEST), label="fleet digest"
        ),
        launcher_digest=_require_digest(
            metadata.attribute_text(ATTR_LAUNCHER_DIGEST), label="launcher digest"
        ),
    )


def _validate_fleet(payload: bytes, vm: VMPolicy) -> None:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuestDeliveryError("fleet metadata is not JSON") from exc
    if vm == VMPolicy(PRIMARY_NAME, PRIMARY_IP):
        allowed_endpoints = ([], [f"https://{SECONDARY_IP}:8081"])
    elif vm == VMPolicy(SECONDARY_NAME, SECONDARY_IP):
        allowed_endpoints = ([],)
    else:
        raise GuestDeliveryError("fleet metadata has no fixed guest identity")
    allowed = [
        {
            "schema": "cathedral_worker_fleet_v1",
            "worker_hotkey": MINER_HOTKEY,
            "endpoints": endpoints,
        }
        for endpoints in allowed_endpoints
    ]
    if document not in allowed:
        raise GuestDeliveryError(
            "fleet metadata differs from the fixed primary-only or two-machine policy"
        )


def install_static_artifacts(metadata: MetadataClient, deployment: Deployment) -> None:
    keys = metadata.attribute(ATTR_KEYS)
    fleet = metadata.attribute(ATTR_FLEET)
    launcher = metadata.attribute(ATTR_LAUNCHER)
    _require_pinned(keys, deployment.keys_digest, label="snapshot public keys")
    _require_pinned(fleet, deployment.fleet_digest, label="fleet manifest")
    _require_pinned(launcher, deployment.launcher_digest, label="launcher")
    _validate_fleet(fleet, deployment.vm)
    if not launcher.startswith(b"#!/usr/bin/env bash\n"):
        raise GuestDeliveryError("launcher is not the reviewed Bash program")
    atomic_write(KEYS_PATH, keys, 0o644)
    atomic_write(FLEET_PATH, fleet, 0o644)
    atomic_write(LAUNCHER_PATH, launcher, 0o700)


def ensure_image(image: str) -> None:
    subprocess.run(
        ["docker", "pull", "--platform", "linux/amd64", image],
        check=True,
        timeout=IMAGE_PULL_TIMEOUT_SECONDS,
    )
    inspected = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{json .}}",
            image,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    try:
        document = json.loads(inspected.stdout)
        repo_digests = document["RepoDigests"]
        platform = f"{document['Os']}/{document['Architecture']}"
        label = document["Config"]["Labels"]["org.cathedral.sn39.runtime-contract"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise GuestDeliveryError("pulled image inspection is incomplete") from exc
    if image not in repo_digests:
        raise GuestDeliveryError("pulled image does not report the exact RepoDigest")
    if platform != "linux/amd64" or label != RUNTIME_CONTRACT:
        raise GuestDeliveryError("pulled image has the wrong platform or runtime contract")


def validate_snapshot(
    candidate: Path, *, deployment: Deployment, now: datetime | None = None
) -> SnapshotStatus:
    command = [
        "docker",
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=8m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit",
        "32",
        "--memory",
        "128m",
        "--memory-swap",
        "128m",
        "--mount",
        f"type=bind,src={candidate},dst=/input/validator-access.json,readonly",
        "--mount",
        f"type=bind,src={KEYS_PATH},dst=/input/snapshot-keys.json,readonly",
        "--entrypoint",
        "/usr/local/bin/python",
        deployment.image,
        "-I",
        "-u",
        "-B",
        "-c",
        SNAPSHOT_VALIDATOR_CODE,
        deployment.keys_digest,
        UID30_HOTKEY,
        str(UID30),
    ]
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=VALIDATOR_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise GuestDeliveryError("snapshot failed isolated signature validation") from exc
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise GuestDeliveryError("snapshot validator returned malformed output") from exc
    if not isinstance(document, dict) or set(document) != {
        "block",
        "block_hash",
        "digest",
        "authorization_digest",
        "generated_at",
        "expires_at",
    }:
        raise GuestDeliveryError("snapshot validator output schema is invalid")
    block = document["block"]
    block_hash = document["block_hash"]
    digest = document["digest"]
    authorization_digest = document["authorization_digest"]
    if isinstance(block, bool) or not isinstance(block, int) or block <= 0:
        raise GuestDeliveryError("validated snapshot block is invalid")
    if not isinstance(block_hash, str) or re.fullmatch(r"0x[0-9a-f]{64}", block_hash) is None:
        raise GuestDeliveryError("validated snapshot block hash is invalid")
    _require_digest(digest, label="validated snapshot digest")
    _require_digest(
        authorization_digest, label="validated snapshot authorization digest"
    )
    status = SnapshotStatus(
        block=block,
        block_hash=block_hash,
        digest=digest,
        authorization_digest=authorization_digest,
        generated_at=_parse_utc(document["generated_at"], label="snapshot generated_at"),
        expires_at=_parse_utc(document["expires_at"], label="snapshot expires_at"),
    )
    if not status.fresh(now or datetime.now(UTC)):
        raise GuestDeliveryError("validated snapshot is stale or exceeds 900 seconds")
    return status


def _high_water_document(status: SnapshotStatus) -> bytes:
    return (
        json.dumps(
            {
                "block": status.block,
                "block_hash": status.block_hash,
                "snapshot_digest": status.digest,
                "authorization_digest": status.authorization_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def load_high_water() -> tuple[int, str, str, str] | None:
    try:
        before = HIGH_WATER_PATH.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != 0
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise GuestDeliveryError("snapshot high-water state is not root-owned mode-0600")
    descriptor = os.open(
        HIGH_WATER_PATH,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise GuestDeliveryError("snapshot high-water state changed during read")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > 4096:
        raise GuestDeliveryError("snapshot high-water state is empty or over its bound")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuestDeliveryError("snapshot high-water state is malformed") from exc
    if not isinstance(document, dict) or set(document) != {
        "block",
        "block_hash",
        "snapshot_digest",
        "authorization_digest",
    }:
        raise GuestDeliveryError("snapshot high-water state schema is invalid")
    block = document["block"]
    block_hash = document["block_hash"]
    snapshot_digest = document["snapshot_digest"]
    authorization_digest = document["authorization_digest"]
    if (
        isinstance(block, bool)
        or not isinstance(block, int)
        or block <= 0
        or not isinstance(block_hash, str)
        or re.fullmatch(r"0x[0-9a-f]{64}", block_hash) is None
        or not isinstance(snapshot_digest, str)
        or DIGEST_RE.fullmatch(snapshot_digest) is None
        or not isinstance(authorization_digest, str)
        or DIGEST_RE.fullmatch(authorization_digest) is None
    ):
        raise GuestDeliveryError("snapshot high-water state values are invalid")
    return block, block_hash, snapshot_digest, authorization_digest


def require_not_rollback(
    status: SnapshotStatus, high_water: tuple[int, str, str, str] | None
) -> bool:
    if high_water is None:
        return False
    block, block_hash, _snapshot_digest, authorization_digest = high_water
    if status.block < block:
        raise GuestDeliveryError("snapshot metadata moved below its durable high-water block")
    if status.block == block:
        if (
            status.block_hash != block_hash
            or status.authorization_digest != authorization_digest
        ):
            raise GuestDeliveryError("snapshot metadata equivocated at its high-water block")
        return True
    return False


def install_snapshot(payload: bytes, *, deployment: Deployment) -> SnapshotStatus:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".validator-access.candidate.", dir=CONFIG_DIRECTORY
    )
    candidate = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        status = validate_snapshot(candidate, deployment=deployment)
        high_water = load_high_water()
        require_not_rollback(status, high_water)
        # A finalized block can remain unchanged for more than one refresh.
        # A fresh re-sign with the same block hash and authorization is safe to
        # install, and its digest must replace the prior high-water digest.
        atomic_write(SNAPSHOT_PATH, payload, 0o644)
        atomic_write(HIGH_WATER_PATH, _high_water_document(status), 0o600)
        return status
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass


def _launcher_environment(deployment: Deployment) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SN39_AUDIT_MINER_IMAGE": deployment.image,
        "CATHEDRAL_MINER_HOTKEY": MINER_HOTKEY,
        "CATHEDRAL_PUBLIC_ENDPOINT": deployment.vm.public_endpoint,
        "CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST": deployment.keys_digest,
    }


def start_launcher(deployment: Deployment) -> subprocess.Popen[bytes]:
    metadata = LAUNCHER_PATH.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise GuestDeliveryError("launcher path lost its root-owned executable contract")
    return subprocess.Popen(
        [str(LAUNCHER_PATH)],
        env=_launcher_environment(deployment),
        start_new_session=True,
    )


def _force_remove_named_container() -> None:
    try:
        subprocess.run(
            ["docker", "rm", "--force", CONTAINER_NAME],
            check=False,
            capture_output=True,
            text=True,
            timeout=CONTAINER_REMOVE_TIMEOUT_SECONDS,
        )
        remaining = subprocess.run(
            [
                "docker",
                "ps",
                "--all",
                "--filter",
                f"name=^/{CONTAINER_NAME}$",
                "--format",
                "{{.Names}}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=CONTAINER_REMOVE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise GuestDeliveryError(
            "timed or failed while removing the fixed miner container"
        ) from exc
    if CONTAINER_NAME in remaining.stdout.splitlines():
        raise GuestDeliveryError("fixed miner container remained after forced removal")


def stop_launcher(child: subprocess.Popen[bytes] | None) -> None:
    if child is None or child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=CHILD_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        kill_error: OSError | None = None
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            kill_error = exc
        wait_error: subprocess.TimeoutExpired | None = None
        try:
            child.wait(timeout=CHILD_KILL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            wait_error = exc
        _force_remove_named_container()
        if kill_error is not None:
            raise GuestDeliveryError("failed to kill the launcher process group") from kill_error
        if wait_error is not None:
            raise GuestDeliveryError("launcher did not exit after SIGKILL") from wait_error


def prepare_directories() -> None:
    if os.geteuid() != 0:
        raise GuestDeliveryError("guest poller must run as root")
    for path in (CONFIG_DIRECTORY, STATE_DIRECTORY, RUNTIME_DIRECTORY, LAUNCHER_PATH.parent):
        _require_root_directory(path, create=True)


def _log(message: str) -> None:
    print(f"sn39-gcp-poller: {message}", file=sys.stderr, flush=True)


def run_forever(metadata: MetadataClient | None = None) -> int:
    prepare_directories()
    client = metadata or MetadataClient()
    deployment = load_deployment(client)
    install_static_artifacts(client, deployment)
    ensure_image(deployment.image)

    stopping = threading.Event()

    def request_stop(signum: int, frame: Any) -> None:
        del signum, frame
        stopping.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    child: subprocess.Popen[bytes] | None = None
    accepted: SnapshotStatus | None = None
    accepted_payload_digest: str | None = None
    try:
        if SNAPSHOT_PATH.exists():
            try:
                candidate = validate_snapshot(SNAPSHOT_PATH, deployment=deployment)
                high_water = load_high_water()
                same_height = require_not_rollback(candidate, high_water)
                if (
                    high_water is None
                    or candidate.block > high_water[0]
                    or (same_height and candidate.digest != high_water[2])
                ):
                    # Recover the narrow crash window between replacing the
                    # accepted snapshot and advancing its durable high-water
                    # row, including a same-height fresh re-sign. The signed
                    # installed snapshot is authoritative only after it passes
                    # the same freshness and rollback checks.
                    atomic_write(
                        HIGH_WATER_PATH, _high_water_document(candidate), 0o600
                    )
                accepted = candidate
                accepted_payload_digest = _sha256(SNAPSHOT_PATH.read_bytes())
            except (GuestDeliveryError, OSError) as exc:
                _log(f"existing snapshot refused: {exc}")
        while not stopping.is_set():
            try:
                payload = client.attribute(ATTR_SNAPSHOT)
                payload_digest = _sha256(payload)
                if payload_digest != accepted_payload_digest:
                    candidate = install_snapshot(payload, deployment=deployment)
                    accepted = candidate
                    accepted_payload_digest = payload_digest
                    _log(
                        f"accepted finalized block {candidate.block}; expires "
                        f"{candidate.expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')}"
                    )
            except (GuestDeliveryError, OSError) as exc:
                _log(f"snapshot refresh refused: {exc}")

            now = datetime.now(UTC)
            fresh = accepted is not None and accepted.fresh(now)
            if fresh and child is None:
                child = start_launcher(deployment)
                _log("started the fixed signed-fleet launcher")
            elif not fresh and child is not None:
                _log("snapshot is stale; stopping the signed-fleet launcher")
                stop_launcher(child)
                child = None
            if child is not None and child.poll() is not None:
                code = child.returncode
                child = None
                raise GuestDeliveryError(f"signed-fleet launcher exited unexpectedly: {code}")
            stopping.wait(POLL_SECONDS)
    finally:
        stop_launcher(child)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sn39-gcp-guest-poller", allow_abbrev=False)
    parser.add_argument(
        "--print-policy",
        action="store_true",
        help="print the fixed public guest policy without contacting metadata",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    if options.print_policy:
        print(
            json.dumps(
                {
                    "project": PROJECT_ID,
                    "zone": ZONE,
                    "machine_type": MACHINE_TYPE,
                    "network": NETWORK,
                    "netuid": NETUID,
                    "minimum_stake_rao": MINIMUM_STAKE_RAO,
                    "miner_uid": MINER_UID,
                    "miner_hotkey": MINER_HOTKEY,
                    "vms": VM_PUBLIC_IPS,
                    "snapshot_refresh_seconds": 300,
                    "snapshot_max_validity_seconds": SNAPSHOT_MAX_VALIDITY_SECONDS,
                    "guest_wallet": False,
                    "guest_chain_rpc": False,
                    "guest_private_seed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    try:
        return run_forever()
    except (GuestDeliveryError, OSError, subprocess.SubprocessError) as exc:
        _log(f"fatal refusal: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
