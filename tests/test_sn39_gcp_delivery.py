"""Fixed-policy tests for the bounded SN39 GCP snapshot delivery bridge."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cathedral.policy_registry import canonical_json
from cathedral.validator_access import (
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
    SignedValidatorSnapshotProvider,
    ValidatorAccessState,
    sign_validator_access_snapshot,
    verify_validator_access_snapshot,
)


def _load_script(name: str, filename: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parents[1] / "scripts" / filename
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


poller = _load_script("sn39_gcp_guest_poller_test", "sn39_gcp_guest_poller.py")
publisher = _load_script(
    "sn39_gcp_snapshot_publisher_test", "sn39_gcp_snapshot_publisher.py"
)
producer = _load_script(
    "cathedral_validator_access_delivery_test", "cathedral_validator_access.py"
)

IMAGE = publisher.ACTIVATION_IMAGE
NOW = datetime(2026, 8, 29, 8, 0, 0, tzinfo=UTC)
SNAPSHOT_SEED = b"s" * 32
SNAPSHOT_KEY_ID = "cathedral-validator-access-1"


def _flag_value(command: list[str], flag: str) -> str:
    return command[command.index(flag) + 1]


def _metadata_scalars(command: list[str]) -> dict[str, str]:
    return dict(row.split("=", 1) for row in _flag_value(command, "--metadata").split(","))


def _deployment(vm=None):
    return poller.Deployment(
        vm=vm or poller.VMPolicy(poller.PRIMARY_NAME, poller.PRIMARY_IP),
        image=IMAGE,
        keys_digest="sha256:" + "b" * 64,
        fleet_digest="sha256:" + "c" * 64,
        launcher_digest="sha256:" + "d" * 64,
    )


def _signed_snapshot(*, generated_at: datetime, expires_at: datetime) -> bytes:
    unsigned = {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": "finney",
        "netuid": 39,
        "block": 8_948_557,
        "block_hash": "0x" + "1" * 64,
        "block_is_finalized": True,
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minimum_stake_rao": 0,
        "validators": [
            {
                "hotkey": publisher.UID30_HOTKEY,
                "uid": publisher.UID30,
                "validator_permit": True,
                "stake_rao": 10_684_800_181_193,
            }
        ],
        "signing_key_id": SNAPSHOT_KEY_ID,
    }
    return canonical_json(sign_validator_access_snapshot(unsigned, SNAPSHOT_SEED))


def _instance(vm=publisher.VMS[0]) -> dict[str, object]:
    return {
        "name": vm.name,
        "status": "RUNNING",
        "creationTimestamp": "2026-08-29T08:00:00Z",
        "machineType": f"zones/{publisher.ZONE}/machineTypes/{publisher.MACHINE_TYPE}",
        "confidentialInstanceConfig": {"confidentialInstanceType": "TDX"},
        "scheduling": {
            "automaticRestart": False,
            "onHostMaintenance": "TERMINATE",
            "instanceTerminationAction": "DELETE",
            "maxRunDuration": {"seconds": str(publisher.MAX_RUN_SECONDS)},
        },
        "serviceAccounts": [],
        "disks": [
            {
                "autoDelete": True,
                "diskSizeGb": str(publisher.BOOT_DISK_GB),
                "interface": "NVME",
            }
        ],
        "networkInterfaces": [
            {
                "network": f"projects/{publisher.PROJECT_ID}/global/networks/{publisher.NETWORK}",
                "subnetwork": (
                    f"projects/{publisher.PROJECT_ID}/regions/{publisher.REGION}/subnetworks/"
                    f"{publisher.SUBNET}"
                ),
                "accessConfigs": [{"natIP": vm.public_ip}],
            }
        ],
        "tags": {"items": [publisher.NETWORK_TAG]},
        "metadata": {
            "items": [
                {"key": publisher.ATTR_BLOCK_PROJECT_SSH_KEYS, "value": "true"},
                {"key": publisher.ATTR_IMAGE, "value": IMAGE},
                {"key": publisher.ATTR_MINER_HOTKEY, "value": publisher.MINER_HOTKEY},
                {"key": publisher.ATTR_PUBLIC_ENDPOINT, "value": vm.public_endpoint},
            ]
        },
        "deletionProtection": False,
    }


def test_plan_is_no_write_and_fully_bounded(capsys, monkeypatch):
    monkeypatch.setattr(
        publisher.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("plan contacted an external command"),
    )

    assert publisher.main(["plan"]) == 0
    document = json.loads(capsys.readouterr().out)

    assert document["cloud_writes"] is False
    assert document["project"] == "polaris-tdx-attest"
    assert document["zone"] == "us-central1-b"
    assert document["firewall"] == {"ingress": "tcp:8081", "ssh": False}
    assert document["machine"] == {
        "base_image": "polaris-attest-base",
        "base_image_id": "3355993504309639309",
        "boot_disk_gb": 20,
        "confidential_compute": "TDX",
        "max_run_seconds": 14_400,
        "service_account": None,
        "termination_action": "DELETE",
        "type": "c3-standard-4",
    }
    assert document["miner"] == {
        "uid": 124,
        "hotkey": publisher.MINER_HOTKEY,
    }
    assert document["activation_image"] == IMAGE
    operations = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "SN39_AUDIT_MINER_OPERATIONS.md"
    ).read_text()
    assert "Source merge: 78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8" in operations
    assert IMAGE in operations
    assert "9fa697989089ba87c0aa798f2c4f3f525d428958" not in operations
    assert document["validator_access"] == {
        "network": "finney",
        "netuid": 39,
        "minimum_stake_rao": 0,
        "required_uid": 30,
        "required_hotkey": publisher.UID30_HOTKEY,
        "valid_seconds": 900,
        "refresh_seconds": 300,
        "maximum_cycles": 48,
    }
    assert document["guest_secrets"] == []
    assert document["guest_wallet"] is False
    assert document["guest_chain_rpc"] is False
    assert [(row["name"], row["static_ip"]) for row in document["vms"]] == [
        (publisher.PRIMARY_NAME, publisher.PRIMARY_IP),
        (publisher.SECONDARY_NAME, publisher.SECONDARY_IP),
    ]


def test_primary_only_plan_is_no_write_and_names_only_uid124_primary(
    capsys, monkeypatch
):
    monkeypatch.setattr(
        publisher.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("plan contacted an external command"),
    )

    assert publisher.main(["plan-primary-only"]) == 0
    document = json.loads(capsys.readouterr().out)

    assert document["cloud_writes"] is False
    assert document["operator_mode"] == "primary_only"
    assert document["cost_estimate"] == {
        "as_of": "2026-08-30",
        "currency": "USD",
        "kind": "conservative_planning_estimate_not_a_spend_cap",
        "per_selected_guest_four_hours_usd": 1.0,
        "selected_guest_count": 1,
        "selected_guests_four_hours_usd": 1.0,
        "includes": [
            "on_demand_c3_standard_4",
            "intel_tdx_surcharge",
            "20_gib_pd_balanced_boot_disk",
            "in_use_external_ipv4",
        ],
        "excludes": [
            "network_egress",
            "taxes",
            "reserved_address_time_outside_the_vm_window",
        ],
        "operator_hard_cap_usd": 20.0,
        "operator_hard_cap_enforced_by_script": False,
    }
    assert document["machine"]["confidential_compute"] == "TDX"
    assert document["machine"]["max_run_seconds"] == 14_400
    assert document["machine"]["termination_action"] == "DELETE"
    assert document["activation_image"] == IMAGE
    assert document["vms"] == [
        {
            "name": publisher.PRIMARY_NAME,
            "static_ip": "35.222.166.235",
            "public_endpoint": "https://35.222.166.235:8081",
            "fleet_candidates_beyond_self": [],
        }
    ]
    assert publisher.SECONDARY_NAME not in json.dumps(document)
    assert publisher.SECONDARY_IP not in json.dumps(document)


def test_fleet_manifests_pin_exact_uid124_topology():
    primary = json.loads(publisher.fleet_bytes(publisher.VMS[0]))
    secondary = json.loads(publisher.fleet_bytes(publisher.VMS[1]))

    assert primary == {
        "schema": "cathedral_worker_fleet_v1",
        "worker_hotkey": publisher.MINER_HOTKEY,
        "endpoints": [f"https://{publisher.SECONDARY_IP}:8081"],
    }
    assert secondary == {
        "schema": "cathedral_worker_fleet_v1",
        "worker_hotkey": publisher.MINER_HOTKEY,
        "endpoints": [],
    }


def test_primary_only_fleet_bytes_are_canonical_and_singleton():
    payload = publisher.fleet_bytes(publisher.PRIMARY_ONLY_VMS[0])

    assert payload == (
        b'{"endpoints":[],"schema":"cathedral_worker_fleet_v1",'
        b'"worker_hotkey":"'
        + publisher.MINER_HOTKEY.encode("ascii")
        + b'"}'
    )
    assert publisher.SECONDARY_IP.encode("ascii") not in payload
    assert payload != publisher.fleet_bytes(publisher.VMS[0])


def test_capture_command_is_fixed_to_finalized_uid30_policy(tmp_path):
    command = publisher.capture_command(
        signing_key=tmp_path / "public-snapshot.seed",
        signing_key_id="cathedral-validator-access-1",
        output=tmp_path / "snapshot.json",
    )

    assert _flag_value(command, "--network") == "finney"
    assert _flag_value(command, "--netuid") == "39"
    assert _flag_value(command, "--minimum-stake-rao") == "0"
    assert _flag_value(command, "--valid-seconds") == "900"
    assert _flag_value(command, "--max-age-seconds") == "900"
    assert _flag_value(command, "--require-hotkey") == publisher.UID30_HOTKEY
    required_mappings = [
        command[index + 1]
        for index, value in enumerate(command)
        if value == "--require-uid-hotkey"
    ]
    assert required_mappings == [
        f"30={publisher.UID30_HOTKEY}",
        f"124={publisher.MINER_HOTKEY}",
    ]
    assert not any("wallet" in value.lower() or "password" in value.lower() for value in command)


def test_snapshot_producer_refuses_changed_uid30_or_uid124_mapping(tmp_path, monkeypatch):
    seed = tmp_path / "validator-access.seed"
    seed.write_text(base64.b64encode(b"s" * 32).decode("ascii") + "\n")
    seed.chmod(0o600)
    output = tmp_path / "snapshot.json"
    neurons = [
        SimpleNamespace(
            uid=30,
            hotkey=publisher.UID30_HOTKEY,
            validator_permit=True,
            total_stake=SimpleNamespace(rao=1),
        ),
        SimpleNamespace(
            uid=124,
            hotkey="5Ct2DBJPULeQxGmFiKrpGvvWuYVxgYEX8tRfNjWYRga8VRbq",
            validator_permit=False,
            total_stake=SimpleNamespace(rao=0),
        ),
    ]
    monkeypatch.setattr(
        producer,
        "_finalized_neurons",
        lambda _network, _netuid: (8_948_557, "0x" + "1" * 64, neurons),
    )
    command = [
        "capture",
        "--network",
        "finney",
        "--netuid",
        "39",
        "--minimum-stake-rao",
        "0",
        "--signing-key-id",
        "cathedral-validator-access-1",
        "--signing-key-file",
        str(seed),
        "--out",
        str(output),
        "--require-hotkey",
        publisher.UID30_HOTKEY,
        "--require-uid-hotkey",
        f"30={publisher.UID30_HOTKEY}",
        "--require-uid-hotkey",
        f"124={publisher.MINER_HOTKEY}",
    ]

    with pytest.raises(SystemExit, match="required finalized UID mapping changed"):
        producer.main(command)
    assert not output.exists()


def test_create_command_pins_every_public_guest_input(tmp_path):
    keys = tmp_path / "snapshot-keys.json"
    keys.write_text('{"cathedral-validator-access-1":"public"}')
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}")
    fleet = tmp_path / "fleet.json"
    fleet.write_bytes(publisher.fleet_bytes(publisher.VMS[0]))
    pins = {
        "keys_digest": publisher._sha256(keys.read_bytes()),
        "launcher_digest": publisher._sha256(publisher.LAUNCHER.read_bytes()),
        "poller_digest": publisher._sha256(publisher.POLLER.read_bytes()),
    }

    command = publisher.create_instance_command(
        publisher.VMS[0],
        image=IMAGE,
        keys_file=keys,
        snapshot=snapshot,
        fleet_file=fleet,
        pins=pins,
    )

    assert command[:5] == [
        "gcloud",
        "compute",
        "instances",
        "create",
        publisher.PRIMARY_NAME,
    ]
    expected_flags = {
        "--confidential-compute-type": "TDX",
        "--machine-type": "c3-standard-4",
        "--max-run-duration": "4h",
        "--instance-termination-action": "DELETE",
        "--boot-disk-size": "20GB",
        "--boot-disk-interface": "NVME",
        "--project": publisher.PROJECT_ID,
        "--zone": publisher.ZONE,
    }
    for flag, value in expected_flags.items():
        assert _flag_value(command, flag) == value
    for flag in (
        "--no-restart-on-failure",
        "--boot-disk-auto-delete",
        "--no-service-account",
        "--no-scopes",
        "--quiet",
    ):
        assert flag in command
    assert publisher.PRIMARY_ADDRESS in _flag_value(command, "--network-interface")
    scalars = _metadata_scalars(command)
    assert scalars[publisher.ATTR_BLOCK_PROJECT_SSH_KEYS] == "true"
    assert scalars[publisher.ATTR_IMAGE] == IMAGE
    assert scalars[publisher.ATTR_MINER_HOTKEY] == publisher.MINER_HOTKEY
    assert scalars[publisher.ATTR_PUBLIC_ENDPOINT] == publisher.VMS[0].public_endpoint
    assert scalars[publisher.ATTR_KEYS_DIGEST] == pins["keys_digest"]
    assert scalars[publisher.ATTR_LAUNCHER_DIGEST] == pins["launcher_digest"]
    assert scalars[publisher.ATTR_POLLER_DIGEST] == pins["poller_digest"]
    metadata_files = dict(
        row.split("=", 1) for row in _flag_value(command, "--metadata-from-file").split(",")
    )
    assert set(metadata_files) == {
        "startup-script",
        publisher.ATTR_POLLER,
        publisher.ATTR_LAUNCHER,
        publisher.ATTR_KEYS,
        publisher.ATTR_FLEET,
        publisher.ATTR_SNAPSHOT,
    }
    joined = " ".join(command).lower()
    assert "wallet" not in joined
    assert "rpc" not in joined
    assert "password" not in joined


def test_snapshot_update_changes_only_one_public_metadata_value(tmp_path):
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}")
    command = publisher.snapshot_update_command(
        publisher.VMS[0],
        snapshot,
        instance=_instance(publisher.VMS[0]),
    )

    assert command == [
        "gcloud",
        "compute",
        "instances",
        "add-metadata",
        publisher.PRIMARY_NAME,
        "--project",
        publisher.PROJECT_ID,
        "--zone",
        publisher.ZONE,
        "--metadata-from-file",
        f"{publisher.ATTR_SNAPSHOT}={snapshot}",
        "--quiet",
    ]


def test_metadata_limits_refuse_before_cloud_command_is_built(tmp_path):
    keys = tmp_path / "keys.json"
    snapshot = tmp_path / "snapshot.json"
    fleet = tmp_path / "fleet.json"
    fleet.write_bytes(publisher.fleet_bytes(publisher.VMS[0]))
    pins = {
        "keys_digest": "sha256:" + "1" * 64,
        "launcher_digest": publisher._sha256(publisher.LAUNCHER.read_bytes()),
        "poller_digest": publisher._sha256(publisher.POLLER.read_bytes()),
    }

    keys.write_bytes(b"k" * (publisher.METADATA_VALUE_LIMIT_BYTES + 1))
    snapshot.write_bytes(b"{}")
    with pytest.raises(publisher.PublisherError, match="256 KiB"):
        publisher.create_instance_command(
            publisher.VMS[0],
            image=IMAGE,
            keys_file=keys,
            snapshot=snapshot,
            fleet_file=fleet,
            pins=pins,
        )

    keys.write_bytes(b"k" * (240 * 1024))
    snapshot.write_bytes(b"s" * (240 * 1024))
    with pytest.raises(publisher.PublisherError, match="512 KiB"):
        publisher.create_instance_command(
            publisher.VMS[0],
            image=IMAGE,
            keys_file=keys,
            snapshot=snapshot,
            fleet_file=fleet,
            pins=pins,
        )

    existing = _instance(publisher.VMS[0])
    existing["metadata"]["items"].append(
        {"key": "bounded-extra", "value": "x" * (250 * 1024)}
    )
    existing["metadata"]["items"].append(
        {"key": "bounded-extra-two", "value": "y" * (15 * 1024)}
    )
    snapshot.write_bytes(b"s" * (250 * 1024))
    with pytest.raises(publisher.PublisherError, match="512 KiB"):
        publisher.snapshot_update_command(
            publisher.VMS[0], snapshot, instance=existing
        )


class _Metadata:
    def __init__(self, *, name=poller.PRIMARY_NAME, image=IMAGE):
        self.scalars = {
            "project/project-id": poller.PROJECT_ID,
            "instance/name": name,
            "instance/zone": f"projects/1/zones/{poller.ZONE}",
            "instance/machine-type": f"projects/1/machineTypes/{poller.MACHINE_TYPE}",
            "instance/network-interfaces/0/access-configs/0/external-ip": (
                poller.VM_PUBLIC_IPS[name]
            ),
        }
        vm = poller.VMPolicy(name, poller.VM_PUBLIC_IPS[name])
        self.attributes = {
            poller.ATTR_IMAGE: image,
            poller.ATTR_MINER_HOTKEY: poller.MINER_HOTKEY,
            poller.ATTR_PUBLIC_ENDPOINT: vm.public_endpoint,
            poller.ATTR_KEYS_DIGEST: "sha256:" + "b" * 64,
            poller.ATTR_FLEET_DIGEST: "sha256:" + "c" * 64,
            poller.ATTR_LAUNCHER_DIGEST: "sha256:" + "d" * 64,
        }

    def text(self, path: str) -> str:
        return self.scalars[path]

    def attribute_text(self, name: str) -> str:
        return self.attributes[name]


def test_guest_deployment_accepts_only_fixed_identity_and_digest_image():
    deployment = poller.load_deployment(_Metadata())

    assert deployment == _deployment()

    wrong_project = _Metadata()
    wrong_project.scalars["project/project-id"] = "other"
    with pytest.raises(poller.GuestDeliveryError, match="pinned GCP project"):
        poller.load_deployment(wrong_project)

    wrong_image = _Metadata(image=publisher.IMAGE_REPOSITORY + ":latest")
    with pytest.raises(poller.GuestDeliveryError, match="activation digest"):
        poller.load_deployment(wrong_image)

    wrong_ip = _Metadata()
    wrong_ip.scalars[
        "instance/network-interfaces/0/access-configs/0/external-ip"
    ] = "203.0.113.1"
    with pytest.raises(poller.GuestDeliveryError, match="pinned static IP"):
        poller.load_deployment(wrong_ip)


def test_guest_fleet_policy_is_exact_for_both_machines():
    primary = poller.VMPolicy(poller.PRIMARY_NAME, poller.PRIMARY_IP)
    secondary = poller.VMPolicy(poller.SECONDARY_NAME, poller.SECONDARY_IP)
    poller._validate_fleet(publisher.fleet_bytes(publisher.VMS[0]), primary)
    poller._validate_fleet(publisher.fleet_bytes(publisher.VMS[1]), secondary)

    wrong = json.loads(publisher.fleet_bytes(publisher.VMS[0]))
    wrong["endpoints"] = []
    with pytest.raises(poller.GuestDeliveryError, match="two-machine policy"):
        poller._validate_fleet(json.dumps(wrong).encode(), primary)


def test_snapshot_freshness_has_exact_900_second_bounds():
    status = poller.SnapshotStatus(
        block=1,
        block_hash="0x" + "1" * 64,
        digest="sha256:" + "2" * 64,
        authorization_digest="sha256:" + "5" * 64,
        generated_at=NOW,
        expires_at=NOW + timedelta(seconds=900),
    )

    assert status.fresh(NOW)
    assert status.fresh(NOW + timedelta(seconds=899))
    assert not status.fresh(NOW + timedelta(seconds=900))
    assert not status.fresh(NOW - timedelta(seconds=1))
    assert not poller.SnapshotStatus(
        block=status.block,
        block_hash=status.block_hash,
        digest=status.digest,
        authorization_digest=status.authorization_digest,
        generated_at=NOW,
        expires_at=NOW + timedelta(seconds=901),
    ).fresh(NOW)


def test_snapshot_high_water_rejects_rollback_and_same_height_equivocation():
    high_water = (
        100,
        "0x" + "1" * 64,
        "sha256:" + "2" * 64,
        "sha256:" + "5" * 64,
    )
    same = poller.SnapshotStatus(
        block=100,
        block_hash=high_water[1],
        digest=high_water[2],
        authorization_digest=high_water[3],
        generated_at=NOW,
        expires_at=NOW + timedelta(seconds=900),
    )
    poller.require_not_rollback(same, high_water)
    resigned = poller.SnapshotStatus(
        block=100,
        block_hash=high_water[1],
        digest="sha256:" + "9" * 64,
        authorization_digest=high_water[3],
        generated_at=NOW,
        expires_at=NOW + timedelta(seconds=900),
    )
    assert poller.require_not_rollback(resigned, high_water) is True
    poller.require_not_rollback(
        poller.SnapshotStatus(
            block=101,
            block_hash="0x" + "3" * 64,
            digest="sha256:" + "4" * 64,
            authorization_digest="sha256:" + "6" * 64,
            generated_at=NOW,
            expires_at=NOW + timedelta(seconds=900),
        ),
        high_water,
    )

    with pytest.raises(poller.GuestDeliveryError, match="below"):
        poller.require_not_rollback(
            poller.SnapshotStatus(
                block=99,
                block_hash="0x" + "3" * 64,
                digest="sha256:" + "4" * 64,
                authorization_digest="sha256:" + "6" * 64,
                generated_at=NOW,
                expires_at=NOW + timedelta(seconds=900),
            ),
            high_water,
        )
    with pytest.raises(poller.GuestDeliveryError, match="equivocated"):
        poller.require_not_rollback(
            poller.SnapshotStatus(
                block=100,
                block_hash="0x" + "3" * 64,
                digest="sha256:" + "4" * 64,
                authorization_digest="sha256:" + "6" * 64,
                generated_at=NOW,
                expires_at=NOW + timedelta(seconds=900),
            ),
            high_water,
        )


def test_same_height_resign_installs_fresh_bytes_and_advances_digest(
    tmp_path, monkeypatch
):
    config = tmp_path / "config"
    config.mkdir()
    installed_path = config / "validator-access.json"
    installed_path.write_bytes(b"installed-snapshot")
    incoming = poller.SnapshotStatus(
        block=100,
        block_hash="0x" + "1" * 64,
        digest="sha256:" + "9" * 64,
        authorization_digest="sha256:" + "5" * 64,
        generated_at=NOW,
        expires_at=NOW + timedelta(seconds=900),
    )
    old_digest = "sha256:" + "2" * 64
    high_water_path = tmp_path / "high-water.json"
    monkeypatch.setattr(poller, "CONFIG_DIRECTORY", config)
    monkeypatch.setattr(poller, "SNAPSHOT_PATH", installed_path)
    monkeypatch.setattr(poller, "HIGH_WATER_PATH", high_water_path)
    monkeypatch.setattr(
        poller,
        "load_high_water",
        lambda: (
            incoming.block,
            incoming.block_hash,
            old_digest,
            incoming.authorization_digest,
        ),
    )
    monkeypatch.setattr(
        poller,
        "validate_snapshot",
        lambda path, **_kwargs: incoming,
    )

    writes = []

    def write(path, payload, mode):
        writes.append((path, payload, mode))
        path.write_bytes(payload)

    monkeypatch.setattr(
        poller,
        "atomic_write",
        write,
    )

    accepted = poller.install_snapshot(b"resigned-snapshot", deployment=_deployment())

    assert accepted == incoming
    assert installed_path.read_bytes() == b"resigned-snapshot"
    assert [row[0] for row in writes] == [installed_path, high_water_path]
    assert json.loads(high_water_path.read_bytes())["snapshot_digest"] == incoming.digest


def test_same_height_resign_remains_served_after_prior_snapshot_expires(
    tmp_path: Path, monkeypatch
):
    config = tmp_path / "config"
    config.mkdir()
    installed_path = config / "validator-access.json"
    high_water_path = tmp_path / "metadata-high-water.json"
    provider_state_path = tmp_path / "provider-state.sqlite"
    first_payload = _signed_snapshot(
        generated_at=NOW,
        expires_at=NOW + timedelta(seconds=60),
    )
    resign_time = NOW + timedelta(seconds=60)
    resigned_payload = _signed_snapshot(
        generated_at=resign_time,
        expires_at=resign_time + timedelta(seconds=900),
    )
    public_key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    trusted_keys = {SNAPSHOT_KEY_ID: public_key}
    verification_time = [NOW]
    high_water: list[tuple[int, str, str, str] | None] = [None]

    def validate(path: Path, **_kwargs) -> poller.SnapshotStatus:
        snapshot = verify_validator_access_snapshot(
            path.read_bytes(),
            trusted_keys,
            network="finney",
            netuid=39,
            required_minimum_stake_rao=0,
            now=verification_time[0],
            max_age_seconds=900,
        )
        return poller.SnapshotStatus(
            block=snapshot.block,
            block_hash=snapshot.block_hash,
            digest=snapshot.digest,
            authorization_digest=snapshot.authorization_digest,
            generated_at=snapshot.generated_at,
            expires_at=snapshot.expires_at,
        )

    def write(path: Path, payload: bytes, mode: int) -> None:
        del mode
        path.write_bytes(payload)
        if path == high_water_path:
            document = json.loads(payload)
            high_water[0] = (
                document["block"],
                document["block_hash"],
                document["snapshot_digest"],
                document["authorization_digest"],
            )

    monkeypatch.setattr(poller, "CONFIG_DIRECTORY", config)
    monkeypatch.setattr(poller, "SNAPSHOT_PATH", installed_path)
    monkeypatch.setattr(poller, "HIGH_WATER_PATH", high_water_path)
    monkeypatch.setattr(poller, "validate_snapshot", validate)
    monkeypatch.setattr(poller, "load_high_water", lambda: high_water[0])
    monkeypatch.setattr(poller, "atomic_write", write)

    first_status = poller.install_snapshot(first_payload, deployment=_deployment())
    provider = SignedValidatorSnapshotProvider(
        str(installed_path),
        trusted_keys,
        network="finney",
        netuid=39,
        minimum_stake_rao=0,
        state=ValidatorAccessState(str(provider_state_path)),
        max_age_seconds=900,
    )
    first = provider.load(now=NOW)
    assert first is not None
    assert first.digest == first_status.digest

    verification_time[0] = resign_time
    resigned_status = poller.install_snapshot(resigned_payload, deployment=_deployment())
    served = provider.load(now=resign_time)

    assert first.expires_at == resign_time
    assert resigned_status.digest != first_status.digest
    assert resigned_status.authorization_digest == first_status.authorization_digest
    assert served is not None
    assert served.digest == resigned_status.digest
    assert served.qualifies(publisher.UID30_HOTKEY, at=resign_time)


def test_snapshot_validation_runs_inside_pinned_isolated_image(tmp_path, monkeypatch):
    candidate = tmp_path / "validator-access.json"
    candidate.write_text("{}")
    keys = tmp_path / "snapshot-keys.json"
    keys.write_text("{}")
    monkeypatch.setattr(poller, "KEYS_PATH", keys)
    observed: list[str] = []

    def fake_run(command, **kwargs):
        observed.extend(command)
        assert kwargs["check"] is True
        assert kwargs["timeout"] == poller.VALIDATOR_TIMEOUT_SECONDS
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "block": 8_948_557,
                    "block_hash": "0x" + "1" * 64,
                    "digest": "sha256:" + "2" * 64,
                    "authorization_digest": "sha256:" + "5" * 64,
                    "generated_at": "2026-08-29T07:55:00Z",
                    "expires_at": "2026-08-29T08:10:00Z",
                }
            )
        )

    monkeypatch.setattr(poller.subprocess, "run", fake_run)
    status = poller.validate_snapshot(candidate, deployment=_deployment(), now=NOW)

    assert status.block == 8_948_557
    assert _flag_value(observed, "--network") == "none"
    assert "--read-only" in observed
    assert _flag_value(observed, "--cap-drop") == "ALL"
    assert _deployment().image in observed
    assert poller.UID30_HOTKEY in observed
    assert str(poller.UID30) in observed
    assert "bittensor" not in " ".join(observed).lower()


def test_instance_verifier_rejects_unbounded_or_accessible_guests():
    accepted = _instance()
    publisher.verify_instance(accepted, publisher.VMS[0], image=IMAGE)

    with_service_account = copy.deepcopy(accepted)
    with_service_account["serviceAccounts"] = [{"email": "unexpected@example.invalid"}]
    with pytest.raises(publisher.PublisherError, match="service account"):
        publisher.verify_instance(with_service_account, publisher.VMS[0], image=IMAGE)

    eight_hours = copy.deepcopy(accepted)
    eight_hours["scheduling"]["maxRunDuration"]["seconds"] = "28800"
    with pytest.raises(publisher.PublisherError, match="four-hour"):
        publisher.verify_instance(eight_hours, publisher.VMS[0], image=IMAGE)

    project_ssh_allowed = copy.deepcopy(accepted)
    project_ssh_allowed["metadata"]["items"][0]["value"] = "FALSE"
    with pytest.raises(publisher.PublisherError, match="runtime metadata"):
        publisher.verify_instance(project_ssh_allowed, publisher.VMS[0], image=IMAGE)

    ssh_key = copy.deepcopy(accepted)
    ssh_key["metadata"]["items"].append({"key": "ssh-keys", "value": "user:key"})
    with pytest.raises(publisher.PublisherError, match="SSH access"):
        publisher.verify_instance(ssh_key, publisher.VMS[0], image=IMAGE)


def test_guest_readiness_requires_both_fixed_tls_endpoints(monkeypatch):
    observed = []
    monkeypatch.setattr(
        publisher,
        "_guest_tls_ready",
        lambda vm, _context: observed.append(vm.name) or True,
    )

    publisher.wait_for_guest_tls()

    assert observed == [publisher.PRIMARY_NAME, publisher.SECONDARY_NAME]


def test_instance_window_discovery_retries_one_transient_read(capsys, monkeypatch):
    instances = {vm.name: _instance(vm) for vm in publisher.VMS}
    attempts = []
    sleeps = []

    def verify(**_kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise publisher.PublisherError("temporary gcloud read failure")
        return instances

    monkeypatch.setattr(publisher, "verify_running_instances", verify)
    monkeypatch.setattr(publisher.time, "sleep", sleeps.append)

    assert publisher.discover_instance_window_deadline(image=IMAGE) == NOW + timedelta(
        seconds=publisher.MAX_RUN_SECONDS
    )
    refusal = json.loads(capsys.readouterr().err)
    assert refusal["status"] == "REFUSED_WINDOW_DISCOVERY"
    assert refusal["attempt"] == 1
    assert refusal["will_retry"] is True
    assert attempts == [True, True]
    assert sleeps == [publisher.WINDOW_DISCOVERY_RETRY_SECONDS]


def test_publish_loop_retries_refused_cycle_and_finishes_bounded_window(
    capsys, monkeypatch
):
    instances = {vm.name: _instance(vm) for vm in publisher.VMS}
    attempts = []
    sleeps = []
    clock = iter(
        [
            NOW,
            NOW,
            NOW + timedelta(seconds=300),
            NOW + timedelta(seconds=300),
        ]
    )

    monkeypatch.setattr(publisher, "SNAPSHOT_REFRESH_CYCLES", 2)
    monkeypatch.setattr(publisher, "validate_inputs", lambda **_kwargs: {})
    monkeypatch.setattr(
        publisher, "verify_running_instances", lambda **_kwargs: instances
    )
    monkeypatch.setattr(publisher, "_utc_now", lambda: next(clock))
    monkeypatch.setattr(publisher.time, "sleep", sleeps.append)

    def publish(**_kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise publisher.PublisherError("temporary finalized read failure")

    monkeypatch.setattr(publisher, "publish_once", publish)

    publisher.publish_loop(
        signing_key=Path("/not-opened.seed"),
        signing_key_id="cathedral-validator-access-1",
        keys_file=Path("/not-opened.json"),
        image=IMAGE,
    )

    captured = capsys.readouterr()
    refusal = json.loads(captured.err)
    output = [json.loads(row) for row in captured.out.splitlines()]
    assert refusal["status"] == "REFUSED_CYCLE"
    assert refusal["cycle"] == 1
    assert refusal["consecutive_failures"] == 1
    assert refusal["will_retry"] is True
    assert len(attempts) == 2
    assert sleeps == [publisher.SNAPSHOT_REFRESH_SECONDS]
    assert output[0]["status"] == "PUBLISHED"
    assert output[0]["cycle"] == 2
    assert output[1] == {
        "cycles_attempted": 2,
        "instance_window_deadline": "2026-08-29T12:00:00Z",
        "next_refresh_seconds": None,
        "reason": "maximum_cycles_reached",
        "status": "INSTANCE_WINDOW_COMPLETE",
    }


def test_publish_loop_does_not_schedule_past_earliest_instance_deadline(
    capsys, monkeypatch
):
    primary = _instance(publisher.VMS[0])
    secondary = _instance(publisher.VMS[1])
    secondary["creationTimestamp"] = "2026-08-29T08:01:00Z"
    instances = {
        publisher.PRIMARY_NAME: primary,
        publisher.SECONDARY_NAME: secondary,
    }
    near_deadline = NOW + timedelta(seconds=publisher.MAX_RUN_SECONDS - 200)
    attempts = []

    monkeypatch.setattr(publisher, "validate_inputs", lambda **_kwargs: {})
    monkeypatch.setattr(
        publisher, "verify_running_instances", lambda **_kwargs: instances
    )
    monkeypatch.setattr(publisher, "_utc_now", lambda: near_deadline)
    monkeypatch.setattr(
        publisher.time,
        "sleep",
        lambda _seconds: pytest.fail("publisher slept past the instance window"),
    )
    monkeypatch.setattr(
        publisher, "publish_once", lambda **_kwargs: attempts.append(True)
    )

    publisher.publish_loop(
        signing_key=Path("/not-opened.seed"),
        signing_key_id="cathedral-validator-access-1",
        keys_file=Path("/not-opened.json"),
        image=IMAGE,
    )

    output = [json.loads(row) for row in capsys.readouterr().out.splitlines()]
    assert attempts == [True]
    assert output[0]["status"] == "PUBLISHED"
    assert output[0]["next_refresh_seconds"] is None
    assert output[1]["status"] == "INSTANCE_WINDOW_COMPLETE"
    assert output[1]["reason"] == "next_refresh_reaches_instance_deadline"
    assert output[1]["instance_window_deadline"] == "2026-08-29T12:00:00Z"


def test_startup_rollback_refusal_never_becomes_accepted(tmp_path, monkeypatch):
    snapshot = tmp_path / "validator-access.json"
    snapshot.write_bytes(b"refused-snapshot")
    now = datetime.now(UTC)
    refused = poller.SnapshotStatus(
        block=100,
        block_hash="0x" + "9" * 64,
        digest="sha256:" + "8" * 64,
        authorization_digest="sha256:" + "7" * 64,
        generated_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=899),
    )

    class OneCycleEvent:
        def __init__(self):
            self.finished = False

        def is_set(self):
            return self.finished

        def set(self):
            self.finished = True

        def wait(self, _seconds):
            self.finished = True

    class RefusingMetadata:
        def attribute(self, _name):
            raise poller.GuestDeliveryError("metadata unavailable")

    monkeypatch.setattr(poller, "SNAPSHOT_PATH", snapshot)
    monkeypatch.setattr(poller, "prepare_directories", lambda: None)
    monkeypatch.setattr(poller, "load_deployment", lambda _client: _deployment())
    monkeypatch.setattr(poller, "install_static_artifacts", lambda *_args: None)
    monkeypatch.setattr(poller, "ensure_image", lambda _image: None)
    monkeypatch.setattr(poller, "validate_snapshot", lambda *_args, **_kwargs: refused)
    monkeypatch.setattr(
        poller,
        "load_high_water",
        lambda: (
            refused.block,
            "0x" + "1" * 64,
            "sha256:" + "2" * 64,
            refused.authorization_digest,
        ),
    )
    monkeypatch.setattr(poller.threading, "Event", OneCycleEvent)
    monkeypatch.setattr(poller.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(
        poller,
        "start_launcher",
        lambda _deployment: pytest.fail("refused startup snapshot launched the miner"),
    )

    assert poller.run_forever(RefusingMetadata()) == 0


def test_hung_launcher_force_removes_container_and_bounds_second_wait(monkeypatch):
    class HungChild:
        returncode = None
        pid = 4321

        def __init__(self):
            self.waits = []
            self.terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            self.waits.append(timeout)
            raise poller.subprocess.TimeoutExpired("launcher", timeout)

    child = HungChild()
    commands = []
    killed_groups = []

    def run(command, **kwargs):
        commands.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(poller.subprocess, "run", run)
    monkeypatch.setattr(
        poller.os,
        "killpg",
        lambda pid, signum: killed_groups.append((pid, signum)),
    )

    with pytest.raises(poller.GuestDeliveryError, match="did not exit after SIGKILL"):
        poller.stop_launcher(child)

    assert child.terminated is True
    assert killed_groups == [(child.pid, poller.signal.SIGKILL)]
    assert child.waits == [
        poller.CHILD_STOP_TIMEOUT_SECONDS,
        poller.CHILD_KILL_TIMEOUT_SECONDS,
    ]
    assert commands[0][0] == [
        "docker",
        "rm",
        "--force",
        poller.CONTAINER_NAME,
    ]
    assert commands[0][1]["timeout"] == poller.CONTAINER_REMOVE_TIMEOUT_SECONDS
    assert commands[1][0][:3] == ["docker", "ps", "--all"]


def test_hung_launcher_reports_bounded_container_removal_timeout(monkeypatch):
    child = SimpleNamespace(
        pid=4321,
        poll=lambda: None,
        terminate=lambda: None,
        wait=lambda timeout: (
            None
            if timeout == poller.CHILD_KILL_TIMEOUT_SECONDS
            else (_ for _ in ()).throw(
                poller.subprocess.TimeoutExpired("launcher", timeout)
            )
        ),
    )

    def timeout(command, **kwargs):
        raise poller.subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(poller.subprocess, "run", timeout)
    monkeypatch.setattr(poller.os, "killpg", lambda *_args: None)

    with pytest.raises(poller.GuestDeliveryError, match="removing"):
        poller.stop_launcher(child)


def test_partial_cloud_write_error_reports_confirmed_and_ambiguous_state(
    capsys, monkeypatch, tmp_path
):
    def partial(**_kwargs):
        raise publisher.PublisherError(
            "second create returned failure",
            completed_cloud_writes=(f"created instance {publisher.PRIMARY_NAME}",),
            ambiguous_cloud_write=f"create instance {publisher.SECONDARY_NAME}",
        )

    monkeypatch.setattr(publisher, "provision", partial)
    code = publisher.main(
        [
            "provision",
            "--signing-key-file",
            "/not-opened.seed",
            "--keys-file",
            "/not-opened.json",
            "--image",
            IMAGE,
            "--acknowledge",
            publisher.PROVISION_ACK,
        ]
    )

    assert code == 2
    report = json.loads(capsys.readouterr().err)
    assert report["cloud_write_state"] == "AMBIGUOUS"
    assert report["completed_cloud_writes"] == [
        f"created instance {publisher.PRIMARY_NAME}"
    ]
    assert report["ambiguous_cloud_write"] == (
        f"create instance {publisher.SECONDARY_NAME}"
    )
    assert "cloud_write_completed" not in report

    monkeypatch.setattr(
        publisher,
        "verify_running_instances",
        lambda **_kwargs: {vm.name: _instance(vm) for vm in publisher.VMS},
    )
    monkeypatch.setattr(publisher, "capture_snapshot", lambda **_kwargs: None)
    observed = []

    def update_command(vm, _snapshot, *, instance):
        assert instance["name"] == vm.name
        if vm == publisher.VMS[1]:
            raise publisher.PublisherError("combined metadata exceeds its bound")
        return ["gcloud", "update", vm.name]

    monkeypatch.setattr(publisher, "snapshot_update_command", update_command)
    monkeypatch.setattr(
        publisher.subprocess,
        "run",
        lambda command, **_kwargs: observed.append(command),
    )
    with pytest.raises(publisher.PublisherError) as refused:
        publisher.publish_once(
            signing_key=tmp_path / "unused.seed",
            signing_key_id="cathedral-validator-access-1",
            keys_file=tmp_path / "unused-keys.json",
            snapshot=tmp_path / "snapshot.json",
            image=IMAGE,
        )
    assert refused.value.completed_cloud_writes == (
        f"updated snapshot metadata on {publisher.PRIMARY_NAME}",
    )
    assert refused.value.ambiguous_cloud_write is None
    assert observed == [["gcloud", "update", publisher.PRIMARY_NAME]]


def test_primary_only_commands_select_only_the_singleton_policy(monkeypatch):
    provision_calls = []
    publish_calls = []
    monkeypatch.setattr(
        publisher, "provision", lambda **kwargs: provision_calls.append(kwargs)
    )
    monkeypatch.setattr(
        publisher, "publish_loop", lambda **kwargs: publish_calls.append(kwargs)
    )
    common = [
        "--signing-key-file",
        "/not-opened.seed",
        "--keys-file",
        "/not-opened.json",
        "--image",
        IMAGE,
    ]

    assert (
        publisher.main(
            [
                "provision-primary-only",
                *common,
                "--acknowledge",
                publisher.PRIMARY_ONLY_PROVISION_ACK,
            ]
        )
        == 0
    )
    assert (
        publisher.main(
            [
                "publish-loop-primary-only",
                *common,
                "--acknowledge",
                publisher.PRIMARY_ONLY_PUBLISH_ACK,
            ]
        )
        == 0
    )

    assert provision_calls[0]["vms"] == publisher.PRIMARY_ONLY_VMS
    assert publish_calls[0]["vms"] == publisher.PRIMARY_ONLY_VMS
    assert publisher.SECONDARY_NAME not in repr(provision_calls + publish_calls)


def test_primary_only_mode_refuses_cross_mode_acknowledgements(capsys, monkeypatch):
    monkeypatch.setattr(
        publisher,
        "provision",
        lambda **_kwargs: pytest.fail("refused mode reached provision"),
    )
    monkeypatch.setattr(
        publisher,
        "publish_loop",
        lambda **_kwargs: pytest.fail("refused mode reached publisher"),
    )
    common = [
        "--signing-key-file",
        "/secret/not-opened.seed",
        "--keys-file",
        "/public/not-opened.json",
        "--image",
        IMAGE,
    ]

    refused_commands = [
        [
            "provision-primary-only",
            *common,
            "--acknowledge",
            publisher.PROVISION_ACK,
        ],
        [
            "provision",
            *common,
            "--acknowledge",
            publisher.PRIMARY_ONLY_PROVISION_ACK,
        ],
        [
            "publish-loop-primary-only",
            *common,
            "--acknowledge",
            publisher.PUBLISH_ACK,
        ],
        [
            "publish-loop",
            *common,
            "--acknowledge",
            publisher.PRIMARY_ONLY_PUBLISH_ACK,
        ],
    ]
    for command in refused_commands:
        assert publisher.main(command) == 2
        report = json.loads(capsys.readouterr().err)
        assert report["status"] == "REFUSED"
        assert report["cloud_write_state"] == "NONE_CONFIRMED"
        assert "acknowledgement does not match" in report["error"]

    with pytest.raises(publisher.PublisherError, match="fixed operator mode"):
        publisher.plan_document(vms=(publisher.VMS[0],))


def test_primary_only_create_ambiguity_names_only_the_primary(capsys, monkeypatch):
    def ambiguous(**_kwargs):
        raise publisher.PublisherError(
            "primary create returned failure",
            ambiguous_cloud_write=f"create instance {publisher.PRIMARY_NAME}",
        )

    monkeypatch.setattr(publisher, "provision", ambiguous)
    code = publisher.main(
        [
            "provision-primary-only",
            "--signing-key-file",
            "/not-opened.seed",
            "--keys-file",
            "/not-opened.json",
            "--image",
            IMAGE,
            "--acknowledge",
            publisher.PRIMARY_ONLY_PROVISION_ACK,
        ]
    )

    assert code == 2
    report = json.loads(capsys.readouterr().err)
    assert report["cloud_write_state"] == "AMBIGUOUS"
    assert report["completed_cloud_writes"] == []
    assert report["ambiguous_cloud_write"] == (
        f"create instance {publisher.PRIMARY_NAME}"
    )
    assert publisher.SECONDARY_NAME not in json.dumps(report)


def test_primary_only_core_never_creates_or_updates_the_secondary(tmp_path, monkeypatch):
    selected = []
    cloud_commands = []
    singleton_fleets = []
    primary = publisher.PRIMARY_ONLY_VMS[0]
    pins = {
        "keys_digest": "sha256:" + "1" * 64,
        "launcher_digest": "sha256:" + "2" * 64,
        "poller_digest": "sha256:" + "3" * 64,
    }

    monkeypatch.setattr(publisher, "validate_inputs", lambda **_kwargs: pins)
    monkeypatch.setattr(
        publisher,
        "verify_shared_infrastructure",
        lambda **kwargs: selected.append(("infrastructure", tuple(kwargs["vms"]))),
    )
    monkeypatch.setattr(
        publisher,
        "_desired_instances_absent",
        lambda **kwargs: selected.append(("absence", tuple(kwargs["vms"]))),
    )
    monkeypatch.setattr(publisher, "capture_snapshot", lambda **_kwargs: None)

    def create_command(vm, **kwargs):
        singleton_fleets.append(kwargs["fleet_file"].read_bytes())
        return ["gcloud", "create", vm.name]

    monkeypatch.setattr(publisher, "create_instance_command", create_command)
    monkeypatch.setattr(
        publisher,
        "verify_running_instances",
        lambda **kwargs: selected.append(("running", tuple(kwargs["vms"])))
        or {primary.name: _instance(primary)},
    )
    monkeypatch.setattr(
        publisher,
        "wait_for_guest_tls",
        lambda **kwargs: selected.append(("tls", tuple(kwargs["vms"]))),
    )
    monkeypatch.setattr(
        publisher.subprocess,
        "run",
        lambda command, **_kwargs: cloud_commands.append(command),
    )

    publisher.provision(
        signing_key=tmp_path / "not-opened.seed",
        signing_key_id="cathedral-validator-access-1",
        keys_file=tmp_path / "not-opened.json",
        image=IMAGE,
        vms=publisher.PRIMARY_ONLY_VMS,
    )
    assert cloud_commands == [["gcloud", "create", publisher.PRIMARY_NAME]]
    assert singleton_fleets == [publisher.fleet_bytes(primary)]
    assert all(vms == publisher.PRIMARY_ONLY_VMS for _stage, vms in selected)

    cloud_commands.clear()
    monkeypatch.setattr(
        publisher,
        "snapshot_update_command",
        lambda vm, _snapshot, *, instance: ["gcloud", "update", vm.name],
    )
    publisher.publish_once(
        signing_key=tmp_path / "not-opened.seed",
        signing_key_id="cathedral-validator-access-1",
        keys_file=tmp_path / "not-opened.json",
        snapshot=tmp_path / "not-opened-snapshot.json",
        image=IMAGE,
        vms=publisher.PRIMARY_ONLY_VMS,
    )

    assert cloud_commands == [["gcloud", "update", publisher.PRIMARY_NAME]]
    assert publisher.SECONDARY_NAME not in repr(cloud_commands)


def test_mutating_modes_require_exact_acknowledgements(capsys):
    common = [
        "--signing-key-file",
        "/secret/not-opened.seed",
        "--keys-file",
        "/public/not-opened.json",
        "--image",
        IMAGE,
        "--acknowledge",
        "wrong",
    ]

    assert publisher.main(["provision", *common]) == 2
    assert "acknowledgement does not match" in capsys.readouterr().err
    assert publisher.main(["publish-loop", *common]) == 2
    assert "acknowledgement does not match" in capsys.readouterr().err
