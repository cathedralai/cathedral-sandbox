#!/usr/bin/env python3
"""Prepare eight Spot G4 request bodies without calling Google or spending money."""
from __future__ import annotations

import argparse
import json
import re


def plan_fleet(*, project: str, zone: str, prefix: str, boot_image: str,
               network: str, max_run_hours: int) -> dict:
    for value, pattern, label in (
        (project, r"[a-z][a-z0-9-]{4,28}[a-z0-9]", "project"),
        (zone, r"[a-z]+-[a-z]+[0-9]-[a-z]", "zone"),
        (prefix, r"[a-z](?:[a-z0-9-]{0,55}[a-z0-9])?", "prefix"),
        (boot_image, r"projects/[a-z][a-z0-9-]+/global/images/[a-z][a-z0-9-]+", "immutable boot image"),
        (network, r"projects/[a-z][a-z0-9-]+/global/networks/[a-z][a-z0-9-]*", "network"),
    ):
        if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
            raise ValueError(f"invalid {label}")
    if type(max_run_hours) is not int or not 1 <= max_run_hours <= 24:
        raise ValueError("max_run_hours must be an explicit integer from 1 to 24")
    instances = []
    for index in range(1, 9):
        instances.append({
            "name": f"{prefix}-{index}",
            "machineType": f"zones/{zone}/machineTypes/g4-standard-48",
            "confidentialInstanceConfig": {"confidentialInstanceType": "SEV"},
            "shieldedInstanceConfig": {"enableSecureBoot": True, "enableVtpm": True,
                                       "enableIntegrityMonitoring": True},
            "scheduling": {"provisioningModel": "SPOT", "onHostMaintenance": "TERMINATE",
                           "automaticRestart": False, "instanceTerminationAction": "DELETE",
                           "maxRunDuration": {"seconds": str(max_run_hours * 3600)}},
            "disks": [{"boot": True, "autoDelete": True, "type": "PERSISTENT",
                       "initializeParams": {"sourceImage": boot_image, "diskSizeGb": "30",
                                            "diskType": f"zones/{zone}/diskTypes/hyperdisk-balanced"}}],
            "networkInterfaces": [{"network": network,
                                   "accessConfigs": [{"name": "External NAT", "type": "ONE_TO_ONE_NAT"}]}],
            "serviceAccounts": [],
            "metadata": {"items": [{"key": "block-project-ssh-keys", "value": "TRUE"}]},
            "labels": {"cathedral-track": "gpu", "cathedral-fleet": prefix,
                       "cathedral-device": str(index)},
        })
    return {
        "schema": "cathedral.g4.fleet-plan.v1", "provisioned": False,
        "profile_id": "gcp-g4-rtx-pro-6000-8gpu-v1", "provider": "gcp",
        "project": project, "zone": zone, "gpu_count": 8, "instance_count": 8,
        "gpus_per_instance": 1, "max_gpu_hours": 8 * max_run_hours,
        "on_demand_fallback": False, "automatic_replacements": 0,
        "cost_estimate_usd": None,
        "trust": {"cpu_tee": "amd_sev", "cpu_attestation": "unattested",
                  "host": "approved_operator_trusted", "private_customer_work": False},
        "instances": instances,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("project", "zone", "prefix", "boot-image", "network"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--max-run-hours", required=True, type=int)
    args = parser.parse_args()
    try:
        result = plan_fleet(**vars(args))
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
