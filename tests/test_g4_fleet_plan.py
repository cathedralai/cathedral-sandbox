import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "g4_plan", Path(__file__).parents[1] / "scripts" / "plan_g4_miner_fleet.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def configuration():
    return dict(project="cathedral-test", zone="us-central1-a", prefix="miner-gpu",
                boot_image="projects/cathedral-test/global/images/reviewed-gpu-image",
                network="projects/cathedral-test/global/networks/miner-network", max_run_hours=1)


def test_plan_requires_eight_supported_confidential_spot_instances_with_bounded_lifetime():
    plan = module.plan_fleet(**configuration())
    assert plan["provisioned"] is False
    assert plan["gpu_count"] == len(plan["instances"]) == 8
    assert plan["max_gpu_hours"] == 8
    assert len({i["name"] for i in plan["instances"]}) == 8
    for instance in plan["instances"]:
        assert instance["machineType"].endswith("/g4-standard-48")
        assert instance["confidentialInstanceConfig"]["confidentialInstanceType"] == "SEV"
        schedule = instance["scheduling"]
        assert schedule["provisioningModel"] == "SPOT"
        assert schedule["automaticRestart"] is False
        assert schedule["instanceTerminationAction"] == "DELETE"
        assert schedule["maxRunDuration"] == {"seconds": "3600"}
        assert instance["disks"][0]["autoDelete"] is True
        assert instance["serviceAccounts"] == []
    assert plan["on_demand_fallback"] is False
    assert plan["automatic_replacements"] == 0
    assert plan["cost_estimate_usd"] is None
    assert plan["trust"]["cpu_attestation"] == "unattested"


@pytest.mark.parametrize("key,value", [("max_run_hours", 0), ("max_run_hours", 25),
    ("max_run_hours", True), ("prefix", "invalid/name"),
    ("boot_image", "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64")])
def test_invalid_or_unbounded_plans_fail(key, value):
    config = configuration()
    config[key] = value
    with pytest.raises(ValueError):
        module.plan_fleet(**config)
