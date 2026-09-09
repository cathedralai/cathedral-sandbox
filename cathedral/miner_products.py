"""The miner products a signed release can describe.

Cathedral ships two miners with the same shape and different everything else:
an Intel TDX "audit" miner and an AMD SEV-SNP miner. Each pins its image in its
own environment variable, runs its own unit and container, is started by its own
launcher, and declares its own runtime contract.

Keeping that in one table rather than hard-coded constants is what lets a single
updater serve both, and it is what makes the release record's ``product`` field
mean something concrete: a record for one product names a repository, a contract
and a pin variable that simply do not match the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MinerProduct:
    """Everything that differs between one miner product and another."""

    product: str
    image_repository: str
    image_variable: str
    runtime_contract: str
    unit: str
    container: str
    launcher_path: Path
    env_path: Path
    # The directory the launcher bind-mounts read-write. Both products happen
    # to use the same one today, which is why it is named rather than assumed.
    durable_state_directory: Path


SN39_AUDIT_MINER = MinerProduct(
    product="sn39-audit-miner",
    image_repository="ghcr.io/cathedralai/cathedral-sn39-audit-miner",
    image_variable="SN39_AUDIT_MINER_IMAGE",
    runtime_contract="signed-validator-fleet-v1",
    unit="cathedral-sn39-audit-miner.service",
    container="cathedral-sn39-audit-miner",
    launcher_path=Path("/usr/local/libexec/cathedral/run-sn39-miner"),
    env_path=Path("/etc/cathedral/sn39-audit-miner.env"),
    durable_state_directory=Path("/var/lib/cathedral/validator-access"),
)

SN39_SNP_MINER = MinerProduct(
    product="sn39-snp-miner",
    image_repository="ghcr.io/cathedralai/cathedral-sn39-snp-miner",
    image_variable="SN39_SNP_MINER_IMAGE",
    runtime_contract="snp-signed-validator-fleet-v1",
    unit="cathedral-sn39-snp-miner.service",
    container="cathedral-sn39-snp-miner",
    launcher_path=Path("/usr/local/sbin/cathedral-run-sn39-snp-miner"),
    env_path=Path("/etc/cathedral/sn39-snp-miner.env"),
    durable_state_directory=Path("/var/lib/cathedral/validator-access"),
)

PRODUCTS = {p.product: p for p in (SN39_AUDIT_MINER, SN39_SNP_MINER)}


def product_by_name(name: str) -> MinerProduct:
    try:
        return PRODUCTS[name]
    except KeyError:
        raise ValueError(f"unknown miner product: {name}") from None


__all__ = ["PRODUCTS", "SN39_AUDIT_MINER", "SN39_SNP_MINER", "MinerProduct", "product_by_name"]
