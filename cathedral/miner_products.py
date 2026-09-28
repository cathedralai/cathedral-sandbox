"""The miner products a signed release can describe, and what their launchers say.

Two miners share the updater: the Intel TDX audit miner and the AMD SEV-SNP
miner. Each is identified here only by a neutral product id, the runtime
contract its launcher enforces, and the contracts its earlier releases
enforced. The earlier contracts let the bootstrap recognise a host that still
runs an older launcher of the same product; they never let the updater
activate one.

Every other product-specific name (image repository, container, the variable
that pins the image, the image label that declares the contract) is read from
the launcher itself. The launcher is the program that actually runs the miner,
so taking these names from it means the updater inspects the container the
launcher starts, pins the variable the launcher reads, and requires the
repository the launcher requires. None of them is compiled into the updater,
and a release that renames them ships the renamed launcher in its bundle.

The miner's systemd unit name, the network and the netuid are deploy config
(``miner_update_cli.HostConfig``), with no defaults.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MinerProduct:
    product: str
    runtime_contract: str
    description: str
    previous_contracts: tuple[str, ...] = ()
    """Contracts earlier releases of this product enforced, oldest first.

    Listed explicitly rather than guessed from the contract's spelling. Only
    the bootstrap reads them, to adopt a running older launcher as the legacy
    release; a signed release must still name ``runtime_contract``.
    """

    @property
    def contracts(self) -> tuple[str, ...]:
        """Every contract this product has enforced, the current one last."""

        return (*self.previous_contracts, self.runtime_contract)


AUDIT_MINER = MinerProduct(
    product="audit-miner",
    runtime_contract="signed-validator-fleet-v2",
    description="Intel TDX audit miner",
    previous_contracts=("signed-validator-fleet-v1",),
)

SNP_MINER = MinerProduct(
    product="snp-miner",
    runtime_contract="snp-signed-validator-fleet-v2",
    description="AMD SEV-SNP miner",
    previous_contracts=("snp-signed-validator-fleet-v1",),
)

PRODUCTS = {p.product: p for p in (AUDIT_MINER, SNP_MINER)}

_PRODUCT_BY_CONTRACT = {c: p for p in PRODUCTS.values() for c in p.contracts}
if len(_PRODUCT_BY_CONTRACT) != sum(len(p.contracts) for p in PRODUCTS.values()):
    raise AssertionError("a runtime contract belongs to more than one miner product")


def product_by_name(name: str) -> MinerProduct:
    try:
        return PRODUCTS[name]
    except KeyError:
        raise ValueError(f"unknown miner product: {name}") from None


def product_for_contract(contract: str) -> MinerProduct | None:
    """The product whose current or earlier releases enforce this contract."""

    return _PRODUCT_BY_CONTRACT.get(contract)


class LauncherProfileError(ValueError):
    """A launcher does not declare what the updater needs to manage it."""


@dataclass(frozen=True)
class LauncherProfile:
    """What one launcher enforces, read from its own text."""

    image_repository: str
    runtime_contract: str
    container: str
    image_variable: str
    contract_label: str

    def as_dict(self) -> dict[str, str]:
        return {
            "image_repository": self.image_repository,
            "runtime_contract": self.runtime_contract,
            "container": self.container,
            "image_variable": self.image_variable,
            "contract_label": self.contract_label,
        }


MAX_LAUNCHER_BYTES = 1024 * 1024

_READONLY_RE = r"^readonly {name}='([^'\n]+)'$"
_IMAGE_VARIABLE_RE = re.compile(
    r'^image_digest="\$\{([A-Z][A-Z0-9_]{0,63})#"\$\{IMAGE_PREFIX\}"\}"$', re.M
)
_LABEL_RE = re.compile(r'\{\{index \.Config\.Labels "([a-z0-9][a-z0-9.-]{0,127})"\}\}')
_REPOSITORY_RE = re.compile(r"^ghcr\.io/cathedralai/[a-z0-9][a-z0-9._-]{0,127}$")
_CONTAINER_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")


def _one(pattern: re.Pattern[str], text: str, what: str) -> str:
    values = set(pattern.findall(text))
    if len(values) != 1:
        raise LauncherProfileError(f"launcher must declare exactly one {what}")
    return values.pop()


def _readonly(name: str, text: str) -> str:
    return _one(re.compile(_READONLY_RE.format(name=name), re.M), text, name)


def parse_launcher_profile(text: str) -> LauncherProfile:
    """Read the names a launcher enforces.

    Refuses a launcher that is ambiguous about any of them, so the updater
    never guesses which container or variable it manages.
    """

    repository = _readonly("IMAGE_PATH", text)
    if _REPOSITORY_RE.fullmatch(repository) is None:
        raise LauncherProfileError("launcher image repository is not a Cathedral repository")
    container = _readonly("CONTAINER_NAME", text)
    if _CONTAINER_RE.fullmatch(container) is None:
        raise LauncherProfileError("launcher container name is invalid")
    return LauncherProfile(
        image_repository=repository,
        runtime_contract=_readonly("RUNTIME_CONTRACT", text),
        container=container,
        image_variable=_one(_IMAGE_VARIABLE_RE, text, "image variable"),
        contract_label=_one(_LABEL_RE, text, "runtime contract label"),
    )


def read_launcher_profile(path: Path) -> LauncherProfile:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LauncherProfileError(f"launcher cannot be read: {path}") from exc
    if len(raw) > MAX_LAUNCHER_BYTES:
        raise LauncherProfileError("launcher is unexpectedly large")
    try:
        return parse_launcher_profile(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise LauncherProfileError("launcher is not UTF-8") from exc


def find_launcher(repository_root: Path, product: MinerProduct) -> Path:
    """Find the one repository launcher that enforces this product's contract.

    Found by contract rather than by file name, so renaming the scripts does
    not need a matching change here.
    """

    matches: list[Path] = []
    for candidate in sorted((repository_root / "scripts").glob("*.sh")):
        try:
            profile = read_launcher_profile(candidate)
        except LauncherProfileError:
            continue
        if profile.runtime_contract == product.runtime_contract:
            matches.append(candidate)
    if len(matches) != 1:
        raise LauncherProfileError(
            f"expected exactly one launcher for {product.product}, found {len(matches)}"
        )
    return matches[0]


__all__ = [
    "AUDIT_MINER",
    "PRODUCTS",
    "SNP_MINER",
    "LauncherProfile",
    "LauncherProfileError",
    "MinerProduct",
    "find_launcher",
    "parse_launcher_profile",
    "product_by_name",
    "product_for_contract",
    "read_launcher_profile",
]
