"""Fixed entrypoint for the SN39 AMD SEV-SNP signed-fleet miner image.

The image has the same public deployment inputs as the TDX miner. It fixes the
SNP collector, the pinned ``snpguest`` verifier, signed validator access, and
the device path. Operators cannot turn it into a development or migration
worker through an argument or environment value.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import NoReturn

from cathedral.audit_miner_entrypoint import (
    FLEET_MANIFEST,
    TLSMaterial,
    VALIDATOR_ACCESS_KEYS,
    VALIDATOR_ACCESS_SNAPSHOT,
    VALIDATOR_ACCESS_STATE,
    VALIDATOR_MINIMUM_STAKE_RAO,
    VALIDATOR_NETUID,
    VALIDATOR_NETWORK,
    WORKER_HOST,
    WORKER_PORT,
    DeploymentInputs,
    EntrypointError,
    generate_tls_material,
    validate_environment,
)

TLS_DIRECTORY = Path("/run/cathedral-snp-miner")
SNPGUEST_PATH = "/usr/local/bin/snpguest"
SNPGUEST_ENV = "CATHEDRAL_SNPGUEST"
TMPDIR = "/run/cathedral-snp-miner"
_CHILD_PATH = "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"


def worker_command(inputs: DeploymentInputs, material: TLSMaterial) -> list[str]:
    """Return the immutable signed-only AMD SEV-SNP worker command."""

    return [
        sys.executable,
        "-I",
        "-u",
        "-B",
        "-m",
        "cathedral.cli",
        "worker",
        "serve-snp",
        "--hotkey",
        inputs.hotkey,
        "--host",
        WORKER_HOST,
        "--port",
        str(WORKER_PORT),
        "--tls-certificate",
        str(material.certificate),
        "--tls-private-key",
        str(material.private_key),
        "--validator-access-snapshot",
        str(VALIDATOR_ACCESS_SNAPSHOT),
        "--validator-access-keys",
        str(VALIDATOR_ACCESS_KEYS),
        "--validator-access-keys-digest",
        inputs.validator_access_keys_digest,
        "--validator-access-state",
        str(VALIDATOR_ACCESS_STATE),
        "--validator-minimum-stake-rao",
        str(VALIDATOR_MINIMUM_STAKE_RAO),
        "--validator-network",
        VALIDATOR_NETWORK,
        "--validator-netuid",
        str(VALIDATOR_NETUID),
        "--public-endpoint",
        inputs.public_endpoint,
        "--fleet-manifest",
        str(FLEET_MANIFEST),
    ]


def _child_environment() -> dict[str, str]:
    """Provide only immutable collector inputs to the child process."""

    return {
        "PATH": _CHILD_PATH,
        SNPGUEST_ENV: SNPGUEST_PATH,
        "TMPDIR": TMPDIR,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    tls_directory: Path = TLS_DIRECTORY,
    execvpe: Callable[[str, Sequence[str], Mapping[str, str]], NoReturn] = os.execvpe,
) -> NoReturn:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        raise EntrypointError("the SNP miner image accepts no command arguments")
    source_environment = os.environ if environ is None else environ
    inputs = validate_environment(source_environment)
    material = generate_tls_material(tls_directory)
    command = worker_command(inputs, material)
    execvpe(command[0], command, _child_environment())
    raise EntrypointError("worker exec returned unexpectedly")


if __name__ == "__main__":
    try:
        main()
    except EntrypointError as exc:
        print(f"SNP miner refused to start: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
