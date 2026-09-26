"""One-time bootstrap: enrol an installed miner into signed automatic updates.

Run as root by ``deploy/miner-update/install-miner-update.sh`` from a checkout
of one pinned commit. It is the only step that needs hands on the host. Every
later change, including to the updater itself, arrives as a signed release.

The trust root is pinned twice: the commit pins the file's content, and the
operator passes that file's SHA-256 (``--keys-sha256``), taken from the release
announcement, which must match before anything is installed (review finding F7).

What it does:

- installs the updater tree built from the checkout, exactly as the offline
  builder would, under ``updater/releases/<tree>`` and makes it current;
- installs the frozen shim, the updater's service and timer, and the deploy
  config (product, network, netuid, channel, channel URL, miner unit), none of
  which has a default;
- records the miner unit's own launcher as ``miner/legacy`` and adds a
  drop-in symlink to ``miner/current/unit.conf``. While ``miner/current`` is
  ``legacy`` the drop-in is empty, so the miner unit is unchanged.

What it does not do: change the running miner, its env file, its hotkey or any
validator-access material; enable the timer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from cathedral.miner_bundle import (
    REPOSITORY_TRUST_ROOT,
    TREE_LAUNCHER,
    assemble_tree,
    atomic_symlink,
    install_directory,
    link_target,
    release_tree_sha256,
    remove_link,
)
from cathedral.miner_products import (
    LauncherProfileError,
    product_by_name,
    read_launcher_profile,
)
from cathedral.miner_release import (
    MinerReleaseError,
    canonical_json,
    TrustState,
    initial_trust_state,
    load_trust_root,
    rotate_trust,
)
from cathedral.miner_updater import (
    CONFIG_SCHEMA,
    LEGACY,
    HostConfig,
    HostPaths,
    MinerUpdateError,
    _atomic_write,
    load_trust_state,
    read_activation_profile,
    trust_backup_path,
    write_trust_state,
)

SHIM_SOURCE = "deploy/miner-update/cathedral-miner-update"
UNIT_SOURCES = (
    "deploy/miner-update/cathedral-miner-update.service",
    "deploy/miner-update/cathedral-miner-update.timer",
    "deploy/miner-update/cathedral-miner-update-alert@.service",
)


class BootstrapError(RuntimeError):
    """The bootstrap refused to install."""


def _copy(source: Path, destination: Path, *, mode: int) -> None:
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.{os.getpid()}.tmp"
    shutil.copyfile(source, temporary)
    os.chmod(temporary, mode)
    os.replace(temporary, destination)


def _write_readonly(path: Path, body: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(body)
    os.chmod(path, 0o444)


def _forward_trust(paths: HostPaths, trust_bytes: bytes, *, uid: int, repair: bool) -> TrustState:
    """The host trust set, moved forward to the pinned root, or a refusal.

    A host that has a trust set, or a backup of one, never starts over: that
    would forget its revocations. If ``trust.json`` is unreadable, only
    ``--repair-trust-set`` goes on, and only forward from the verified backup.
    """

    backup = trust_backup_path(paths.trust_file)
    if not paths.trust_file.exists() and not backup.exists():
        return initial_trust_state(trust_bytes)
    try:
        start = load_trust_state(paths.trust_file, expected_uid=uid)
    except MinerUpdateError as exc:
        if not repair:
            raise BootstrapError(
                f"this host's trust set is unreadable ({exc}). Run again with --repair-trust-set "
                f"to move forward from its verified backup, {backup}. Deleting it would forget "
                "every revoked key"
            ) from exc
        try:
            start = load_trust_state(backup, expected_uid=uid)
        except MinerUpdateError as backup_exc:
            raise BootstrapError(
                f"neither the trust set nor its backup can be read ({backup_exc}); see "
                "docs/MINER_AUTO_UPDATE.md, \"Repairing the trust set\""
            ) from backup_exc
    try:
        return rotate_trust(start, trust_bytes)
    except MinerReleaseError as exc:
        raise BootstrapError(f"the pinned trust root cannot replace this host's trust set: {exc}") from exc


def install(
    source: Path,
    *,
    paths: HostPaths,
    keys_sha256: str,
    config: HostConfig,
    unit_exec_start: Callable[[str], Path],
    systemctl: Callable[[Sequence[str]], None],
    repair_trust_set: bool = False,
) -> dict[str, object]:
    product = product_by_name(config.product)

    # 1. The trust root, pinned by digest before anything is installed.
    trust_path = source / REPOSITORY_TRUST_ROOT
    try:
        trust_bytes = trust_path.read_bytes()
    except FileNotFoundError as exc:
        raise BootstrapError(
            "this revision carries no miner release trust root; use a revision "
            "that commits the release public keys"
        ) from exc
    actual = hashlib.sha256(trust_bytes).hexdigest()
    if actual != keys_sha256:
        raise BootstrapError(
            f"the trust root at this revision has sha256 {actual}, not the pinned {keys_sha256}"
        )
    try:
        keys = load_trust_root(trust_bytes)
    except MinerReleaseError as exc:
        raise BootstrapError(f"the trust root is invalid: {exc}") from exc
    if not any(config.channel in key.channels for key in keys.values()):
        raise BootstrapError(f"no key in the trust root may sign the {config.channel} channel")
    # The host's trust set only moves forward. A re-bootstrap revokes every key
    # the pinned root drops, and refuses a root that lists a revoked key, so a
    # key removed after a compromise is never trusted again on this host.
    uid = os.getuid()
    trust = _forward_trust(paths, trust_bytes, uid=uid, repair=repair_trust_set)

    # 2. The launcher the miner unit runs today becomes the legacy release. A
    #    unit that already runs the managed launcher (the shipped example units
    #    for a fresh host, or a second bootstrap) has no legacy launcher of its own.
    exec_path = unit_exec_start(config.miner_unit)
    managed = paths.miner_current / "launcher"
    container: str | None = None
    if exec_path == managed or exec_path == Path("/") / managed.relative_to(paths.root):
        if paths.miner_legacy.exists():
            container = str(read_activation_profile(paths, LEGACY)["container"])
    else:
        try:
            profile = read_launcher_profile(exec_path)
        except LauncherProfileError as exc:
            raise BootstrapError(
                f"{config.miner_unit} does not run a recognised miner launcher ({exec_path}): {exc}"
            ) from exc
        if profile.runtime_contract != product.runtime_contract:
            raise BootstrapError(
                f"{config.miner_unit} runs a launcher for another product "
                f"({profile.runtime_contract}, not {product.runtime_contract})"
            )
        container = profile.container

    # The trust set moves forward first, so a key this bootstrap revokes stays
    # revoked even if a later step fails.
    paths.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(paths.state_dir, 0o700)
    write_trust_state(paths.trust_file, trust)

    # 3. The updater tree, built exactly as the offline builder builds it.
    # Assemble beside the releases, so the final rename stays on one filesystem.
    paths.updater_releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    staging = paths.updater_releases / f".bootstrap-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    try:
        assemble_tree(source, product, staging)
        tree = release_tree_sha256(staging)
        if container is None:
            # A fresh host: the container is the one this product's launcher names.
            container = read_launcher_profile(staging / TREE_LAUNCHER).container
        install_directory(staging, tree_sha256=tree, releases=paths.updater_releases)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    # No fallback to whatever was installed before the bootstrap: that tree
    # may be the one the operator is replacing (trust review P0-1).
    remove_link(paths.updater_previous)
    atomic_symlink(paths.updater_current, f"releases/{tree}")

    # 4. The frozen shim, and the operator's command.
    _copy(source / SHIM_SOURCE, paths.shim, mode=0o755)
    atomic_symlink(paths.operator_command, str(Path("/") / paths.shim.relative_to(paths.root)))

    # 5. The legacy release and the miner drop-in.
    if not paths.miner_legacy.exists():
        paths.miner_legacy.mkdir(mode=0o755, parents=True)
        _write_readonly(paths.miner_legacy / "unit.conf", b"")
        _write_readonly(
            paths.miner_legacy / "profile.json",
            canonical_json({"container": container}) + b"\n",
        )
    if link_target(paths.miner_current) is None:
        atomic_symlink(paths.miner_current, LEGACY)
    dropin_target = Path("/") / (paths.miner_current / "unit.conf").relative_to(paths.root)
    if paths.root != Path("/"):
        dropin_target = paths.miner_current / "unit.conf"
    atomic_symlink(paths.dropin(config.miner_unit), str(dropin_target))

    # 6. Deploy config, state directory and the updater's own units.
    paths.config_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    _atomic_write(paths.config_file, canonical_json(config.as_document()) + b"\n", mode=0o644)
    for unit in UNIT_SOURCES:
        _copy(source / unit, paths.systemd_dir / Path(unit).name, mode=0o644)
    systemctl(["daemon-reload"])

    return {
        "installed_tree": tree,
        "trust_root_sha256": actual,
        "trust_generation": trust.generation,
        "revoked_keys": sorted(entry["key_id"] for entry in trust.revoked.values()),
        "trusted_keys": {
            key_id: {"fingerprint": key.fingerprint, "channels": sorted(key.channels)}
            for key_id, key in sorted(keys.items())
        },
        "miner_unit": config.miner_unit,
        "legacy_container": container,
        "config": config.as_document(),
    }


# --- command line -------------------------------------------------------------------------

_EXEC_PATH_RE = re.compile(r"path=(\S+)")


def _systemctl(arguments: Sequence[str]) -> str:
    try:
        result = subprocess.run(  # noqa: S603
            ["systemctl", *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError(f"systemctl {arguments[0]} failed: {exc}") from exc
    if result.returncode != 0:
        raise BootstrapError(f"systemctl {arguments[0]} failed: {result.stderr.strip()[:200]}")
    return result.stdout


def unit_exec_start(unit: str) -> Path:
    if _systemctl(["show", "--property=LoadState", "--value", unit]).strip() != "loaded":
        raise BootstrapError(f"{unit} is not installed on this host")
    match = _EXEC_PATH_RE.search(_systemctl(["show", "--property=ExecStart", "--value", unit]))
    if match is None:
        raise BootstrapError(f"cannot read the ExecStart of {unit}")
    return Path(match.group(1))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="miner_bootstrap")
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("--source", required=True)
    install_parser.add_argument("--keys-sha256", required=True)
    install_parser.add_argument("--product", required=True)
    install_parser.add_argument("--network", required=True)
    install_parser.add_argument("--netuid", required=True, type=int)
    install_parser.add_argument("--channel", required=True, choices=["canary", "stable"])
    install_parser.add_argument("--channel-url", required=True)
    install_parser.add_argument("--miner-unit", required=True)
    install_parser.add_argument("--minimum-sequence", required=True, type=int)
    install_parser.add_argument(
        "--repair-trust-set",
        action="store_true",
        help="rebuild an unreadable trust.json from its verified backup, moving only forward",
    )
    arguments = parser.parse_args(argv)
    if re.fullmatch(r"[0-9a-f]{64}", arguments.keys_sha256) is None:
        parser.error("--keys-sha256 must be 64 lowercase hex characters")
    if os.geteuid() != 0:
        parser.error("run as root")
    try:
        config = HostConfig.from_document(
            {
                "schema": CONFIG_SCHEMA,
                "product": arguments.product,
                "network": arguments.network,
                "netuid": arguments.netuid,
                "channel": arguments.channel,
                "channel_url": arguments.channel_url,
                "miner_unit": arguments.miner_unit,
                "minimum_sequence": arguments.minimum_sequence,
            }
        )
        report = install(
            Path(arguments.source),
            paths=HostPaths(),
            keys_sha256=arguments.keys_sha256,
            config=config,
            unit_exec_start=unit_exec_start,
            systemctl=lambda args: _systemctl(list(args)) and None,
            repair_trust_set=arguments.repair_trust_set,
        )
    except (BootstrapError, MinerUpdateError, LauncherProfileError, OSError) as exc:
        print(f"refusing to install: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
