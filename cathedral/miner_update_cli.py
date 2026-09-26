"""Command entry point for the miner updater.

This is the only module that talks to systemd, docker and the network. The
state machine in ``miner_updater`` stays free of them so its crash paths stay
testable. Every host effect turns its failures (a timeout, a missing binary)
into ``MinerUpdateError``, so they come out as documented refusals rather than
tracebacks (review finding F16).

It runs through the frozen shim ``bin/cathedral-miner-update``, which sets
``CATHEDRAL_MINER_UPDATE_RELEASE`` to the release directory it started. The
trust root is read from that directory, never from the network.

    cathedral-miner-update check
    cathedral-miner-update status
    cathedral-miner-update pause [--reason TEXT] | resume
    cathedral-miner-update pin --version V | --current ; unpin
    cathedral-miner-update resolve --accept-release | --restore-previous | --retry
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from cathedral.miner_bundle import (
    MAX_ARCHIVE_BYTES,
    TREE_TRUST_ROOT,
    BundleError,
    require_root_controlled,
)
from cathedral.miner_products import LauncherProfile
from cathedral.miner_release import (
    MAX_RELEASE_DOCUMENT_BYTES,
    MinerRelease,
    MinerReleaseError,
    TrustedKey,
    https_url,
    load_trust_root,
)
from cathedral.miner_updater import (
    DOCUMENTED_EXIT_STATUSES,
    EXIT_HALTED,
    EXIT_OK,
    EXIT_REFUSED,
    HostConfig,
    HostPaths,
    MinerUpdateError,
    MinerUpdateHalted,
    MinerUpdaterHost,
    UpdateOutcome,
    _atomic_write,
    describe_status,
    load_config,
    probe_release,
    read_pin,
    read_state,
    recover_crashed_updater,
    resolve,
    update_once,
)

ROOT_ENV = "CATHEDRAL_MINER_UPDATE_ROOT"
RELEASE_ENV = "CATHEDRAL_MINER_UPDATE_RELEASE"
LOCK_FD_ENV = "CATHEDRAL_MINER_UPDATE_LOCK_FD"
HANDOFF_DEPTH_ENV = "CATHEDRAL_MINER_UPDATE_HANDOFF_DEPTH"

# Time budgets. The unit's TimeoutStartSec must exceed their worst-case sum
# (``worst_case_seconds``) so systemd never kills a check between two durable
# steps (review finding F15). A test holds the unit to that.
FETCH_METADATA_DEADLINE_SECONDS = 60
FETCH_BUNDLE_DEADLINE_SECONDS = 180
FETCH_READ_TIMEOUT_SECONDS = 20
PROBE_TIMEOUT_SECONDS = 60
PULL_TIMEOUT_SECONDS = 600
INSPECT_TIMEOUT_SECONDS = 30
DAEMON_RELOAD_TIMEOUT_SECONDS = 60
RESET_FAILED_TIMEOUT_SECONDS = 30
RESTART_TIMEOUT_SECONDS = 180
SETTLE_TIMEOUT_SECONDS = 120
SETTLE_POLL_SECONDS = 3
# How long the container must have been up before it counts as running.
# A crash-looping container reports Running=true between restarts; without a
# dwell the updater can sample one of those windows and commit a broken release.
SETTLE_DWELL_SECONDS = 20
# A restart makes the miner re-read its validator-access snapshot, and a
# rollback may need a second restart. So a restart is only started with enough
# validity left for the restart, the settle and a rollback (review finding F3).
MINIMUM_ACCESS_REMAINING_SECONDS = 600
SYSTEMD_MARGIN_SECONDS = 120


def worst_case_seconds() -> int:
    """The longest one ``check`` can take: a self-update handoff wrapping an
    activation that fails and rolls back."""

    restart = DAEMON_RELOAD_TIMEOUT_SECONDS + RESET_FAILED_TIMEOUT_SECONDS + RESTART_TIMEOUT_SECONDS
    settle = SETTLE_TIMEOUT_SECONDS + SETTLE_POLL_SECONDS + 2 * INSPECT_TIMEOUT_SECONDS
    activation = FETCH_METADATA_DEADLINE_SECONDS + PULL_TIMEOUT_SECONDS + 4 * INSPECT_TIMEOUT_SECONDS
    activation += 2 * (restart + settle)
    parent = FETCH_METADATA_DEADLINE_SECONDS + FETCH_BUNDLE_DEADLINE_SECONDS + PROBE_TIMEOUT_SECONDS
    return parent + activation


# --- network ----------------------------------------------------------------------------


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects. The record and bundle are fetched from exact URLs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise MinerUpdateError(f"the server attempted a redirect to {newurl!r}")


def fetch(url: str, *, maximum_bytes: int, deadline_seconds: float) -> bytes:
    """Fetch bounded bytes over https, enforcing the deadline while reading.

    Reads with ``read1`` so each wait is one socket read, bounded by the read
    timeout, and the total deadline is checked between reads. A server that
    drips bytes cannot hold the lock past the deadline (review finding F15).
    Follows the validator's ``fetch_bounded_https``.
    """

    try:
        https_url(url, "download URL")
    except MinerReleaseError as exc:
        raise MinerUpdateError(str(exc)) from exc
    deadline = time.monotonic() + deadline_seconds
    opener = urllib.request.build_opener(_NoRedirects)
    request = urllib.request.Request(url, headers={"Accept": "application/json,application/octet-stream"})
    chunks: list[bytes] = []
    total = 0
    try:
        with opener.open(request, timeout=FETCH_READ_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise MinerUpdateError(f"the server answered {response.status}")
            stated = response.headers.get("Content-Length")
            if stated is not None and (not stated.isdecimal() or int(stated) > maximum_bytes):
                raise MinerUpdateError("the response exceeds its size limit")
            reader = getattr(response, "read1", None) or response.read
            while True:
                if time.monotonic() > deadline:
                    raise MinerUpdateError("the download exceeded its total deadline")
                chunk = reader(min(65_536, maximum_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_bytes:
                    raise MinerUpdateError("the response exceeds its size limit")
                chunks.append(chunk)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise MinerUpdateError(f"the download failed: {exc}") from exc
    return b"".join(chunks)


# --- processes ---------------------------------------------------------------------------


def run(argv: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603 - fixed argument vectors only
            list(argv),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise MinerUpdateError(f"{argv[0]} {argv[1] if len(argv) > 1 else ''} timed out") from exc
    except OSError as exc:
        raise MinerUpdateError(f"{argv[0]} could not be run: {exc}") from exc


def prepare_image(release: MinerRelease, profile: LauncherProfile) -> None:
    """Pull the image and confirm it is the exact artifact the record names.

    Done while the previous release is still selected, so an unreachable
    registry, a digest mismatch, a wrong platform or a wrong contract label
    costs nothing.
    """

    image = release.image
    pull = run(["docker", "pull", "--platform", "linux/amd64", image], timeout=PULL_TIMEOUT_SECONDS)
    if pull.returncode != 0:
        raise MinerUpdateError(f"docker pull failed: {pull.stderr.strip()[:200]}")
    digests = run(
        ["docker", "image", "inspect", "--format", "{{range .RepoDigests}}{{println .}}{{end}}", image],
        timeout=INSPECT_TIMEOUT_SECONDS,
    )
    if digests.returncode != 0 or image not in digests.stdout.split():
        raise MinerUpdateError("the pulled image does not report the requested digest")
    platform = run(
        ["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image],
        timeout=INSPECT_TIMEOUT_SECONDS,
    )
    if platform.returncode != 0 or platform.stdout.strip() != "linux/amd64":
        raise MinerUpdateError("the pulled image is not linux/amd64")
    label = run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            f'{{{{index .Config.Labels "{profile.contract_label}"}}}}',
            image,
        ],
        timeout=INSPECT_TIMEOUT_SECONDS,
    )
    if label.returncode != 0 or label.stdout.strip() != release.runtime_contract:
        raise MinerUpdateError("the pulled image does not declare the runtime contract the release names")


_SYSTEMCTL_TIMEOUTS = {
    "daemon-reload": DAEMON_RELOAD_TIMEOUT_SECONDS,
    "reset-failed": RESET_FAILED_TIMEOUT_SECONDS,
    "restart": RESTART_TIMEOUT_SECONDS,
}


def systemctl(arguments: Sequence[str]) -> None:
    verb = arguments[0]
    if verb not in _SYSTEMCTL_TIMEOUTS:
        raise MinerUpdateError(f"systemctl {verb} is not an updater command")
    result = run(["systemctl", *arguments], timeout=_SYSTEMCTL_TIMEOUTS[verb])
    if result.returncode != 0:
        raise MinerUpdateError(f"systemctl {verb} failed: {result.stderr.strip()[:200]}")


def _inspect(container: str) -> tuple[bool, str, str] | None:
    result = run(
        [
            "docker",
            "container",
            "inspect",
            "--format",
            "{{.State.Running}} {{.State.StartedAt}} {{.Config.Image}}",
            container,
        ],
        timeout=INSPECT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None
    parts = result.stdout.strip().split(None, 2)
    if len(parts) != 3:
        return None
    return parts[0] == "true", parts[1], parts[2]


def current_image(container: str) -> str | None:
    """The image a container reports right now, without waiting."""

    try:
        inspected = _inspect(container)
    except MinerUpdateError:
        return None
    if inspected is None or not inspected[0]:
        return None
    return inspected[2]


def settled_image(unit: str, container: str) -> str | None:
    """The image the miner container reports once it has settled.

    Not accepted as running: a container up for less than
    ``SETTLE_DWELL_SECONDS``, or a unit that is not ``active`` (systemd reports
    ``activating`` while restarting a failing service and ``failed`` once the
    start limit trips).
    """

    deadline = time.monotonic() + SETTLE_TIMEOUT_SECONDS
    while True:
        try:
            state = run(["systemctl", "is-active", unit], timeout=INSPECT_TIMEOUT_SECONDS)
            inspected = _inspect(container)
        except MinerUpdateError:
            inspected = None
            state = None
        if state is not None and state.stdout.strip() == "active" and inspected is not None:
            running, started, image = inspected
            if running and _uptime_seconds(started) >= SETTLE_DWELL_SECONDS:
                return image
        if time.monotonic() >= deadline:
            return None
        time.sleep(SETTLE_POLL_SECONDS)


def _uptime_seconds(started_at: str) -> float:
    """Seconds since the container started, or 0 if unreadable (fails safe)."""

    text = started_at.strip()
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(c for c in tail if c.isdigit())[:6]
        suffix = tail[len(tail.rstrip("Z")) :] or ""
        text = f"{head}.{digits}{'Z' if text.endswith('Z') else suffix}"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())


def validator_access_remaining_seconds(snapshot: Path) -> float | None:
    """Seconds of validator-access validity left, or None if unreadable."""

    try:
        document = json.loads(snapshot.read_text(encoding="utf-8"))
        expires = str(document["expires_at"])
        parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed - datetime.now(timezone.utc)).total_seconds()


def safe_to_activate(snapshot: Path) -> bool:
    """Whether the miner may be restarted now.

    A restart makes the miner re-read its validator-access snapshot, and the
    snapshot is short-lived. The first live run of the previous version
    restarted into a lapsed snapshot and crash-looped. So a restart needs
    ``MINIMUM_ACCESS_REMAINING_SECONDS`` left, and an unreadable snapshot is
    unsafe. The updater's unit must leave this file visible; review finding
    F1 was a unit that hid it, so every unattended check deferred.
    """

    remaining = validator_access_remaining_seconds(snapshot)
    return remaining is not None and remaining >= MINIMUM_ACCESS_REMAINING_SECONDS


# --- the updater's own processes ----------------------------------------------------------


def _child_environment(paths: HostPaths, release_dir: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONSAFEPATH": "1",
        "PYTHONPATH": str(release_dir / "updater"),
        RELEASE_ENV: str(release_dir),
        ROOT_ENV: str(paths.root),
    }


def _last_json(text: str) -> Mapping[str, object] | None:
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                return None
            return document if isinstance(document, dict) else None
    return None


def probe_updater(paths: HostPaths, release_dir: Path, record: Path) -> Mapping[str, object]:
    """Run the new updater's ``probe`` from its own tree, before it is current."""

    try:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-s", "-B", "-m", "cathedral.miner_update_cli", "probe", "--record", str(record)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            env=_child_environment(paths, release_dir),
            # `python -m` puts the working directory first on sys.path.
            cwd=release_dir / "updater",
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise MinerUpdateError(f"the probe did not complete: {exc}") from exc
    document = _last_json(result.stdout)
    if result.returncode != 0 or document is None:
        if document is not None and isinstance(document.get("reason"), str):
            detail = document["reason"]
        else:
            detail = (result.stderr.strip().splitlines() or ["no output"])[-1]
        raise MinerUpdateError(f"the probe exited {result.returncode}: {detail[:300]}")
    return document


def handoff(
    paths: HostPaths, release_dir: Path, lock_fd: int, depth: int
) -> tuple[int, Mapping[str, object] | None]:
    """Run the rest of this check under the new updater, holding our lock."""

    environment = _child_environment(paths, release_dir)
    environment[LOCK_FD_ENV] = str(lock_fd)
    environment[HANDOFF_DEPTH_ENV] = str(depth + 1)
    try:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-s", "-B", "-m", "cathedral.miner_update_cli", "check"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            env=environment,
            cwd=release_dir / "updater",
            pass_fds=(lock_fd,),
            check=False,
        )
    except OSError as exc:
        return 127, {"error": str(exc)}
    sys.stderr.flush()
    return result.returncode, _last_json(result.stdout)


# --- wiring ----------------------------------------------------------------------------------


def host_paths() -> HostPaths:
    return HostPaths(root=Path(os.environ.get(ROOT_ENV, "/")))


def expected_uid(paths: HostPaths) -> int:
    """Root on a host. A relocated root exists only in tests, owned by the test user."""

    return 0 if paths.root == Path("/") else os.getuid()


def running_release(paths: HostPaths) -> Path | None:
    value = os.environ.get(RELEASE_ENV)
    if not value:
        return None
    release = Path(value).resolve()
    if release.parent != paths.updater_releases.resolve():
        raise MinerUpdateError(f"{RELEASE_ENV} is not an installed release: {value}")
    return release


def load_own_trust_root(release: Path, uid: int) -> dict[str, TrustedKey]:
    """The trust root shipped in the tree this updater runs from."""

    path = release / TREE_TRUST_ROOT
    try:
        require_root_controlled(path, expected_uid=uid)
        require_root_controlled(path.parent, expected_uid=uid)
        with path.open("rb") as handle:
            raw = handle.read(64 * 1024 + 1)
        return load_trust_root(raw)
    except (OSError, BundleError, MinerReleaseError) as exc:
        raise MinerUpdateError(f"trust root is unusable: {exc}") from exc


def build_host(paths: HostPaths, config: HostConfig) -> MinerUpdaterHost:
    uid = expected_uid(paths)
    release = running_release(paths)
    trusted = load_own_trust_root(release, uid) if release is not None else {}
    lock_fd = os.environ.get(LOCK_FD_ENV)
    depth = int(os.environ.get(HANDOFF_DEPTH_ENV, "0") or 0)
    return MinerUpdaterHost(
        config=config,
        paths=paths,
        trusted_keys=trusted,
        running_tree=release.name if release is not None else None,
        fetch_metadata=lambda: fetch(
            config.channel_url,
            maximum_bytes=MAX_RELEASE_DOCUMENT_BYTES,
            deadline_seconds=FETCH_METADATA_DEADLINE_SECONDS,
        ),
        fetch_bundle=lambda bundle: fetch(
            bundle.url, maximum_bytes=MAX_ARCHIVE_BYTES, deadline_seconds=FETCH_BUNDLE_DEADLINE_SECONDS
        ),
        probe_updater=lambda release_dir, record: probe_updater(paths, release_dir, record),
        handoff=lambda release_dir, fd: handoff(paths, release_dir, fd, depth),
        prepare_image=prepare_image,
        systemctl=systemctl,
        current_image=current_image,
        settled_image=lambda container: settled_image(config.miner_unit, container),
        safe_to_activate=lambda: safe_to_activate(paths.snapshot),
        now_unix=lambda: int(time.time()),
        expected_uid=uid,
        handoff_depth=depth,
        lock_fd=int(lock_fd) if lock_fd else None,
    )


def _emit(outcome: UpdateOutcome) -> int:
    print(json.dumps(outcome.as_dict(), sort_keys=True))
    return outcome.exit_status


def _write_operator_file(path: Path, body: str) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _atomic_write(path, body.encode("ascii"), mode=0o644)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cathedral-miner-update", description="Cathedral miner updater")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="verify the channel and apply a newer signed release")
    commands.add_parser("status", help="print what is installed and what happened last")
    probe = commands.add_parser("probe", help="internal: verify a saved record from this tree")
    probe.add_argument("--record", required=True)
    recover = commands.add_parser("recover", help="internal: take over from a crashed updater")
    recover.add_argument("--crashed-release", required=True)
    pause = commands.add_parser("pause", help="stop checking until resumed")
    pause.add_argument("--reason", default="")
    commands.add_parser("resume", help="undo pause")
    pin = commands.add_parser("pin", help="hold the miner at one version")
    pin_target = pin.add_mutually_exclusive_group(required=True)
    pin_target.add_argument("--version")
    pin_target.add_argument("--current", action="store_true")
    commands.add_parser("unpin", help="undo pin")
    resolve_parser = commands.add_parser("resolve", help="decide a halted activation")
    resolve_action = resolve_parser.add_mutually_exclusive_group(required=True)
    resolve_action.add_argument("--accept-release", action="store_true")
    resolve_action.add_argument("--restore-previous", action="store_true")
    resolve_action.add_argument("--retry", action="store_true")
    arguments = parser.parse_args(argv)

    paths = host_paths()
    uid = expected_uid(paths)
    try:
        if arguments.command == "pause":
            _write_operator_file(paths.pause_file, (arguments.reason or "paused by operator") + "\n")
            print(json.dumps({"action": "paused", "file": str(paths.pause_file)}))
            return EXIT_OK
        if arguments.command == "resume":
            paths.pause_file.unlink(missing_ok=True)
            print(json.dumps({"action": "resumed"}))
            return EXIT_OK
        if arguments.command == "unpin":
            paths.pin_file.unlink(missing_ok=True)
            print(json.dumps({"action": "unpinned"}))
            return EXIT_OK
        if arguments.command == "pin":
            version = arguments.version
            if arguments.current:
                current = read_state(paths.state_file)["miner"].get("current")  # type: ignore[union-attr]
                if not isinstance(current, dict) or not isinstance(current.get("version"), str):
                    raise MinerUpdateError("no release is active yet, so there is no current version to pin")
                version = current["version"]
            _write_operator_file(paths.pin_file, f"{version}\n")
            read_pin(paths.pin_file)
            print(json.dumps({"action": "pinned", "version": version}))
            return EXIT_OK

        if arguments.command == "status":
            try:
                config: HostConfig | None = load_config(paths.config_file, expected_uid=uid)
            except MinerUpdateError:
                config = None
            print(json.dumps(describe_status(paths, config), indent=2, sort_keys=True))
            return EXIT_OK

        config = load_config(paths.config_file, expected_uid=uid)
        host = build_host(paths, config)
        if arguments.command == "check":
            return _emit(update_once(host))
        if arguments.command == "resolve":
            action = (
                "accept-release"
                if arguments.accept_release
                else "restore-previous" if arguments.restore_previous else "retry"
            )
            return _emit(resolve(host, action))
        if arguments.command == "recover":
            return _emit(recover_crashed_updater(host, Path(arguments.crashed_release)))
        if arguments.command == "probe":
            raw = Path(arguments.record).read_bytes()
            print(json.dumps(probe_release(host, raw), sort_keys=True))
            return EXIT_OK
    except MinerUpdateHalted as exc:
        print(json.dumps({"action": "halted", "reason": str(exc)}, sort_keys=True))
        return EXIT_HALTED
    except (MinerUpdateError, MinerReleaseError, BundleError, OSError) as exc:
        print(json.dumps({"action": "refused", "reason": str(exc)}, sort_keys=True))
        return EXIT_REFUSED
    parser.error(f"unhandled command {arguments.command}")
    return EXIT_REFUSED


if __name__ == "__main__":
    status = main()
    if status not in DOCUMENTED_EXIT_STATUSES:
        status = EXIT_REFUSED
    raise SystemExit(status)
