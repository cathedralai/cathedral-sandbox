"""Command entry point for the miner updater.

This is the only module that talks to systemd, docker and the network. The
state machine in ``miner_updater`` stays free of them so its crash paths stay
testable. Every host effect turns its failures (a timeout, a missing binary, a
truncated response) into ``MinerUpdateError``, so they come out as documented
refusals rather than tracebacks (review finding F16, trust review P0-1), and
``main`` turns anything else into the documented fault status 13.

It runs through the frozen shim ``bin/cathedral-miner-update``, which sets
``CATHEDRAL_MINER_UPDATE_RELEASE`` to the release directory it started. The
trust set comes from the host's state (``/var/lib/cathedral-miner-update/trust.json``),
never from that directory and never from the network.

    cathedral-miner-update check
    cathedral-miner-update status
    cathedral-miner-update pause [--reason TEXT] | resume
    cathedral-miner-update pin --current | unpin
    cathedral-miner-update resolve --accept-release | --restore-previous | --abandon | --retry
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
import signal
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from cathedral.miner_bundle import MAX_ARCHIVE_BYTES, BundleError
from cathedral.miner_products import LauncherProfile
from cathedral.miner_release import MAX_RELEASE_DOCUMENT_BYTES, MinerRelease, MinerReleaseError, https_url
from cathedral.miner_updater import (
    DOCUMENTED_EXIT_STATUSES,
    EXIT_FAULT,
    EXIT_HALTED,
    EXIT_OK,
    EXIT_REFUSED,
    PROBATION_SAMPLE_SECONDS,
    STATE_SCHEMA_LABEL,
    GateImpossible,
    HostConfig,
    HostPaths,
    MinerUpdateError,
    MinerUpdateHalted,
    MinerUpdaterHost,
    Observation,
    UpdateOutcome,
    _atomic_write,
    describe_status,
    fallback_to_previous,
    load_config,
    pin_document,
    probe_release,
    read_state,
    resolve,
    update_once,
)

ROOT_ENV = "CATHEDRAL_MINER_UPDATE_ROOT"
RELEASE_ENV = "CATHEDRAL_MINER_UPDATE_RELEASE"
LOCK_FD_ENV = "CATHEDRAL_MINER_UPDATE_LOCK_FD"
HANDOFF_DEPTH_ENV = "CATHEDRAL_MINER_UPDATE_HANDOFF_DEPTH"

# Time budgets. The unit's TimeoutStartSec must exceed ``worst_case_seconds``
# so systemd never kills a check between two durable steps (review finding
# F15). A test holds the unit to that.
FETCH_METADATA_DEADLINE_SECONDS = 60
FETCH_BUNDLE_DEADLINE_SECONDS = 180
FETCH_READ_TIMEOUT_SECONDS = 20
PROBE_TIMEOUT_SECONDS = 60
PULL_TIMEOUT_SECONDS = 480
INSPECT_TIMEOUT_SECONDS = 30
DAEMON_RELOAD_TIMEOUT_SECONDS = 30
RESET_FAILED_TIMEOUT_SECONDS = 30
# `systemctl restart` of the miner waits for the stop and the start. The stop
# is at most the miner unit's TimeoutStopSec=30s. The start first runs what the
# unit Wants= and is ordered After=, which on a TDX host is #211's
# cathedral-validator-access-fetch.service: its fetch has a 30 s deadline and
# the unit a 2 min TimeoutStartSec. 30 + 120 = 150 s, so 180 s leaves 30 s for
# systemd itself and a normal restart never times out. A restart error is
# final (activation review P2), so this must not be tight.
RESTART_TIMEOUT_SECONDS = 180
SETTLE_TIMEOUT_SECONDS = 90
SETTLE_POLL_SECONDS = 3
# How long the container must have been up before it counts as running. A
# crash-looping container reports Running=true between restarts.
SETTLE_DWELL_SECONDS = 20
# How old the snapshot a healthy host holds can be, from #211's numbers:
#   - the control host signs a snapshot on a timer every 120 s, with up to
#     15 s of random delay and 5 s of timer accuracy: a new one at least every
#     140 s, whose generated_at is backdated by 30 s. At publication it is at
#     most 140 + 30 = 170 s old;
#   - the worker fetches on the same timer, and each fetch may take its full
#     30 s deadline: a completed fetch at least every 140 + 30 = 170 s.
# So the snapshot a worker holds is at most 170 + 170 = 340 s old.
SNAPSHOT_REFRESH_ALLOWANCE_SECONDS = 340
# A restart makes the miner re-read its validator-access snapshot, and a
# rollback may need another restart. So a restart is only started with enough
# validity left for the restart, the settle, the second look and a rollback
# restart (review finding F3): (30 + 30 + 180) + 90 + 45 + 180 = 555 s, which
# a test holds. 560 s is that, rounded up, and still leaves #211's default
# 900 s snapshot passing the gate at its oldest: 900 - 340 = 560.
MINIMUM_ACCESS_REMAINING_SECONDS = 560
SYSTEMD_MARGIN_SECONDS = 120


def _restart_budget() -> int:
    return DAEMON_RELOAD_TIMEOUT_SECONDS + RESET_FAILED_TIMEOUT_SECONDS + RESTART_TIMEOUT_SECONDS


def _settle_budget() -> int:
    return SETTLE_TIMEOUT_SECONDS + SETTLE_POLL_SECONDS + 3 * INSPECT_TIMEOUT_SECONDS


def _observe_budget() -> int:
    return 2 * INSPECT_TIMEOUT_SECONDS


def _prove_start_budget() -> int:
    start = _restart_budget() + _settle_budget()
    second_look = PROBATION_SAMPLE_SECONDS + _observe_budget()
    rollback = 2 * start
    return start + start + second_look + rollback


def child_budget_seconds() -> int:
    """One check with no self-update: a reconcile that restarts and rolls back,
    then an activation that pulls, restarts twice, and rolls back, then the
    miner health check that closes a check with no activation in progress."""

    reconcile = _observe_budget() + _restart_budget() + _prove_start_budget()
    activation = (
        FETCH_METADATA_DEADLINE_SECONDS
        + PULL_TIMEOUT_SECONDS
        + 4 * INSPECT_TIMEOUT_SECONDS
        + _observe_budget()
        + _prove_start_budget()
    )
    return reconcile + activation + _settle_budget()


def fallback_budget_seconds() -> int:
    """The shim's fallback: a fetch (when the current updater fetched nothing),
    a probe of a tree the current updater could not install, and the health check."""

    return FETCH_METADATA_DEADLINE_SECONDS + PROBE_TIMEOUT_SECONDS + _settle_budget()


HANDOFF_TIMEOUT_SECONDS = child_budget_seconds() + 60
"""The new updater's first run is killed after this long and not kept."""


def worst_case_seconds() -> int:
    """The longest one unit run can take: a reconcile, a self-update whose
    first run uses its whole budget, the fetch that judges it, and the
    shim's fallback."""

    reconcile = _observe_budget() + _restart_budget() + _prove_start_budget()
    parent = reconcile + FETCH_METADATA_DEADLINE_SECONDS + FETCH_BUNDLE_DEADLINE_SECONDS
    parent += PROBE_TIMEOUT_SECONDS + HANDOFF_TIMEOUT_SECONDS + FETCH_METADATA_DEADLINE_SECONDS
    return parent + fallback_budget_seconds()


# --- network ----------------------------------------------------------------------------


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects. The record and bundle are fetched from exact URLs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise MinerUpdateError(f"the server attempted a redirect to {newurl!r}")


def fetch(url: str, *, maximum_bytes: int, deadline_seconds: float) -> bytes:
    """Fetch bounded bytes over https, enforcing the deadline while reading.

    Reads with ``read1`` so each wait is one socket read, bounded by the read
    timeout, and the total deadline is checked between reads (review finding
    F15). A truncated or malformed response is a refusal (trust review P0-1).
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
    except MinerUpdateError:
        raise
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError, ValueError) as exc:
        raise MinerUpdateError(f"the download failed: {type(exc).__name__}: {exc}") from exc
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


def prepare_image(release: MinerRelease, profile: LauncherProfile) -> int | None:
    """Pull the image, confirm it is the exact artifact the record names, and
    return its state-schema label (None if it has none).

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
    labels = run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            f'{{{{index .Config.Labels "{profile.contract_label}"}}}}|'
            f'{{{{index .Config.Labels "{STATE_SCHEMA_LABEL}"}}}}',
            image,
        ],
        timeout=INSPECT_TIMEOUT_SECONDS,
    )
    contract, _, schema = labels.stdout.strip().partition("|")
    if labels.returncode != 0 or contract != release.runtime_contract:
        raise MinerUpdateError("the pulled image does not declare the runtime contract the release names")
    schema = schema.strip()
    if schema in ("", "<no value>"):
        return None
    if not schema.isdecimal() or not 0 < int(schema) <= 1_000_000:
        raise MinerUpdateError(f"the pulled image's {STATE_SCHEMA_LABEL} label is malformed")
    return int(schema)


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


def unit_state(unit: str) -> str:
    try:
        result = run(["systemctl", "show", "--property=ActiveState", "--value", unit], timeout=INSPECT_TIMEOUT_SECONDS)
    except MinerUpdateError:
        return "unknown"
    return result.stdout.strip() or "unknown"


def _parse_started_at(started_at: str) -> float | None:
    """Unix seconds from Docker's StartedAt, or None if unreadable."""

    text = started_at.strip()
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(c for c in tail if c.isdigit())[:6]
        suffix = tail[len(tail.rstrip("Z")) :] or ""
        text = f"{head}.{digits}{'Z' if text.endswith('Z') else suffix}"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _uptime_seconds(started_at: str) -> float:
    """Seconds since the container started, or 0 if it cannot be read (fails safe)."""

    started = _parse_started_at(started_at)
    if started is None:
        return 0.0
    return max(0.0, time.time() - started)


def observe(unit: str, container: str) -> Observation | None:
    """One look at the container and the unit, without waiting."""

    try:
        show = run(
            ["systemctl", "show", "--property=ActiveState", "--property=NRestarts", unit],
            timeout=INSPECT_TIMEOUT_SECONDS,
        )
        inspect = run(
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
    except MinerUpdateError:
        return None
    if inspect.returncode != 0:
        return None
    parts = inspect.stdout.strip().split(None, 2)
    if len(parts) != 3:
        return None
    started = _parse_started_at(parts[1])
    if started is None:
        return None
    properties = dict(line.partition("=")[::2] for line in show.stdout.splitlines() if "=" in line)
    restarts = properties.get("NRestarts", "0")
    return Observation(
        image=parts[2],
        started_at=started,
        restarts=int(restarts) if restarts.isdecimal() else 0,
        active=parts[0] == "true" and properties.get("ActiveState") == "active",
    )


def settle(unit: str, container: str) -> Observation | None:
    """A look once the unit is active and the container has been up for the dwell."""

    deadline = time.monotonic() + SETTLE_TIMEOUT_SECONDS
    while True:
        seen = observe(unit, container)
        if seen is not None and seen.active and time.time() - seen.started_at >= SETTLE_DWELL_SECONDS:
            return seen
        if time.monotonic() >= deadline:
            return None
        time.sleep(SETTLE_POLL_SECONDS)


def boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unknown"


def _snapshot_times(snapshot: Path) -> tuple[float, float] | None:
    try:
        document = json.loads(snapshot.read_text(encoding="utf-8"))
        generated = datetime.fromisoformat(str(document["generated_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(document["expires_at"]).replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return generated.timestamp(), expires.timestamp()


def validator_access_remaining_seconds(snapshot: Path) -> float | None:
    """Seconds of validator-access validity left, or None if unreadable."""

    times = _snapshot_times(snapshot)
    if times is None:
        return None
    return times[1] - time.time()


def safe_to_activate(snapshot: Path) -> bool:
    """Whether the miner may be restarted now.

    A restart makes the miner re-read its validator-access snapshot, and the
    snapshot is short-lived. So a restart needs ``MINIMUM_ACCESS_REMAINING_SECONDS``
    left, and an unreadable snapshot is unsafe. The updater's unit must leave
    this file visible; review finding F1 was a unit that hid it.

    If the snapshot's whole lifetime cannot cover the margin plus the oldest
    a healthy host's snapshot can be, the gate cannot pass reliably; that
    raises ``GateImpossible`` so the check alerts at once instead of deferring
    for hours.
    """

    times = _snapshot_times(snapshot)
    if times is None:
        return False
    generated, expires = times
    lifetime = expires - generated
    if lifetime < MINIMUM_ACCESS_REMAINING_SECONDS + SNAPSHOT_REFRESH_ALLOWANCE_SECONDS:
        raise GateImpossible(
            f"the validator-access snapshot lives {int(lifetime)} s, but a safe restart needs "
            f"{MINIMUM_ACCESS_REMAINING_SECONDS} s left on a snapshot that may be "
            f"{SNAPSHOT_REFRESH_ALLOWANCE_SECONDS} s old; lengthen the snapshot lifetime to at least "
            f"{MINIMUM_ACCESS_REMAINING_SECONDS + SNAPSHOT_REFRESH_ALLOWANCE_SECONDS} s, or updates "
            "will not activate reliably"
        )
    return expires - time.time() >= MINIMUM_ACCESS_REMAINING_SECONDS


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
    """Run the rest of this check under the new updater, holding our lock.

    Killed after ``HANDOFF_TIMEOUT_SECONDS``, well inside the unit's
    TimeoutStartSec, so this updater always survives to judge the new one.
    """

    environment = _child_environment(paths, release_dir)
    environment[LOCK_FD_ENV] = str(lock_fd)
    environment[HANDOFF_DEPTH_ENV] = str(depth + 1)
    try:
        child = subprocess.Popen(  # noqa: S603
            [sys.executable, "-s", "-B", "-m", "cathedral.miner_update_cli", "check"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            env=environment,
            cwd=release_dir / "updater",
            pass_fds=(lock_fd,),
            # Its own process group, so a timeout also ends any docker or
            # systemctl client it started.
            start_new_session=True,
        )
    except OSError as exc:
        return 127, {"error": str(exc)}
    try:
        stdout, _ = child.communicate(timeout=HANDOFF_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            os.killpg(child.pid, signal.SIGKILL)
        child.communicate()
        return 124, {"error": "the new updater's first run timed out"}
    return child.returncode, _last_json(stdout or "")


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


def build_host(paths: HostPaths, config: HostConfig) -> MinerUpdaterHost:
    uid = expected_uid(paths)
    release = running_release(paths)
    lock_fd = os.environ.get(LOCK_FD_ENV)
    depth = int(os.environ.get(HANDOFF_DEPTH_ENV, "0") or 0)
    unit = config.miner_unit
    return MinerUpdaterHost(
        config=config,
        paths=paths,
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
        unit_state=lambda: unit_state(unit),
        observe=lambda container: observe(unit, container),
        settle=lambda container: settle(unit, container),
        safe_to_activate=lambda: safe_to_activate(paths.snapshot),
        now_unix=lambda: int(time.time()),
        sleep=time.sleep,
        boot_id=boot_id,
        expected_uid=uid,
        handoff_depth=depth,
        lock_fd=int(lock_fd) if lock_fd else None,
    )


def _emit(outcome: UpdateOutcome) -> int:
    print(json.dumps(outcome.as_dict(), sort_keys=True))
    return outcome.exit_status


def _write_operator_file(path: Path, body: bytes) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _atomic_write(path, body, mode=0o644)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cathedral-miner-update", description="Cathedral miner updater")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="verify the channel and apply a newer signed release")
    commands.add_parser("status", help="print what is installed and what happened last")
    probe = commands.add_parser("probe", help="internal: verify a saved record from this tree")
    probe.add_argument("--record", required=True)
    fallback = commands.add_parser("fallback", help="internal: judge the current updater after it failed")
    fallback.add_argument("--current-status", required=True, type=int)
    pause = commands.add_parser("pause", help="stop checking until resumed")
    pause.add_argument("--reason", default="")
    commands.add_parser("resume", help="undo pause")
    pin = commands.add_parser("pin", help="hold the miner at the release it runs now")
    pin.add_argument("--current", action="store_true", required=True)
    commands.add_parser("unpin", help="undo pin")
    resolve_parser = commands.add_parser("resolve", help="decide a halted or unfinished activation")
    action = resolve_parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--accept-release", action="store_true")
    action.add_argument("--restore-previous", action="store_true")
    action.add_argument("--abandon", action="store_true")
    action.add_argument("--retry", action="store_true")
    return parser


def _dispatch(arguments: argparse.Namespace, paths: HostPaths) -> int:
    uid = expected_uid(paths)
    if arguments.command == "pause":
        _write_operator_file(paths.pause_file, ((arguments.reason or "paused by operator") + "\n").encode("utf-8"))
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
        current = read_state(paths.state_file)["miner"].get("current")  # type: ignore[union-attr]
        if not isinstance(current, dict) or not all(
            isinstance(current.get(key), str) for key in ("image", "tree_sha256", "version")
        ):
            raise MinerUpdateError("no release is committed yet, so there is nothing to pin")
        _write_operator_file(paths.pin_file, pin_document(current))
        print(json.dumps({"action": "pinned", "version": current["version"], "image": current["image"]}))
        return EXIT_OK
    if arguments.command == "status":
        try:
            config: HostConfig | None = load_config(paths.config_file, expected_uid=uid)
        except MinerUpdateError:
            config = None
        print(json.dumps(describe_status(paths, config, expected_uid=uid), indent=2, sort_keys=True))
        return EXIT_OK

    config = load_config(paths.config_file, expected_uid=uid)
    host = build_host(paths, config)
    if arguments.command == "check":
        return _emit(update_once(host))
    if arguments.command == "fallback":
        return _emit(fallback_to_previous(host, arguments.current_status))
    if arguments.command == "resolve":
        name = next(
            flag
            for flag in ("accept_release", "restore_previous", "abandon", "retry")
            if getattr(arguments, flag)
        )
        return _emit(resolve(host, name.replace("_", "-")))
    if arguments.command == "probe":
        raw = Path(arguments.record).read_bytes()
        print(json.dumps(probe_release(host, raw), sort_keys=True))
        return EXIT_OK
    raise MinerUpdateError(f"unhandled command {arguments.command}")


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    status = _main(arguments)
    if arguments.command == "fallback" and status == EXIT_REFUSED:
        # A fallback that could not run passes the current updater's own
        # status through, so a crash or a fault still pages.
        current = arguments.current_status
        return current if current in DOCUMENTED_EXIT_STATUSES else EXIT_FAULT
    return status


def _main(arguments: argparse.Namespace) -> int:
    paths = host_paths()
    try:
        return _dispatch(arguments, paths)
    except MinerUpdateHalted as exc:
        print(json.dumps({"action": "halted", "reason": str(exc)}, sort_keys=True))
        return EXIT_HALTED
    except (MinerUpdateError, MinerReleaseError, BundleError, OSError) as exc:
        print(json.dumps({"action": "refused", "reason": str(exc)}, sort_keys=True))
        return EXIT_REFUSED
    except Exception as exc:  # noqa: BLE001 - never Python's bare exit status 1
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({"action": "fault", "reason": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return EXIT_FAULT


if __name__ == "__main__":
    status = main()
    if status not in DOCUMENTED_EXIT_STATUSES:
        status = EXIT_FAULT
    raise SystemExit(status)
