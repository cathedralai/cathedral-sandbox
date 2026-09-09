"""Command entry point for the SN39 miner updater.

This is the only module that talks to systemd, docker and the network. The
state machine in ``miner_updater`` stays free of them so its crash paths stay
testable.

    cathedral-sn39-miner-update check --channel stable --channel-url https://...
    cathedral-sn39-miner-update status
"""

from __future__ import annotations

import argparse
import hashlib
import os
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cathedral.miner_release import MAX_RELEASE_DOCUMENT_BYTES, MinerRelease
from cathedral.miner_products import PRODUCTS, MinerProduct, product_by_name
from cathedral.miner_updater import (
    DEFAULT_ENV_PATH,
    DEFAULT_LOCK_PATH,
    DEFAULT_PAUSE_PATH,
    DEFAULT_STATE_PATH,
    MinerUpdateError,
    MinerUpdaterHost,
    describe_status,
    update_once,
)

DEFAULT_KEYS_PATH = Path("/etc/cathedral/sn39-miner-update-keys.json")
MAX_KEYS_BYTES = 64 * 1024
MAX_LAUNCHER_BYTES = 4 * 1024 * 1024

FETCH_TIMEOUT_SECONDS = 30
FETCH_TOTAL_DEADLINE_SECONDS = 60
# The miner pulls nothing at this point (prepare already did) but still
# generates TLS material and binds. Measured starts are a few seconds.
SETTLE_TIMEOUT_SECONDS = 120
SETTLE_POLL_SECONDS = 3
# How long the container must have been up before it counts as running.
#
# Learned the hard way on a live TDX box: a container that starts and then
# exits immediately still reports Running=true in the window between. Without a
# dwell the updater samples one of those windows, calls the release healthy, and
# commits an update to a miner that is in fact crash-looping until systemd's
# start limit stops it altogether.
SETTLE_DWELL_SECONDS = 20
# A restart makes the miner re-read its validator-access snapshot. If that has
# expired the new container refuses to start, so a restart is only safe with
# comfortable margin left.
VALIDATOR_ACCESS_PATH = Path("/etc/cathedral/validator-access/validator-access.json")
MINIMUM_ACCESS_REMAINING_SECONDS = 300


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects outright.

    A signed record is fetched from an exact URL. Following a redirect would
    let whoever controls that URL move the fetch to another host, including a
    plain-HTTP or link-local one. The signature would still be checked, but the
    request itself is a capability worth not handing away.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise MinerUpdateError(f"channel attempted a redirect to {newurl!r}")


def load_trusted_keys(path: Path) -> dict[str, bytes]:
    """Read the miner release public keys this host trusts.

    Deliberately separate from any validator key material. A host holding only
    this file cannot verify a validator release at all, which is the outermost
    of the three barriers against cross-product installation.
    """

    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_KEYS_BYTES + 1)
    except FileNotFoundError as exc:
        raise MinerUpdateError(f"trusted key file is missing: {path}") from exc
    except OSError as exc:
        raise MinerUpdateError(f"trusted key file is unreadable: {path}") from exc
    if len(raw) > MAX_KEYS_BYTES:
        raise MinerUpdateError("trusted key file is unexpectedly large")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise MinerUpdateError("trusted key file is not strict JSON") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema") != "cathedral_sn39_miner_release_keys_v1"
    ):
        raise MinerUpdateError("trusted key file schema is unsupported")
    keys = document.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise MinerUpdateError("trusted key file contains no keys")
    resolved: dict[str, bytes] = {}
    for key_id, value in keys.items():
        if not isinstance(key_id, str) or not isinstance(value, str):
            raise MinerUpdateError("trusted key entry is malformed")
        try:
            decoded = bytes.fromhex(value)
        except ValueError as exc:
            raise MinerUpdateError("trusted key is not hex") from exc
        if len(decoded) != 32:
            raise MinerUpdateError("trusted key is not 32 bytes")
        resolved[key_id] = decoded
    return resolved


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise MinerUpdateError("the channel URL must be https")
    started = time.monotonic()
    opener = urllib.request.build_opener(_NoRedirects)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise MinerUpdateError(f"channel answered {response.status}")
            # One byte past the cap, so an oversized body is detected rather
            # than silently truncated to something that might still parse.
            body = response.read(MAX_RELEASE_DOCUMENT_BYTES + 1)
    except urllib.error.URLError as exc:
        raise MinerUpdateError(f"channel is unreachable: {exc}") from exc
    if time.monotonic() - started > FETCH_TOTAL_DEADLINE_SECONDS:
        raise MinerUpdateError("channel exceeded the total fetch deadline")
    if len(body) > MAX_RELEASE_DOCUMENT_BYTES:
        raise MinerUpdateError("channel response is oversized")
    return body


def run(argv: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argument vectors only
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def verify_launcher(product: MinerProduct, release: MinerRelease) -> None:
    """Confirm this host runs the launcher the release was built against.

    The launcher hard-codes the runtime contract it accepts and refuses to
    start on a mismatch. Without this check an incompatible release would stop
    a working miner and only then fail, so the compatibility question is asked
    while the previous image is still serving.
    """

    try:
        with product.launcher_path.open("rb") as handle:
            body = handle.read(MAX_LAUNCHER_BYTES + 1)
    except OSError as exc:
        raise MinerUpdateError(f"installed launcher cannot be read: {product.launcher_path}") from exc
    if len(body) > MAX_LAUNCHER_BYTES:
        raise MinerUpdateError("installed launcher is unexpectedly large")
    digest = hashlib.sha256(body).hexdigest()
    if digest != release.launcher_sha256:
        raise MinerUpdateError(
            "the installed launcher is not the one this release was built "
            f"against (installed {digest[:12]}, release names "
            f"{release.launcher_sha256[:12]}); update the launcher first"
        )
    text = body.decode("utf-8", errors="replace")
    if f"readonly RUNTIME_CONTRACT='{release.runtime_contract}'" not in text:
        raise MinerUpdateError(
            "the installed launcher does not accept the runtime contract this "
            f"release names ({release.runtime_contract})"
        )


def durable_digest(product: MinerProduct) -> str:
    """Fingerprint the state the miner may mutate.

    The launcher bind-mounts this directory read-write, so it is where a
    started image would leave traces. Comparing it before and after is the only
    positive evidence available that a release wrote nothing, and rollback is
    gated on it.

    Unreadable content is folded into the digest as an explicit marker rather
    than skipped, so a permissions change cannot make two different states look
    identical.
    """

    accumulator = hashlib.sha256()
    root = product.durable_state_directory
    if not root.is_dir():
        return "absent"
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root)).encode("utf-8")
        accumulator.update(len(relative).to_bytes(4, "big") + relative)
        try:
            if path.is_symlink():
                accumulator.update(b"L" + os.readlink(path).encode("utf-8"))
            elif path.is_dir():
                accumulator.update(b"D")
            else:
                with path.open("rb") as handle:
                    accumulator.update(b"F")
                    while chunk := handle.read(1024 * 1024):
                        accumulator.update(chunk)
        except OSError:
            accumulator.update(b"?unreadable")
    return accumulator.hexdigest()


def prepare_image(product: MinerProduct, release: MinerRelease) -> None:
    """Pull the image and confirm it is the exact artifact the record names.

    Done while the previous image is still pinned, so an unreachable registry,
    a digest mismatch, a wrong platform or a wrong runtime contract costs
    nothing. The launcher checks the same things at startup; checking here
    turns a failed restart plus a rollback into a refusal that never touches
    the running miner.
    """

    image = release.image
    pull = run(["docker", "pull", "--platform", "linux/amd64", image], timeout=900)
    if pull.returncode != 0:
        raise MinerUpdateError(f"docker pull failed: {pull.stderr.strip()[:200]}")

    digests = run(
        ["docker", "image", "inspect", "--format",
         "{{range .RepoDigests}}{{println .}}{{end}}", image]
    )
    if digests.returncode != 0 or image not in digests.stdout.split():
        raise MinerUpdateError("the pulled image does not report the requested digest")

    platform = run(["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image])
    if platform.returncode != 0 or platform.stdout.strip() != "linux/amd64":
        raise MinerUpdateError("the pulled image is not linux/amd64")

    label = run(
        ["docker", "image", "inspect", "--format",
         '{{index .Config.Labels "org.cathedral.sn39.runtime-contract"}}', image]
    )
    if label.returncode != 0 or label.stdout.strip() != release.runtime_contract:
        raise MinerUpdateError(
            "the pulled image does not declare the runtime contract the release names"
        )


def restart_service(product: MinerProduct) -> None:
    result = run(["systemctl", "restart", product.unit], timeout=180)
    if result.returncode != 0:
        raise MinerUpdateError(f"systemctl restart failed: {result.stderr.strip()[:200]}")


def running_image(product: MinerProduct) -> str | None:
    """The image the running miner container reports, once it has settled.

    Two things this deliberately does NOT accept as running:

    A container observed up for less than ``SETTLE_DWELL_SECONDS``. A
    crash-looping miner is up for a fraction of a second at a time, and
    sampling one of those windows would report a broken release as healthy.

    A unit that is not ``active``. systemd reports ``activating`` while it is
    restarting a failing service, and ``failed`` once the start limit trips.
    """

    deadline = time.monotonic() + SETTLE_TIMEOUT_SECONDS
    while True:
        unit = run(["systemctl", "is-active", product.unit], timeout=30)
        inspect = run(
            [
                "docker",
                "container",
                "inspect",
                "--format",
                "{{.State.Running}} {{.State.StartedAt}} {{.Config.Image}}",
                product.container,
            ],
            timeout=30,
        )
        if unit.stdout.strip() == "active" and inspect.returncode == 0:
            parts = inspect.stdout.strip().split(None, 2)
            if len(parts) == 3 and parts[0] == "true":
                started, image = parts[1], parts[2]
                if _uptime_seconds(started) >= SETTLE_DWELL_SECONDS:
                    return image
        if time.monotonic() >= deadline:
            return None
        time.sleep(SETTLE_POLL_SECONDS)


def _uptime_seconds(started_at: str) -> float:
    """Seconds since the container started, or 0 if it cannot be read.

    Unparseable means "assume it just started", which fails safe: the caller
    keeps waiting rather than accepting an unsettled container.
    """

    from datetime import datetime, timezone

    text = started_at.strip()
    # Docker emits nanosecond precision, which fromisoformat cannot take.
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


def validator_access_remaining_seconds() -> float | None:
    """Seconds of validator-access validity left, or None if unreadable."""

    from datetime import datetime, timezone

    try:
        document = json.loads(VALIDATOR_ACCESS_PATH.read_text(encoding="utf-8"))
        expires = str(document["expires_at"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None
    try:
        parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed - datetime.now(timezone.utc)).total_seconds()


def safe_to_activate() -> bool:
    """Whether the miner may be restarted right now.

    A restart makes the miner re-read its validator-access snapshot. That
    snapshot is short-lived and refreshed out of band, so restarting close to
    its expiry can leave the miner unable to start at all: it crash-loops until
    systemd's start limit stops it, and then nothing is serving.

    That is not hypothetical. It happened on the live TDX box during the first
    end-to-end update: the snapshot lapsed, the upgraded image refused to start
    five times, and the unit gave up.

    So the miner is only restarted with comfortable validity remaining. An
    unreadable snapshot is treated as unsafe, because an unknown answer is not
    a licence to stop a working miner.

    This is also the hook that grows a customer-work condition later, which is
    why it is injected rather than called inline.
    """

    remaining = validator_access_remaining_seconds()
    if remaining is None:
        return False
    return remaining >= MINIMUM_ACCESS_REMAINING_SECONDS


def build_host(arguments: argparse.Namespace, product: MinerProduct) -> MinerUpdaterHost:
    url = arguments.channel_url
    keys = load_trusted_keys(Path(arguments.keys_path))

    return MinerUpdaterHost(
        fetch_metadata=lambda: fetch(url),
        restart_service=lambda: restart_service(product),
        running_image=lambda: running_image(product),
        durable_digest=lambda: durable_digest(product),
        prepare_image=lambda release: prepare_image(product, release),
        verify_launcher=lambda release: verify_launcher(product, release),
        safe_to_activate=safe_to_activate,
        image_variable=product.image_variable,
        # Bound to this product, so a record naming the other one is
        # refused on both its product field and its image repository.
        expected_product=product.product,
        expected_image_repository=product.image_repository,
        env_path=Path(arguments.env_path or product.env_path),
        state_path=Path(arguments.state_path),
        pause_path=Path(arguments.pause_path),
        lock_path=Path(arguments.lock_path),
        trusted_keys=keys,
        now_unix=lambda: int(time.time()),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cathedral SN39 miner updater")
    parser.add_argument("command", choices=["check", "status"])
    parser.add_argument("--channel", default="stable", choices=["canary", "stable"])
    parser.add_argument("--channel-url", default=None)
    parser.add_argument("--product", default="sn39-snp-miner", choices=sorted(PRODUCTS))
    parser.add_argument("--env-path", default=None)
    parser.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))
    parser.add_argument("--pause-path", default=str(DEFAULT_PAUSE_PATH))
    parser.add_argument("--lock-path", default=str(DEFAULT_LOCK_PATH))
    parser.add_argument("--keys-path", default=str(DEFAULT_KEYS_PATH))
    arguments = parser.parse_args(argv)

    product = product_by_name(arguments.product)

    if arguments.command == "status":
        # Status must work without a channel URL, so an operator can always ask
        # what is installed even when the channel is unreachable.
        host = MinerUpdaterHost(
            fetch_metadata=lambda: b"",
            restart_service=lambda: None,
            running_image=lambda: None,
            env_path=Path(arguments.env_path or product.env_path),
            image_variable=product.image_variable,
            state_path=Path(arguments.state_path),
            pause_path=Path(arguments.pause_path),
            lock_path=Path(arguments.lock_path),
        )
        try:
            print(json.dumps(describe_status(host), indent=2, sort_keys=True))
        except MinerUpdateError as exc:
            print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
            return 1
        return 0

    if not arguments.channel_url:
        parser.error("check requires --channel-url")
    try:
        outcome = update_once(build_host(arguments, product), channel=arguments.channel)
    except MinerUpdateError as exc:
        print(json.dumps({"action": "failed", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(outcome.as_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
