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

MINER_UNIT = "cathedral-sn39-snp-miner.service"
CONTAINER_NAME = "cathedral-sn39-snp-miner"
# The launcher the release is built against, and the state it bind-mounts
# read-write. Both are fixed by scripts/run_sn39_snp_miner.sh.
LAUNCHER_PATH = Path("/usr/local/sbin/cathedral-run-sn39-snp-miner")
DURABLE_STATE_DIRECTORY = Path("/var/lib/cathedral/validator-access")
DEFAULT_KEYS_PATH = Path("/etc/cathedral/sn39-miner-update-keys.json")
MAX_KEYS_BYTES = 64 * 1024
MAX_LAUNCHER_BYTES = 4 * 1024 * 1024

FETCH_TIMEOUT_SECONDS = 30
FETCH_TOTAL_DEADLINE_SECONDS = 60
# The miner pulls nothing at this point (prepare already did) but still
# generates TLS material and binds. Measured starts are a few seconds.
SETTLE_TIMEOUT_SECONDS = 120
SETTLE_POLL_SECONDS = 3


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


def verify_launcher(release: MinerRelease) -> None:
    """Confirm this host runs the launcher the release was built against.

    The launcher hard-codes the runtime contract it accepts and refuses to
    start on a mismatch. Without this check an incompatible release would stop
    a working miner and only then fail, so the compatibility question is asked
    while the previous image is still serving.
    """

    try:
        with LAUNCHER_PATH.open("rb") as handle:
            body = handle.read(MAX_LAUNCHER_BYTES + 1)
    except OSError as exc:
        raise MinerUpdateError(f"installed launcher cannot be read: {LAUNCHER_PATH}") from exc
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


def durable_digest() -> str:
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
    root = DURABLE_STATE_DIRECTORY
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


def prepare_image(release: MinerRelease) -> None:
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


def restart_service() -> None:
    result = run(["systemctl", "restart", MINER_UNIT], timeout=180)
    if result.returncode != 0:
        raise MinerUpdateError(f"systemctl restart failed: {result.stderr.strip()[:200]}")


def running_image() -> str | None:
    """The image the running miner container actually reports.

    Waits for the container to settle, then answers with its immutable image
    reference, or None when nothing is running. Deliberately not "is the unit
    active": after an interrupted activation the previous container is still
    active, and treating that as success commits a release that never started.
    """

    deadline = time.monotonic() + SETTLE_TIMEOUT_SECONDS
    while True:
        # Config.Image is the reference the container was created from, which
        # is the digest-pinned string the launcher was given, so it compares
        # directly against the release's image.
        inspect = run(
            [
                "docker",
                "container",
                "inspect",
                "--format",
                "{{.State.Running}} {{.Config.Image}}",
                CONTAINER_NAME,
            ],
            timeout=30,
        )
        if inspect.returncode == 0:
            parts = inspect.stdout.strip().split(None, 1)
            if len(parts) == 2 and parts[0] == "true":
                return parts[1]
        if time.monotonic() >= deadline:
            return None
        time.sleep(SETTLE_POLL_SECONDS)


def safe_to_activate() -> bool:
    """Whether the miner may be restarted right now.

    Today the miner serves only signed validator requests, each bounded and
    retried by the validator on its next cycle, so a restart costs at most one
    cycle and there is nothing to wait for.

    This is the hook that changes when the host carries customer work. It must
    then return False while a customer command is in flight. It is injected
    rather than called inline precisely so that is one edit in one place.
    """

    return True


def build_host(arguments: argparse.Namespace) -> MinerUpdaterHost:
    url = arguments.channel_url
    return MinerUpdaterHost(
        fetch_metadata=lambda: fetch(url),
        restart_service=restart_service,
        running_image=running_image,
        durable_digest=durable_digest,
        prepare_image=prepare_image,
        verify_launcher=verify_launcher,
        safe_to_activate=safe_to_activate,
        env_path=Path(arguments.env_path),
        state_path=Path(arguments.state_path),
        pause_path=Path(arguments.pause_path),
        lock_path=Path(arguments.lock_path),
        trusted_keys=load_trusted_keys(Path(arguments.keys_path)),
        now_unix=lambda: int(time.time()),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cathedral SN39 miner updater")
    parser.add_argument("command", choices=["check", "status"])
    parser.add_argument("--channel", default="stable", choices=["canary", "stable"])
    parser.add_argument("--channel-url", default=None)
    parser.add_argument("--env-path", default=str(DEFAULT_ENV_PATH))
    parser.add_argument("--state-path", default=str(DEFAULT_STATE_PATH))
    parser.add_argument("--pause-path", default=str(DEFAULT_PAUSE_PATH))
    parser.add_argument("--lock-path", default=str(DEFAULT_LOCK_PATH))
    parser.add_argument("--keys-path", default=str(DEFAULT_KEYS_PATH))
    arguments = parser.parse_args(argv)

    if arguments.command == "status":
        # Status must work without a channel URL, so an operator can always ask
        # what is installed even when the channel is unreachable.
        host = MinerUpdaterHost(
            fetch_metadata=lambda: b"",
            restart_service=lambda: None,
            running_image=lambda: None,
            env_path=Path(arguments.env_path),
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
        outcome = update_once(build_host(arguments), channel=arguments.channel)
    except MinerUpdateError as exc:
        print(json.dumps({"action": "failed", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(outcome.as_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
