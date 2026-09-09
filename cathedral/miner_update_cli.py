"""Command entry point for the SN39 miner updater.

This is the only place that talks to systemd, docker and the network. The state
machine in ``miner_updater`` stays free of them so its crash paths stay
testable.

    cathedral-sn39-miner-update check --channel stable
    cathedral-sn39-miner-update status
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cathedral.miner_release import MAX_RELEASE_DOCUMENT_BYTES
from cathedral.miner_updater import (
    DEFAULT_ENV_PATH,
    DEFAULT_PAUSE_PATH,
    DEFAULT_STATE_PATH,
    MinerUpdateError,
    MinerUpdaterHost,
    describe_status,
    update_once,
)

MINER_UNIT = "cathedral-sn39-snp-miner.service"
CONTAINER_NAME = "cathedral-sn39-snp-miner"
DEFAULT_KEYS_PATH = Path("/etc/cathedral/sn39-miner-update-keys.json")
FETCH_TIMEOUT_SECONDS = 30
# Give the miner time to pull nothing (the image is already local by now),
# start, generate TLS material and bind. Measured starts are a few seconds.
HEALTH_TIMEOUT_SECONDS = 120
HEALTH_POLL_SECONDS = 3


def load_trusted_keys(path: Path) -> dict[str, bytes]:
    """Read the miner release public keys this host trusts.

    Deliberately separate from any validator key material. A host that holds
    only this file cannot verify a validator release at all, which is the
    outermost of the three barriers against cross-product installation.
    """

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MinerUpdateError(f"trusted key file is missing: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise MinerUpdateError(f"trusted key file is unreadable: {path}") from exc
    if not isinstance(document, dict) or document.get("schema") != "cathedral_sn39_miner_release_keys_v1":
        raise MinerUpdateError("trusted key file schema is unsupported")
    keys = document.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise MinerUpdateError("trusted key file contains no keys")
    resolved: dict[str, bytes] = {}
    for key_id, value in keys.items():
        if not isinstance(key_id, str) or not isinstance(value, str):
            raise MinerUpdateError("trusted key entry is malformed")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise MinerUpdateError("trusted key is not lowercase hex") from exc
        if len(raw) != 32:
            raise MinerUpdateError("trusted key is not 32 bytes")
        resolved[key_id] = raw
    return resolved


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise MinerUpdateError("the channel URL must be https")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise MinerUpdateError(f"channel answered {response.status}")
            # Read one byte past the cap so an oversized body is detected rather
            # than silently truncated to something that might still parse.
            body = response.read(MAX_RELEASE_DOCUMENT_BYTES + 1)
    except urllib.error.URLError as exc:
        raise MinerUpdateError(f"channel is unreachable: {exc}") from exc
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


def prepare_image(image: str) -> None:
    """Pull the image and confirm the registry returned that exact digest.

    Done while the previous image is still pinned, so an unreachable registry
    or a digest mismatch costs nothing.
    """

    pull = run(["docker", "pull", "--platform", "linux/amd64", image], timeout=900)
    if pull.returncode != 0:
        raise MinerUpdateError(f"docker pull failed: {pull.stderr.strip()[:200]}")
    inspect = run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{range .RepoDigests}}{{println .}}{{end}}",
            image,
        ]
    )
    if inspect.returncode != 0:
        raise MinerUpdateError("docker image inspect failed after pull")
    if image not in inspect.stdout.split():
        raise MinerUpdateError("the pulled image does not report the requested digest")


def restart_service() -> None:
    result = run(["systemctl", "restart", MINER_UNIT], timeout=180)
    if result.returncode != 0:
        raise MinerUpdateError(f"systemctl restart failed: {result.stderr.strip()[:200]}")


def is_healthy() -> bool:
    """Confirm the miner is running after a restart.

    The worker serves POST only and has no health route, so a GET probe returns
    501 and proves nothing. Health here means systemd reports the unit active
    and the container is running. That is weaker than an end-to-end signed
    request, and it is stated as such rather than dressed up: a validator's next
    cycle is the real proof the miner works.
    """

    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        unit = run(["systemctl", "is-active", MINER_UNIT], timeout=30)
        container = run(
            ["docker", "container", "inspect", "--format", "{{.State.Running}}", CONTAINER_NAME],
            timeout=30,
        )
        if unit.stdout.strip() == "active" and container.stdout.strip() == "true":
            return True
        time.sleep(HEALTH_POLL_SECONDS)
    return False


def safe_to_activate() -> bool:
    """Whether the miner may be restarted right now.

    Today the miner serves only signed validator requests, each bounded and
    retried by the validator on its next cycle, so a restart costs at most one
    cycle and there is nothing to wait for.

    This is the hook that changes when the host carries customer work. It must
    then return False while a customer command is in flight. It is a separate
    function, and injected rather than called inline, precisely so that change
    is one edit in one place.
    """

    return True


def build_host(arguments: argparse.Namespace) -> MinerUpdaterHost:
    url = arguments.channel_url
    return MinerUpdaterHost(
        fetch_metadata=lambda: fetch(url),
        restart_service=restart_service,
        is_healthy=is_healthy,
        prepare_image=prepare_image,
        safe_to_activate=safe_to_activate,
        env_path=Path(arguments.env_path),
        state_path=Path(arguments.state_path),
        pause_path=Path(arguments.pause_path),
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
    parser.add_argument("--keys-path", default=str(DEFAULT_KEYS_PATH))
    arguments = parser.parse_args(argv)

    if arguments.command == "status":
        # Status must work without a channel URL, so an operator can always ask
        # what is installed even when the channel is unreachable.
        host = MinerUpdaterHost(
            fetch_metadata=lambda: b"",
            restart_service=lambda: None,
            is_healthy=lambda: False,
            env_path=Path(arguments.env_path),
            state_path=Path(arguments.state_path),
            pause_path=Path(arguments.pause_path),
        )
        print(json.dumps(describe_status(host), indent=2, sort_keys=True))
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
