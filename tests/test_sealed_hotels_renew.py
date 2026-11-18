"""ops/sealed-hotels-renew.sh (AB#800 PLAN step 0): sign, verify, upload to KV.

The real publisher and the real standalone verifier run against a key
generated in-test; Cloudflare is a local HTTP server that records requests.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ops" / "sealed-hotels-renew.sh"
SERVICE = ROOT / "ops" / "sealed-hotels-renew.service"
TIMER = ROOT / "ops" / "sealed-hotels-renew.timer"
PUBLISHER = ROOT / "scripts" / "cathedral_sealed_hotels_publish.py"
ACCOUNT = "a" * 32
NAMESPACE = "b" * 32
TOKEN = "renew-test-token-canary-7f3c"
KV_PATH = (
    f"/client/v4/accounts/{ACCOUNT}/storage/kv/namespaces/{NAMESPACE}/values/sealed_hotels_current"
)
HOTELS = {"renew-hotel-a": {"chip_id": "ab" * 64, "measurements": ["11" * 48]}}


class FakeKV:
    def __init__(self) -> None:
        self.value: bytes | None = None
        self.requests: list[tuple[str, str, str | None]] = []
        self.put_status = 200
        # GETs after a PUT that still answer the previous value (KV staleness).
        self.stale_gets = 0
        self._previous: bytes | None = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/client/v4"

    def _handler(self):
        kv = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:  # keep pytest output quiet
                pass

            def _reply(self, status: int, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self) -> bool:
                kv.requests.append((self.command, self.path, self.headers.get("Authorization")))
                if self.path != KV_PATH:
                    self._reply(404, b'{"success":false}')
                    return False
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self._reply(401, b'{"success":false}')
                    return False
                return True

            def do_GET(self) -> None:
                if not self._authorized():
                    return
                if kv.stale_gets > 0 and self.command == "GET" and kv._previous is not kv.value:
                    kv.stale_gets -= 1
                    if kv._previous is None:
                        self._reply(404, b'{"success":false,"errors":[{"code":10009}]}')
                    else:
                        self._reply(200, kv._previous)
                elif kv.value is None:
                    self._reply(404, b'{"success":false,"errors":[{"code":10009}]}')
                else:
                    self._reply(200, kv.value)

            def do_PUT(self) -> None:
                if not self._authorized():
                    return
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if kv.put_status == 200:
                    kv._previous = kv.value
                    kv.value = body
                self._reply(kv.put_status, b'{"success":true}')

        return Handler

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _private(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _pins(path: Path, key: Ed25519PrivateKey, key_id: str) -> Path:
    now = datetime.now(UTC)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    path.write_text(
        json.dumps(
            {
                "schema": "cathedral_sealed_hotels_pins_v1",
                "keys": {
                    key_id: {
                        "algorithm": "ed25519",
                        "public_key_hex": public.hex(),
                        "not_before": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "not_after": (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                },
            }
        )
    )
    return path


@pytest.fixture
def renew(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    keydir = tmp_path / "keys"
    keydir.mkdir(mode=0o700)
    pem = _private(
        keydir / "k.pem",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"pw"),
        ),
    )
    passphrase = _private(keydir / "k.pass", b"pw")
    config = _private(
        keydir / "signers.json",
        json.dumps(
            {
                "sealed_hotels": {
                    "backend": "local_file",
                    "key_id": "renew-test-1",
                    "path": str(pem),
                    "passphrase_path": str(passphrase),
                }
            }
        ).encode(),
    )
    pins = _pins(tmp_path / "pins.json", key, "renew-test-1")
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"hotels": HOTELS}))
    state = tmp_path / "state" / "publisher-state.json"
    out = tmp_path / "releases"
    out.mkdir()
    # Release 1 is made by hand with --init-state, as on the key host.
    first = subprocess.run(
        [sys.executable, str(PUBLISHER), "--signer-config", str(config), "--pins", str(pins), "--inventory", str(inventory),
         "--state", str(state), "--out-dir", str(out), "--init-state", "--release", "1"],
        check=False, capture_output=True, text=True,
    )  # fmt: skip
    assert first.returncode == 0, first.stderr
    token = _private(keydir / "cf-token", (TOKEN + "\n").encode())
    kv = FakeKV()
    env = {
        "PATH": os.environ["PATH"],
        "PYTHON": sys.executable,
        "SEALED_HOTELS_SIGNER_CONFIG": str(config),
        "SEALED_HOTELS_INVENTORY": str(inventory),
        "SEALED_HOTELS_PINS": str(pins),
        "SEALED_HOTELS_VERIFY_PINS": str(pins),
        "SEALED_HOTELS_STATE": str(state),
        "SEALED_HOTELS_OUT_DIR": str(out),
        "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
        "SEALED_HOTELS_KV_NAMESPACE_ID": NAMESPACE,
        "CLOUDFLARE_API_TOKEN_FILE": str(token),
        "CLOUDFLARE_API_BASE": kv.base,
        "SEALED_HOTELS_READBACK_DELAY": "0",
    }
    yield {
        "env": env,
        "state": state,
        "out": out,
        "kv": kv,
        "token": token,
        "key": key,
        "tmp": tmp_path,
    }
    kv.close()


def _run(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPT), *args], check=False, capture_output=True, text=True, env=env, cwd="/"
    )


def _last_release(state: Path) -> int:
    return json.loads(state.read_text())["last_release"]


def _no_token(result: subprocess.CompletedProcess) -> None:
    assert TOKEN not in result.stdout and TOKEN not in result.stderr


def test_renews_verifies_and_uploads_exact_bytes(renew) -> None:
    result = _run(renew["env"])
    assert result.returncode == 0, result.stderr
    _no_token(result)
    summary = json.loads(result.stdout)
    assert summary["release"] == 2 and summary["uploaded"] is True
    signed = (renew["out"] / "release-2.json").read_bytes()
    assert renew["kv"].value == signed
    assert summary["digest"] == "sha256:" + hashlib.sha256(signed).hexdigest()
    assert "PASS release 2" in result.stderr
    assert _last_release(renew["state"]) == 2
    methods = [method for method, _, _ in renew["kv"].requests]
    assert methods == ["GET", "PUT", "GET"]
    assert all(auth == f"Bearer {TOKEN}" for _, _, auth in renew["kv"].requests)

    again = _run(renew["env"])
    assert again.returncode == 0, again.stderr
    assert json.loads(again.stdout)["release"] == 3
    assert renew["kv"].value == (renew["out"] / "release-3.json").read_bytes()


def test_no_upload_signs_and_verifies_without_network(renew) -> None:
    env = {
        k: v
        for k, v in renew["env"].items()
        if not k.startswith("CLOUDFLARE_") and k != "SEALED_HOTELS_KV_NAMESPACE_ID"
    }
    result = _run(env, "--no-upload")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "release": 2,
        "digest": "sha256:"
        + hashlib.sha256((renew["out"] / "release-2.json").read_bytes()).hexdigest(),
        "uploaded": False,
    }
    assert renew["kv"].requests == []


@pytest.mark.parametrize("problem", ["missing", "readable", "empty", "unset_namespace"])
def test_bad_upload_config_refuses_before_signing(renew, problem: str) -> None:
    env = dict(renew["env"])
    if problem == "missing":
        env["CLOUDFLARE_API_TOKEN_FILE"] = str(renew["tmp"] / "nope")
    elif problem == "readable":
        renew["token"].chmod(0o644)
    elif problem == "empty":
        renew["token"].write_bytes(b"")
    else:
        del env["SEALED_HOTELS_KV_NAMESPACE_ID"]
    result = _run(env)
    assert result.returncode != 0 and "refusing" in result.stderr
    _no_token(result)
    assert _last_release(renew["state"]) == 1  # no release number burned
    assert not (renew["out"] / "release-2.json").exists()
    assert renew["kv"].requests == []


def test_missing_state_is_never_initialized(renew) -> None:
    renew["state"].unlink()
    result = _run(renew["env"])
    assert result.returncode != 0 and "no publisher state" in result.stderr
    assert not renew["state"].exists()
    assert renew["kv"].requests == []


def test_verifier_failure_blocks_upload(renew) -> None:
    other = _pins(renew["tmp"] / "other-pins.json", Ed25519PrivateKey.generate(), "renew-test-1")
    env = {**renew["env"], "SEALED_HOTELS_VERIFY_PINS": str(other)}
    result = _run(env)
    assert result.returncode != 0 and "failed the standalone verifier" in result.stderr
    assert renew["kv"].requests == []


def test_newer_release_in_kv_is_not_replaced(renew) -> None:
    renew["kv"].value = json.dumps({"release": 99}).encode()
    result = _run(renew["env"])
    assert result.returncode != 0 and "newer or conflicting" in result.stderr
    _no_token(result)
    assert renew["kv"].value == json.dumps({"release": 99}).encode()
    assert [method for method, _, _ in renew["kv"].requests] == ["GET"]


def test_failed_kv_write_fails_the_run(renew) -> None:
    renew["kv"].put_status = 500
    result = _run(renew["env"])
    assert result.returncode != 0 and "KV write answered HTTP 500" in result.stderr
    _no_token(result)
    assert renew["kv"].value is None


def test_overlapping_run_refuses_before_signing(renew) -> None:
    # A run holding the lock (here: this test) blocks a second run before it
    # signs, so it cannot burn a release number or upload over a newer one.
    import fcntl

    lock = Path(str(renew["state"]) + ".renew.lock")
    with open(lock, "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = _run(renew["env"])
    assert result.returncode != 0 and "another renewal holds" in result.stderr
    _no_token(result)
    assert _last_release(renew["state"]) == 1
    assert renew["kv"].requests == [] and renew["kv"].value is None
    # Lock released: the next run proceeds normally.
    after = _run(renew["env"])
    assert after.returncode == 0, after.stderr
    assert _last_release(renew["state"]) == 2


def test_delayed_kv_visibility_is_waited_out(renew) -> None:
    # KV can answer the old value for a while after a successful PUT.
    renew["kv"].stale_gets = 5
    result = _run(renew["env"])
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["uploaded"] is True
    assert [m for m, _, _ in renew["kv"].requests].count("GET") == 1 + 6


def test_readback_gives_up_after_configured_tries(renew) -> None:
    renew["kv"].stale_gets = 100
    env = dict(renew["env"], SEALED_HOTELS_READBACK_TRIES="3")
    result = _run(env)
    assert result.returncode != 0 and "KV readback does not match" in result.stderr
    assert [m for m, _, _ in renew["kv"].requests].count("GET") == 1 + 3


def _directives(path: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "[")) and "=" in line:
            key, _, value = line.partition("=")
            result.setdefault(key, []).append(value)
    return result


def test_units_run_the_script_every_six_hours() -> None:
    timer = _directives(TIMER)
    assert timer["OnCalendar"] == ["*-*-* 00/6:00:00 UTC"]
    assert timer["Persistent"] == ["true"]
    assert timer["Unit"] == ["sealed-hotels-renew.service"]
    service = _directives(SERVICE)
    assert service["Type"] == ["oneshot"]
    assert service["EnvironmentFile"] == ["/etc/cathedral/sealed-hotels-renew.env"]
    assert service["ExecStart"] == ["/bin/bash ${CATHEDRAL_SANDBOX_DIR}/ops/sealed-hotels-renew.sh"]
    # The default state and output directory must be writable under ProtectSystem=strict.
    assert service["ProtectSystem"] == ["strict"]
    assert service["ReadWritePaths"] == ["/var/lib/cathedral-sealed-hotels"]
    script = SCRIPT.read_text()
    assert "/var/lib/cathedral-sealed-hotels/publisher-state.json" in script
    assert "/var/lib/cathedral-sealed-hotels/releases" in script
