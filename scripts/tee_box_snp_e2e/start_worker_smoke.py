#!/usr/bin/env python3
"""Start SNP tee-box worker on a measured guest with live HOST_DATA (no inject).

TEST / SMOKE ONLY. Creates throwaway TLS + validator-access materials under
``/var/lib/cathedral-e2e/snp-worker``. Does **not** overwrite
``/usr/share/cathedral/central-root-keys.json``.

``serve-snp`` requires signed validator-access. Tee-box API calls still need
central-access signatures from the measured root private key (held offline by
the root owner) — this script only proves the worker **starts**.

Usage (root on :2225, after setup.sh prepare):
  export PYTHONPATH=/opt/cathedral/sandbox
  unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
  /opt/cathedral-e2e/venv/bin/python scripts/tee_box_snp_e2e/start_worker_smoke.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORK = Path(os.environ.get("E2E_SNP_WORKER", "/var/lib/cathedral-e2e/snp-worker"))
HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
NETWORK, NETUID = "finney", 94
SNAPSHOT_SEED = b"s" * 32
MARKER = Path("/run/cathedral-tee-e2e/TEST_BOX")


def die(msg: str, code: int = 2) -> int:
    print(f"FAIL: {msg}", file=sys.stderr)
    return code


def _pip_install_sr25519(python: str) -> tuple[bool, str]:
    """Install a *wheel only* — never compile (measured guests have no Rust)."""
    pip = [python, "-m", "pip", "install", "-q", "--only-binary=:all:", "py-sr25519-bindings==0.2.2"]
    r = subprocess.run(pip, capture_output=True, text=True)
    if r.returncode == 0:
        return True, ""
    return False, (r.stdout + r.stderr)[-500:]


def _bootstrap_uv_python313() -> tuple[str | None, str]:
    """Measured Ubuntu 26 images ship only 3.14; fetch portable CPython 3.13 via uv."""
    venv = Path("/opt/cathedral-e2e/venv313")
    py = venv / "bin" / "python"
    if py.is_file():
        return str(py), f"reuse {py}"

    uv = shutil.which("uv")
    if uv is None:
        install = subprocess.run(
            "curl -LsSf https://astral.sh/uv/install.sh | sh",
            shell=True,
            capture_output=True,
            text=True,
        )
        if install.returncode != 0:
            return None, f"uv install failed: {(install.stdout + install.stderr)[-400:]}"
        local_uv = Path.home() / ".local" / "bin" / "uv"
        uv = str(local_uv) if local_uv.is_file() else shutil.which("uv")
        if not uv:
            return None, "uv installed but not on PATH (~/.local/bin/uv missing)"

    env = os.environ.copy()
    env["PATH"] = f"{Path.home() / '.local' / 'bin'}:{env.get('PATH', '')}"
    steps = [
        [uv, "python", "install", "3.13"],
        [uv, "venv", str(venv), "--python", "3.13"],
    ]
    for cmd in steps:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            return None, f"{' '.join(cmd)} failed: {(r.stdout + r.stderr)[-400:]}"
    if not py.is_file():
        return None, f"uv venv did not create {py}"
    # cryptography + sr25519 into the portable 3.13 venv
    deps = subprocess.run(
        [
            str(py),
            "-m",
            "pip",
            "install",
            "-q",
            "--upgrade",
            "pip",
        ],
        capture_output=True,
        text=True,
    )
    if deps.returncode != 0:
        # uv venvs may need `uv pip`
        alt = subprocess.run(
            [uv, "pip", "install", "--python", str(py), "cryptography", "py-sr25519-bindings==0.2.2"],
            capture_output=True,
            text=True,
            env=env,
        )
        if alt.returncode != 0:
            return None, f"pip bootstrap failed: {(deps.stdout + deps.stderr + alt.stdout + alt.stderr)[-500:]}"
        return str(py), f"bootstrapped portable 3.13 at {py} via uv pip"
    ok, err = _pip_install_sr25519(str(py))
    crypto = subprocess.run(
        [str(py), "-m", "pip", "install", "-q", "--only-binary=:all:", "cryptography>=42"],
        capture_output=True,
        text=True,
    )
    if not ok or crypto.returncode != 0:
        alt = subprocess.run(
            [uv, "pip", "install", "--python", str(py), "cryptography", "py-sr25519-bindings==0.2.2"],
            capture_output=True,
            text=True,
            env=env,
        )
        if alt.returncode != 0:
            return None, (
                f"deps into 3.13 venv failed: sr25519={err[-200:]} "
                f"crypto={(crypto.stdout + crypto.stderr)[-200:]} "
                f"uv={(alt.stdout + alt.stderr)[-200:]}"
            )
    return str(py), f"bootstrapped portable 3.13 at {py}"


def _python_with_sr25519() -> tuple[str | None, str]:
    """Return an interpreter that can import sr25519, or (None, why)."""
    candidates: list[str] = [sys.executable]
    # Ubuntu 26 / Python 3.14 often has no manylinux wheel; prefer 3.13/3.12.
    for name in ("python3.13", "python3.12", "python3.11"):
        path = shutil.which(name)
        if path and path not in candidates:
            candidates.append(path)
    portable = Path("/opt/cathedral-e2e/venv313/bin/python")
    if portable.is_file() and str(portable) not in candidates:
        candidates.append(str(portable))

    tried: list[str] = []
    for py in candidates:
        probe = subprocess.run(
            [py, "-c", "import sr25519; print(sr25519.__file__)"],
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            return py, f"already present in {py}"
        ok, err = _pip_install_sr25519(py)
        tried.append(f"{py}: {'ok' if ok else err.splitlines()[-1] if err else 'fail'}")
        if not ok:
            continue
        probe = subprocess.run(
            [py, "-c", "import sr25519"],
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            return py, f"installed wheel into {py}"

    # Last resort on 3.14-only measured images: portable CPython via uv.
    if sys.version_info[:2] >= (3, 14) or not any("3.13" in t or "3.12" in t for t in tried):
        print("bootstrapping portable CPython 3.13 via uv (no system python3.13)...", flush=True)
        py, detail = _bootstrap_uv_python313()
        if py is not None:
            probe = subprocess.run(
                [py, "-c", "import cryptography, sr25519"],
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0:
                return py, detail
            tried.append(f"uv313: import failed {(probe.stdout + probe.stderr)[-200:]}")
        else:
            tried.append(f"uv313: {detail}")

    ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    return None, (
        f"no py-sr25519-bindings wheel for this guest (python {ver}). "
        f"wheels exist for cp310–cp313 only. tried: {'; '.join(tried)}. "
        "Manual fix: curl -LsSf https://astral.sh/uv/install.sh | sh && "
        "uv python install 3.13 && uv venv /opt/cathedral-e2e/venv313 --python 3.13 && "
        "uv pip install --python /opt/cathedral-e2e/venv313/bin/python "
        "cryptography 'py-sr25519-bindings==0.2.2'"
    )


def ensure_deps() -> tuple[str | None, str | None]:
    """Return (python_to_use, error). python_to_use may differ from sys.executable."""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return None, (
            "cryptography missing; use /opt/cathedral-e2e/venv/bin/python after setup prepare"
        )
    py, detail = _python_with_sr25519()
    if py is None:
        return None, detail
    print(f"sr25519: {detail}", flush=True)
    return py, None


def write_tls(work: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tee-box-snp-e2e.invalid")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path = work / "key.pem"
    cert_path = work / "cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def write_validator_access(work: Path) -> dict[str, str | int]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from cathedral.policy_registry import canonical_json
    from cathedral.validator_access import (
        VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        sign_validator_access_snapshot,
    )

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys_doc = {"cathedral-validator-access": base64.b64encode(pub).decode("ascii")}
    keys_bytes = canonical_json(keys_doc)
    keys_path = work / "validator-access-keys.json"
    keys_path.write_bytes(keys_bytes)
    digest = "sha256:" + hashlib.sha256(keys_bytes).hexdigest()

    now = datetime.now(UTC)
    document = {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": NETWORK,
        "netuid": NETUID,
        "block": 8_948_557,
        "block_hash": "0x" + "a" * 64,
        "block_is_finalized": True,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minimum_stake_rao": 1_000,
        "validators": [
            {
                "hotkey": HOTKEY,
                "uid": 30,
                "validator_permit": True,
                "stake_rao": 2_000,
            }
        ],
        "signing_key_id": "cathedral-validator-access",
    }
    snap_path = work / "validator-access-snapshot.json"
    snap_path.write_bytes(canonical_json(sign_validator_access_snapshot(document, SNAPSHOT_SEED)))
    state_path = work / "validator-access.sqlite"
    if state_path.exists():
        state_path.unlink()
    return {
        "snapshot": str(snap_path),
        "keys": str(keys_path),
        "digest": digest,
        "state": str(state_path),
        "minimum_stake_rao": 1_000,
        "public_endpoint": "https://127.0.0.1:8443",
    }


def main() -> int:
    if os.geteuid() != 0:
        return die("run as root on the measured SNP guest")
    for bad in ("E2E_HOST_DATA_HEX", "CATHEDRAL_E2E_HOST_DATA_HEX"):
        if os.environ.get(bad):
            return die(f"inject env {bad} is set — refuse")
    if not MARKER.is_file():
        return die(f"missing {MARKER}; run: TEE=snp bash scripts/tee_box_tdx_e2e/setup.sh prepare")
    worker_py, miss = ensure_deps()
    if miss or worker_py is None:
        return die(miss or "no python with sr25519")

    sys.path.insert(0, str(ROOT))
    WORK.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = write_tls(WORK)
    # Material writers run under *this* interpreter (cryptography); worker may
    # be a different python that has the sr25519 wheel.
    access = write_validator_access(WORK)
    token = secrets.token_hex(24)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONUNBUFFERED"] = "1"
    env["CATHEDRAL_WORKER_BEARER_TOKEN"] = token
    env["E2E_SRC"] = str(ROOT)
    env["E2E_BINDING"] = "real"
    env.pop("E2E_MRCONFIGID_HEX", None)

    state = "/run/cathedral-tee-box/central.sqlite"
    Path("/run/cathedral-tee-box").mkdir(parents=True, exist_ok=True)
    log_path = WORK / "worker.log"
    argv = [
        worker_py,
        str(ROOT / "scripts/tee_box_tdx_e2e/serve_worker.py"),
        "worker",
        "serve-snp",
        "--hotkey",
        HOTKEY,
        "--host",
        "127.0.0.1",
        "--port",
        "8443",
        "--tls-certificate",
        str(cert_path),
        "--tls-private-key",
        str(key_path),
        "--validator-network",
        NETWORK,
        "--validator-netuid",
        str(NETUID),
        "--validator-access-snapshot",
        str(access["snapshot"]),
        "--validator-access-keys",
        str(access["keys"]),
        "--validator-access-keys-digest",
        str(access["digest"]),
        "--validator-access-state",
        str(access["state"]),
        "--validator-minimum-stake-rao",
        str(access["minimum_stake_rao"]),
        "--public-endpoint",
        str(access["public_endpoint"]),
        "--tee-box-central-state",
        state,
        "--tee-box-executor",
        "runsc",
        "--tee-box-detect-addresses",
        "--tee-box-capacity",
        "2,2048,1024",
        "--tee-box-default-shape",
        "1,512,256",
        "--tee-box-no-disk-quota",
        "--tee-box-id",
        "tee-box-snp-e2e",
    ]
    print("starting:", " ".join(argv), flush=True)
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            argv,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(WORK),
        )
    # Wait for startup JSON or failure.
    deadline = time.time() + 90
    while time.time() < deadline:
        if proc.poll() is not None:
            text = log_path.read_text(errors="replace")
            print(text[-4000:])
            return die(f"worker exited {proc.returncode}; see {log_path}", 1)
        text = log_path.read_text(errors="replace")
        if "cathedral_effective_startup_v1" in text:
            for line in text.splitlines():
                if "cathedral_effective_startup_v1" in line:
                    print(line)
                    doc = json.loads(line)
                    tee = doc.get("tee_box") or {}
                    print(
                        "worker_smoke=PASS",
                        f"pid={proc.pid}",
                        f"port={doc.get('port')}",
                        f"fresh_boot_hw={tee.get('boot', {}).get('fresh_boot_hardware_backed')}",
                        f"root={tee.get('central_root_digest')}",
                        flush=True,
                    )
                    print(
                        "note=tee-box API still needs Fred-signed central-access "
                        "(root private key offline); leave worker running or kill",
                        proc.pid,
                        flush=True,
                    )
                    return 0
        time.sleep(0.5)
    proc.kill()
    print(log_path.read_text(errors="replace")[-4000:])
    return die(f"worker start timed out; see {log_path}", 1)


if __name__ == "__main__":
    raise SystemExit(main())
