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


def ensure_deps() -> str | None:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return "cryptography missing; use /opt/cathedral-e2e/venv/bin/python after setup prepare"
    try:
        import sr25519  # noqa: F401
    except ImportError:
        pip = Path(sys.executable).parent / "pip"
        r = subprocess.run(
            [str(pip), "install", "-q", "py-sr25519-bindings==0.2.2"],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            return f"need py-sr25519-bindings: {(r.stdout + r.stderr)[-400:]}"
    return None


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
    miss = ensure_deps()
    if miss:
        return die(miss)

    sys.path.insert(0, str(ROOT))
    WORK.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = write_tls(WORK)
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
        sys.executable,
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
