#!/usr/bin/env python3
"""Render a disabled API grant and host deployment for a selected machine."""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

REVISION = "0be0cda0c9a73dc3f08e3af2a07dda9407635aa7"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--pki", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allocation-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--bind-address", required=True)
    parser.add_argument("--host-name", required=True)
    parser.add_argument("--cpus", type=float, required=True)
    parser.add_argument("--memory-gib", type=int, required=True)
    parser.add_argument("--platform", choices=("kvm", "systrap"), required=True)
    parser.add_argument("--expires-at", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", args.allocation_id):
        parser.error("allocation ID must contain lowercase letters, digits and hyphens")
    try:
        owner = str(uuid.UUID(args.owner_id))
        address = ipaddress.ip_address(args.bind_address)
        expiry = datetime.fromisoformat(args.expires_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError
    except ValueError:
        parser.error("owner UUID, bind address or future timezone-aware expiry is invalid")
    if address.is_unspecified or address.is_multicast:
        parser.error("bind to the specific interface protected by the executor firewall")
    endpoint = urlsplit(args.endpoint)
    if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password
            or endpoint.path not in ("", "/") or endpoint.query or endpoint.fragment):
        parser.error("endpoint must be an HTTPS origin")
    try:
        port = endpoint.port or 443
    except ValueError:
        parser.error("invalid endpoint port")
    if not 1024 <= port <= 65535:
        parser.error("use an unprivileged dedicated executor port")
    if not math.isfinite(args.cpus) or not 1 <= args.cpus <= 1024 or not 16 <= args.memory_gib <= 4096:
        parser.error("provide measured CPU and memory limits for the selected host")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,190}", args.host_name):
        parser.error("host name must be an inventory identifier")
    manifest = json.loads(args.manifest.read_text())
    if (manifest.get("schema") != "cathedral_reliquary_build_v1" or manifest.get("source_revision") != REVISION
            or manifest.get("platform") != "linux/amd64"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest.get("image_id", ""))
            or not re.fullmatch(r"grader-sha256:[0-9a-f]{64}", manifest.get("runtime_id", ""))):
        parser.error("manifest is not a pinned Reliquary executor build")
    output = args.output.expanduser().absolute()
    old_mask = os.umask(0o077)
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        host_dir, api_dir = output / "host", output / "api"
        host_dir.mkdir(mode=0o700)
        api_dir.mkdir(mode=0o700)
        for role, target, files in (
            ("executor", host_dir / "pki", ("ca.crt", "server.crt", "server.key")),
            ("api", api_dir / "pki", ("ca.crt", "client.crt", "client.key")),
        ):
            target.mkdir(mode=0o700)
            for name in files:
                source = args.pki / role / name
                if not source.is_file() or source.is_symlink():
                    parser.error("PKI package is incomplete or contains a symlink")
                shutil.copyfile(source, target / name)
                os.chmod(target / name, 0o600)
        env = {
            "RELIQUARY_CPU_EXECUTOR_HOST": str(address), "RELIQUARY_CPU_EXECUTOR_PORT": str(port),
            "RELIQUARY_CPU_EXECUTOR_POOL_SIZE": "50", "RELIQUARY_CPU_EXECUTOR_MAX_INFLIGHT": "50",
            "RELIQUARY_CPU_EXECUTOR_REUSE_WORKERS": "0", "RELIQUARY_RUNSC_PLATFORM": args.platform,
            "RELIQUARY_GRADER_RUNTIME_ID": manifest["runtime_id"], "RELIQUARY_CPU_EXECUTOR_ID": args.allocation_id,
            "RELIQUARY_CPU_EXECUTOR_TLS_CERT": "/etc/reliquary/pki/server.crt",
            "RELIQUARY_CPU_EXECUTOR_TLS_KEY": "/etc/reliquary/pki/server.key",
            "RELIQUARY_CPU_EXECUTOR_CLIENT_CA": "/etc/reliquary/pki/ca.crt",
            "GRADER_HEALTH_PATH": "/tmp/reliquary-cpu-executor-health.json", "GRADER_METRICS_PORT": "9876",
        }
        (host_dir / "executor.env").write_text("".join(f"{key}={value}\n" for key, value in env.items()))
        compose = f'''services:
  executor:
    image: {json.dumps(manifest["image_id"])}
    pull_policy: never
    restart: "no"
    init: true
    privileged: true
    cgroup: host
    ipc: private
    pid: private
    network_mode: host
    read_only: true
    stop_grace_period: 140s
    cpus: {json.dumps(str(args.cpus))}
    mem_limit: {args.memory_gib}g
    memswap_limit: {args.memory_gib}g
    pids_limit: 8192
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    tmpfs:
      - /tmp:rw,nosuid,nodev,noexec,size=2g
      - /run:rw,nosuid,nodev,size=512m
    env_file:
      - executor.env
    volumes:
      - ./pki:/etc/reliquary/pki:ro
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
'''
        (host_dir / "compose.yaml").write_text(compose)
        shutil.copyfile(Path(__file__).with_name("cathedral-reliquary@.service"), output / "cathedral-reliquary@.service")
        remote_pki = f"/etc/polaris/workers/{args.allocation_id}/pki"
        configuration = {
            "schema": "polaris_workers_grants_v1",
            "allocations": [{"allocation_id": args.allocation_id, "owner_id": owner,
                "endpoint": args.endpoint.rstrip("/"), "runtime_id": manifest["runtime_id"],
                "concurrent_limit": 50, "enabled": False,
                "ca_cert": remote_pki + "/ca.crt", "client_cert": remote_pki + "/client.crt",
                "client_key": remote_pki + "/client.key"}],
            "grants": [{"grant_id": args.allocation_id + "-grant", "owner_id": owner,
                "allocation_id": args.allocation_id, "concurrent_limit": 50,
                "expires_at": expiry.astimezone(timezone.utc).isoformat(), "source": "operator-trial"}],
        }
        (api_dir / "grants.json").write_text(json.dumps(configuration, indent=2) + "\n")
        (output / "allocation-record.json").write_text(json.dumps({
            "allocation_id": args.allocation_id, "owner_id": owner, "host_name": args.host_name,
            "cpu_quota": args.cpus, "memory_limit_gib": args.memory_gib, "pool_size": 50,
            "sandbox_platform": args.platform, "source_revision": REVISION,
            "image_id": manifest["image_id"], "runtime_id": manifest["runtime_id"],
            "qualification": "NOT_RUN", "exclusive_host_verification": "PENDING",
            "admission": "DISABLED",
        }, indent=2) + "\n")
    finally:
        os.umask(old_mask)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
