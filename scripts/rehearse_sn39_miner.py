#!/usr/bin/env python3
"""Run the public miner protocol locally without hardware, chain, or wallet access.

This is an onboarding rehearsal, not an attestation or production-readiness test.
It binds only to an ephemeral loopback port, returns explicitly synthetic TDX
and SEV-SNP evidence, solves one canonical SAT challenge per evidence kind, and
validates a two-machine fleet manifest without contacting either endpoint.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cathedral.common import Evidence, EvidenceKind
from cathedral.lanes.sat import SatLane
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.validator_access import ValidatorAccessError, load_fleet_manifest
from cathedral.worker import WorkerServer

REHEARSAL_HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
REHEARSAL_PRIMARY = "https://8.8.8.8:8081"
REHEARSAL_SECONDARY = "https://1.1.1.1:8081"
_PROXY_ENVIRONMENT = (
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
)


class RehearsalFailure(RuntimeError):
    """Raised when one of the bounded rehearsal assertions fails."""


@contextmanager
def _without_ambient_proxies() -> Iterator[None]:
    """Keep every rehearsal request inside this process and on loopback."""

    previous = {name: os.environ.get(name) for name in _PROXY_ENVIRONMENT}
    try:
        for name in _PROXY_ENVIRONMENT:
            os.environ.pop(name, None)
        os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"
        os.environ["no_proxy"] = "127.0.0.1,localhost,::1"
        yield
    finally:
        for name in _PROXY_ENVIRONMENT:
            os.environ.pop(name, None)
        for name, value in previous.items():
            if value is not None:
                os.environ[name] = value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RehearsalFailure(message)


def _post_json(url: str, document: dict[str, object]) -> tuple[int, bytes]:
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    # This rehearsal is loopback-only. Ignore ambient proxy configuration so a
    # corporate HTTP(S)_PROXY cannot receive or break its synthetic requests.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _synthetic_collector(kind: EvidenceKind) -> Callable[..., Evidence]:
    def collect(nonce: bytes, hotkey: str, **_kwargs: object) -> Evidence:
        return Evidence(
            kind=kind,
            quote=b"synthetic-onboarding-evidence:" + kind.value.encode("ascii"),
            nonce=nonce,
            miner_hotkey=hotkey,
        )

    return collect


def _exercise_protocol(kind: EvidenceKind) -> dict[str, object]:
    server = WorkerServer(
        configured_hotkey=REHEARSAL_HOTKEY,
        evidence_collector=_synthetic_collector(kind),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = _post_json(f"{server.base_url}/v1/evidence", {})
        _require(status == 400, f"{kind.value}: invalid evidence health check was not 400")
        _require(
            body == b'{"error":"invalid evidence schema"}',
            f"{kind.value}: invalid evidence health body changed",
        )

        remote = RemoteMiner(
            server.base_url,
            REHEARSAL_HOTKEY,
            allow_insecure_http=True,
        )
        nonce = os.urandom(32)
        evidence = remote.fetch_evidence(nonce)
        _require(evidence.kind is kind, f"{kind.value}: evidence kind changed")
        _require(evidence.nonce == nonce, f"{kind.value}: evidence nonce was not bound")
        _require(
            evidence.miner_hotkey == REHEARSAL_HOTKEY,
            f"{kind.value}: evidence hotkey was not bound",
        )

        customer_sat = remote.supports_customer_sat()
        _require(customer_sat is False, f"{kind.value}: customer SAT unexpectedly enabled")

        lane = SatLane(namespace=f"miner-rehearsal-{kind.value}")
        item = lane.dispatch(REHEARSAL_HOTKEY, budget=1)
        certificate = remote.do_sat_work(item)
        verified = lane.verify(item, certificate)
        _require(verified is not None, f"{kind.value}: canonical SAT certificate failed")

        return {
            "evidence_kind": kind.value,
            "health": "PASS",
            "synthetic_evidence_round_trip": "PASS",
            "capabilities": "PASS",
            "canonical_sat": "PASS",
        }
    finally:
        server.shutdown()
        thread.join(timeout=2)
        _require(not thread.is_alive(), f"{kind.value}: loopback worker did not stop")


def _write_manifest(path: Path, endpoints: list[str]) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "cathedral_worker_fleet_v1",
                "worker_hotkey": REHEARSAL_HOTKEY,
                "endpoints": endpoints,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def run_rehearsal() -> dict[str, Any]:
    with (
        _without_ambient_proxies(),
        tempfile.TemporaryDirectory(prefix="cathedral-miner-rehearsal-") as directory,
    ):
        state_root = Path(directory)
        _require(not any(state_root.iterdir()), "temporary rehearsal state was not fresh")

        manifest = state_root / "fleet.json"
        _write_manifest(manifest, [REHEARSAL_SECONDARY])
        endpoints = load_fleet_manifest(
            str(manifest),
            worker_hotkey=REHEARSAL_HOTKEY,
            public_endpoint=REHEARSAL_PRIMARY,
        )
        _require(
            endpoints == (REHEARSAL_PRIMARY, REHEARSAL_SECONDARY),
            "valid extra-machine fleet order changed",
        )

        duplicate_manifest = state_root / "fleet-duplicate.json"
        _write_manifest(
            duplicate_manifest,
            [REHEARSAL_SECONDARY, REHEARSAL_SECONDARY],
        )
        try:
            load_fleet_manifest(
                str(duplicate_manifest),
                worker_hotkey=REHEARSAL_HOTKEY,
                public_endpoint=REHEARSAL_PRIMARY,
            )
        except ValidatorAccessError as exc:
            _require(
                str(exc) == "fleet manifest contains duplicate endpoints",
                "duplicate fleet failure changed",
            )
        else:
            raise RehearsalFailure("duplicate fleet endpoints were accepted")

        protocol = [
            _exercise_protocol(EvidenceKind.TDX),
            _exercise_protocol(EvidenceKind.SEV_SNP),
        ]
        state_path = str(state_root)

    return {
        "schema": "cathedral_miner_onboarding_rehearsal_v1",
        "status": "PASS",
        "fresh_temporary_state_removed": not Path(state_path).exists(),
        "checks": {
            "fleet_primary_plus_secondary": "PASS",
            "duplicate_fleet_rejected": "PASS",
            "protocol": protocol,
        },
        "scope": "loopback-only synthetic onboarding rehearsal",
        "not_proven": [
            "Intel TDX or AMD SEV-SNP hardware",
            "vendor evidence validity, measurement, TCB, or guest policy",
            "native TLS, live-key binding, or signed validator access",
            "public reachability, registration, weight, or emission",
        ],
    }


def main() -> int:
    try:
        result = run_rehearsal()
    except (OSError, RehearsalFailure, RemoteError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema": "cathedral_miner_onboarding_rehearsal_v1",
                    "status": "FAIL",
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
