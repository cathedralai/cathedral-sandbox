#!/usr/bin/env python3
"""Rehearse Rollout step 3 of docs/MINER_AUTO_UPDATE.md on a scratch host.

It makes throwaway release keys, signs a canary and a stable record with the
real offline signer, bootstraps a host under a scratch root, and captures what
step 3 asks for: the signed record, the key fingerprints, `status` before and
after, and the journal. Then it runs the two negative controls on the same
host: a record with a bad signature, and a rolled-back sequence. Both must be
refused and must leave the serving release untouched.

docker and systemd are faked, as in tests/test_miner_update_end_to_end.py, so
this runs anywhere with python3-cryptography. It commits no trust root, signs
nothing a real host would accept, and deletes the throwaway keys on exit
unless --keep-keys is given.

    rehearse_miner_update.py --evidence-dir DIR [--product snp-miner] [--keep-keys]

DIR receives evidence.json (and the signed records). Exit 0 only if every
check passed. The live run repeats the same capture with the real keys, the
committed release-keys.json and `cathedral-miner-update status|check` on the
test host, so the evidence has the same shape.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from cathedral.miner_bootstrap import install  # noqa: E402
from cathedral.miner_bundle import link_target  # noqa: E402
from cathedral.miner_products import find_launcher, product_by_name, read_launcher_profile  # noqa: E402
from cathedral.miner_release import TRUST_ROOT_SCHEMA  # noqa: E402
from cathedral.miner_updater import (  # noqa: E402
    CONFIG_SCHEMA,
    HostConfig,
    HostPaths,
    MinerUpdaterHost,
    Observation,
    describe_status,
    read_activation_profile,
    update_once,
)

SIGNER = REPOSITORY_ROOT / "deploy" / "miner-update" / "build_signed_miner_release.py"
NETWORK = "testnet"
WEEK = 7 * 24 * 3600
BUNDLE_URL = "https://127.0.0.1:9/miner/bundle.tar.gz"  # a closed port: nothing is fetched
CHANNEL_URL = "https://127.0.0.1:9/miner/stable.json"
MINER_UNIT = "cathedral-rehearsal-miner.service"
MANAGED_FILES = [
    "cathedral/__init__.py",
    *(f"cathedral/{name}" for name in (
        "miner_release.py", "miner_products.py", "miner_bundle.py", "miner_updater.py", "miner_update_cli.py",
    )),
    "deploy/miner-update/miner-unit.conf",
    "deploy/miner-update/cathedral-miner-update",
    "deploy/miner-update/cathedral-miner-update.service",
    "deploy/miner-update/cathedral-miner-update.timer",
    "deploy/miner-update/cathedral-miner-update-alert@.service",
]


class Rehearsal:
    def __init__(self, work: Path, evidence: Path, product_name: str) -> None:
        self.work = work
        self.evidence = evidence
        self.product = product_by_name(product_name)
        self.netuid = random.SystemRandom().randrange(1, 65535)
        self.passphrase = secrets.token_urlsafe(24)
        self.checks: list[dict[str, object]] = []
        self.journal: list[str] = []

    # --- helpers -----------------------------------------------------------------

    def check(self, name: str, passed: bool, detail: object = None) -> None:
        self.checks.append({"check": name, "passed": bool(passed), "detail": detail})
        self.journal.append(f"check {'ok' if passed else 'FAILED'}: {name}")

    def sign(self, *arguments: str, expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(SIGNER), *arguments],
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "CATHEDRAL_MINER_RELEASE_PASSPHRASE": self.passphrase},
        )
        if expect_ok and result.returncode != 0:
            raise SystemExit(f"signer failed: {result.stderr[-1500:]}")
        return result

    def key_file(self, name: str, key: Ed25519PrivateKey) -> Path:
        path = self.work / "keys" / f"{name}.pem"
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self.passphrase.encode()),
            )
        )
        path.chmod(0o600)
        return path

    @staticmethod
    def public_hex(key: Ed25519PrivateKey) -> str:
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ).hex()

    def status(self) -> dict[str, object]:
        return json.loads(json.dumps(describe_status(self.paths, self.config, expected_uid=os.getuid())))

    def serving(self) -> dict[str, object]:
        status = self.status()
        miner = status["miner"]
        assert isinstance(miner, dict)
        release = miner.get("current_release") or {}
        return {
            "active": miner.get("active"),
            "version": release.get("version") if isinstance(release, dict) else None,
            "sequence": release.get("sequence") if isinstance(release, dict) else None,
            "image": release.get("image") if isinstance(release, dict) else None,
        }

    # --- steps -------------------------------------------------------------------

    def make_keys_and_records(self) -> None:
        (self.work / "keys").mkdir(mode=0o700)
        canary_key, stable_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.canary_pem = self.key_file("canary", canary_key)
        self.stable_pem = self.key_file("stable", stable_key)
        self.trust = self.work / "release-keys.json"
        self.trust.write_bytes(
            json.dumps(
                {
                    "schema": TRUST_ROOT_SCHEMA,
                    "keys": {
                        "rehearsal-canary": {"public_key_hex": self.public_hex(canary_key), "channels": ["canary"]},
                        "rehearsal-stable": {"public_key_hex": self.public_hex(stable_key), "channels": ["stable"]},
                    },
                },
                sort_keys=True,
            ).encode("ascii")
        )
        built = json.loads(
            self.sign(
                "bundle", "--product", self.product.product,
                "--out-dir", str(self.work / "out"), "--trust-root", str(self.trust),
            ).stdout
        )
        self.bundle = built
        repository = read_launcher_profile(find_launcher(REPOSITORY_ROOT, self.product)).image_repository
        self.image = f"{repository}@sha256:{'2' * 64}"
        canary = self.sign(
            "canary", "--private-key", str(self.canary_pem), "--signing-key-id", "rehearsal-canary",
            "--product", self.product.product, "--network", NETWORK, "--netuid", str(self.netuid),
            "--image", self.image, "--state-schema", "1",
            "--bundle-archive", built["archive"], "--bundle-url", BUNDLE_URL,
            "--version", "rehearsal-1", "--sequence", "1", "--lifetime-seconds", str(WEEK),
            "--out", str(self.work / "canary.json"),
        )
        self.canary_summary = json.loads(canary.stdout)
        self.stable_summary = self.promote(sequence=2, out="stable.json")
        self.journal.append("signed canary seq 1 and stable seq 2 with throwaway keys")

    def promote(self, *, sequence: int, out: str) -> dict[str, object]:
        result = self.sign(
            "stable", "--private-key", str(self.stable_pem), "--signing-key-id", "rehearsal-stable",
            "--promote", str(self.work / "canary.json"), "--bundle-archive", self.bundle["archive"],
            "--trust-root", str(self.trust), "--sequence", str(sequence), "--lifetime-seconds", str(WEEK),
            "--out", str(self.work / out),
        )
        return json.loads(result.stdout)

    def bootstrap_host(self) -> None:
        source = self.work / "src"
        for relative in MANAGED_FILES:
            (source / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(REPOSITORY_ROOT / relative, source / relative)
        (source / "scripts").mkdir()
        self.launcher = find_launcher(REPOSITORY_ROOT, self.product)
        shutil.copy(self.launcher, source / "scripts" / self.launcher.name)
        shutil.copy(self.trust, source / "deploy/miner-update/release-keys.json")
        self.paths = HostPaths(root=self.work / "root")
        self.config = HostConfig.from_document(
            {
                "schema": CONFIG_SCHEMA, "product": self.product.product, "network": NETWORK,
                "netuid": self.netuid, "channel": "stable", "channel_url": CHANNEL_URL,
                "miner_unit": MINER_UNIT, "minimum_sequence": 0,
            }
        )
        self.keys_sha256 = hashlib.sha256(self.trust.read_bytes()).hexdigest()
        report = install(
            source, paths=self.paths, keys_sha256=self.keys_sha256, config=self.config,
            unit_exec_start=lambda unit: self.launcher, systemctl=lambda arguments: None,
        )
        self.tree = str(report["installed_tree"])
        self.check("bootstrap installs the tree the signed bundle ships", self.tree == self.bundle["tree_sha256"])

    def build_host(self) -> None:
        container = read_launcher_profile(self.launcher).container
        self.clock = [int(time.time())]
        self.running = {container: ("legacy@sha256:" + "1" * 64, 0.0)}
        self.metadata = self.work / "stable.json"

        def systemctl(arguments) -> None:
            self.journal.append("systemctl " + " ".join(arguments))
            if arguments[0] == "restart":
                self.clock[0] += 1
                profile = read_activation_profile(self.paths, link_target(self.paths.miner_current))
                self.running[str(profile["container"])] = (str(profile.get("image")), float(self.clock[0]))

        def observe(name: str) -> Observation:
            image, started = self.running[name]
            return Observation(image=image, started_at=started, restarts=0, active=True)

        self.host = MinerUpdaterHost(
            config=self.config, paths=self.paths, running_tree=self.tree,
            fetch_metadata=lambda: self.metadata.read_bytes(),
            fetch_bundle=lambda bundle: Path(self.bundle["archive"]).read_bytes(),
            probe_updater=lambda release, record: {},
            handoff=lambda release, fd: (1, None),
            prepare_image=lambda release, profile: release.state_schema,
            systemctl=systemctl, unit_state=lambda: "active", observe=observe, settle=observe,
            safe_to_activate=lambda: True, now_unix=lambda: self.clock[0],
            sleep=lambda seconds: None, boot_id=lambda: "boot", expected_uid=os.getuid(),
        )

    def run_check(self, label: str):
        outcome = update_once(self.host)
        self.journal.append(f"{label}: action={outcome.action} exit={outcome.exit_status} reason={outcome.reason}")
        return outcome

    def happy_path(self) -> dict[str, object]:
        before = self.status()
        serving_before = self.serving()
        activated = self.run_check("check 1 (valid stable seq 2)")
        self.clock[0] += 3600  # past probation
        confirmed = self.run_check("check 2 (after probation)")
        after = self.status()
        serving_after = self.serving()
        self.check("signed release is activated", activated.action == "activated", activated.reason)
        self.check("release is confirmed after probation", confirmed.action == "current", confirmed.reason)
        self.check("serving version after is the signed version", serving_after["version"] == "rehearsal-1", serving_after)
        self.check("serving release changed", serving_before != serving_after)
        self.check("release.env carries the signed image", (self.paths.miner_current / "release.env").read_text().count(self.image) == 1)
        return {"status_before": before, "status_after": after, "serving_before": serving_before, "serving_after": serving_after}

    def negative_controls(self) -> dict[str, object]:
        baseline = self.serving()
        floors_before = self.status().get("floors")
        results: dict[str, object] = {}

        # 1. A record with a bad signature: seq 3, valid body, one signature byte flipped.
        good = self.promote(sequence=3, out="stable-seq3.json")
        document = json.loads((self.work / "stable-seq3.json").read_bytes())
        raw = bytearray(base64.b64decode(document["signature"]["value_base64"]))
        raw[0] ^= 0xFF
        document["signature"]["value_base64"] = base64.b64encode(bytes(raw)).decode("ascii")
        tampered = self.work / "stable-bad-signature.json"
        tampered.write_bytes(json.dumps(document, sort_keys=True, indent=2).encode("ascii") + b"\n")
        self.metadata = tampered
        bad = self.run_check("negative control: bad signature (seq 3)")
        self.check("bad signature is refused", bad.action == "refused" and "signature" in bad.reason, {"action": bad.action, "reason": bad.reason})
        self.check("bad signature leaves the serving release untouched", self.serving() == baseline)
        results["bad_signature"] = {"action": bad.action, "exit_status": bad.exit_status, "reason": bad.reason, "record": str(tampered.name), "untampered_signed_sha256": good["signed_sha256"]}

        # 2. A rolled-back sequence: stable seq 1 is below the committed seq 2.
        self.promote(sequence=1, out="stable-seq1.json")
        self.metadata = self.work / "stable-seq1.json"
        rollback = self.run_check("negative control: rolled-back sequence (seq 1 after seq 2)")
        self.check("rolled-back sequence is refused", rollback.action == "refused" and "rolls back" in rollback.reason, {"action": rollback.action, "reason": rollback.reason})
        self.check("rollback leaves the serving release untouched", self.serving() == baseline)
        results["rollback"] = {"action": rollback.action, "exit_status": rollback.exit_status, "reason": rollback.reason, "record": "stable-seq1.json"}

        results["status_after_controls"] = self.status()
        self.check("floors unchanged by refused records", self.status().get("floors") == floors_before)
        self.metadata = self.work / "stable.json"
        return results

    def run(self) -> dict[str, object]:
        self.make_keys_and_records()
        self.bootstrap_host()
        self.build_host()
        happy = self.happy_path()
        controls = self.negative_controls()
        for name in ("canary.json", "stable.json", "stable-seq3.json", "stable-seq1.json", "stable-bad-signature.json"):
            if (self.work / name).exists():
                shutil.copy(self.work / name, self.evidence / name)
        return {
            "schema": "cathedral.miner-update-rehearsal.v1",
            "scratch": True,
            "note": "throwaway keys, faked docker and systemd; not evidence for the live E2E done-line",
            "product": self.product.product,
            "network": NETWORK,
            "netuid": self.netuid,
            "trust_root_sha256": self.keys_sha256,
            "key_fingerprints": (happy["status_after"]["trust"] or {}).get("keys"),  # type: ignore[index, union-attr]
            "signed_records": {"canary": self.canary_summary, "stable": self.stable_summary},
            **happy,
            "negative_controls": controls,
            "journal": self.journal,
            "checks": self.checks,
            "passed": all(item["passed"] for item in self.checks),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--product", default="snp-miner")
    parser.add_argument("--keep-keys", action="store_true", help="keep the throwaway keys under the scratch dir")
    arguments = parser.parse_args(argv)
    evidence = Path(arguments.evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True)
    out = evidence / "evidence.json"
    if out.exists():
        raise SystemExit(f"refusing: {out} exists, never overwrite evidence")
    with tempfile.TemporaryDirectory(prefix="miner-rehearsal-") as scratch:
        work = Path(scratch)
        try:
            report = Rehearsal(work, evidence, arguments.product).run()
        finally:
            if arguments.keep_keys:
                shutil.copytree(work / "keys", evidence / "throwaway-keys", dirs_exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    for item in report["checks"]:  # type: ignore[union-attr]
        print(("ok     " if item["passed"] else "FAILED ") + str(item["check"]))
    print(f"evidence: {out}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
