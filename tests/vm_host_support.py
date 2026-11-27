"""A sealed VM host for the room-kit/vm tests (AB#999 VM3): bundles, the host switch file
(/etc/cathedral/snp-vm-host.json in production) and fake host tools. No root, no KVM."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import vm_measure_support as support

KIT = Path(__file__).resolve().parents[1] / "room-kit" / "vm"
MEASUREMENT = "ab" * 48
FAKE_LOG = '#!/bin/sh\necho "$(basename "$0") $*" >> "$FAKE_STATE.tools"\n'
# getent finds nothing, so create runs useradd and groupadd (logged, not run).
FAKE_USER_TOOLS = {"useradd": FAKE_LOG, "userdel": FAKE_LOG, "groupadd": FAKE_LOG, "chown": FAKE_LOG,
                   "udevadm": FAKE_LOG, "getent": FAKE_LOG + "exit 2\n"}


def fake_measure_tool(directory: Path, output: str = MEASUREMENT) -> Path:
    path = directory / "sev-snp-measure"
    path.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo "sev-snp-measure 0.0.12"; exit 0; fi\n'
                    f'echo "{output}"\n')
    path.chmod(0o755)
    return path


def install_bundle(vm_root: Path, family: str = "genoa") -> str:
    """One vector bundle at $VM_ROOT/bundles/<id>/; returns the id."""
    vec = support.load()
    staging = support.materialize(vec, vm_root.parent / f"bundle-staging-{family}", family)
    bundle = hashlib.sha256((staging / "manifest.json").read_bytes()).hexdigest()
    (vm_root / "bundles").mkdir(parents=True, exist_ok=True)
    staging.rename(vm_root / "bundles" / bundle)
    return bundle


def sealed_host(tmp_path: Path, fake_bin: Path, family: str = "genoa") -> dict:
    """Write a bundle, the host config and the fake tools; return the env vm_ctl needs."""
    for name, text in FAKE_USER_TOOLS.items():
        (fake_bin / name).write_text(text)
        (fake_bin / name).chmod(0o755)
    bundle = install_bundle(tmp_path / "vms", family)
    config = tmp_path / "snp-vm-host.json"
    config.write_text(json.dumps({"version": 1, "cpu_family": family, "bundles": [bundle],
                                  "default_bundle": bundle, "sev_snp_measure": str(fake_measure_tool(fake_bin))}))
    return {"VM_HOST_CONFIG": str(config), "VM_UDEV_RULES_DIR": str(tmp_path / "udev"), "VM_TEST_BUNDLE": bundle}
