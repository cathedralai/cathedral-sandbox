"""T6b1 packaging: runsc ships only in the separate opt-in layer, pinned and checked."""

from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
RUNSC_BUNDLE_URL = (
    "https://storage.googleapis.com/gvisor/releases/release/20261005.0/x86_64/gvisor.tar.zstd"
)
RUNSC_SHA256 = "210b437a9cfae51e8f8c9074ed19b8b5e59477178e2e391a18117d8d6b924f7a"
BASE = (
    "python:3.12-slim-bookworm@"
    "sha256:4427763a1ba36f5aa8f656a03e5d00f3b8d61f5dd950c73df6c14f8c7640f8ab"
)


def _read(name: str) -> str:
    return (REPOSITORY_ROOT / name).read_text()


def test_the_opt_in_layer_pins_runsc_by_release_and_sha256():
    dockerfile = _read("Dockerfile.tee-box-runsc")
    assert dockerfile.count(RUNSC_BUNDLE_URL) == 1
    assert RUNSC_SHA256 in dockerfile
    assert "assert digest == expected" in dockerfile
    assert f'org.cathedral.tee-box.runsc-sha256="{RUNSC_SHA256}"' in dockerfile
    assert "gvisor.tar.zstd" in dockerfile
    assert "http://" not in dockerfile
    assert "# syntax=" not in dockerfile
    # The fetch stage uses the miner images' own pinned base.
    assert f"FROM {BASE} AS runsc" in dockerfile
    for name in ("Dockerfile.sn94-audit-miner", "Dockerfile.sn94-snp-miner"):
        assert f"FROM {BASE}" in _read(name)


def test_the_opt_in_layer_needs_an_explicit_digest_pinned_miner_image():
    dockerfile = _read("Dockerfile.tee-box-runsc")
    assert re.search(r"^ARG MINER_IMAGE$", dockerfile, flags=re.MULTILINE)
    assert "ARG MINER_IMAGE=" not in dockerfile  # no default base
    assert re.findall(r"^FROM .*$", dockerfile, flags=re.MULTILINE)[-1] == "FROM ${MINER_IMAGE}"
    assert "*@sha256:" + "?" * 64 + ")" in dockerfile
    # It only adds the binary and labels: no entrypoint, port or user change.
    tail = dockerfile.split("FROM ${MINER_IMAGE}", 1)[1]
    assert re.findall(r"^([A-Z]+) ", tail, flags=re.MULTILINE) == ["LABEL", "COPY"]


def test_production_miner_images_and_publishers_do_not_ship_runsc():
    for name in (
        "Dockerfile.sn94-audit-miner",
        "Dockerfile.sn94-snp-miner",
        ".github/workflows/publish-sn94-audit-miner.yml",
        ".github/workflows/publish-sn94-snp-miner.yml",
    ):
        text = _read(name)
        assert "runsc" not in text and "gvisor" not in text.lower(), name
        assert "tee-box-runsc" not in text, name
