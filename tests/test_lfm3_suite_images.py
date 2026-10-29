"""Hardware-free checks for the LFM3 sealed-pool image recipes."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "images" / "room-lfm3-suite"
ROOM_17B = ROOT / "images" / "room-lfm3"
BASE = ROOT / "images" / "room-lfm3-1.7b-base"
CATALOG = ROOT / "broker" / "catalog.go"

SUITE_MODELS = (
    "lfm3-vl-2b",
    "lfm3-omni-2b",
    "d1-2b",
    "lfm3-audio-2b",
    "d1-omni-2b",
)


def test_published_1_7b_recipe_is_b11960() -> None:
    text = (ROOM_17B / "Dockerfile").read_text(encoding="utf-8")
    assert "LLAMA_CPP_TAG=b11960" in text
    assert "8642541b255bfb5dc39cd351a178be09013a55d6" in text
    assert "LFM3-1.7B-Q4_K_M.gguf" in text


def test_suite_recipe_is_b11960_and_builds_server() -> None:
    text = (SUITE / "Dockerfile").read_text(encoding="utf-8")
    assert "LLAMA_CPP_TAG=b11960" in text
    assert "8642541b255bfb5dc39cd351a178be09013a55d6" in text
    assert "llama-server" in text
    assert "tdx_cpu" not in text


def test_suite_model_pins_are_digest_hex() -> None:
    for name in SUITE_MODELS:
        env = (SUITE / "models" / f"{name}.env").read_text(encoding="utf-8")
        assert "GGUF_SHA256=" in env
        assert "LICENSE_SHA256=" in env
        assert "GGUF_REVISION=" in env
        sha = next(
            line.split("=", 1)[1].strip()
            for line in env.splitlines()
            if line.startswith("GGUF_SHA256=")
        )
        assert len(sha) == 64 and all(c in "0123456789abcdef" for c in sha), name


def test_catalog_names_match_suite_images() -> None:
    catalog = CATALOG.read_text(encoding="utf-8")
    assert "amd_sev_snp" in catalog
    assert "lfm3-1.7b" in catalog and "sealedReady" in catalog
    assert '"tdx_cpu"' not in catalog
    assert "hardware_class\": \"tdx_cpu\"" not in catalog
    for name in SUITE_MODELS:
        assert name in catalog
        env = (SUITE / "models" / f"{name}.env").read_text(encoding="utf-8")
        image_name = next(
            line.split("=", 1)[1].strip()
            for line in env.splitlines()
            if line.startswith("IMAGE_NAME=")
        )
        # #363: suite images are published digests, still sealed pending until prefetch.
        assert f"ghcr.io/cathedralai/{image_name}:unpublished" not in catalog
        assert f"ghcr.io/cathedralai/{image_name}" in catalog
        assert "sha256:" in catalog


def test_base_image_pins_safetensors() -> None:
    text = (BASE / "Dockerfile").read_text(encoding="utf-8")
    assert "LFM3-1.7B-Base" in text
    assert "61a3f541d65b03a2180d08964bf0d55e349463a2706032814d455ae046bc8b59" in text
    assert (BASE / "serve.py").is_file()


def test_prefetch_script_targets_sealed_only() -> None:
    script = (ROOT / "scripts" / "prepull-sealed-lfm3.sh").read_text(encoding="utf-8")
    assert "sealed" in script
    assert "b1ba8837ea388c8c98720772b0f41af5813d4cebf214637fde20aae58a1ea761" in script
    assert "/v1/images/prefetch" in script
