from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from cathedral.audit_miner_entrypoint import (
    HOTKEY_ENV,
    PUBLIC_ENDPOINT_ENV,
    VALIDATOR_ACCESS_KEYS_DIGEST_ENV,
    EntrypointError,
)
from cathedral.snp_miner_entrypoint import (
    SNPGUEST_ENV,
    SNPGUEST_PATH,
    TLS_DIRECTORY,
    TMPDIR,
    main,
)

HOTKEY = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"
ENVIRONMENT = {
    HOTKEY_ENV: HOTKEY,
    PUBLIC_ENDPOINT_ENV: "https://8.8.8.8:8081",
    VALIDATOR_ACCESS_KEYS_DIGEST_ENV: "sha256:" + "ab" * 32,
}
REPOSITORY_ROOT = Path(__file__).parents[1]
SNP_IMAGE_PATH = "ghcr.io/cathedralai/cathedral-sn39-snp-miner"
SNPGUEST_DIGEST = "70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0"


def test_snp_entrypoint_execs_only_the_fixed_signed_snp_command(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_execvpe(file: str, argv, environ) -> None:
        captured.update(file=file, argv=list(argv), environ=dict(environ))
        raise RuntimeError("exec captured")

    with pytest.raises(RuntimeError, match="exec captured"):
        main(
            [],
            environ={**ENVIRONMENT, "PATH": "/usr/bin", "WALLET_SEED": "not forwarded"},
            tls_directory=tmp_path / "tls",
            execvpe=fake_execvpe,
        )

    argv = captured["argv"]
    child_environment = captured["environ"]
    assert argv[1:8] == ["-I", "-u", "-B", "-m", "cathedral.cli", "worker", "serve-snp"]
    assert "--tee" not in argv
    assert "--migration-mode" not in argv
    assert "--allow-customer-sat" not in argv
    assert child_environment == {
        "PATH": "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
        SNPGUEST_ENV: SNPGUEST_PATH,
        "TMPDIR": TMPDIR,
    }
    assert HOTKEY_ENV not in child_environment
    assert "WALLET_SEED" not in child_environment


def test_snp_entrypoint_refuses_caller_snpguest_override_before_writing_tls(tmp_path: Path) -> None:
    with pytest.raises(EntrypointError, match="only the miner hotkey"):
        main(
            [],
            environ={**ENVIRONMENT, SNPGUEST_ENV: "/tmp/unreviewed-snpguest"},
            tls_directory=tmp_path / "tls",
        )
    assert not (tmp_path / "tls").exists()


def test_snp_image_pins_official_snpguest_and_fixed_entrypoint() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile.sn39-snp-miner").read_text()

    assert "https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest" in dockerfile
    assert SNPGUEST_DIGEST in dockerfile
    assert 'ENTRYPOINT ["python", "-I", "-u", "-B", "-m", "cathedral.snp_miner_entrypoint"]' in dockerfile
    assert 'org.cathedral.sn39.runtime-contract="snp-signed-validator-fleet-v1"' in dockerfile
    assert "TSM_REPORT_ROOT" not in dockerfile
    assert "WALLET_SEED" not in dockerfile


def test_snp_host_launcher_is_syntax_valid_and_exposes_only_sev_guest_hardware() -> None:
    script_path = REPOSITORY_ROOT / "scripts" / "run_sn39_snp_miner.sh"
    script = script_path.read_text()

    result = subprocess.run(
        ["bash", "-n", str(script_path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "SN39_SNP_MINER_IMAGE" in script
    assert SNP_IMAGE_PATH in script
    assert "--device \"${SEV_GUEST_DEVICE}:${SEV_GUEST_DEVICE}:rwm\"" in script
    assert "/dev/sev-guest" in script
    assert "/sys/kernel/config/tsm/report" not in script
    assert "/dev/tdx_guest" not in script
    assert "--read-only" in script
    assert "--cap-drop ALL" in script
    assert "--security-opt no-new-privileges=true" in script
    assert "WALLET" not in script
    assert "SEED" not in script
    assert "RPC" not in script
    assert hashlib.sha256(script_path.read_bytes()).hexdigest() != ""


def test_snp_doc_does_not_claim_a_published_or_live_machine() -> None:
    document = (REPOSITORY_ROOT / "docs" / "SN39_SNP_MINER_IMAGE.md").read_text().lower()
    assert "no digest is listed" in document
    assert "a source change and a green test suite" in document
    assert "receiving weight" not in document
    assert str(TLS_DIRECTORY) not in document
