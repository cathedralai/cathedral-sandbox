from __future__ import annotations

import hashlib
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cathedral.audit_miner_entrypoint import (
    HOTKEY_ENV,
    TLS_CERTIFICATE,
    TLS_PRIVATE_KEY,
    WORKER_BEARER_ENV,
    WORKER_HOST,
    WORKER_PORT,
    WORKER_TEE,
    EntrypointError,
    generate_tls_material,
    main,
    validate_environment,
    validate_public_hotkey,
)

HOTKEY = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"
REPOSITORY_ROOT = Path(__file__).parents[1]
BASE_MANIFEST_DIGEST = "sha256:4427763a1ba36f5aa8f656a03e5d00f3b8d61f5dd950c73df6c14f8c7640f8ab"
IMAGE_PATH = "ghcr.io/cathedralai/cathedral-sn39-audit-miner"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SS58_PREFIX = b"SS58PRE"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _base58_encode(value: bytes) -> str:
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    leading_zeroes = len(value) - len(value.lstrip(b"\x00"))
    return "1" * leading_zeroes + encoded


def _single_byte_format_address(ss58_format: int) -> str:
    payload = bytes([ss58_format]) + bytes(range(32))
    checksum = hashlib.blake2b(SS58_PREFIX + payload, digest_size=64).digest()[:2]
    return _base58_encode(payload + checksum)


def test_public_hotkey_validation_accepts_one_canonical_ss58_address() -> None:
    assert validate_public_hotkey(HOTKEY) == HOTKEY


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        f" {HOTKEY}",
        f"{HOTKEY} ",
        HOTKEY[:-1],
        HOTKEY[:-1] + "0",
        HOTKEY[:-1] + ("1" if HOTKEY[-1] != "1" else "2"),
        "é" * 48,
    ],
)
def test_public_hotkey_validation_refuses_noncanonical_input(value: object) -> None:
    with pytest.raises(EntrypointError):
        validate_public_hotkey(value)


def test_public_hotkey_validation_refuses_valid_non_bittensor_format() -> None:
    address = _single_byte_format_address(11)
    assert len(address) == 48
    with pytest.raises(EntrypointError, match="format 42"):
        validate_public_hotkey(address)


@pytest.mark.parametrize(
    "unknown_name",
    [
        WORKER_BEARER_ENV,
        "CATHEDRAL_TDX_TSM_REPORT_ROOT",
        "CATHEDRAL_WALLET_SEED",
        "CATHEDRAL_GPU_COLLECT_CMD",
    ],
)
def test_environment_accepts_only_the_public_hotkey_input(unknown_name: str) -> None:
    assert validate_environment({HOTKEY_ENV: HOTKEY, "PATH": "/usr/bin"}) == HOTKEY
    with pytest.raises(EntrypointError, match=f"only {HOTKEY_ENV}"):
        validate_environment({HOTKEY_ENV: HOTKEY, unknown_name: "caller-controlled"})


def test_tls_material_is_fresh_self_signed_matching_and_owner_only(tmp_path: Path) -> None:
    tls_directory = tmp_path / "tls"
    material = generate_tls_material(
        tls_directory,
        now=datetime(2026, 8, 26, tzinfo=UTC),
    )

    assert material.certificate == tls_directory / TLS_CERTIFICATE
    assert material.private_key == tls_directory / TLS_PRIVATE_KEY
    assert _mode(tls_directory) == 0o700
    assert _mode(material.certificate) == 0o600
    assert _mode(material.private_key) == 0o600

    certificate = x509.load_pem_x509_certificate(material.certificate.read_bytes())
    private_key = serialization.load_pem_private_key(
        material.private_key.read_bytes(), password=None
    )
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    assert certificate.issuer == certificate.subject
    assert certificate_public == private_public


def test_tls_material_changes_on_each_start(tmp_path: Path) -> None:
    tls_directory = tmp_path / "tls"
    first = generate_tls_material(tls_directory)
    first_certificate = first.certificate.read_bytes()
    first_key = first.private_key.read_bytes()

    second = generate_tls_material(tls_directory)

    assert second.certificate.read_bytes() != first_certificate
    assert second.private_key.read_bytes() != first_key


def test_tls_material_replaces_insecure_old_files_with_owner_only_files(
    tmp_path: Path,
) -> None:
    tls_directory = tmp_path / "tls"
    tls_directory.mkdir(mode=0o777)
    certificate = tls_directory / TLS_CERTIFICATE
    private_key = tls_directory / TLS_PRIVATE_KEY
    certificate.write_text("old certificate")
    private_key.write_text("old key")
    certificate.chmod(0o666)
    private_key.chmod(0o666)

    generate_tls_material(tls_directory)

    assert _mode(tls_directory) == 0o700
    assert _mode(certificate) == 0o600
    assert _mode(private_key) == 0o600


@pytest.mark.parametrize("path_kind", ["file", "symlink"])
def test_tls_material_refuses_non_directory_runtime_path(
    tmp_path: Path,
    path_kind: str,
) -> None:
    tls_directory = tmp_path / "tls"
    if path_kind == "file":
        tls_directory.write_text("not a directory")
    else:
        target = tmp_path / "target"
        target.mkdir()
        tls_directory.symlink_to(target, target_is_directory=True)

    with pytest.raises(EntrypointError, match="real directory"):
        generate_tls_material(tls_directory)


def test_tls_material_replaces_symlink_without_touching_target(tmp_path: Path) -> None:
    tls_directory = tmp_path / "tls"
    tls_directory.mkdir()
    target = tmp_path / "outside"
    target.write_text("do not replace")
    certificate = tls_directory / TLS_CERTIFICATE
    private_key = tls_directory / TLS_PRIVATE_KEY
    certificate.symlink_to(target)
    private_key.symlink_to(target)

    generate_tls_material(tls_directory)

    assert target.read_text() == "do not replace"
    assert certificate.is_file() and not certificate.is_symlink()
    assert private_key.is_file() and not private_key.is_symlink()
    assert _mode(certificate) == 0o600
    assert _mode(private_key) == 0o600


def test_entrypoint_execs_only_the_fixed_tls_tdx_worker_command(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_execvpe(file: str, argv, environ) -> None:
        captured.update(file=file, argv=list(argv), environ=dict(environ))
        raise RuntimeError("exec captured")

    with pytest.raises(RuntimeError, match="exec captured"):
        main(
            [],
            environ={
                HOTKEY_ENV: HOTKEY,
                "PATH": "/usr/bin",
                "WALLET_SEED": "must-not-reach-worker",
            },
            tls_directory=tmp_path / "tls",
            execvpe=fake_execvpe,
        )

    argv = captured["argv"]
    child_environment = captured["environ"]
    assert argv[1:8] == ["-I", "-u", "-B", "-m", "cathedral.cli", "worker", "serve"]
    assert argv[argv.index("--hotkey") + 1] == HOTKEY
    assert argv[argv.index("--host") + 1] == WORKER_HOST
    assert argv[argv.index("--port") + 1] == str(WORKER_PORT)
    assert argv[argv.index("--tee") + 1] == WORKER_TEE == "tdx"
    assert argv[argv.index("--tls-certificate") + 1].endswith(TLS_CERTIFICATE)
    assert argv[argv.index("--tls-private-key") + 1].endswith(TLS_PRIVATE_KEY)
    assert "--development-no-auth" not in argv
    assert "--development-allow-non-loopback" not in argv
    assert "--allow-customer-sat" not in argv
    assert "--gpu-composite" not in argv
    assert set(child_environment) == {"PATH", WORKER_BEARER_ENV}
    assert child_environment["PATH"].startswith("/usr/local/bin:")
    assert HOTKEY_ENV not in child_environment
    assert "WALLET_SEED" not in child_environment
    assert re.fullmatch(r"[0-9a-f]{64}", child_environment[WORKER_BEARER_ENV])


def test_entrypoint_refuses_command_overrides_before_writing_tls(tmp_path: Path) -> None:
    tls_directory = tmp_path / "tls"
    with pytest.raises(EntrypointError, match="no command arguments"):
        main(
            ["sh"],
            environ={HOTKEY_ENV: HOTKEY},
            tls_directory=tls_directory,
        )
    assert not tls_directory.exists()


def test_entrypoint_refuses_unknown_environment_before_writing_tls(tmp_path: Path) -> None:
    tls_directory = tmp_path / "tls"
    with pytest.raises(EntrypointError, match=f"only {HOTKEY_ENV}"):
        main(
            [],
            environ={HOTKEY_ENV: HOTKEY, WORKER_BEARER_ENV: "override"},
            tls_directory=tls_directory,
        )
    assert not tls_directory.exists()


def test_image_pins_amd64_base_fixed_entrypoint_and_one_tls_port() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile.sn39-audit-miner").read_text()

    assert f"FROM python:3.12-slim-bookworm@{BASE_MANIFEST_DIGEST}" in dockerfile
    assert (
        'ENTRYPOINT ["python", "-I", "-u", "-B", "-m", "cathedral.audit_miner_entrypoint"]'
    ) in dockerfile
    assert "# syntax=" not in dockerfile
    assert re.findall(r"^EXPOSE\s+(.+)$", dockerfile, flags=re.MULTILINE) == ["8081/tcp"]
    assert WORKER_BEARER_ENV not in dockerfile
    assert "WALLET_SEED" not in dockerfile


def test_runtime_dependency_lock_is_exact_wheel_only_and_hash_checked() -> None:
    requirements = (REPOSITORY_ROOT / "requirements" / "sn39-audit-miner.txt").read_text()

    assert requirements.count("==") == 3
    assert requirements.count("--hash=sha256:") == 8
    assert "git+" not in requirements
    assert "http://" not in requirements
    assert "https://" not in requirements
    dockerfile = (REPOSITORY_ROOT / "Dockerfile.sn39-audit-miner").read_text()
    assert "--only-binary=:all:" in dockerfile
    assert "--require-hashes" in dockerfile


def test_publisher_is_least_privilege_commit_tagged_and_digest_pinned() -> None:
    workflow = (
        REPOSITORY_ROOT / ".github" / "workflows" / "publish-sn39-audit-miner.yml"
    ).read_text()

    assert "branches:\n      - main" in workflow
    assert "permissions: {}" in workflow
    assert workflow.count("packages: write") == 1
    assert workflow.count("contents: read") == 1
    assert workflow.count("id-token: write") == 1
    assert workflow.count("attestations: write") == 1
    assert workflow.count("artifact-metadata: write") == 1
    assert workflow.count("Log in to GHCR") == 1
    assert "pull_request:" not in workflow
    assert "persist-credentials: false" in workflow
    assert workflow.count("version: v0.36.1") == 3
    assert (
        workflow.count(
            "moby/buildkit:v0.32.2@"
            "sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
        )
        == 3
    )
    assert "platforms: linux/amd64" in workflow
    assert "push: true" in workflow
    assert 'commit_tag="sha-${GITHUB_SHA}"' in workflow
    assert "Refuse to overwrite the commit tag" in workflow
    assert "Could not prove the immutable image tag is unused" in workflow
    assert "group: sn39-audit-miner-${{ github.sha }}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "provenance: mode=max" in workflow
    assert "subject-digest: ${{ steps.pin.outputs.digest }}" in workflow
    assert "push-to-registry: true" in workflow
    assert 'image_ref="${IMAGE_PATH}@${DIGEST}"' in workflow
    assert 'docker buildx imagetools inspect "$IMAGE_REF"' in workflow
    assert "latest" not in workflow.lower()
    assert ":main" not in workflow

    action_references = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", workflow, re.MULTILINE)
    assert action_references
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for revision in action_references)


def test_operator_doc_keeps_digest_and_tdx_measurement_as_separate_boundaries() -> None:
    documentation = (REPOSITORY_ROOT / "docs" / "SN39_AUDIT_MINER_IMAGE.md").read_text()

    assert f"{IMAGE_PATH}@sha256:<64-hex>" in documentation
    assert "/sys/kernel/config/tsm/report" in documentation
    assert "uses the kernel configfs TSM path" in documentation
    assert "operator-enforced supply-chain pin" in documentation
    assert "does not place the post-boot OCI image digest into MRTD" in documentation
    assert "sha256:[0-9a-f]{64}" in documentation
    assert "Do not copy `worker.key`" in documentation
    assert "UID30 IP-literal attested-SPKI transport" in documentation
    assert "ordinary production `RemoteMiner`" in documentation
    assert "same-SPKI SAT round trip" in documentation
    assert "wallet seed" in documentation.lower()
