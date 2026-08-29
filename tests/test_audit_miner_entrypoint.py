from __future__ import annotations

import hashlib
import re
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cathedral.audit_miner_entrypoint import (
    FLEET_MANIFEST,
    HOTKEY_ENV,
    PUBLIC_ENDPOINT_ENV,
    TSM_REPORT_ROOT,
    TSM_REPORT_ROOT_ENV,
    TLS_CERTIFICATE,
    TLS_PRIVATE_KEY,
    VALIDATOR_ACCESS_KEYS,
    VALIDATOR_ACCESS_KEYS_DIGEST_ENV,
    VALIDATOR_ACCESS_SNAPSHOT,
    VALIDATOR_ACCESS_STATE,
    VALIDATOR_MINIMUM_STAKE_RAO,
    VALIDATOR_NETWORK,
    VALIDATOR_NETUID,
    WORKER_BEARER_ENV,
    WORKER_HOST,
    WORKER_PORT,
    EntrypointError,
    generate_tls_material,
    main,
    validate_environment,
    validate_public_hotkey,
)

HOTKEY = "5CtobNq2yNmUKaaR9HL5eSY2jN4j43iz1GLXNeNp2tbkwawK"
PUBLIC_ENDPOINT = "https://8.8.8.8:8081"
KEYS_DIGEST = "sha256:" + "ab" * 32
DEPLOYMENT_ENVIRONMENT = {
    HOTKEY_ENV: HOTKEY,
    PUBLIC_ENDPOINT_ENV: PUBLIC_ENDPOINT,
    VALIDATOR_ACCESS_KEYS_DIGEST_ENV: KEYS_DIGEST,
}
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
        TSM_REPORT_ROOT_ENV,
        "CATHEDRAL_WALLET_SEED",
        "CATHEDRAL_GPU_COLLECT_CMD",
    ],
)
def test_environment_accepts_only_the_three_public_deployment_inputs(unknown_name: str) -> None:
    inputs = validate_environment({**DEPLOYMENT_ENVIRONMENT, "PATH": "/usr/bin"})
    assert inputs.hotkey == HOTKEY
    assert inputs.public_endpoint == PUBLIC_ENDPOINT
    assert inputs.validator_access_keys_digest == KEYS_DIGEST
    with pytest.raises(EntrypointError, match="only the miner hotkey"):
        validate_environment(
            {**DEPLOYMENT_ENVIRONMENT, unknown_name: "caller-controlled"}
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (PUBLIC_ENDPOINT_ENV, "http://8.8.8.8:8081"),
        (PUBLIC_ENDPOINT_ENV, "https://example.com:8081"),
        (PUBLIC_ENDPOINT_ENV, "https://127.0.0.1:8081"),
        (PUBLIC_ENDPOINT_ENV, "https://8.8.8.8:443"),
        (PUBLIC_ENDPOINT_ENV, "https://[2606:4700:4700::1111]:8081"),
        (VALIDATOR_ACCESS_KEYS_DIGEST_ENV, "ab" * 32),
        (VALIDATOR_ACCESS_KEYS_DIGEST_ENV, "sha256:" + "AB" * 32),
    ],
)
def test_environment_refuses_invalid_public_inputs(name: str, value: str) -> None:
    with pytest.raises(EntrypointError):
        validate_environment({**DEPLOYMENT_ENVIRONMENT, name: value})


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
                **DEPLOYMENT_ENVIRONMENT,
                "PATH": "/usr/bin",
                "WALLET_SEED": "must-not-reach-worker",
            },
            tls_directory=tmp_path / "tls",
            execvpe=fake_execvpe,
        )

    argv = captured["argv"]
    child_environment = captured["environ"]
    assert argv[1:8] == ["-I", "-u", "-B", "-m", "cathedral.cli", "worker", "migrate"]
    assert argv[argv.index("--hotkey") + 1] == HOTKEY
    assert argv[argv.index("--host") + 1] == WORKER_HOST
    assert argv[argv.index("--port") + 1] == str(WORKER_PORT)
    assert "--tee" not in argv
    assert argv[argv.index("--tls-certificate") + 1].endswith(TLS_CERTIFICATE)
    assert argv[argv.index("--tls-private-key") + 1].endswith(TLS_PRIVATE_KEY)
    assert argv[argv.index("--validator-access-snapshot") + 1] == str(
        VALIDATOR_ACCESS_SNAPSHOT
    )
    assert argv[argv.index("--validator-access-keys") + 1] == str(VALIDATOR_ACCESS_KEYS)
    assert argv[argv.index("--validator-access-keys-digest") + 1] == KEYS_DIGEST
    assert argv[argv.index("--validator-access-state") + 1] == str(VALIDATOR_ACCESS_STATE)
    assert argv[argv.index("--validator-minimum-stake-rao") + 1] == str(
        VALIDATOR_MINIMUM_STAKE_RAO
    ) == "0"
    assert argv[argv.index("--validator-network") + 1] == VALIDATOR_NETWORK == "finney"
    assert argv[argv.index("--validator-netuid") + 1] == str(VALIDATOR_NETUID) == "39"
    assert argv[argv.index("--public-endpoint") + 1] == PUBLIC_ENDPOINT
    assert argv[argv.index("--fleet-manifest") + 1] == str(FLEET_MANIFEST)
    assert argv[argv.index("--migration-mode") + 1] == "public-legacy-audit"
    assert "--allow-public-legacy-audit" not in argv
    assert "--allow-public-bootstrap-evidence" not in argv
    assert "--development-no-auth" not in argv
    assert "--development-allow-non-loopback" not in argv
    assert "--allow-customer-sat" not in argv
    assert "--gpu-composite" not in argv
    assert set(child_environment) == {
        "PATH",
        TSM_REPORT_ROOT_ENV,
    }
    assert child_environment["PATH"].startswith("/usr/local/bin:")
    assert child_environment[TSM_REPORT_ROOT_ENV] == TSM_REPORT_ROOT
    assert HOTKEY_ENV not in child_environment
    assert "WALLET_SEED" not in child_environment
    assert WORKER_BEARER_ENV not in child_environment


def test_entrypoint_refuses_command_overrides_before_writing_tls(tmp_path: Path) -> None:
    tls_directory = tmp_path / "tls"
    with pytest.raises(EntrypointError, match="no command arguments"):
        main(
            ["sh"],
            environ=DEPLOYMENT_ENVIRONMENT,
            tls_directory=tls_directory,
        )
    assert not tls_directory.exists()


@pytest.mark.parametrize("unknown_name", [WORKER_BEARER_ENV, TSM_REPORT_ROOT_ENV])
def test_entrypoint_refuses_unknown_environment_before_writing_tls(
    tmp_path: Path, unknown_name: str
) -> None:
    tls_directory = tmp_path / "tls"
    with pytest.raises(EntrypointError, match="only the miner hotkey"):
        main(
            [],
            environ={**DEPLOYMENT_ENVIRONMENT, unknown_name: "caller-override"},
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
    assert f"install -d -o root -g root -m 0755 {TSM_REPORT_ROOT}" in dockerfile
    assert 'org.cathedral.sn39.runtime-contract="signed-validator-fleet-v1"' in dockerfile
    assert "import cathedral.audit_miner_entrypoint, cathedral.cli" in dockerfile
    assert "preflight_sr25519_verifier(load_sr25519_verifier())" in dockerfile


def test_runtime_dependency_lock_is_exact_wheel_only_and_hash_checked() -> None:
    requirements = (REPOSITORY_ROOT / "requirements" / "sn39-audit-miner.txt").read_text()

    assert requirements.count("==") == 4
    assert requirements.count("--hash=sha256:") == 9
    assert "py-sr25519-bindings==0.2.2" in requirements
    assert "849f77ab12210e8549e58d444e9199d9aba83a988e99ca8bef04dd53e81f9561" in requirements
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
    assert "- scripts/run_sn39_signed_fleet_miner.sh" in workflow
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
    normalized_documentation = " ".join(documentation.split())

    assert f"{IMAGE_PATH}@sha256:<64-hex>" in documentation
    assert "/sys/kernel/config/tsm/report" in documentation
    assert f"src=/sys/kernel/config/tsm/report,dst={TSM_REPORT_ROOT}" in documentation
    assert "--tmpfs /sys/kernel/config" not in documentation
    assert "uses the kernel configfs TSM path" in documentation
    assert "operator-enforced supply-chain pin" in documentation
    assert "does not place the post-boot OCI image digest into MRTD" in documentation
    assert "sha256:[0-9a-f]{64}" in documentation
    assert "Do not copy `worker.key`" in documentation
    assert "UID30 IP-literal attested-SPKI transport" in documentation
    assert "ordinary production `RemoteMiner`" in documentation
    assert "same-SPKI SAT round trip" in documentation
    assert "wallet seed" in documentation.lower()
    assert "It cannot launch the reviewed legacy digest" in documentation
    assert "First activation stays blocked" in normalized_documentation
    assert "A digest-only swap is not a rollback plan" in normalized_documentation


def test_operator_docs_do_not_attribute_source_only_posture_split_to_published_digest() -> None:
    image_documentation = (
        REPOSITORY_ROOT / "docs" / "SN39_AUDIT_MINER_IMAGE.md"
    ).read_text()
    operations = (
        REPOSITORY_ROOT / "docs" / "SN39_AUDIT_MINER_OPERATIONS.md"
    ).read_text()
    work_request = (REPOSITORY_ROOT / "docs" / "WORK_REQUEST_V2.md").read_text()

    for documentation in (image_documentation, operations, work_request):
        normalized = " ".join(documentation.split())
        assert "8ad7f6e127ad7dcc4dd150f0e1eb47ce72c5ab22" in normalized
        assert "worker serve" in normalized
        assert "--allow-public-legacy-audit" in normalized
        assert "worker migrate --migration-mode public-legacy-audit" in normalized
        assert "cathedral_effective_startup_v1" in normalized
        assert "must not be attributed" in normalized

    assert "source-only replacement contract" in image_documentation
    assert "Record a new source merge, immutable" in operations
    assert "remains source-only until a replacement image" in " ".join(
        work_request.split()
    )


def test_host_startup_is_syntax_valid_and_pins_the_exact_pulled_runtime() -> None:
    script_path = REPOSITORY_ROOT / "scripts" / "run_sn39_signed_fleet_miner.sh"
    script = script_path.read_text()

    result = subprocess.run(
        ["bash", "-n", str(script_path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert 'IMAGE_PREFIX="${IMAGE_PATH}@sha256:"' in script
    assert '${SN39_AUDIT_MINER_IMAGE}" == "${IMAGE_PREFIX}"*' in script
    assert 'image_digest="${SN39_AUDIT_MINER_IMAGE#"${IMAGE_PREFIX}"}"' in script
    assert '"${image_digest}" =~ ^[0-9a-f]{64}$' in script
    assert 'docker pull --platform linux/amd64 "${SN39_AUDIT_MINER_IMAGE}"' in script
    assert ".RepoDigests" in script
    assert 'grep -Fx -- "${SN39_AUDIT_MINER_IMAGE}"' in script
    assert "{{.Os}}/{{.Architecture}}" in script
    assert "org.cathedral.sn39.runtime-contract" in script
    assert "--pull never" in script


def test_host_startup_installs_only_the_fixed_tcp_8081_nftables_boundary() -> None:
    script = (
        REPOSITORY_ROOT / "scripts" / "run_sn39_signed_fleet_miner.sh"
    ).read_text()

    assert "NFT_FAMILY='inet'" in script
    assert "NFT_TABLE='cathedral_sn39'" in script
    assert "table inet cathedral_sn39" in script
    assert "counter tcp_8081_accept" in script
    assert "counter tcp_8081_drop" in script
    assert "policy accept" in script
    assert "ip saddr timeout 1m limit rate over 4/second burst 8 packets" in script
    assert "ip saddr ct count over 2" in script
    assert "meta nfproto ipv6 tcp dport 8081" in script
    assert "ct state established,related counter name tcp_8081_accept accept" in script
    assert "meta nfproto ipv4 tcp dport 8081 counter name tcp_8081_drop drop" in script
    assert 'nft --check --file "${nft_rules}"' in script
    assert 'nft --file "${nft_rules}"' in script
    assert 'nft delete table "${NFT_FAMILY}" "${NFT_TABLE}"' in script
    nft_rule_lines = [line for line in script.splitlines() if " tcp dport " in line]
    assert nft_rule_lines
    assert all("tcp dport 8081" in line for line in nft_rule_lines)
    assert "CATHEDRAL_NFT" not in script
    assert "CATHEDRAL_RATE" not in script
    assert "CATHEDRAL_CONNECTION" not in script


def test_host_startup_serializes_table_ownership_through_signal_cleanup() -> None:
    script = (
        REPOSITORY_ROOT / "scripts" / "run_sn39_signed_fleet_miner.sh"
    ).read_text()

    lock = script.index('flock --nonblock 9')
    trap = script.index('trap cleanup EXIT')
    first_docker = script.index('docker container inspect')
    first_nft = script.index('nft list table')
    delete_table = script.index('nft delete table "${NFT_FAMILY}" "${NFT_TABLE}"')
    unlock = script.index('flock --unlock 9')
    close_lock = script.index('exec 9>&-')
    first_remove = script.index('docker rm --force "${CONTAINER_NAME}"')
    kill_client = script.index('kill "${docker_client_pid}"')
    reap_client = script.index('wait "${docker_client_pid}"', kill_client)
    second_remove = script.index('docker rm --force "${CONTAINER_NAME}"', first_remove + 1)
    assert "STARTUP_LOCK='/run/cathedral-sn39-startup.lock'" in script
    assert lock < trap < first_docker
    assert lock < first_nft
    assert delete_table < unlock < close_lock
    assert first_remove < kill_client < reap_client < second_remove < delete_table
    assert "kill %%" in script
    assert "wait >/dev/null 2>&1 || true" in script
    assert "trap 'exit 130' INT" in script
    assert "trap 'exit 143' TERM" in script
    assert "trap 'exit 129' HUP" in script
    assert '"${SN39_AUDIT_MINER_IMAGE}" &' in script
    assert "docker_client_pid=$!" in script
    assert 'wait "${docker_client_pid}"' in script


def test_host_startup_uses_fixed_owner_checked_mounts_and_container_limits() -> None:
    script = (
        REPOSITORY_ROOT / "scripts" / "run_sn39_signed_fleet_miner.sh"
    ).read_text()

    assert "0:0:700:directory" in script
    assert "0:0:${mode}:regular file" in script
    assert 'validator-access.json" 644' in script
    assert 'snapshot-keys.json" 644' in script
    assert 'fleet.json" 644' in script
    assert 'validator-access.sqlite" 600' in script
    assert "${CONFIG_DIRECTORY},dst=/etc/cathedral/validator-access,readonly" in script
    assert "${STATE_DIRECTORY},dst=/var/lib/cathedral/validator-access" in script
    tsm_mount = next(
        line for line in script.splitlines() if "dst=/opt/cathedral-audit-miner/tsm-report" in line
    )
    assert "readonly" not in tsm_mount
    assert "--read-only" in script
    assert "--tmpfs /run/cathedral-audit-miner:rw,noexec,nosuid,nodev,mode=0700,size=16m" in script
    assert "--cap-drop ALL" in script
    assert "--init" in script
    assert "--security-opt no-new-privileges=true" in script
    assert "--pids-limit 128" in script
    assert "--memory 1g" in script
    assert "--memory-swap 1g" in script
    assert "--ulimit nofile=1024:1024" in script
    assert "--network host" in script
    assert "/dev/tdx_guest" not in script
    assert "WALLET" not in script
    assert "BEARER" not in script
    assert "SEED" not in script
    assert "RPC" not in script
