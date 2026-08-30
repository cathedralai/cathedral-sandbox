"""The public mining path stays current, narrow, and internally linked."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_REFERENCE_RE = re.compile(
    r"(?<!/)\b((?:docs|cathedral|tests|scripts)/[A-Za-z0-9_./-]+\.(?:md|py))\b"
)


def test_every_doc_cited_repo_path_exists():
    missing: list[str] = []
    for document in sorted((REPO_ROOT / "docs").rglob("*.md")):
        for reference in sorted(set(_REFERENCE_RE.findall(document.read_text()))):
            if not (REPO_ROOT / reference).exists():
                missing.append(f"{document.name} -> {reference}")
    assert missing == [], f"docs cite nonexistent repo files: {missing}"


def test_readme_is_the_single_current_mining_guide() -> None:
    readme = (REPO_ROOT / "README.md").read_text()
    mining = (REPO_ROOT / "MINING.md").read_text()
    map_text = (REPO_ROOT / "docs" / "README.md").read_text()
    normalized = " ".join(readme.split())

    for expected in (
        "does not use a weight relay",
        "zero burn",
        "each distinct verified machine",
        "Intel TDX",
        "AMD SEV-SNP",
        "Validator-supported production admission",
        "c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99",
        "current migration bridge",
        "btcli axon set",
        "/usr/local/libexec/cathedral/run-sn39-miner",
        "separate miner-controlled machine",
        "not yet a one-command unattended installation",
        "process supervisor",
    ):
        assert expected.lower() in normalized.lower(), expected

    assert "single current mining guide" in mining
    assert "only active operator guide" in " ".join(map_text.split())
    assert len(mining.splitlines()) <= 8


def test_current_operator_docs_exclude_retired_launch_paths() -> None:
    current_paths = (
        "README.md",
        "MINING.md",
        "docs/README.md",
        "docs/SN39_AUDIT_MINER_IMAGE.md",
        "docs/SN39_AUDIT_MINER_OPERATIONS.md",
        "docs/WORK_REQUEST_V2.md",
        "docs/TDX_LAUNCH.md",
        "docs/TDX_VERIFIER_RELEASE.md",
        "docs/AMD_SEV_SNP_FRIEND_TEST.md",
        "docs/SN39_SNP_MINER_IMAGE.md",
        "docs/TESTING.md",
    )
    text = "\n".join((REPO_ROOT / path).read_text() for path in current_paths)
    normalized = text.lower()

    for retired in (
        "api.cathedral.computer",
        "10% burn",
        "validated_supply_v2",
        "uid124",
        "/v1/enroll",
    ):
        assert retired not in normalized, retired


def test_current_guide_never_runs_user_writable_code_as_root() -> None:
    readme = (REPO_ROOT / "README.md").read_text()

    assert "sudo .venv" not in readme
    assert "sudo cathedral-runtime/" not in readme
    assert "sudo cathedral-access/" not in readme
    assert "sudo --preserve-env" in readme
    assert "/usr/local/libexec/cathedral/run-sn39-miner" in readme
    assert "d56a82bb76eb2d976edfcd4574ff6ed19a41532ffa50d01a2411df51a002b615" in readme


def test_validator_access_signing_seed_stays_outside_the_checkout() -> None:
    readme = (REPO_ROOT / "README.md").read_text()
    contract = (REPO_ROOT / "docs" / "WORK_REQUEST_V2.md").read_text()
    gitignore = (REPO_ROOT / ".gitignore").read_text()

    assert "cathedral-access/operator-state" not in readme
    assert "--signing-key-out cathedral-validator-access-state/snapshot.seed" in readme
    assert "--signing-key-out ../cathedral-validator-access-state/snapshot.seed" in contract
    assert "*.seed" in gitignore


def test_additional_machine_flow_reuses_the_signer_and_restarts_the_primary() -> None:
    readme = (REPO_ROOT / "README.md").read_text()
    section = " ".join(
        readme.split("## Add more machines to one UID", maxsplit=1)[1].split()
    )

    assert "Do not create a second signing key" in section
    assert "/etc/cathedral/validator-access/.fleet.json.new" in section
    assert "The worker reads `fleet.json` only at startup" in section


def test_current_guide_proves_reachability_before_paid_registration() -> None:
    readme = (REPO_ROOT / "README.md").read_text()

    assert readme.index("### 3. Start the reviewed image") < readme.index(
        "### 4. Register and announce the hotkey"
    )
    assert readme.index('test "$HEALTH_STATUS" = 400') < readme.index(
        "subnet register --netuid 39"
    )
    assert "btcli --network finney query uid" in readme
    assert "btcli --network finney --json query weights --netuid 39" in readme
    assert "There is not yet a public validator-result feed" in readme


def test_public_repo_has_no_invite_only_miner_form() -> None:
    assert not (REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "miner-beta.yml").exists()


def test_amd_friend_test_never_runs_the_checkout_or_download_as_root() -> None:
    guide = (REPO_ROOT / "docs" / "AMD_SEV_SNP_FRIEND_TEST.md").read_text()

    assert "sudo .venv" not in guide
    assert 'sudo "$SNP_GUEST_DOWNLOAD"' not in guide
    assert "sudo git" not in guide
    assert 'CATHEDRAL_SNPGUEST="$SNP_GUEST_DOWNLOAD"' in guide
    assert "test -r /dev/sev-guest -a -w /dev/sev-guest" in guide
    assert 'org.opencontainers.image.revision' in guide
    assert "steps 1 and 2" not in guide


def test_amd_friend_test_creates_exact_launcher_directories() -> None:
    guide = (REPO_ROOT / "docs" / "AMD_SEV_SNP_FRIEND_TEST.md").read_text()

    assert "sudo install -d -o root -g root -m 0700" in guide
    assert "/etc/cathedral/validator-access" in guide
    assert "/var/lib/cathedral/validator-access" in guide


def test_current_docs_state_direct_validator_security_contracts() -> None:
    launch = (REPO_ROOT / "docs" / "TDX_LAUNCH.md").read_text()
    measurement = " ".join((REPO_ROOT / "docs" / "MRTD.md").read_text().split())
    operations = " ".join(
        (REPO_ROOT / "docs" / "SN39_AUDIT_MINER_OPERATIONS.md").read_text().split()
    )

    assert "does not trust the self-signed certificate through a public CA" in launch
    assert "fresh QVL-verified" in launch
    assert "does not retain it or use it as a weight gate" in launch
    assert "does not consult this registry, retain the emitted measurement" in measurement
    assert "every verified claimant in that collision scores zero" in operations


def test_legacy_cli_is_unmistakable_and_has_no_cathedral_api_dependency() -> None:
    from cathedral.cli import build_parser

    parser = build_parser()
    command_group = parser._subparsers._group_actions[0].choices
    help_text = (
        command_group["enroll"].format_help()
        + command_group["lifecycle"].format_help()
        + command_group["policy-registry"].format_help()
        + command_group["runtime"].format_help()
        + command_group["provenance"].format_help()
    )

    assert "Retained legacy" in help_text
    assert "not use this" in help_text
    assert "api.cathedral.computer" not in help_text


def test_retained_executables_do_not_claim_current_launch_proof() -> None:
    legacy_sources = (
        "cathedral/challenge.py",
        "cathedral/economics.py",
        "cathedral/evidence.py",
        "cathedral/launch_limits.py",
        "cathedral/lanes/__init__.py",
        "cathedral/poster.py",
        "cathedral/prober.py",
        "cathedral/replay.py",
        "cathedral/runtime.py",
        "cathedral/score_class.py",
        "cathedral/workproof.py",
        "scripts/cathedral_isolated_republisher.py",
        "scripts/cathedral_measurement_approval.py",
        "scripts/cross_repo_launch_verify.py",
        "scripts/tdx_cpu_launch_canary.py",
        "scripts/thin_subnet_e2e.py",
    )

    for relative in legacy_sources:
        opening = " ".join((REPO_ROOT / relative).read_text().split()[:80]).lower()
        assert "retained" in opening, relative
        assert "current" in opening and "not" in opening, relative

    for relative in (
        "scripts/sn39_gcp_guest_poller.py",
        "scripts/sn39_gcp_snapshot_publisher.py",
    ):
        text = (REPO_ROOT / relative).read_text().lower()
        assert "retired" in text, relative
        assert "not part of current direct sn39 mining" in text or "not current sn39 mining" in text


def test_runtime_help_does_not_point_at_deleted_documents() -> None:
    retired = (
        "docs/ADMISSION_POLICY.md",
        "docs/BUDGET.md",
        "docs/PROVENANCE.md",
        "docs/RELEASE_CHECKLIST.md",
        "docs/SN39_GCP_SIGNED_FLEET_DELIVERY.md",
    )
    source = "\n".join(
        path.read_text()
        for root in (REPO_ROOT / "cathedral", REPO_ROOT / "scripts")
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".py", ".sh"}
    )

    for removed in retired:
        assert removed not in source, removed
