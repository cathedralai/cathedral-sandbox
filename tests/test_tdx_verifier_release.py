from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release-tdx-verifier.yml"
TEMPLATE_PATH = ROOT / "docs" / "TDX_VERIFIER_RELEASE_NOTES_TEMPLATE.md"
GUIDE_PATH = ROOT / "docs" / "TDX_VERIFIER_RELEASE.md"
EXPECTED_SHA256 = "4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148"


def test_verifier_release_requires_an_explicit_exact_semver_tag():
    workflow = WORKFLOW_PATH.read_text()
    trigger = workflow.split("on:\n", 1)[1].split("\npermissions:", 1)[0].strip()

    assert trigger == 'push:\n    tags:\n      - "cathedral-tdx-verifier-v*"'
    assert '      - "cathedral-tdx-verifier-v*"' in workflow
    assert "workflow_dispatch:" not in workflow
    assert "pull_request:" not in workflow
    assert "branches:" not in workflow
    assert "test \"$GITHUB_EVENT_NAME\" = push" in workflow
    assert "test \"$GITHUB_REF_TYPE\" = tag" in workflow
    assert (
        r'^cathedral-tdx-verifier-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
        in workflow
    )
    assert workflow.index("permissions: {}") < workflow.index("jobs:")
    assert workflow.count("contents: write") == 1
    assert "persist-credentials: false" in workflow
    assert "fetch-depth: 0" in workflow
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main' in workflow
    assert "CATHEDRAL_RELEASE_ADMIN_READ_TOKEN" in workflow
    assert "CATHEDRAL_TDX_RELEASE_TAG_RULESET_ID" in workflow
    assert '"repos/${GITHUB_REPOSITORY}/immutable-releases"' in workflow
    assert '"repos/${GITHUB_REPOSITORY}/rulesets/${TAG_RULESET_ID}"' in workflow
    assert '.target == "tag"' in workflow
    assert 'index("update") != null' in workflow
    assert 'index("deletion") != null' in workflow
    assert "((.bypass_actors // []) | length == 0)" in workflow

    actions = re.findall(r"uses: ([^\s]+)", workflow)
    assert actions == [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
    ]
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", action) for action in actions)


def test_verifier_release_build_and_two_asset_contract_are_fixed():
    workflow = WORKFLOW_PATH.read_text()
    normalized = " ".join(workflow.split())

    for expected in (
        'GO_VERSION: "1.25.13"',
        'CGO_ENABLED: "0"',
        "GOOS: linux",
        "GOARCH: amd64",
        "GOAMD64: v1",
        'GOENV: "off"',
        "GOTOOLCHAIN: local",
        'GOWORK: "off"',
        'test "$(go env GOVERSION)" = "go${GO_VERSION}"',
        "go mod verify",
        "go vet ./...",
        "go test -race ./...",
        "go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...",
        "go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w'",
        'cmp -- "$build_one/$ARTIFACT_NAME" "$build_two/$ARTIFACT_NAME"',
        f"EXPECTED_SHA256: {EXPECTED_SHA256}",
        'sha256sum --check --strict "$CHECKSUM_NAME"',
        "statically linked",
        "stripped",
        " INTERP ",
        " DYNAMIC ",
    ):
        assert expected in normalized or expected in workflow

    release_step = workflow.split(
        "- name: Create the tagged release with two assets", 1
    )[1]
    assert release_step.count('"$GITHUB_WORKSPACE/dist/$') == 2
    assert 'test "${#assets[@]}" -eq 2' in release_step
    assert 'gh release create "$RELEASE_TAG" "${assets[@]}"' in release_step
    assert "--verify-tag" in release_step
    assert "--latest=false" in release_step
    assert release_step.count("verify_remote_tag_target") == 3
    assert "--json isImmutable" in release_step
    assert 'test "$(gh release view' in release_step
    assert "dist/*" not in workflow
    assert "gh release upload" not in workflow
    assert workflow.count('GOCACHE="$build_') == 2

    anonymous_step = workflow.split(
        "- name: Download both release assets without credentials", 1
    )[1]
    assert "GH_TOKEN" not in anonymous_step
    assert "secrets." not in anonymous_step
    assert anonymous_step.count("curl --fail --location") == 2
    assert 'sha256sum --check --strict "$CHECKSUM_NAME"' in anonymous_step
    assert "permissions: {}" in workflow.split("verify-anonymous-download:", 1)[1]


def test_release_notes_template_binds_provenance_and_states_trust_limits():
    workflow = WORKFLOW_PATH.read_text()
    template = TEMPLATE_PATH.read_text()
    normalized_template = " ".join(template.split())
    guide = GUIDE_PATH.read_text()
    normalized_guide = " ".join(guide.split())

    assert template.count("{{TAG}}") == 1
    assert template.count("{{SOURCE_REVISION}}") == 4
    assert template.count("{{GO_MOD_SHA256}}") == 1
    assert template.count("{{GO_SUM_SHA256}}") == 1
    assert 'sha256sum cmd/cathedral-tdx-verifier/go.mod' in workflow
    assert 'sha256sum cmd/cathedral-tdx-verifier/go.sum' in workflow
    assert 'notes.replace("{{GO_MOD_SHA256}}"' in workflow
    assert 'notes.replace("{{GO_SUM_SHA256}}"' in workflow
    for expected in (
        EXPECTED_SHA256,
        "Go `1.25.13`",
        "CGO_ENABLED=0",
        "GOOS=linux",
        "GOARCH=amd64",
        "GOAMD64=v1",
        "{{GO_MOD_SHA256}}",
        "{{GO_SUM_SHA256}}",
        "GitHub-hosted runner and release control plane",
        "quote freshness",
        "stable platform identity",
        "not evidence of a deployment",
        "not Cathedral's runtime verifier implementation digest",
        "The literal build command is:",
    ):
        assert expected in normalized_template

    rendered = template.replace("{{TAG}}", "cathedral-tdx-verifier-v1.2.3")
    rendered = rendered.replace("{{SOURCE_REVISION}}", "a" * 40)
    rendered = rendered.replace("{{GO_MOD_SHA256}}", "b" * 64)
    rendered = rendered.replace("{{GO_SUM_SHA256}}", "c" * 64)
    assert "{{" not in rendered and "}}" not in rendered
    assert "cathedral-tdx-verifier-v1.2.3" in rendered
    assert "a" * 40 in rendered

    assert "does not claim that a tag or GitHub release exists" in normalized_guide
    assert "exactly two explicit assets" in normalized_guide
    assert "not reachable from the current `origin/main`" in normalized_guide
    assert "does not change GitHub's latest-release marker" in normalized_guide
    assert "not use the raw asset SHA" in normalized_guide
    assert "before any publishing command" in normalized_guide
    assert "requires GitHub to report the published release as immutable" in normalized_guide
    assert "no bypass actors" in normalized_guide
    assert "separate empty Go build caches" in normalized_guide
    assert "live anonymous-download proof" in normalized_guide
    assert "Do not download the verifier from a Cathedral API" in normalized_guide
    assert "docs/RELEASE_CHECKLIST.md" in guide
    assert "TDX_VERIFIER_RELEASE_NOTES_TEMPLATE.md" in workflow
