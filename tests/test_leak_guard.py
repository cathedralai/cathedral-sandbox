"""Tests for scripts/leak_guard.py.

Test values that the guard must catch are built at run time, so that this
file does not itself contain a public address, a token or a private term.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import leak_guard as guard

# A public address that is not in an allowed range.
PUBLIC_IP = ".".join(["45", "33", "12", "7"])
OTHER_PUBLIC_IP = ".".join(["185", "4", "200", "61"])
TERM = "Exam" + "pleHost"


def rules(line: str, denylist: str = "") -> list[str]:
    source = guard.text_source("file", "f.txt", line)
    findings = guard.scan_sources([source], guard.compile_denylist(denylist))
    return [f.rule for f in findings]


# --- public rules ---------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        f"ssh root@{PUBLIC_IP}",
        f"HOST={PUBLIC_IP}",
        f"curl http://{PUBLIC_IP}/health",
        f"address: {OTHER_PUBLIC_IP}.",
        f"({PUBLIC_IP})",
    ],
)
def test_public_ipv4_is_blocked(line: str) -> None:
    assert rules(line) == ["ipv4"]


def test_host_port_is_its_own_rule() -> None:
    assert rules(f"connect to {PUBLIC_IP}:8444 now") == ["ipv4-host-port"]


@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",
        "127.8.9.10",
        "10.20.30.40",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.10",
        "169.254.169.254",
        "0.0.0.0",
        "255.255.255.0",
        "192.0.2.15",
        "198.51.100.7",
        "203.0.113.200",
        "100.64.0.1",
        "100.127.255.254",
        "8.8.8.8",
        "1.1.1.1",
        "1.2.3.4",
        "168.63.129.16",
        "192.0.0.192",
        "198.18.0.1",
        "224.0.0.251",
        "240.0.0.1",
    ],
)
def test_allowed_ranges_pass(addr: str) -> None:
    assert rules(f"bind {addr}:8080 and {addr}") == []


def test_edges_of_allowed_ranges() -> None:
    # 172.32/12 and 100.128/10 are outside the private and shared ranges.
    assert rules("peer " + ".".join(["172", "32", "0", "1"])) == ["ipv4"]
    assert rules("peer " + ".".join(["100", "128", "0", "1"])) == ["ipv4"]


@pytest.mark.parametrize(
    "line",
    [
        "image v1.2.3.4 is out",
        "V2.10.0.1",
        "pkg-1.2.3.4.tar.gz",
        "requests==2.31.0.1",
        "cryptography>=42.0.0.5",
        "version 4.3.2.1",
        "release: 5.6.7.8",
        "oid 1.3.6.1.4.1.311",
        "256.1.1.1 and 1.2.3.999",
        "01.02.03.04",
        "build-5.6.7.8",
        "1.2.3.4a",
    ],
)
def test_version_like_strings_pass(line: str) -> None:
    assert rules(line) == []


def test_server_word_is_not_version_context() -> None:
    assert rules(f"server {PUBLIC_IP}") == ["ipv4"]


def test_private_key_header() -> None:
    header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    assert rules(header) == ["private-key"]
    assert rules("-----BEGIN " + "PRIVATE KEY-----") == ["private-key"]
    assert rules("-----BEGIN PUBLIC KEY-----") == []


@pytest.mark.parametrize(
    "token, rule",
    [
        ("ghp_" + "a1B2" * 9, "token-github"),
        ("github_pat_" + "x1" * 30, "token-github"),
        ("sk-ant-" + "api03-" + "Z9" * 20, "token-anthropic"),
        ("sk-" + "proj-" + "ab12" * 10, "token-openai"),
        ("AKIA" + "ABCDEFGH12345678", "token-aws"),
        ("xoxb-" + "1234567890-abc", "token-slack"),
        ("glpat-" + "q" * 20, "token-gitlab"),
        ("AIza" + "S" * 35, "token-google"),
        ("sk_live_" + "4eC39HqLyjWDarjt", "token-stripe"),
        ("hf_" + "k" * 34, "token-huggingface"),
        ("https://discord.com/api/" + "webhooks/123456/abc", "webhook-url"),
    ],
)
def test_token_prefixes(token: str, rule: str) -> None:
    assert rules(f"value = {token}") == [rule]


def test_short_prefix_mentions_pass() -> None:
    assert rules("GitHub tokens start with ghp_ and Anthropic keys with sk-ant-") == []
    assert rules("sk-cathedral-sandbox-public-runner-configuration-name") == []


# --- allow mechanisms -----------------------------------------------------


def test_allow_comment_skips_the_line() -> None:
    assert rules(f"{PUBLIC_IP}  # leak-guard: allow (public NTP pool)") == []
    assert rules(f"{TERM} leak-guard: allow", denylist=TERM) == []


def test_allow_comment_covers_only_its_own_line() -> None:
    source = guard.text_source("file", "f.txt", f"x # leak-guard: allow\n{PUBLIC_IP}")
    findings = guard.scan_sources([source], [])
    assert [(f.rule, f.line) for f in findings] == [("ipv4", 2)]


def test_path_allowlist(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_text("# vendored\nvendor/*\n\n", encoding="utf-8")
    globs = guard.load_allow_paths(allow)
    assert globs == ["vendor/*"]
    assert guard.path_is_allowed("vendor/geo.csv", globs, "allow.txt")
    assert not guard.path_is_allowed("docs/geo.csv", globs, "allow.txt")
    # The allowlist file can not exempt itself.
    assert not guard.path_is_allowed("allow.txt", ["*"], "allow.txt")


# --- private rules --------------------------------------------------------


def test_denylist_whole_word_and_case() -> None:
    assert rules(f"runs on {TERM.upper()} now", denylist=TERM) == ["denylist"]
    assert rules(f"{TERM.lower()}_box", denylist=TERM) == ["denylist"]
    assert rules(f"pre{TERM}", denylist=TERM) == []
    assert rules(f"{TERM}s", denylist=TERM) == []


def test_denylist_comments_and_regex_entries() -> None:
    raw = "# suppliers\n\n  re:acme(?!-tools)  \n"
    assert rules("we rent from Acme", denylist=raw) == ["denylist"]
    assert rules("pip install acme-tools", denylist=raw) == []


def test_denylist_dotted_terms_are_literal() -> None:
    host = "box1" + ".example.org"
    assert rules(f"see {host}", denylist=host) == ["denylist"]
    assert rules("see box1Xexample.org", denylist=host) == []


def test_denylist_message_never_contains_the_term() -> None:
    source = guard.text_source("file", "docs/a.md", f"host {TERM}")
    (finding,) = guard.scan_sources([source], guard.compile_denylist(TERM))
    assert finding.message() == "denylisted term matched in docs/a.md:1"
    assert TERM.lower() not in guard.annotation(finding).lower()


def test_annotations_never_contain_matched_values() -> None:
    source = guard.text_source("file", "a,b:c.md", f"{PUBLIC_IP}:22")
    (finding,) = guard.scan_sources([source], [])
    line = guard.annotation(finding)
    assert PUBLIC_IP not in line
    assert line.startswith("::error file=a%2Cb%3Ac.md,line=1,col=1,")


# --- diff parsing ---------------------------------------------------------


def test_parse_added_lines_only() -> None:
    diff = "\n".join(
        [
            "diff --git a/docs/x.md b/docs/x.md",
            "--- a/docs/x.md",
            "+++ b/docs/x.md",
            "@@ -3,0 +4,2 @@",
            f"+new {PUBLIC_IP}",
            "+second",
            "@@ -10 +12 @@",
            f"-old {OTHER_PUBLIC_IP}",
            "+replaced",
            "diff --git a/gone.md b/gone.md",
            "--- a/gone.md",
            "+++ /dev/null",
            "@@ -1 +0,0 @@",
            f"-{OTHER_PUBLIC_IP}",
        ]
    )
    (source,) = guard.parse_added_lines(diff)
    assert source.name == "docs/x.md"
    assert source.lines == ((4, f"new {PUBLIC_IP}"), (5, "second"), (12, "replaced"))


# --- end to end with git --------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "old.md").write_text(f"old {OTHER_PUBLIC_IP}\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def _event(tmp_path: Path, title: str, body: str | None) -> Path:
    path = tmp_path / "event.json"
    path.write_text(json.dumps({"pull_request": {"title": title, "body": body}}))
    return path


def test_end_to_end_reports_diff_title_body_and_commits(
    repo: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch, capsys
) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "docs").mkdir()
    (repo / "docs" / "evidence.md").write_text(f"clean\nhost {PUBLIC_IP}:8444\n", "utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", f"Add evidence\n\nfrom {TERM}")
    head = _git(repo, "rev-parse", "HEAD")
    event = _event(tmp_path_factory.mktemp("ev"), f"{TERM} join evidence", f"see {PUBLIC_IP}")
    summary_file = tmp_path_factory.mktemp("sum") / "summary.md"
    monkeypatch.setenv("LEAK_DENYLIST", TERM)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    code = guard.main(
        ["--repo", str(repo), "--base", base, "--head", head, "--event", str(event)]
    )

    out = capsys.readouterr().out
    assert code == 1
    assert "::error file=docs/evidence.md,line=2,col=6,title=leak-guard::" in out
    assert "denylisted term matched in pr-title line 1" in out
    assert "rule ipv4 matched in pr-body line 1" in out
    assert f"denylisted term matched in commit {head[:12]} message line 3" in out
    # The old line in the base commit is not new text.
    assert "old.md" not in out
    assert PUBLIC_IP not in out and TERM.lower() not in out.lower()
    assert "| denylist | 2 |" in summary_file.read_text()
    assert "Private rules: active." in summary_file.read_text()


def test_end_to_end_reports_value_removed_by_a_later_commit(
    repo: Path, monkeypatch, capsys
) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "e.md").write_text(f"host {PUBLIC_IP}\n", "utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add")
    leaking = _git(repo, "rev-parse", "HEAD")
    (repo / "e.md").write_text("host <redacted>\n", "utf-8")
    _git(repo, "commit", "-q", "-am", "redact")
    head = _git(repo, "rev-parse", "HEAD")
    monkeypatch.delenv("LEAK_DENYLIST", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    assert guard.main(["--repo", str(repo), "--base", base, "--head", head]) == 1
    out = capsys.readouterr().out
    assert f"commit {leaking[:12]} e.md:1 (removed later, still in history)" in out
    assert "::error file=" not in out


def test_line_in_net_diff_is_reported_once(repo: Path, monkeypatch, capsys) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "e.md").write_text(f"host {PUBLIC_IP}\n", "utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add")
    head = _git(repo, "rev-parse", "HEAD")
    monkeypatch.delenv("LEAK_DENYLIST", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    assert guard.main(["--repo", str(repo), "--base", base, "--head", head]) == 1
    out = capsys.readouterr().out
    assert out.count("::error ") == 1
    assert "::error file=e.md,line=1," in out


def test_end_to_end_without_secret_skips_private_rules(
    repo: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch, capsys
) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "notes.md").write_text(f"made on {TERM}\n", "utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "notes")
    head = _git(repo, "rev-parse", "HEAD")
    event = _event(tmp_path_factory.mktemp("ev"), "Fork PR", None)
    monkeypatch.delenv("LEAK_DENYLIST", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    code = guard.main(
        ["--repo", str(repo), "--base", base, "--head", head, "--event", str(event)]
    )

    out = capsys.readouterr().out
    assert code == 0
    assert "::notice title=leak-guard::LEAK_DENYLIST is not available" in out
    assert "Private rules skipped" in out
    assert "Result: no matches." in out


def test_end_to_end_secret_missing_still_runs_public_rules(
    repo: Path, monkeypatch, capsys
) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "notes.md").write_text(f"{PUBLIC_IP}\n", "utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "notes")
    head = _git(repo, "rev-parse", "HEAD")
    monkeypatch.setenv("LEAK_DENYLIST", "\n# only comments\n")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    assert guard.main(["--repo", str(repo), "--base", base, "--head", head]) == 1
    out = capsys.readouterr().out
    assert "Private rules skipped" in out
    assert "rule ipv4 matched in notes.md:1" in out


def test_all_files_mode_respects_path_allowlist(repo: Path, monkeypatch, capsys) -> None:
    (repo / ".github").mkdir()
    (repo / ".github" / "leak-guard-allow-paths.txt").write_text("old.md\n", "utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "allow")
    monkeypatch.delenv("LEAK_DENYLIST", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    assert guard.main(["--repo", str(repo), "--all-files"]) == 0
    assert "Result: no matches." in capsys.readouterr().out
