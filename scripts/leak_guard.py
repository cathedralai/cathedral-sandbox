#!/usr/bin/env python3
"""Block host addresses, secrets and private names from a public repository.

The guard scans new text only: the lines that a pull request or push adds
(the net diff, and each commit on its own), the pull request title and body,
and the commit messages. It has two rule sets:

* Public rules in this file: public IPv4 addresses, IPv4 host:port forms,
  private key headers and common token prefixes.
* Private rules from the LEAK_DENYLIST environment variable: one term per
  line, matched as a whole word without regard to case. The guard never
  prints a private term or the line that contains it. When the variable is
  empty (for example on a pull request from a fork), the guard skips the
  private rules and writes a notice.

A line that contains ``leak-guard: allow`` is not scanned. Paths that match a
glob in .github/leak-guard-allow-paths.txt are not scanned.

The guard does not print matched values for any rule, because CI logs stay
public after a commit is removed.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

ALLOW_MARKER = "leak-guard: allow"
DEFAULT_ALLOW_PATHS_FILE = ".github/leak-guard-allow-paths.txt"
DENYLIST_ENV = "LEAK_DENYLIST"
MAX_FILE_BYTES = 2 * 1024 * 1024

# Address ranges that do not identify one of our hosts.
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",  # "this network", includes the wildcard bind address
        "127.0.0.0/8",  # loopback
        "10.0.0.0/8",  # RFC 1918
        "172.16.0.0/12",  # RFC 1918
        "192.168.0.0/16",  # RFC 1918
        "169.254.0.0/16",  # link local and cloud metadata
        "100.64.0.0/10",  # shared address space (CGNAT, Tailscale)
        "192.0.2.0/24",  # documentation, RFC 5737
        "198.51.100.0/24",  # documentation, RFC 5737
        "203.0.113.0/24",  # documentation, RFC 5737
        "192.0.0.0/24",  # IETF protocol assignments
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "198.18.0.0/15",  # benchmark testing
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, includes netmasks and broadcast
    )
)

# Well-known addresses that are not ours: public resolvers, the Azure
# platform address and the usual placeholder.
ALLOWED_ADDRESSES = frozenset(
    ipaddress.ip_address(addr)
    for addr in (
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
        "168.63.129.16",
        "1.2.3.4",
    )
)

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

# The look-behind rejects version strings such as v1.2.3.4 or pkg-1.2.3.4 and
# parts of longer dotted numbers such as OIDs. The look-ahead rejects a fifth
# dotted part and trailing word characters.
IPV4_RE = re.compile(
    r"(?<![\w.\-^~])"
    rf"(?P<ip>{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET})"
    r"(?![\w]|\.\d)"
    r"(?P<port>:\d{1,5}(?!\d))?"
)

# Text just before the match that marks a version, not an address.
VERSION_CONTEXT_RE = re.compile(r"(?i)(?:[=<>!~]=|\b(?:version|release|ver|build))[\s:=\"']*$")

SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    ),
    ("token-github", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})")),
    ("token-anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("token-openai", re.compile(r"\bsk-(?!ant-)(?=[A-Za-z0-9_\-]*\d)[A-Za-z0-9_\-]{32,}")),
    ("token-aws", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("token-slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("token-gitlab", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("token-google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("token-stripe", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}")),
    ("token-huggingface", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    (
        "token-discord",
        re.compile(r"\b[MNO][A-Za-z\d_\-]{23,27}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,40}\b"),
    ),
    (
        "webhook-url",
        re.compile(
            r"https://(?:(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/"
            r"|hooks\.slack\.com/services/T)"
        ),
    ),
)


@dataclass(frozen=True)
class Source:
    """One piece of new text, with a location for the report."""

    kind: str  # "file", "commit-file", "pr-title", "pr-body" or "commit"
    name: str  # path, commit id, or "commit id:path" for a commit-file
    lines: tuple[tuple[int, str], ...]  # (line number, text)


@dataclass(frozen=True)
class Finding:
    rule: str
    source: Source
    line: int
    column: int

    def location(self) -> str:
        if self.source.kind == "file":
            return f"{self.source.name}:{self.line}"
        if self.source.kind == "commit":
            return f"commit {self.source.name[:12]} message line {self.line}"
        if self.source.kind == "commit-file":
            sha, _, path = self.source.name.partition(":")
            return f"commit {sha[:12]} {path}:{self.line} (removed later, still in history)"
        return f"{self.source.kind} line {self.line}"

    def message(self) -> str:
        if self.rule == "denylist":
            return f"denylisted term matched in {self.location()}"
        return f"rule {self.rule} matched in {self.location()}"


# ---------------------------------------------------------------------------
# Rules


def is_allowed_ipv4(text: str) -> bool:
    addr = ipaddress.ip_address(text)
    return addr in ALLOWED_ADDRESSES or any(addr in net for net in ALLOWED_NETWORKS)


def scan_ipv4(line: str) -> Iterator[tuple[str, int]]:
    for match in IPV4_RE.finditer(line):
        ip = match.group("ip")
        # A leading zero in any part means this is not an address we write.
        if any(len(part) > 1 and part.startswith("0") for part in ip.split(".")):
            continue
        if VERSION_CONTEXT_RE.search(line[: match.start()]):
            continue
        if is_allowed_ipv4(ip):
            continue
        rule = "ipv4-host-port" if match.group("port") else "ipv4"
        yield rule, match.start() + 1


def scan_secrets(line: str) -> Iterator[tuple[str, int]]:
    for rule, pattern in SECRET_RULES:
        for match in pattern.finditer(line):
            yield rule, match.start() + 1


def compile_denylist(raw: str) -> list[re.Pattern[str]]:
    """Turn the secret value into patterns.

    One term per line. Blank lines and lines that start with # are ignored.
    A line that starts with ``re:`` is a regular expression (case is still
    ignored), for terms that need an exception such as ``re:acme(?!-tools)``.
    Any other line is a literal term matched as a whole word.
    """
    patterns: list[re.Pattern[str]] = []
    for entry in raw.splitlines():
        term = entry.strip()
        if not term or term.startswith("#"):
            continue
        if term.startswith("re:"):
            body = term[3:]
        else:
            body = re.escape(term)
        patterns.append(re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])", re.IGNORECASE))
    return patterns


def scan_denylist(line: str, patterns: list[re.Pattern[str]]) -> Iterator[tuple[str, int]]:
    for pattern in patterns:
        match = pattern.search(line)
        if match:
            yield "denylist", match.start() + 1


def scan_sources(sources: Iterable[Source], denylist: list[re.Pattern[str]]) -> list[Finding]:
    findings: list[Finding] = []
    for source in sources:
        for number, text in source.lines:
            if ALLOW_MARKER in text:
                continue
            hits = list(scan_ipv4(text)) + list(scan_secrets(text))
            hits += list(scan_denylist(text, denylist))
            for rule, column in hits:
                findings.append(Finding(rule, source, number, column))
    return findings


# ---------------------------------------------------------------------------
# Inputs


def load_allow_paths(path: Path) -> list[str]:
    if not path.is_file():
        return []
    globs = []
    for entry in path.read_text(encoding="utf-8").splitlines():
        entry = entry.strip()
        if entry and not entry.startswith("#"):
            globs.append(entry)
    return globs


def path_is_allowed(path: str, globs: list[str], allow_paths_file: str) -> bool:
    # The allowlist file can not exempt itself.
    if path == allow_paths_file:
        return False
    return any(fnmatch.fnmatchcase(path, glob) for glob in globs)


def text_source(kind: str, name: str, text: str | None) -> Source:
    lines = tuple(enumerate((text or "").splitlines(), start=1))
    return Source(kind, name, lines)


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_added_lines(diff: str) -> list[Source]:
    """Return the added lines of a unified diff, grouped by new path."""
    files: dict[str, list[tuple[int, str]]] = {}
    path: str | None = None
    line_no = 0
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            path = None
            continue
        if raw.startswith("+++ "):
            target = raw[4:]
            path = None if target == "/dev/null" else _strip_prefix(target)
            continue
        if raw.startswith("--- "):
            continue
        hunk = HUNK_RE.match(raw)
        if hunk:
            line_no = int(hunk.group(1))
            continue
        if path is None:
            continue
        if raw.startswith("+"):
            files.setdefault(path, []).append((line_no, raw[1:]))
            line_no += 1
        elif raw.startswith(" "):
            line_no += 1
    return [Source("file", p, tuple(lines)) for p, lines in files.items()]


def _strip_prefix(target: str) -> str:
    if target.startswith('"') and target.endswith('"'):
        target = target[1:-1]
    return target[2:] if target.startswith("b/") else target


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, errors="replace"
    )
    return result.stdout


def diff_sources(base: str, head: str, repo: Path) -> list[Source]:
    diff = git(
        "diff", "--unified=0", "--no-color", "--no-ext-diff", "--no-renames",
        f"{base}...{head}", cwd=repo,
    )
    return parse_added_lines(diff)


def commit_patch_sources(base: str, head: str, repo: Path) -> list[Source]:
    """Added lines of each commit, one source per commit and path.

    A merge commit keeps every commit of the branch in public history. A
    value that one commit adds and a later commit removes is not in the net
    diff, so the guard also scans each commit on its own.
    """
    sources = []
    for sha in git("rev-list", "--no-merges", f"{base}..{head}", cwd=repo).split():
        patch = git(
            "show", "--format=", "--unified=0", "--no-color", "--no-ext-diff",
            "--no-renames", sha, cwd=repo,
        )
        for source in parse_added_lines(patch):
            sources.append(Source("commit-file", f"{sha}:{source.name}", source.lines))
    return sources


def drop_net_duplicates(commit_files: list[Source], net: list[Source]) -> list[Source]:
    """Keep only commit lines that are not also in the net diff.

    The net diff gives exact file and line annotations, so a line that is in
    both is reported once, from the net diff.
    """
    net_lines = {(s.name, text) for s in net for _, text in s.lines}
    kept = []
    for source in commit_files:
        path = source.name.split(":", 1)[1]
        lines = tuple((n, t) for n, t in source.lines if (path, t) not in net_lines)
        if lines:
            kept.append(Source(source.kind, source.name, lines))
    return kept


def commit_sources(base: str, head: str, repo: Path) -> list[Source]:
    out = git("log", "--format=%H%x00%B%x1e", f"{base}..{head}", cwd=repo)
    sources = []
    for record in out.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, _, body = record.partition("\x00")
        sources.append(text_source("commit", sha, body))
    return sources


def tree_sources(repo: Path) -> list[Source]:
    """Every tracked text file in the work tree, for a full audit."""
    sources = []
    for rel in git("ls-files", "-z", cwd=repo).split("\0"):
        if not rel:
            continue
        full = repo / rel
        try:
            if not full.is_file() or full.stat().st_size > MAX_FILE_BYTES:
                continue
            data = full.read_bytes()
        except OSError:
            continue
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        sources.append(text_source("file", rel, text))
    return sources


def event_sources(event_path: str | None) -> list[Source]:
    if not event_path or not Path(event_path).is_file():
        return []
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pr = event.get("pull_request")
    if not pr:
        return []
    return [
        text_source("pr-title", "title", pr.get("title")),
        text_source("pr-body", "body", pr.get("body")),
    ]


# ---------------------------------------------------------------------------
# Output


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def annotation(finding: Finding) -> str:
    props = ["title=leak-guard"]
    if finding.source.kind == "file":
        props.insert(0, f"file={_escape_property(finding.source.name)}")
        props.insert(1, f"line={finding.line}")
        props.insert(2, f"col={finding.column}")
    return f"::error {','.join(props)}::{_escape_data(finding.message())}"


def summary(findings: list[Finding], denylist_active: bool, scanned: int) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule] = counts.get(finding.rule, 0) + 1
    out = ["## Leak guard", ""]
    out.append(f"Scanned {scanned} sources.")
    out.append(
        "Private rules: "
        + ("active." if denylist_active else "skipped (LEAK_DENYLIST is not available).")
    )
    out.append("")
    if not findings:
        out.append("Result: no matches.")
    else:
        out.append(f"Result: {len(findings)} matches. Remove them, or see the README.")
        out.append("")
        out.append("| Rule | Matches |")
        out.append("| --- | --- |")
        for rule in sorted(counts):
            out.append(f"| {rule} | {counts[rule]} |")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Entry point


def build_sources(args: argparse.Namespace, repo: Path) -> list[Source]:
    sources: list[Source] = []
    if args.all_files:
        sources += tree_sources(repo)
    if args.base and args.head:
        net = diff_sources(args.base, args.head, repo)
        sources += net
        sources += drop_net_duplicates(commit_patch_sources(args.base, args.head, repo), net)
        sources += commit_sources(args.base, args.head, repo)
    sources += event_sources(args.event)
    globs = load_allow_paths(repo / args.allow_paths)
    return [s for s in sources if not _source_path_allowed(s, globs, args.allow_paths)]


def _source_path_allowed(source: Source, globs: list[str], allow_paths_file: str) -> bool:
    if source.kind == "file":
        return path_is_allowed(source.name, globs, allow_paths_file)
    if source.kind == "commit-file":
        return path_is_allowed(source.name.split(":", 1)[1], globs, allow_paths_file)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="base commit for the diff and commit list")
    parser.add_argument("--head", help="head commit for the diff and commit list")
    parser.add_argument("--event", help="GitHub event JSON, for the PR title and body")
    parser.add_argument("--all-files", action="store_true", help="scan every tracked file")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--allow-paths", default=DEFAULT_ALLOW_PATHS_FILE)
    parser.add_argument("--summary-only", action="store_true", help="print counts, not locations")
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    sources = build_sources(args, repo)

    raw_denylist = os.environ.get(DENYLIST_ENV, "")
    denylist = compile_denylist(raw_denylist)
    if not denylist:
        print(
            f"::notice title=leak-guard::{DENYLIST_ENV} is not available "
            "(a pull request from a fork, or the secret is not set). "
            "Private rules skipped. Public rules still run."
        )

    findings = scan_sources(sources, denylist)
    if not args.summary_only:
        for finding in findings:
            print(annotation(finding))

    report = summary(findings, bool(denylist), len(sources))
    print(report)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
