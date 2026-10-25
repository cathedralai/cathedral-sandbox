# Public leak guard

This repository is public. The `Leak guard` workflow
(`.github/workflows/leak-guard.yml`, script `scripts/leak_guard.py`) stops
host addresses, secrets and private names before they reach `main`.

What it scans:

- The lines that a pull request or push adds. It scans the net diff and
  each commit on its own, because a merge keeps every commit in public
  history. A value that a later commit removes is still a match.
- The pull request title and body.
- All commit messages in the pull request or push.

What it blocks:

- Public IPv4 addresses, and IPv4 `host:port` forms. Private, loopback,
  link-local, shared (100.64.0.0/10), documentation, multicast and reserved
  ranges are allowed. Version strings such as `v1.2.3.4` are not addresses.
- Private key headers and common token prefixes (GitHub, Anthropic, OpenAI,
  AWS, Slack, GitLab, Google, Stripe, Hugging Face, Discord, webhook URLs).
- Private terms from the `LEAK_DENYLIST` Actions secret: supplier names,
  customer names, our host names and our exact addresses. The match is a
  whole word and ignores case.

The guard never prints a matched value. For a private term it prints only
`denylisted term matched in <file>:<line>`. A pull request from a fork does
not get secrets. The guard then skips the private rules, writes a notice and
still runs the public rules.

To add a private term, ask an org admin of `cathedralai`. The
secret holds one term per line. Lines that start with `#` are comments. A line
that starts with `re:` is a regular expression, for a term that needs an
exception, for example `re:acme(?!-tools)`. The admin replaces the full value:

```sh
gh secret set LEAK_DENYLIST --org cathedralai --visibility all < denylist.txt
```

Do not put the terms in this repository, in an issue or in a pull request.

To allow a false positive:

1. Remove the value if you can. Use a documentation address (192.0.2.0/24,
   198.51.100.0/24 or 203.0.113.0/24) or a placeholder such as `<host>`.
2. If the line must stay, add `leak-guard: allow` to that line, with a short
   reason. The reviewer must agree.
3. For vendored or generated data, add a glob to
   `.github/leak-guard-allow-paths.txt`. A change to that file needs review.

If the guard finds a value in a commit that was removed later, rewrite the
branch (squash or rebase) so that the value is not in any commit. Rotate any
secret that was pushed, even for a short time.

To run the guard locally before you push:

```sh
python scripts/leak_guard.py --base origin/main --head HEAD
```
