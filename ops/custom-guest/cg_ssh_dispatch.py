#!/usr/bin/python3 -I
"""Forced command for the operator machine's key on a custom guest hotel (AB#1008).

Install on the hotel (OPERATOR.md, install step 3):

    install -m 0755 -o root -g root <checkout>/ops/custom-guest/cg_ssh_dispatch.py /usr/local/sbin/cathedral-cg-dispatch

and give the operator key this line in root's authorized_keys:

    command="/usr/local/sbin/cathedral-cg-dispatch <hotel> <sha7>",from="<operator address>",restrict ssh-ed25519 ...

sshd then runs this program instead of what the client asked for, and puts the client's request in
SSH_ORIGINAL_COMMAND. That includes a subsystem request: an sftp client arrives here with the configured
subsystem command (`/usr/lib/openssh/sftp-server` or `internal-sftp`) and is refused like any other text,
because the forced command overrides the subsystem.

Exactly two forms run, with a fixed environment (nothing from sshd or the client):

- `/opt/cathedral/cathedral-sandbox-cg-<sha7>/ops/custom-guest/custom-guest-host.sh <phase> --hotel <hotel> ...`:
  the installed checkout only (its sha7 is in the command= arguments), the 15 phases custom_guest.py sends over
  SSH (host_call), and only their options;
- `scp -t /srv/custom-guest/<hotel>/inbox/cg-<12 hex>/<vmlinuz|initrd|root.raw>`: the intake upload, which the
  operator sends with `scp -O`.

Anything else gets one refusal line and exit 1. The hotel comes from the command= arguments, never from the client.
The request is checked as one string against a short character set and split on spaces (as vm_ctl.py does for the
broker's commands): there is no shell and no quote handling to get wrong.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys

TOOL_REL = "ops/custom-guest/custom-guest-host.sh"
SAFE = re.compile(r"[A-Za-z0-9 ._/-]+")
HOTEL_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,58}")
SHA7_RE = re.compile(r"[0-9a-f]{7}")
LAUNCH = r"cg-[0-9a-f]{12}"
# Every phase custom_guest.py sends over SSH, with the options it sends besides --hotel; all of them are required.
# The host tool's other phases (tick, check-start, exited, boot-record) run from units on the hotel, never over SSH.
PHASES: dict[str, dict[str, str]] = {
    **{p: {"--launch-id": LAUNCH} for p in (
        "facts", "inbox", "intake", "measure", "hold-baseline", "unhold", "discard", "boot", "stop", "return-kit",
        "return-finish", "wipe")},
    "hold-stop": {"--launch-id": LAUNCH, "--part": r"[ab]"},
    "verify-disks": {"--launch-id": LAUNCH, "--context": r"boot[1-9][0-9]*"},
    "folders": {},
}
UPLOAD_NAMES = r"(vmlinuz|initrd|root\.raw)"
FIXED_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class Refused(Exception):
    pass


def check(cmd: str | None, hotel: str, tool: str, srv: str = "/srv/custom-guest", scp: str = "/usr/bin/scp") -> list[str]:
    """The argv to exec for this request (argv[0] is the program's path), or Refused. No file system, no env."""
    if not cmd:
        raise Refused("no command: a login shell is not offered")
    if not SAFE.fullmatch(cmd):
        raise Refused("a character outside letters, digits, space and ._/-")
    w = cmd.split()
    if w[0] == tool:
        if len(w) < 2 or w[1] not in PHASES:
            raise Refused("not a phase the operator sends")
        allowed = {"--hotel": re.escape(hotel), **PHASES[w[1]]}
        opts, seen = w[2:], set()
        if len(opts) % 2:
            raise Refused("an option without a value")
        for k, v in zip(opts[::2], opts[1::2]):
            if k not in allowed or k in seen:
                raise Refused(f"option {k} is not allowed for {w[1]}, or is repeated")
            if not re.fullmatch(allowed[k], v):
                raise Refused(f"bad value for {k}")
            seen.add(k)
        if seen != set(allowed):
            raise Refused(f"{w[1]} needs " + " ".join(sorted(set(allowed) - seen)))
        return w
    if w[0] == "scp":
        target = re.escape(f"{srv}/{hotel}/inbox/") + LAUNCH + "/" + UPLOAD_NAMES
        if len(w) == 3 and w[1] == "-t" and re.fullmatch(target, w[2]):
            return [scp, "-t", w[2]]
        raise Refused("not the intake upload")
    raise Refused("not the host tool of this install")


def trusted(tool: str, root: str, owner: int) -> None:
    """The tool, the files beside it and each folder up to the install root: owned by `owner`, not writable by
    others, no links. What runs as root is custom_guest_host.py and its siblings, so they count too. Group write is
    allowed only for root's own group on a root-owned checkout: `git archive` writes 0775/0664 (tar.umask 002), and
    a checkout extracted as root keeps those modes."""
    if os.path.realpath(tool) != tool:
        raise Refused("the tool path has a link in it")
    here = os.path.dirname(tool)
    paths = [os.path.join(here, n) for n in sorted(os.listdir(here))]
    d = here
    while True:
        paths.append(d)
        if d == root or len(d) <= len(root):
            break
        d = os.path.dirname(d)
    if d != root:
        raise Refused("the tool is not under the install root")
    for p in paths:
        st = os.lstat(p)
        group_ok = owner == 0 and st.st_gid == 0
        if stat.S_ISLNK(st.st_mode) or st.st_uid != owner or st.st_mode & stat.S_IWOTH \
                or (st.st_mode & stat.S_IWGRP and not group_ok):
            raise Refused(f"{p} is a link, not owned by uid {owner}, or writable by others")


def refuse(reason: str, cmd: str | None) -> int:
    # host_call reads the RESULT line, so a refusal reads as a code, not a lost answer.
    print("RESULT " + json.dumps({"ok": False, "error_code": "custom_guest_request_invalid",
                                  "detail": f"cathedral-cg-dispatch refused: {reason}"}), flush=True)
    line = f"cathedral-cg-dispatch: refused: {reason}: {repr(cmd)[:300]}"
    print(line, file=sys.stderr, flush=True)
    try:
        import syslog
        syslog.openlog("cathedral-cg-dispatch", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_WARNING, line)
    except Exception:
        pass
    return 1


def install_args(argv: list[str]) -> dict:
    """The command= arguments: <hotel> <sha7>, then (tests) --root, --srv, --scp, --owner-uid."""
    if len(argv) < 2 or not HOTEL_RE.fullmatch(argv[0]) or not SHA7_RE.fullmatch(argv[1]) or len(argv) % 2:
        raise Refused("install error: the command= line needs <hotel> <sha7>")
    a = {"hotel": argv[0], "sha7": argv[1], "root": "/opt/cathedral", "srv": "/srv/custom-guest",
         "scp": "/usr/bin/scp", "owner": 0}
    for k, v in zip(argv[2::2], argv[3::2]):
        if k not in ("--root", "--srv", "--scp", "--owner-uid"):
            raise Refused(f"install error: unknown argument {k}")
        a["owner" if k == "--owner-uid" else k[2:]] = int(v) if k == "--owner-uid" else v
    return a


def main(argv: list[str]) -> int:
    cmd = os.environ.get("SSH_ORIGINAL_COMMAND")
    try:
        a = install_args(argv)
        tool = f"{a['root']}/cathedral-sandbox-cg-{a['sha7']}/{TOOL_REL}"
        run = check(cmd, a["hotel"], tool, a["srv"], a["scp"])
        if run[0] == tool:
            trusted(tool, a["root"], a["owner"])
    except (Refused, OSError, ValueError) as e:
        return refuse(str(e), cmd)
    os.execve(run[0], run, dict(FIXED_ENV))
    return 1  # not reached


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
