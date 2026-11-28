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
  SSH (host_call), and only their options; and only while the whole checkout is root's alone (trusted());
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


def check(cmd: str | None, hotel: str, tool: str, srv: str = "/srv/custom-guest",
          scp: str = "/usr/bin/scp") -> list[str]:
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


def _sound(p: str, st: os.stat_result, owner: int) -> None:
    if st.st_uid != owner or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Refused(f"{p} is not owned by uid {owner}, or is writable by group or others")


def _walk_error(e: OSError) -> None:
    raise e


def trusted(checkout: str, root: str, owner: int) -> None:
    """Every file and folder of the pinned checkout, the checkout and the install root: owned by `owner`, not
    writable by group or others. Root runs much more than the .sh: custom_guest_host.py, sev_status.py,
    custom-net.sh, room-kit/sealed/write-units.sh and snp_qemu.py (a link into room-kit), so the whole checkout
    counts. A link may point only inside the checkout, where the walk checks its target too. A `git archive`
    extracted as root keeps 0775/0664 (tar.umask 002): the guide's `chmod -R go-w` comes first."""
    if os.path.realpath(checkout) != checkout or os.path.dirname(checkout) != root:
        raise Refused("the checkout path has a link in it, or is not in the install root")
    for d in (root, checkout):
        _sound(d, os.lstat(d), owner)
    for top, dirs, files in os.walk(checkout, onerror=_walk_error):
        for name in dirs + files:
            p = os.path.join(top, name)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                target = os.path.realpath(p)
                if os.path.commonpath([target, checkout]) != checkout or not os.path.exists(target):
                    raise Refused(f"{p} links outside the checkout")
                continue
            _sound(p, st, owner)


def refuse(reason: str, cmd: str | None) -> int:
    # host_call reads the RESULT line, so a refusal reads as a code, not a lost answer. The request goes back too:
    # sshd drops a subsystem session's stderr, so stdout is the only place an sftp refusal can be read.
    request = repr(cmd)[:300]
    print("RESULT " + json.dumps({"ok": False, "error_code": "custom_guest_request_invalid",
                                  "detail": f"cathedral-cg-dispatch refused: {reason}", "request": request}),
          flush=True)
    line = f"cathedral-cg-dispatch: refused: {reason}: {request}"
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
        checkout = f"{a['root']}/cathedral-sandbox-cg-{a['sha7']}"
        tool = f"{checkout}/{TOOL_REL}"
        run = check(cmd, a["hotel"], tool, a["srv"], a["scp"])
        if run[0] == tool:
            trusted(checkout, a["root"], a["owner"])
    except (Refused, OSError, ValueError) as e:
        return refuse(str(e), cmd)
    os.execve(run[0], run, dict(FIXED_ENV))
    return 1  # not reached


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
