"""The operator key's forced command on a custom guest hotel (ops/custom-guest/cg_ssh_dispatch.py, AB#1008).

The table tests drive the pure check; the main tests run the program with a fake checkout and a polluted
environment; the sshd tests (CG_SSHD_TESTS=1, root, in the custom guest unit workflow) put it behind a real sshd and
show that sftp, a shell command and plain scp are refused while the operator's forms run.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DISPATCH = REPO / "ops" / "custom-guest" / "cg_ssh_dispatch.py"
HOTEL, SHA7, LAUNCH = "hotel-a", "abcdef1", "cg-0123456789ab"
TOOL = f"/opt/cathedral/cathedral-sandbox-cg-{SHA7}/ops/custom-guest/custom-guest-host.sh"
INBOX = f"/srv/custom-guest/{HOTEL}/inbox/{LAUNCH}"


def load():
    spec = spec_from_file_location("cg_ssh_dispatch", DISPATCH)
    m = module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


LAUNCH_PHASES = ["facts", "inbox", "intake", "measure", "hold-baseline", "unhold", "discard", "boot", "stop",
                 "return-kit", "return-finish", "wipe"]
ALLOWED = (
    [f"{TOOL} {p} --hotel {HOTEL} --launch-id {LAUNCH}" for p in LAUNCH_PHASES]
    + [f"{TOOL} hold-stop --hotel {HOTEL} --launch-id {LAUNCH} --part {x}" for x in "ab"]
    + [f"{TOOL} verify-disks --hotel {HOTEL} --launch-id {LAUNCH} --context boot{n}" for n in (1, 12, 1000)]
    + [f"{TOOL} folders --hotel {HOTEL}", f"{TOOL} facts --launch-id {LAUNCH} --hotel {HOTEL}"]
)
UPLOADS = [f"scp -t {INBOX}/{n}" for n in ("vmlinuz", "initrd", "root.raw")]

REFUSED = {
    "no command": None,
    "empty": "",
    "shell command": "true",
    "a shell": "bash",
    "sh -c": "sh -c id",
    # An sftp request arrives with the configured subsystem command; the forced command overrides it.
    "sftp server": "/usr/lib/openssh/sftp-server",
    "internal-sftp": "internal-sftp",
    "sftp": "sftp",
    "host-only phase tick": f"{TOOL} tick --hotel {HOTEL} --launch-id {LAUNCH}",
    "host-only phase check-start": f"{TOOL} check-start --hotel {HOTEL} --launch-id {LAUNCH}",
    "host-only phase exited": f"{TOOL} exited --hotel {HOTEL} --launch-id {LAUNCH}",
    "host-only phase boot-record": f"{TOOL} boot-record --hotel {HOTEL} --launch-id {LAUNCH}",
    "unknown phase": f"{TOOL} shell --hotel {HOTEL} --launch-id {LAUNCH}",
    "no phase": TOOL,
    "another hotel": f"{TOOL} facts --hotel hotel-b --launch-id {LAUNCH}",
    "no --hotel": f"{TOOL} facts --launch-id {LAUNCH}",
    "folders without --hotel": f"{TOOL} folders",
    "no --launch-id": f"{TOOL} facts --hotel {HOTEL}",
    "--launch-id on folders": f"{TOOL} folders --hotel {HOTEL} --launch-id {LAUNCH}",
    "short launch id": f"{TOOL} facts --hotel {HOTEL} --launch-id cg-0123",
    "long launch id": f"{TOOL} facts --hotel {HOTEL} --launch-id cg-0123456789abc",
    "upper-case launch id": f"{TOOL} facts --hotel {HOTEL} --launch-id cg-0123456789AB",
    "--part c": f"{TOOL} hold-stop --hotel {HOTEL} --launch-id {LAUNCH} --part c",
    "hold-stop without --part": f"{TOOL} hold-stop --hotel {HOTEL} --launch-id {LAUNCH}",
    "--part on another phase": f"{TOOL} facts --hotel {HOTEL} --launch-id {LAUNCH} --part a",
    "--context R5": f"{TOOL} verify-disks --hotel {HOTEL} --launch-id {LAUNCH} --context R5",
    "--context boot0": f"{TOOL} verify-disks --hotel {HOTEL} --launch-id {LAUNCH} --context boot0",
    "--context on stop": f"{TOOL} stop --hotel {HOTEL} --launch-id {LAUNCH} --context boot1",
    "repeated --hotel": f"{TOOL} facts --hotel {HOTEL} --hotel {HOTEL} --launch-id {LAUNCH}",
    "extra option": f"{TOOL} facts --hotel {HOTEL} --launch-id {LAUNCH} --root /tmp",
    "dangling option": f"{TOOL} facts --hotel {HOTEL} --launch-id {LAUNCH} --part",
    "semicolon": f"{TOOL} facts --hotel {HOTEL} --launch-id {LAUNCH}; id",
    "and": f"{TOOL} facts --hotel {HOTEL} --launch-id {LAUNCH} && id",
    "dollar": f"{TOOL} facts --hotel $(id) --launch-id {LAUNCH}",
    "backtick": f"{TOOL} facts --hotel `id` --launch-id {LAUNCH}",
    "newline": f"{TOOL} facts --hotel {HOTEL} --launch-id {LAUNCH}\nid",
    "tab": f"{TOOL}\tfacts --hotel {HOTEL} --launch-id {LAUNCH}",
    "quote": f"'{TOOL}' facts --hotel {HOTEL} --launch-id {LAUNCH}",
    "unbalanced quote": f"{TOOL} facts --hotel \"{HOTEL} --launch-id {LAUNCH}",
    "another checkout": TOOL.replace(SHA7, "1234567") + f" facts --hotel {HOTEL} --launch-id {LAUNCH}",
    "dot-dot in the tool path": TOOL.replace("/ops/", "/ops/../ops/") + f" facts --hotel {HOTEL} --launch-id {LAUNCH}",
    "double slash": TOOL.replace("/ops/", "//ops/") + f" facts --hotel {HOTEL} --launch-id {LAUNCH}",
    "relative tool": f"ops/custom-guest/custom-guest-host.sh facts --hotel {HOTEL} --launch-id {LAUNCH}",
    "scp download": f"scp -f {INBOX}/vmlinuz",
    "scp recursive": f"scp -r -t {INBOX}/vmlinuz",
    "scp with -p": f"scp -p -t {INBOX}/vmlinuz",
    "scp with -d": f"scp -d -t {INBOX}/vmlinuz",
    "scp to /tmp": "scp -t /tmp/vmlinuz",
    "scp to rootXraw": f"scp -t {INBOX}/rootXraw",
    "scp other name": f"scp -t {INBOX}/passwd",
    "scp to the inbox folder": f"scp -t {INBOX}/",
    "scp second target": f"scp -t {INBOX}/vmlinuz {INBOX}/initrd",
    "scp another hotel": f"scp -t /srv/custom-guest/hotel-b/inbox/{LAUNCH}/vmlinuz",
    "scp dot-dot": f"scp -t /srv/custom-guest/{HOTEL}/inbox/{LAUNCH}/../vmlinuz",
}


@pytest.mark.parametrize("cmd", ALLOWED)
def test_each_form_the_operator_sends_runs_as_sent(cmd):
    assert load().check(cmd, HOTEL, TOOL) == cmd.split()


@pytest.mark.parametrize("cmd", UPLOADS)
def test_the_intake_upload_runs_scp_sink_for_that_file_only(cmd):
    assert load().check(cmd, HOTEL, TOOL, scp="/usr/bin/scp") == ["/usr/bin/scp", "-t", cmd.split()[2]]


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_everything_else_is_refused(name):
    d = load()
    with pytest.raises(d.Refused):
        d.check(REFUSED[name], HOTEL, TOOL)


def test_the_phase_list_matches_the_host_tool():
    """Every phase the dispatcher lets through exists in the host tool, and the host-only ones stay out."""
    src = (REPO / "ops" / "custom-guest" / "custom_guest_host.py").read_text()
    d = load()
    for phase in d.PHASES:
        assert f'"{phase}": (' in src, phase
    for phase in ("tick", "check-start", "exited", "boot-record"):
        assert phase not in d.PHASES


# ---------------------------------------------------------------- the program, with a fake checkout

FAKE_TOOL = '''#!{py} -I
import json, os, sys
print("RESULT " + json.dumps({{"ok": True, "argv": sys.argv, "env": dict(os.environ)}}))
'''


def checkout(tmp: Path, sha7: str = SHA7) -> tuple[Path, Path]:
    root = Path(os.path.realpath(tmp)) / "opt"
    here = root / f"cathedral-sandbox-cg-{sha7}" / "ops" / "custom-guest"
    here.mkdir(parents=True)
    tool = here / "custom-guest-host.sh"
    tool.write_text(FAKE_TOOL.format(py=sys.executable))
    tool.chmod(0o755)
    (here / "custom_guest_host.py").write_text("# the real tool's code\n")
    for d in (here, here.parent, here.parent.parent, root):
        d.chmod(0o755)
    return root, tool


def dispatch(root: Path, cmd: str | None, *extra: str, env: dict | None = None) -> subprocess.CompletedProcess:
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **(env or {})}
    if cmd is not None:
        e["SSH_ORIGINAL_COMMAND"] = cmd
    argv = [sys.executable, "-I", str(DISPATCH), HOTEL, SHA7, "--root", str(root), "--owner-uid", str(os.getuid()),
            *extra]
    return subprocess.run(argv, capture_output=True, text=True, env=e, timeout=60)


def result(p: subprocess.CompletedProcess) -> dict:
    lines = [ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")]
    assert len(lines) == 1, (p.stdout, p.stderr)
    return json.loads(lines[0][len("RESULT "):])


# Interpreter or platform additions that no caller sets (macOS adds the first one to every process).
PLATFORM_ENV = {"__CF_USER_TEXT_ENCODING", "PWD", "SHLVL", "_"}


def test_the_tool_runs_with_a_fixed_environment_only(tmp_path):
    """N1: nothing sshd or the client set reaches the root tool; CG_* would re-root it or skip its timeout."""
    root, tool = checkout(tmp_path)
    hostile = {"CG_SEV_STATUS": "/bin/sh", "CG_ROOT": "/tmp/x", "CG_DEADLINE": "boot", "CG_KIT_DIR": "/tmp/k",
               "CG_QEMU": "/bin/sh", "CG_FAULT": "x", "LD_PRELOAD": "/tmp/x.so", "PYTHONPATH": "/tmp",
               "SSH_CONNECTION": "192.0.2.1 5000 192.0.2.2 22", "HOME": "/root", "LANG": "xx"}
    p = dispatch(root, f"{tool} folders --hotel {HOTEL}", env=hostile)
    r = result(p)
    assert p.returncode == 0 and r["ok"] is True, (p.stdout, p.stderr)
    assert r["argv"] == [str(tool), "folders", "--hotel", HOTEL]
    env = {k: v for k, v in r["env"].items() if k not in PLATFORM_ENV}
    assert env == load().FIXED_ENV, env


def test_the_upload_runs_scp_with_a_fixed_environment_only(tmp_path):
    root, _ = checkout(tmp_path)
    scp = tmp_path / "fake-scp"
    scp.write_text(FAKE_TOOL.format(py=sys.executable))
    scp.chmod(0o755)
    srv = tmp_path / "srv"
    target = f"{srv}/{HOTEL}/inbox/{LAUNCH}/root.raw"
    p = dispatch(root, f"scp -t {target}", "--srv", str(srv), "--scp", str(scp), env={"CG_ROOT": "/tmp/x"})
    r = result(p)
    assert r["argv"] == [str(scp), "-t", target]
    assert {k: v for k, v in r["env"].items() if k not in PLATFORM_ENV} == load().FIXED_ENV


def test_a_refusal_is_one_coded_result_line_and_exit_1(tmp_path):
    root, tool = checkout(tmp_path)
    for cmd in (None, "/usr/lib/openssh/sftp-server", "internal-sftp", f"{tool} facts --hotel \"{HOTEL}",
                f"{tool} tick --hotel {HOTEL} --launch-id {LAUNCH}"):
        p = dispatch(root, cmd)
        r = result(p)
        assert p.returncode == 1 and r["ok"] is False and r["error_code"] == "custom_guest_request_invalid", p
        assert "Traceback" not in p.stderr and len(p.stderr.strip().splitlines()) == 1, p.stderr
        assert p.stderr.startswith("cathedral-cg-dispatch: refused: "), p.stderr


def test_only_the_installed_checkout_runs(tmp_path):
    """The sha7 in the command= line pins the checkout: an older one left on disk is refused."""
    root, _ = checkout(tmp_path)
    _, other = checkout(tmp_path, "1234567")
    p = dispatch(root, f"{other} folders --hotel {HOTEL}")
    assert p.returncode == 1 and "not the host tool of this install" in result(p)["detail"]


@pytest.mark.parametrize("weak", ["tool", "sibling", "folder", "link"])
def test_a_checkout_others_could_change_is_refused(tmp_path, weak):
    root, tool = checkout(tmp_path)
    here = tool.parent
    if weak == "tool":
        tool.chmod(0o775)
    elif weak == "sibling":
        (here / "custom_guest_host.py").chmod(0o666)
    elif weak == "folder":
        here.parent.chmod(0o777)
    else:
        real = here.parent.parent.with_name("elsewhere")
        here.parent.parent.rename(real)
        here.parent.parent.symlink_to(real)
    p = dispatch(root, f"{tool} folders --hotel {HOTEL}")
    assert p.returncode == 1 and result(p)["ok"] is False and "argv" not in result(p), p.stdout


@pytest.mark.parametrize("args", [["Bad_Hotel", SHA7], [HOTEL, "xyz"], [HOTEL], [HOTEL, SHA7, "--path", "/tmp"]])
def test_a_bad_command_line_in_authorized_keys_refuses_everything(tmp_path, args):
    root, tool = checkout(tmp_path)
    e = {"PATH": "/usr/bin:/bin", "SSH_ORIGINAL_COMMAND": f"{tool} folders --hotel {HOTEL}"}
    p = subprocess.run([sys.executable, "-I", str(DISPATCH), *args], capture_output=True, text=True, env=e, timeout=60)
    assert p.returncode == 1 and "install error" in result(p)["detail"]


# ---------------------------------------------------------------- the operator side and the guide

def test_the_default_scp_uses_the_legacy_protocol():
    """Without -O, scp asks for the sftp subsystem, which the forced command refuses: the upload would fail."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("CG_")}
    p = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import custom_guest as g; "
                        "print(g.SCP)", str(REPO / "ops" / "custom-guest")], capture_output=True, text=True, env=env,
                       timeout=60)
    assert "-O" in eval(p.stdout), (p.stdout, p.stderr)


def test_the_guide_installs_the_forced_command():
    text = (REPO / "ops" / "custom-guest" / "OPERATOR.md").read_text()
    assert 'command="/usr/local/sbin/cathedral-cg-dispatch <hotel> <sha7>",from="<operator address>",restrict' in text
    assert "install -m 0755 -o root -g root" in text and "/usr/local/sbin/cathedral-cg-dispatch" in text
    scp = [ln for ln in text.splitlines() if ln.strip().startswith("CG_SCP=")]
    assert scp and all(" -O " in ln for ln in scp), scp


# ---------------------------------------------------------------- behind a real sshd (root, CI)

SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
# Skipped unless asked for; once asked for (the workflow sets CG_SSHD_TESTS=1), a missing sshd or root fails.
sshd_tests = pytest.mark.skipif(os.environ.get("CG_SSHD_TESTS") != "1",
                                reason="needs CG_SSHD_TESTS=1, root and sshd (the custom guest unit workflow)")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


@pytest.fixture(params=["/usr/lib/openssh/sftp-server", "internal-sftp"])
def sshd(tmp_path, request):
    assert os.geteuid() == 0 and os.path.exists(SSHD), "CG_SSHD_TESTS=1 needs root and sshd"
    d = Path(os.path.realpath(tmp_path))
    d.chmod(0o755)
    root, tool = checkout(d)
    # As P1 installs it: git archive (tar.umask 002) extracted as root gives root:root 0775/0664.
    for f in tool.parent.iterdir():
        f.chmod(f.stat().st_mode | 0o020)
    srv = d / "srv"
    (srv / HOTEL / "inbox" / LAUNCH).mkdir(parents=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "hostkey")], check=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "key")], check=True)
    forced = (f"{sys.executable} -I {DISPATCH} {HOTEL} {SHA7} --root {root} --srv {srv} --scp /usr/bin/scp "
              f"--owner-uid 0")
    (d / "authorized_keys").write_text(f'command="{forced}",restrict {(d / "key.pub").read_text().strip()}\n')
    port = free_port()
    (d / "sshd_config").write_text("\n".join([
        f"Port {port}", "ListenAddress localhost", f"HostKey {d}/hostkey", f"PidFile {d}/sshd.pid",
        f"AuthorizedKeysFile {d}/authorized_keys", "PermitRootLogin prohibit-password", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "UsePAM no", "StrictModes no", "LogLevel VERBOSE",
        # The worst case for N1: sshd accepts the client's CG_* variables. The fixed env must still drop them.
        "AcceptEnv CG_*", f"Subsystem sftp {request.param}", ""]))
    Path("/run/sshd").mkdir(exist_ok=True)
    p = subprocess.Popen([SSHD, "-D", "-e", "-f", str(d / "sshd_config")], stderr=open(d / "sshd.log", "w"))
    # Wait on the log, not a probe connection: OpenSSH 10's PerSourcePenalties defers a source that drops a connection.
    for _ in range(100):
        if "Server listening on" in (d / "sshd.log").read_text():
            break
        time.sleep(0.1)
    base = ["-F", "/dev/null", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-i", str(d / "key")]
    yield {"d": d, "port": port, "base": base, "tool": tool, "srv": srv, "subsystem": request.param}
    p.terminate()
    p.wait(timeout=10)


def ssh(s, *cmd: str, opts: tuple = ()) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh", *s["base"], *opts, "-p", str(s["port"]), "root@localhost", *cmd],
                          capture_output=True, text=True, timeout=60)


@sshd_tests
def test_behind_sshd_a_shell_command_and_sftp_are_refused(sshd):
    p = ssh(sshd, "true")
    assert p.returncode == 1 and "refused" in p.stdout, (p.stdout, p.stderr)
    p = ssh(sshd, "cat /etc/shadow")
    assert p.returncode == 1 and "root:" not in p.stdout
    p = subprocess.run(["sftp", *sshd["base"], "-P", str(sshd["port"]), "-b", "-", "root@localhost"],
                       input="ls /\n", capture_output=True, text=True, timeout=60)
    assert p.returncode != 0 and "etc" not in p.stdout, (p.stdout, p.stderr)
    # The sftp request reached the forced command, with the configured subsystem command as SSH_ORIGINAL_COMMAND.
    assert f"cathedral-cg-dispatch: refused: not the host tool of this install: {sshd['subsystem']!r}" in p.stderr, \
        p.stderr
    log = (sshd["d"] / "sshd.log").read_text()
    assert log.count("Starting session: forced-command (key-option)") == 3 and "subsystem 'sftp'" not in log, log[-3000:]


@sshd_tests
def test_behind_sshd_the_operator_phase_runs_with_the_fixed_env(sshd):
    p = ssh(sshd, f"{sshd['tool']} folders --hotel {HOTEL}", opts=("-o", "SetEnv=CG_SEV_STATUS=/bin/sh CG_ROOT=/tmp"))
    r = result(p)
    assert r["ok"] is True and r["argv"] == [str(sshd["tool"]), "folders", "--hotel", HOTEL], p
    assert {k: v for k, v in r["env"].items() if k not in PLATFORM_ENV} == load().FIXED_ENV, r["env"]


@sshd_tests
def test_behind_sshd_only_the_legacy_upload_to_the_inbox_works(sshd):
    src = sshd["d"] / "vmlinuz.src"
    src.write_bytes(os.urandom(4096))
    dest = sshd["srv"] / HOTEL / "inbox" / LAUNCH
    scp = ["scp", "-q", *sshd["base"], "-P", str(sshd["port"])]
    p = subprocess.run([*scp, "-O", str(src), f"root@localhost:{dest}/vmlinuz"], capture_output=True, text=True,
                       timeout=60)
    assert p.returncode == 0 and (dest / "vmlinuz").read_bytes() == src.read_bytes(), p.stderr
    for target, extra in ((f"{dest}/initrd", []), (f"{dest}/rootXraw", ["-O"]), (f"{sshd['d']}/elsewhere", ["-O"])):
        p = subprocess.run([*scp, *extra, str(src), f"root@localhost:{target}"], capture_output=True, text=True,
                           timeout=60)
        assert p.returncode != 0 and not Path(target).exists(), (target, p.stderr)
