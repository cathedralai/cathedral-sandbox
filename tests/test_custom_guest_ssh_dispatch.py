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
    "one space": " ",
    "spaces only": "   ",
    "shell command": "true",
    "a shell": "bash",
    "sh -c": "sh -c id",
    # An sftp request arrives with the configured subsystem command; the forced command overrides it.
    "sftp server": "/usr/lib/openssh/sftp-server",
    "internal-sftp": "internal-sftp",
    # As sshd passes them (the subsystem command plus its empty arguments).
    "sftp server, as sshd sends it": "/usr/lib/openssh/sftp-server ",
    "internal-sftp, as sshd sends it": "internal-sftp ",
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
    """A checkout shaped like the real one where it matters: root runs more than the .sh (the Python tool, its
    siblings, a kit script), and snp_qemu.py is a link into room-kit."""
    root = Path(os.path.realpath(tmp)) / "opt"
    top = root / f"cathedral-sandbox-cg-{sha7}"
    here = top / "ops" / "custom-guest"
    for d in (here / "systemd", top / "room-kit" / "vm", top / "room-kit" / "sealed"):
        d.mkdir(parents=True)
    tool = here / "custom-guest-host.sh"
    tool.write_text(FAKE_TOOL.format(py=sys.executable))
    files = {here / "custom_guest_host.py": 0o755, here / "sev_status.py": 0o755, here / "custom-net.sh": 0o755,
             here / "systemd" / "cathedral-custom-guest@.service": 0o644,
             top / "room-kit" / "vm" / "snp_qemu.py": 0o644,
             top / "room-kit" / "sealed" / "write-units.sh": 0o755}
    for f, mode in files.items():
        f.write_text("# code root runs\n")
        f.chmod(mode)
    (here / "snp_qemu.py").symlink_to("../../room-kit/vm/snp_qemu.py")
    tool.chmod(0o755)
    for d in [root, *[p for p in top.rglob("*") if p.is_dir() and not p.is_symlink()], top]:
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
    for cmd in (None, " ", "/usr/lib/openssh/sftp-server", "internal-sftp", f"{tool} facts --hotel \"{HOTEL}",
                f"{tool} tick --hotel {HOTEL} --launch-id {LAUNCH}"):
        p = dispatch(root, cmd)
        r = result(p)
        assert p.returncode == 1 and r["ok"] is False and r["error_code"] == "custom_guest_request_invalid", p
        assert r["request"] == repr(cmd)[:300], r
        assert "Traceback" not in p.stderr and len(p.stderr.strip().splitlines()) == 1, p.stderr
        assert p.stderr.startswith("cathedral-cg-dispatch: refused: "), p.stderr


def test_only_the_installed_checkout_runs(tmp_path):
    """The sha7 in the command= line pins the checkout: an older one left on disk is refused."""
    root, _ = checkout(tmp_path)
    _, other = checkout(tmp_path, "1234567")
    p = dispatch(root, f"{other} folders --hotel {HOTEL}")
    assert p.returncode == 1 and "not the host tool of this install" in result(p)["detail"]


# Each weak spot, and the path the refusal must name.
WEAK = {"tool": "ops/custom-guest/custom-guest-host.sh is",
        "group-writable python": "ops/custom-guest/custom_guest_host.py is",
        "other-writable python": "ops/custom-guest/sev_status.py is", "folder": "/ops is", "link": "link",
        "link target": "room-kit/vm/snp_qemu.py is", "kit script": "room-kit/sealed/write-units.sh is",
        "unit file in a subfolder": "systemd/cathedral-custom-guest@.service is", "subfolder": "room-kit/sealed is",
        "link out of the checkout": "ops/custom-guest/snp_qemu.py links outside", "install root": "/opt is"}


@pytest.mark.parametrize("weak", sorted(WEAK))
def test_a_checkout_others_could_change_is_refused(tmp_path, weak):
    """The whole pinned checkout counts, not just the .sh: root runs the Python tool and what it calls."""
    root, tool = checkout(tmp_path)
    here, top = tool.parent, tool.parents[2]
    if weak == "tool":
        tool.chmod(0o775)
    elif weak == "group-writable python":
        (here / "custom_guest_host.py").chmod(0o775)
    elif weak == "other-writable python":
        (here / "sev_status.py").chmod(0o757)
    elif weak == "folder":
        here.parent.chmod(0o777)
    elif weak == "link":
        real = top.with_name("elsewhere")
        top.rename(real)
        top.symlink_to(real)
    elif weak == "link target":
        (top / "room-kit" / "vm" / "snp_qemu.py").chmod(0o664)
    elif weak == "kit script":
        (top / "room-kit" / "sealed" / "write-units.sh").chmod(0o775)
    elif weak == "unit file in a subfolder":
        (here / "systemd" / "cathedral-custom-guest@.service").chmod(0o664)
    elif weak == "subfolder":
        (top / "room-kit" / "sealed").chmod(0o775)
    elif weak == "link out of the checkout":
        outside = tmp_path / "outside.py"
        outside.write_text("# not in the checkout\n")
        (here / "snp_qemu.py").unlink()
        (here / "snp_qemu.py").symlink_to(outside)
    else:
        root.chmod(0o775)
    p = dispatch(root, f"{tool} folders --hotel {HOTEL}")
    r = result(p)
    assert p.returncode == 1 and r["ok"] is False and "argv" not in r, p.stdout
    assert WEAK[weak] in r["detail"], r["detail"]


def test_a_sound_checkout_with_its_link_runs(tmp_path):
    root, tool = checkout(tmp_path)
    p = dispatch(root, f"{tool} folders --hotel {HOTEL}")
    assert p.returncode == 0 and result(p)["ok"] is True, (p.stdout, p.stderr)


@pytest.mark.skipif(not (REPO / ".git").exists() or not shutil.which("git"), reason="needs a git checkout")
def test_this_commit_installed_as_the_guide_says_passes_the_check(tmp_path):
    """The real tree (git archive, as the host checkout is made), after the guide's chown and chmod, is trusted;
    the same tree with one group-writable Python file is not."""
    d = load()
    root = Path(os.path.realpath(tmp_path)) / "opt"
    top = root / f"cathedral-sandbox-cg-{SHA7}"
    top.mkdir(parents=True)
    archive = subprocess.run(["git", "-C", str(REPO), "archive", "HEAD"], capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", str(top)], input=archive, check=True)
    subprocess.run(["chmod", "-R", "go-w", str(root)], check=True)
    d.trusted(str(top), str(root), os.getuid())
    (top / "ops" / "custom-guest" / "custom_guest_host.py").chmod(0o775)
    with pytest.raises(d.Refused):
        d.trusted(str(top), str(root), os.getuid())


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
    code = "import json, sys; sys.path.insert(0, sys.argv[1]); import custom_guest as g; print(json.dumps(g.SCP))"
    p = subprocess.run([sys.executable, "-I", "-c", code, str(REPO / "ops" / "custom-guest")], capture_output=True,
                       text=True, env=env, timeout=60)
    assert "-O" in json.loads(p.stdout), (p.stdout, p.stderr)


# ---------------------------------------------------------------- the install-time sshd guard

GOOD_PUE = "permituserenvironment no\n"
SSHD_DUMPS = {
    # What the dedicated hotel's sshd -T shows today.
    "LANG LC_* COLORTERM NO_COLOR, one per line": (
        "acceptenv LANG\nacceptenv LC_*\nacceptenv COLORTERM\nacceptenv NO_COLOR\n" + GOOD_PUE, True),
    "LANG LC_* COLORTERM NO_COLOR, one line": ("acceptenv LANG LC_* COLORTERM NO_COLOR\n" + GOOD_PUE, True),
    "no acceptenv": (GOOD_PUE, True),
    "CG_*": ("acceptenv CG_*\n" + GOOD_PUE, True),
    "*": ("acceptenv LANG *\n" + GOOD_PUE, False),
    "L*": ("acceptenv L*\n" + GOOD_PUE, False),
    "LD_PRELOAD": ("acceptenv LD_PRELOAD\n" + GOOD_PUE, False),
    "LD_*": ("acceptenv LD_*\n" + GOOD_PUE, False),
    "LD_BIND_NOW": ("acceptenv LD_BIND_NOW\n" + GOOD_PUE, False),
    "BASH_ENV": ("acceptenv BASH_ENV\n" + GOOD_PUE, False),
    "B*": ("acceptenv B*\n" + GOOD_PUE, False),
    "ENV": ("acceptenv ENV\n" + GOOD_PUE, False),
    "E??": ("acceptenv E??\n" + GOOD_PUE, False),
    "PATH": ("acceptenv PATH\n" + GOOD_PUE, False),
    "P?TH": ("acceptenv P?TH\n" + GOOD_PUE, False),
    "BASH_FUNC_*": ("acceptenv BASH_FUNC_*\n" + GOOD_PUE, False),
    "SHELLOPTS": ("acceptenv SHELLOPTS\n" + GOOD_PUE, False),
    "permituserenvironment yes": ("acceptenv LANG\npermituserenvironment yes\n", False),
    "permituserenvironment a list": ("acceptenv LANG\npermituserenvironment LANG,LC_*\n", False),
    "permituserenvironment missing": ("acceptenv LANG\n", False),
    "empty dump": ("", False),
}


@pytest.mark.parametrize("name", sorted(SSHD_DUMPS))
def test_the_sshd_guard_refuses_variables_root_s_shell_reads(name):
    """sshd hands accepted variables to root's shell, which runs before the dispatcher: the fixed env can't undo
    them."""
    dump, ok = SSHD_DUMPS[name]
    problems = load().sshd_env_problems(dump)
    assert (problems == []) is ok, problems


def fake_sshd(tmp: Path, dump: str, rc: int = 0) -> Path:
    f = tmp / "fake-sshd"
    f.write_text(f"#!{sys.executable} -I\nimport json, sys\n"
                 "open(sys.argv[0] + '.args', 'w').write(json.dumps(sys.argv[1:]))\n"
                 f"sys.stdout.write({dump!r})\nsys.exit({rc})\n")
    f.chmod(0o755)
    return f


def check_sshd(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(DISPATCH), "--check-sshd", *args], capture_output=True,
                          text=True, env={"PATH": "/usr/bin:/bin", "LD_PRELOAD": "x"}, timeout=60)


def test_the_sshd_guard_reads_sshd_for_a_root_login_from_the_operator(tmp_path):
    f = fake_sshd(tmp_path, SSHD_DUMPS["LANG LC_* COLORTERM NO_COLOR, one per line"][0])
    p = check_sshd("--sshd", str(f), "--addr", "192.0.2.10")
    assert p.returncode == 0 and p.stdout.startswith("OK sshd"), (p.stdout, p.stderr)
    args = json.loads((tmp_path / "fake-sshd.args").read_text())
    assert args == ["-T", "-C", "user=root,host=192.0.2.10,addr=192.0.2.10"], args


@pytest.mark.parametrize("dump,rc", [("acceptenv BASH_ENV\n" + GOOD_PUE, 0), (GOOD_PUE, 255), ("", 0)])
def test_the_sshd_guard_fails_closed(tmp_path, dump, rc):
    p = check_sshd("--sshd", str(fake_sshd(tmp_path, dump, rc)), "--addr", "192.0.2.10")
    assert p.returncode == 1 and p.stdout.startswith("FAIL sshd"), (p.stdout, p.stderr)


@pytest.mark.parametrize("args", [["--addr", "192.0.2.10,user=x"], ["--addr"], ["--port", "22"]])
def test_the_sshd_guard_takes_only_its_own_arguments(tmp_path, args):
    p = check_sshd("--sshd", str(fake_sshd(tmp_path, GOOD_PUE)), *args)
    assert p.returncode == 1 and p.stdout.startswith("FAIL sshd"), (p.stdout, p.stderr)
    assert not (tmp_path / "fake-sshd.args").exists()


def test_the_guide_installs_the_forced_command():
    text = (REPO / "ops" / "custom-guest" / "OPERATOR.md").read_text()
    assert ("cg_ssh_dispatch.py --check-sshd --addr <operator address> && install -m 0755 -o root -g root"
            in text)
    assert "chown -R root:root /opt/cathedral/cathedral-sandbox-cg-<sha7>" in text
    assert "chmod -R go-w /opt/cathedral/cathedral-sandbox-cg-<sha7>" in text
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
    # The same subsystem request from ssh -s, which reads the whole answer (the sftp client quits on the first bad
    # packet, and sshd drops a subsystem's stderr): it reached the forced command, with the configured subsystem
    # command as SSH_ORIGINAL_COMMAND.
    p = ssh(sshd, "sftp", opts=("-s",))
    r = result(p)
    assert p.returncode == 1 and r["error_code"] == "custom_guest_request_invalid", (p.stdout, p.stderr)
    # sshd passes the subsystem command with its (empty) arguments: OpenSSH 10.2 adds a trailing space.
    assert r["request"] in (repr(sshd["subsystem"]), repr(sshd["subsystem"] + " ")), r
    assert "not the host tool of this install" in r["detail"], r
    log = (sshd["d"] / "sshd.log").read_text()
    assert log.count("Starting session: forced-command (key-option)") == 4, log[-3000:]
    assert "subsystem 'sftp'" not in log, log[-3000:]


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


@sshd_tests
def test_behind_sshd_a_group_writable_python_file_refuses_every_phase(sshd):
    """As root, on a root:root checkout: group write on a file root runs is refused too (git archive gives 0775)."""
    py = sshd["tool"].parent / "custom_guest_host.py"
    py.chmod(0o775)
    p = ssh(sshd, f"{sshd['tool']} folders --hotel {HOTEL}")
    r = result(p)
    assert p.returncode == 1 and r["ok"] is False and "argv" not in r and "custom_guest_host.py" in r["detail"], r
    py.chmod(0o755)
    assert result(ssh(sshd, f"{sshd['tool']} folders --hotel {HOTEL}"))["ok"] is True


@sshd_tests
def test_behind_sshd_the_install_guard_reads_the_real_sshd(sshd):
    """sshd -T on a real config: the test sshd passes (CG_* is not a risk); a risky AcceptEnv, globally or in a
    Match block for the operator's address, or PermitUserEnvironment yes, fails."""
    base = (sshd["d"] / "sshd_config").read_text()
    for name, extra, ok in (("as is", "", True), ("global", "AcceptEnv BASH_ENV\n", False),
                            ("user env", "PermitUserEnvironment yes\n", False),
                            ("match", "Match Address 192.0.2.10\n    AcceptEnv LD_PRELOAD\n", False)):
        cfg = sshd["d"] / f"sshd_config.{name.replace(' ', '-')}"
        cfg.write_text(extra + base if not extra.startswith("Match") else base + extra)
        p = check_sshd("--sshd", SSHD, "--config", str(cfg), "--addr", "192.0.2.10")
        assert (p.returncode == 0 and p.stdout.startswith("OK sshd")) is ok, (name, p.stdout, p.stderr)
