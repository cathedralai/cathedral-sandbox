"""The stock-systemd rehearsal root check (AB#1008, AB#1027): it fails on the v1 rehearsal
root, which has no dbus and masks networkd, and passes on a root with dbus, udev and networkd
enabled and the guest network written at boot. Synthetic trees only; no image is built."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
CHECK = REPO / "ops" / "custom-guest" / "rehearsal-image" / "check_stock_root.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load("check_stock_root", CHECK)
recipe = _load("custom_root_recipe_for_check", REPO / "scripts" / "build_custom_guest_root.py")
HELPER = b"helper"
HELPER_SHA = hashlib.sha256(HELPER).hexdigest()
LIB = "usr/lib/systemd/system"
ETC = "etc/systemd/system"


def _file(root, name, data=b"[Unit]\n", mode=0o644):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(mode)


def _link(root, name, target):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        path.unlink()
    os.symlink(target, path)


def _v1_root(tmp_path):
    """A merged-usr bookworm-shaped base after the reference recipe, as the v1 rehearsal root."""
    root = tmp_path / "root"
    for name in ("sbin/init", "usr/sbin/sshd", "usr/bin/ip"):
        _file(root, name, b"\x7fELFsynthetic", 0o755)
    (root / "etc/ssh").mkdir(parents=True)
    _file(root, "etc/shadow", "root:!:20000:0:99999:7:::\n")
    _file(root, "etc/passwd", "root:x:0:0:root:/root:/bin/sh\nsystemd-network:x:998:998::/:/usr/sbin/nologin\n")
    (root / "root/.ssh").mkdir(parents=True)
    os.symlink("usr/lib", root / "lib")
    for unit in ("systemd-networkd.service", "systemd-networkd.socket"):
        _file(root, f"{LIB}/{unit}")
    # The base enables ssh.service; the recipe masks it (a Wants= on a masked unit is harmless).
    _link(root, f"{ETC}/multi-user.target.wants/ssh.service", "/lib/systemd/system/ssh.service")
    recipe.configure(root, HELPER, HELPER_SHA)
    return root


def _stock_root(tmp_path):
    """What the stock-systemd variant must leave: the v1 root plus dbus and udev, networkd
    unmasked and enabled, and the network written at boot."""
    root = _v1_root(tmp_path)
    for unit in ("systemd-networkd.service", "systemd-networkd.socket"):
        (root / ETC / unit).unlink()
    for unit in ("dbus.service", "dbus.socket", "systemd-udevd.service", "systemd-udevd-kernel.socket",
                 "systemd-udevd-control.socket"):
        _file(root, f"{LIB}/{unit}")
    _link(root, f"{LIB}/sockets.target.wants/dbus.socket", "../dbus.socket")
    _link(root, f"{LIB}/sockets.target.wants/systemd-udevd-kernel.socket", "../systemd-udevd-kernel.socket")
    _file(root, "usr/bin/dbus-daemon", b"\x7fELFdbus", 0o755)
    _file(root, "usr/bin/udevadm", b"\x7fELFudev", 0o755)
    _link(root, "usr/lib/systemd/systemd-udevd", "../../bin/udevadm")
    with (root / "etc/passwd").open("a") as passwd:
        passwd.write("messagebus:x:100:101::/nonexistent:/usr/sbin/nologin\n")
    _link(root, "etc/systemd/network/99-default.link", "/dev/null")
    _link(root, f"{ETC}/multi-user.target.wants/systemd-networkd.service", "/lib/systemd/system/systemd-networkd.service")
    _link(root, f"{ETC}/sockets.target.wants/systemd-networkd.socket", "/lib/systemd/system/systemd-networkd.socket")
    _file(root, f"{ETC}/cathedral-network.service",
          "[Unit]\nBefore=systemd-networkd.service cathedral-sshd.service\n\n[Service]\nType=oneshot\n"
          "EnvironmentFile=/run/cathedral/network.env\n" + check.WRITER_EXEC + "\nRemainAfterExit=yes\n")
    _file(root, "usr/lib/cathedral/write-network", "#!/bin/sh\n", 0o755)
    _file(root, f"{ETC}/systemd-networkd.service.d/10-cathedral.conf",
          "[Unit]\nWants=cathedral-network.service\nAfter=cathedral-network.service\n")
    return root


def _run(root):
    return subprocess.run([sys.executable, "-I", str(CHECK), "--tree", str(root), "--attest-sha256", HELPER_SHA],
                          capture_output=True, text=True)


def test_the_v1_rehearsal_root_fails_without_dbus_and_with_networkd_masked(tmp_path):
    r = _run(_v1_root(tmp_path))
    assert r.returncode == 1
    lines = r.stdout.splitlines()
    assert "ROOTCHECK: FAIL usr/bin/dbus-daemon: missing, so there is no system bus" in lines
    assert f"ROOTCHECK: FAIL {ETC}/systemd-networkd.service: masked" in lines
    assert f"ROOTCHECK: FAIL {ETC}/systemd-networkd.socket: masked" in lines
    assert "ROOTCHECK: FAIL usr/lib/systemd/systemd-udevd: missing, so networkd leaves every link pending udev" in lines
    assert any("cathedral-network.service: does not run /usr/lib/cathedral/write-network" in line for line in lines)
    # What v1 keeps is not a finding.
    assert not any("cathedral-attest" in line or "sshd" in line for line in lines), lines


def test_a_stock_systemd_root_passes(tmp_path):
    r = _run(_stock_root(tmp_path))
    assert r.returncode == 0, r.stdout
    assert r.stdout.startswith("ROOTCHECK: PASS")


def test_links_are_read_inside_the_root_never_on_the_build_host(tmp_path):
    root = _stock_root(tmp_path)
    (root / "usr/bin/dbus-daemon").unlink()
    # The build host has this file; inside the root the link leads nowhere.
    _link(root, "usr/bin/dbus-daemon", "/bin/sh")
    lines = _run(root).stdout.splitlines()
    assert "ROOTCHECK: FAIL usr/bin/dbus-daemon: missing, so there is no system bus" in lines


def test_a_masked_bus_socket_fails(tmp_path):
    root = _stock_root(tmp_path)
    _link(root, f"{ETC}/dbus.socket", "/dev/null")
    lines = _run(root).stdout.splitlines()
    assert f"ROOTCHECK: FAIL {ETC}/dbus.socket: masked" in lines


def test_a_unit_that_requires_a_masked_unit_fails(tmp_path):
    root = _stock_root(tmp_path)
    _link(root, f"{ETC}/cathedral-sshd.service.requires/ssh.socket", "/lib/systemd/system/ssh.socket")
    lines = _run(root).stdout.splitlines()
    assert f"ROOTCHECK: FAIL {ETC}/cathedral-sshd.service.requires/ssh.socket: cathedral-sshd.service " \
           "requires ssh.socket, which is masked" in lines


def test_networkd_must_wait_for_the_network_writer(tmp_path):
    root = _stock_root(tmp_path)
    (root / ETC / "systemd-networkd.service.d" / "10-cathedral.conf").unlink()
    lines = _run(root).stdout.splitlines()
    assert any(line.endswith("no Wants=cathedral-network.service, so networkd may start before its config")
               for line in lines)


def test_a_baked_network_file_and_an_unmasked_rename_policy_fail(tmp_path):
    root = _stock_root(tmp_path)
    _file(root, "etc/systemd/network/10-eth0.network", "[Match]\nName=eth0\n")
    (root / "etc/systemd/network/99-default.link").unlink()
    lines = _run(root).stdout.splitlines()
    assert any(line.startswith("ROOTCHECK: FAIL etc/systemd/network/10-eth0.network:") for line in lines)
    assert any(line.startswith("ROOTCHECK: FAIL etc/systemd/network/99-default.link: not masked") for line in lines)


def test_another_attest_or_sshd_config_fails(tmp_path):
    root = _stock_root(tmp_path)
    _file(root, "usr/bin/cathedral-attest", b"other", 0o755)
    _file(root, "etc/ssh/cathedral_sshd_config", recipe.SSH_CONFIG + "PasswordAuthentication yes\n")
    lines = _run(root).stdout.splitlines()
    assert f"ROOTCHECK: FAIL usr/bin/cathedral-attest: not {HELPER_SHA}" in lines
    assert "ROOTCHECK: FAIL etc/ssh/cathedral_sshd_config: differs from the reference recipe's" in lines
