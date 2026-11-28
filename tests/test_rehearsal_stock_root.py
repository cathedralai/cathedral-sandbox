"""The stock-systemd rehearsal root check (AB#1008, AB#1027): it fails on the v1 rehearsal
root, which has no dbus and masks networkd, and passes on a root with dbus, udev and networkd
enabled and the guest network written at boot. Synthetic trees only; no image is built."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parents[1]
CHECK = REPO / "ops" / "custom-guest" / "rehearsal-image" / "check_stock_root.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load("check_stock_root", CHECK)
stock = _load("stock_systemd", REPO / "ops" / "custom-guest" / "rehearsal-image" / "stock_systemd.py")
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


def _packages(root):
    """What dbus and udev install in the base (vendor units and links, binaries, users)."""
    for unit in ("dbus.service", "dbus.socket", "systemd-udevd.service", "systemd-udevd-kernel.socket",
                 "systemd-udevd-control.socket", "systemd-udev-trigger.service"):
        _file(root, f"{LIB}/{unit}")
    _link(root, f"{LIB}/sockets.target.wants/systemd-udevd-kernel.socket", "../systemd-udevd-kernel.socket")
    _file(root, "usr/bin/dbus-daemon", b"\x7fELFdbus", 0o755)
    _file(root, "usr/bin/udevadm", b"\x7fELFudev", 0o755)
    _link(root, "usr/lib/systemd/systemd-udevd", "../../bin/udevadm")
    with (root / "etc/passwd").open("a") as passwd:
        passwd.write("messagebus:x:100:101::/nonexistent:/usr/sbin/nologin\n")


def _stock_root(tmp_path):
    """The v1 base plus the dbus and udev packages, through the recipe and customize()."""
    root = _v1_root(tmp_path)
    _packages(root)
    stock.customize(root)
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


def test_customize_enables_what_the_packages_left_off_and_keeps_vendor_links(tmp_path):
    root = _stock_root(tmp_path)
    etc = root / ETC
    # The package enabled the kernel socket in usr/lib: no second link in etc.
    assert not (etc / "sockets.target.wants/systemd-udevd-kernel.socket").is_symlink()
    for name, target in (("sockets.target.wants/dbus.socket", "/lib/systemd/system/dbus.socket"),
                         ("sockets.target.wants/systemd-udevd-control.socket", "/lib/systemd/system/systemd-udevd-control.socket"),
                         ("sysinit.target.wants/systemd-udev-trigger.service", "/lib/systemd/system/systemd-udev-trigger.service"),
                         ("multi-user.target.wants/systemd-networkd.service", "/lib/systemd/system/systemd-networkd.service"),
                         ("sockets.target.wants/systemd-networkd.socket", "/lib/systemd/system/systemd-networkd.socket"),
                         ("dbus-org.freedesktop.network1.service", "/lib/systemd/system/systemd-networkd.service")):
        assert os.readlink(etc / name) == target, name
    assert os.readlink(root / "etc/systemd/network/99-default.link") == "/dev/null"
    assert (root / "usr/lib/cathedral/write-network").stat().st_mode & 0o777 == 0o755


def test_customize_refuses_a_base_without_dbus(tmp_path):
    root = _v1_root(tmp_path)
    with pytest.raises(ValueError, match="missing usr/bin/dbus-daemon"):
        stock.customize(root)


def _writer(tmp_path):
    out = tmp_path / "run-network"
    script = tmp_path / "write-network"
    script.write_text(stock.WRITE_NETWORK.replace("dir=/run/systemd/network", f"dir={out}"))
    return script, out


def test_write_network_writes_the_guest_network_from_three_words(tmp_path):
    script, out = _writer(tmp_path)
    subprocess.run(["sh", str(script), "eth0", "10.217.0.2/30", "10.217.0.1"], check=True)
    network = out / "10-cathedral.network"
    assert network.read_text() == ("[Match]\nName=eth0\n\n[Link]\nRequiredForOnline=yes\n\n[Network]\n"
                                   "Address=10.217.0.2/30\nGateway=10.217.0.1\nDHCP=no\n"
                                   "LinkLocalAddressing=no\nIPv6AcceptRA=no\n")
    assert network.stat().st_mode & 0o777 == 0o644
    assert [p.name for p in out.iterdir()] == ["10-cathedral.network"]


@pytest.mark.parametrize("args", [
    ("eth0;x", "10.217.0.2/30", "10.217.0.1"),
    ("eth0", "10.217.0.2/33", "10.217.0.1"),
    ("eth0", "10.217.0.2", "10.217.0.1"),
    ("eth0", "10.217.0.2/30/1", "10.217.0.1"),
    ("eth0", "256.217.0.2/30", "10.217.0.1"),
    ("eth0", "10.217.0.2/30", "10.217.0"),
    ("eth0", "10.217.0.2/30", "10.217.0.1\nDNS=x"),
    ("eth0", "10.217.0.2/30"),
])
def test_write_network_refuses_any_other_shape_and_writes_nothing(tmp_path, args):
    script, out = _writer(tmp_path)
    r = subprocess.run(["sh", str(script), *args], capture_output=True, text=True)
    assert r.returncode == 2 and r.stderr.startswith("write-network: ")
    assert not out.exists() or not any(out.iterdir())
