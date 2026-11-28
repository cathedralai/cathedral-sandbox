#!/usr/bin/env python3
"""Check that a rehearsal root boots stock systemd networking: dbus, udev and networkd
enabled, the guest network written at boot, cathedral-attest and the sshd rules kept.

REHEARSAL-ONLY (AB#1008, AB#1027), never offered to customers. Run 7 needs a root in which
reference initrd v2 can show dbus and networkd active. The v1 rehearsal root has no dbus and
masks networkd (scripts/build_custom_guest_root.py), so it must fail here.

Two facts of systemd 252 (the Debian bookworm base) shape the rules:
- With /sys read-write, as v2 hands it to the root, networkd waits for udev to initialize
  each link (src/shared/udev-util.c udev_available, src/network/networkd-link.c). A root with
  networkd and no udevd leaves eth0 pending: no address, no SSH.
- udev renames interfaces by its 99-default.link policy, but network.env names the interface
  the initrd saw. So the root masks 99-default.link and keeps the kernel name.

  check_stock_root.py ROOT.RAW      extract the squashfs (unsquashfs) and check it
  check_stock_root.py --tree DIR    check an extracted root

Links are resolved the way a chroot would: an absolute target is read inside the root, and
nothing outside the root is ever read. One "ROOTCHECK: FAIL <path>: <reason>" line per
problem, then exit 1; or one "ROOTCHECK: PASS" line and exit 0.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[3]
ETC = "etc/systemd/system"
LIB = "usr/lib/systemd/system"
UNIT_DIRS = (ETC, LIB)
# The cathedral-attest of reference-build run 46063612613, which reference initrd v1 and v2
# pin (build-ref-root.sh ATTEST_SHA256).
ATTEST_SHA256 = "44824e132fc3529c0aff01ba1f2a093d2844beb82a3478613a26b11f012f4f29"
WRITER = "/usr/lib/cathedral/write-network"
WRITER_EXEC = f"ExecStart={WRITER} ${{CATHEDRAL_INTERFACE}} ${{CATHEDRAL_GUEST_CIDR}} ${{CATHEDRAL_GATEWAY}}"
# The reference recipe's masks that a stock-systemd root keeps: only networkd's two units
# are unmasked.
KEPT_MASKS = ("ssh.service", "sshd.service", "ssh.socket", "getty@.service", "serial-getty@.service",
              "console-getty.service", "container-getty@.service", "console-shell.service",
              "rescue.service", "emergency.service", "getty.target", "debug-shell.service",
              "systemd-firstboot.service", "networking.service", "apt-daily.timer",
              "apt-daily-upgrade.timer", "systemd-networkd-wait-online.service")
# The units this root's boot rests on: none may require a masked unit (B5, #833).
NAMED_UNITS = ("dbus.service", "dbus.socket", "systemd-udevd.service", "systemd-networkd.service",
               "systemd-networkd.socket", "cathedral-network.service", "cathedral-sshd.service")
HARD_DEPS = ("Requires", "BindsTo", "Requisite")


def recipe():
    spec = importlib.util.spec_from_file_location("custom_root_recipe", REPO / "scripts" / "build_custom_guest_root.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve(root, name, limit=40):
    """The real path of NAME inside ROOT, links followed as in a chroot: an absolute target
    starts again at ROOT and ".." stops at ROOT. None when it is missing, a parent is not a
    directory, or the links loop."""
    parts = [p for p in PurePosixPath(name).parts if p != "/"]
    done, hops = [], 0
    while parts:
        part = parts.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if done:
                done.pop()
            continue
        here = Path(root, *done, part)
        try:
            st = here.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            hops += 1
            if hops > limit:
                return None
            target = os.readlink(here)
            if target.startswith("/"):
                done = []
            parts = [p for p in PurePosixPath(target).parts if p != "/"] + parts
            continue
        if parts and not stat.S_ISDIR(st.st_mode):
            return None
        done.append(part)
    return Path(root, *done)


def regular(root, name):
    path = resolve(root, name)
    return path if path is not None and stat.S_ISREG(path.lstat().st_mode) else None


def read(root, name):
    path = regular(root, name)
    return path.read_bytes() if path else None


def link_target(path):
    try:
        return os.readlink(path) if stat.S_ISLNK(path.lstat().st_mode) else None
    except OSError:
        return None


def masked(root, unit):
    """The unit directory where UNIT is a link to /dev/null, or None."""
    for unit_dir in UNIT_DIRS:
        if link_target(Path(root, unit_dir, unit)) == "/dev/null":
            return unit_dir
    return None


def unit_file(root, unit):
    """The unit file systemd loads for UNIT (etc before usr/lib), or None."""
    for unit_dir in UNIT_DIRS:
        if link_target(Path(root, unit_dir, unit)) == "/dev/null":
            return None
        path = regular(root, f"{unit_dir}/{unit}")
        if path:
            return path
    return None


def enabled(root, unit, target):
    """True when TARGET.wants/UNIT (etc or usr/lib) leads to a unit file in the root."""
    for unit_dir in UNIT_DIRS:
        want = Path(root, unit_dir, f"{target}.wants", unit)
        try:
            want.lstat()
        except OSError:
            continue
        if regular(root, f"{unit_dir}/{target}.wants/{unit}"):
            return True
    return False


def unit_text(root, unit):
    """The unit file and its drop-ins, in load order, as text."""
    texts = []
    path = unit_file(root, unit)
    if path:
        texts.append(path.read_text(errors="replace"))
    for unit_dir in reversed(UNIT_DIRS):
        drop = resolve(root, f"{unit_dir}/{unit}.d")
        if drop is None or not stat.S_ISDIR(drop.lstat().st_mode):
            continue
        for conf in sorted(drop.iterdir()):
            if conf.name.endswith(".conf"):
                data = read(root, f"{unit_dir}/{unit}.d/{conf.name}")
                if data is not None:
                    texts.append(data.decode(errors="replace"))
    return "\n".join(texts)


def directive(text, key):
    """Every value of KEY= in TEXT, split into words."""
    words = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(key + "="):
            words.extend(line.split("=", 1)[1].split())
    return words


def users(root):
    data = read(root, "etc/passwd") or b""
    return {line.split(":", 1)[0] for line in data.decode(errors="replace").splitlines() if ":" in line}


def elf(root, name):
    path = regular(root, name)
    return bool(path) and path.read_bytes()[:4] == b"\x7fELF"


def problems(root, attest_sha256=ATTEST_SHA256):
    root = Path(root)
    out = []
    fail = out.append
    accounts = users(root)

    # dbus: the system bus, socket-activated at boot.
    if not elf(root, "usr/bin/dbus-daemon"):
        fail("usr/bin/dbus-daemon: missing, so there is no system bus")
    for unit in ("dbus.service", "dbus.socket"):
        where = masked(root, unit)
        if where:
            fail(f"{where}/{unit}: masked")
        elif unit_file(root, unit) is None:
            fail(f"{LIB}/{unit}: missing")
    if not enabled(root, "dbus.socket", "sockets.target"):
        fail("sockets.target.wants/dbus.socket: missing, so the system bus does not start at boot")
    if "messagebus" not in accounts:
        fail("etc/passwd: no messagebus user for dbus-daemon")

    # udev: networkd waits for it once /sys is read-write.
    if not elf(root, "usr/lib/systemd/systemd-udevd"):
        fail("usr/lib/systemd/systemd-udevd: missing, so networkd leaves every link pending udev")
    for unit in ("systemd-udevd.service", "systemd-udevd-kernel.socket", "systemd-udevd-control.socket",
                 "systemd-udev-trigger.service"):
        where = masked(root, unit)
        if where:
            fail(f"{where}/{unit}: masked")
        elif unit_file(root, unit) is None:
            fail(f"{LIB}/{unit}: missing")
    if not enabled(root, "systemd-udevd-kernel.socket", "sockets.target"):
        fail("sockets.target.wants/systemd-udevd-kernel.socket: missing, so udevd does not start at boot")
    # eth0 appeared before udevd started: only the coldplug trigger gives it a udev entry.
    if not enabled(root, "systemd-udev-trigger.service", "sysinit.target"):
        fail("sysinit.target.wants/systemd-udev-trigger.service: missing, so links present at boot stay pending udev")
    if link_target(root / "etc/systemd/network/99-default.link") != "/dev/null":
        fail("etc/systemd/network/99-default.link: not masked, so udev may rename the interface network.env names")

    # networkd: enabled, with its user.
    for unit, target in (("systemd-networkd.service", "multi-user.target"), ("systemd-networkd.socket", "sockets.target")):
        where = masked(root, unit)
        if where:
            fail(f"{where}/{unit}: masked")
        elif unit_file(root, unit) is None:
            fail(f"{LIB}/{unit}: missing")
        elif not enabled(root, unit, target):
            fail(f"{target}.wants/{unit}: missing, so {unit} is not enabled")
    if "systemd-network" not in accounts:
        fail("etc/passwd: no systemd-network user for networkd")

    # The guest network: written at boot from network.env, before networkd reads it.
    network = unit_text(root, "cathedral-network.service")
    if WRITER_EXEC not in network.splitlines():
        fail(f"{ETC}/cathedral-network.service: does not run {WRITER} with the three network.env values")
    if "EnvironmentFile=/run/cathedral/network.env" not in network.splitlines():
        fail(f"{ETC}/cathedral-network.service: does not read /run/cathedral/network.env")
    if "systemd-networkd.service" not in directive(network, "Before"):
        fail(f"{ETC}/cathedral-network.service: not Before=systemd-networkd.service")
    writer = regular(root, WRITER)
    if writer is None or not writer.lstat().st_mode & 0o111:
        fail(f"{WRITER.lstrip('/')}: missing or not executable")
    networkd = unit_text(root, "systemd-networkd.service")
    for key in ("Wants", "After"):
        if "cathedral-network.service" not in directive(networkd, key):
            fail(f"{ETC}/systemd-networkd.service.d: no {key}=cathedral-network.service, so networkd may start before its config")
    baked = resolve(root, "etc/systemd/network")
    if baked is not None and stat.S_ISDIR(baked.lstat().st_mode):
        for path in sorted(baked.iterdir()):
            if path.name.endswith(".network"):
                fail(f"etc/systemd/network/{path.name}: a .network in the image; the guest network is written at boot")

    # Kept: the report helper the initrd pins, and the sshd rules.
    attest = read(root, "usr/bin/cathedral-attest")
    if attest is None or hashlib.sha256(attest).hexdigest() != attest_sha256:
        fail(f"usr/bin/cathedral-attest: not {attest_sha256}")
    if read(root, "usr/share/cathedral/report-helper.sha256") != (attest_sha256 + "\n").encode():
        fail("usr/share/cathedral/report-helper.sha256: not the pinned helper digest")
    reference = recipe()
    if read(root, "etc/ssh/cathedral_sshd_config") != reference.SSH_CONFIG.encode():
        fail("etc/ssh/cathedral_sshd_config: differs from the reference recipe's")
    if read(root, f"{ETC}/cathedral-sshd.service") != reference.SSH_UNIT.encode():
        fail(f"{ETC}/cathedral-sshd.service: differs from the reference recipe's")
    if not enabled(root, "cathedral-sshd.service", "multi-user.target"):
        fail("multi-user.target.wants/cathedral-sshd.service: missing")
    for unit in KEPT_MASKS:
        if link_target(root / ETC / unit) != "/dev/null":
            fail(f"{ETC}/{unit}: not masked")

    # No unit this boot rests on may require a masked unit: systemd drops the requirer.
    for unit_dir in UNIT_DIRS:
        base = resolve(root, unit_dir)
        if base is None or not stat.S_ISDIR(base.lstat().st_mode):
            continue
        for dep in sorted(base.iterdir()):
            if not dep.name.endswith(".requires") or stat.S_ISLNK(dep.lstat().st_mode) or not dep.is_dir():
                continue
            for link in sorted(dep.iterdir()):
                if masked(root, link.name):
                    fail(f"{unit_dir}/{dep.name}/{link.name}: {dep.name[:-9]} requires {link.name}, which is masked")
    for unit in NAMED_UNITS:
        text = unit_text(root, unit)
        for key in HARD_DEPS:
            for dep in directive(text, key):
                if masked(root, dep):
                    fail(f"{unit}: {key}={dep}, which is masked")
    return out


def extract(image, dest):
    subprocess.run(["unsquashfs", "-no-progress", "-no-xattrs", "-d", str(dest), str(image)],
                   check=True, stdout=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def writable(tree):
    """Let the temp dir go: an extracted root keeps modes such as 0555 directories."""
    for top, dirs, _ in os.walk(tree, followlinks=False):
        for name in dirs:
            path = Path(top, name)
            if not path.is_symlink():
                path.chmod(0o700)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("image", nargs="?", type=Path, help="root.raw (squashfs, verity tree after it)")
    group.add_argument("--tree", type=Path, help="an extracted root")
    parser.add_argument("--attest-sha256", default=ATTEST_SHA256, help="the cathedral-attest the initrd pins")
    args = parser.parse_args()
    if args.tree:
        found = problems(args.tree, args.attest_sha256)
    else:
        with tempfile.TemporaryDirectory(prefix="stock-root-check-") as temp:
            tree = Path(temp) / "root"
            extract(args.image, tree)
            try:
                found = problems(tree, args.attest_sha256)
            finally:
                writable(tree)
                shutil.rmtree(tree)
    for line in found:
        print(f"ROOTCHECK: FAIL {line}")
    if found:
        return 1
    print("ROOTCHECK: PASS dbus, udev and networkd enabled; the guest network written at boot; "
          "cathedral-attest and the sshd rules kept")
    return 0


if __name__ == "__main__":
    sys.exit(main())
