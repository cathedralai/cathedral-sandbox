#!/usr/bin/env python3
"""Build the REHEARSAL-ONLY stock-systemd root (AB#1008, AB#1027): the reference root recipe
(scripts/build_custom_guest_root.py) on a base with dbus and udev, then customize(), which
turns the guest network over to systemd-networkd. Never offered to customers.

customize() changes only what networkd needs and keeps the rest of the recipe byte for byte
(cathedral-attest, the sshd config and unit, every other mask):
- networkd's service and socket are unmasked and enabled, as "systemctl enable" links them;
- cathedral-network.service keeps its name (cathedral-sshd.service requires it) but now runs
  /usr/lib/cathedral/write-network, which writes /run/systemd/network/10-cathedral.network
  from the three network.env values, before networkd starts;
- 99-default.link is masked: udev keeps the interface name network.env gives (eth0);
- dbus.socket and udev's sockets and coldplug trigger are enabled if the packages did not;
- /var/lib/systemd/linger ships empty: with dbus present logind starts, and on the read-only
  root systemd cannot create its StateDirectory (238/STATE_DIRECTORY, seen in the boot smoke).

check_stock_root.py checks the result. Usage, as the reference recipe without the data disk:
  stock_systemd.py --base BASE.TAR --base-sha256 SHA --helper ATTEST --helper-sha256 SHA \\
      --epoch N --output ROOT.RAW
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("custom_root_recipe", REPO / "scripts" / "build_custom_guest_root.py")
recipe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(recipe)

ETC = "etc/systemd/system"
LIB = "usr/lib/systemd/system"
VENDOR = "/lib/systemd/system"   # where Debian's systemctl points enable links
WRITER = "usr/lib/cathedral/write-network"

NETWORK_UNIT = '''[Unit]
Description=Write the init-validated custom guest network for systemd-networkd
DefaultDependencies=no
Before=systemd-networkd.service cathedral-sshd.service shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
EnvironmentFile=/run/cathedral/network.env
ExecStart=/usr/lib/cathedral/write-network ${CATHEDRAL_INTERFACE} ${CATHEDRAL_GUEST_CIDR} ${CATHEDRAL_GATEWAY}
RemainAfterExit=yes
'''

NETWORKD_DROPIN = '''[Unit]
Wants=cathedral-network.service
After=cathedral-network.service
'''

# systemd passes each ${CATHEDRAL_*} as one argv word, so the values are never shell text.
# They are the measured init's validated values; this refuses any other shape anyway.
WRITE_NETWORK = r'''#!/bin/sh
# Write the guest network for systemd-networkd (REHEARSAL-ONLY stock-systemd root).
# Usage: write-network INTERFACE ADDRESS/PREFIX GATEWAY, from /run/cathedral/network.env.
set -eu
die() { echo "write-network: $*" >&2; exit 2; }
[ "$#" -eq 3 ] || die "want INTERFACE ADDRESS/PREFIX GATEWAY"
iface=$1 cidr=$2 gateway=$3
quad() {
  case $1 in ''|*[!0-9.]*|.*|*.|*..*) return 1 ;; esac
  saved=$IFS; IFS=.; set -- $1; IFS=$saved
  [ "$#" -eq 4 ] || return 1
  for octet in "$@"; do
    [ "${#octet}" -le 3 ] && [ "$octet" -le 255 ] || return 1
  done
}
case $iface in ''|*[!a-z0-9]*) die "bad interface" ;; esac
[ "${#iface}" -le 15 ] || die "bad interface"
case $cidr in */*/*|*/) die "bad address" ;; */*) ;; *) die "bad address" ;; esac
prefix=${cidr#*/}
case $prefix in ''|*[!0-9]*) die "bad prefix" ;; esac
[ "${#prefix}" -le 2 ] && [ "$prefix" -ge 1 ] && [ "$prefix" -le 32 ] || die "bad prefix"
quad "${cidr%/*}" || die "bad address"
quad "$gateway" || die "bad gateway"
umask 022
dir=/run/systemd/network
mkdir -p "$dir"
tmp=$(mktemp "$dir/.10-cathedral.network.XXXXXX")
printf '[Match]\nName=%s\n\n[Link]\nRequiredForOnline=yes\n\n[Network]\nAddress=%s\nGateway=%s\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n' \
  "$iface" "$cidr" "$gateway" > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$dir/10-cathedral.network"
'''


def _require_file(root, name):
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("stock-systemd base is missing " + name)


def _wanted(root, unit, target):
    return any((root / unit_dir / f"{target}.wants" / unit).is_symlink() for unit_dir in (ETC, LIB))


def _enable(root, unit, target):
    """Link TARGET.wants/UNIT in etc unless the package already did (etc or usr/lib)."""
    _require_file(root, f"{LIB}/{unit}")
    if not _wanted(root, unit, target):
        recipe.link(root, f"{ETC}/{target}.wants/{unit}", f"{VENDOR}/{unit}")


def customize(root):
    root = Path(root)
    for name in ("usr/bin/dbus-daemon", f"{LIB}/dbus.service", f"{LIB}/dbus.socket",
                 f"{LIB}/systemd-udevd.service", f"{LIB}/systemd-networkd.service", f"{LIB}/systemd-networkd.socket"):
        _require_file(root, name)
    for unit in ("systemd-networkd.service", "systemd-networkd.socket"):
        path = root / ETC / unit
        if not path.is_symlink() or os.readlink(path) != "/dev/null":
            raise ValueError("the reference recipe no longer masks " + unit)
        path.unlink()
    # As "systemctl enable systemd-networkd" links it ([Install] of the unit: WantedBy,
    # Also=systemd-networkd.socket, Alias=dbus-org.freedesktop.network1.service).
    recipe.link(root, f"{ETC}/multi-user.target.wants/systemd-networkd.service", f"{VENDOR}/systemd-networkd.service")
    recipe.link(root, f"{ETC}/sockets.target.wants/systemd-networkd.socket", f"{VENDOR}/systemd-networkd.socket")
    recipe.link(root, f"{ETC}/dbus-org.freedesktop.network1.service", f"{VENDOR}/systemd-networkd.service")
    recipe.write(root, f"{ETC}/cathedral-network.service", NETWORK_UNIT)
    recipe.write(root, f"{ETC}/systemd-networkd.service.d/10-cathedral.conf", NETWORKD_DROPIN)
    recipe.write(root, WRITER, WRITE_NETWORK, 0o755)
    recipe.link(root, "etc/systemd/network/99-default.link", "/dev/null")
    _enable(root, "dbus.socket", "sockets.target")
    _enable(root, "systemd-udevd-kernel.socket", "sockets.target")
    _enable(root, "systemd-udevd-control.socket", "sockets.target")
    _enable(root, "systemd-udev-trigger.service", "sysinit.target")
    # logind's StateDirectory=systemd/linger. An existing 0755 root directory needs no write at
    # boot (systemd's setup_exec_directory then only checks it); a missing one fails logind.
    linger = root / "var/lib/systemd/linger"
    if linger.parent.is_symlink() or not linger.parent.is_dir():
        raise ValueError("stock-systemd base is missing var/lib/systemd")
    if linger.is_symlink() or not linger.parent.resolve().is_relative_to(root.resolve()) \
            or (linger.exists() and not linger.is_dir()):
        raise ValueError("var/lib/systemd/linger must be a plain directory inside the root")
    linger.mkdir(mode=0o755, exist_ok=True)
    linger.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--base-sha256", required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--helper-sha256", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(recipe.build(args.base, args.base_sha256, args.helper, args.helper_sha256,
                                  args.epoch, args.output, customize=customize), sort_keys=True))


if __name__ == "__main__":
    main()
