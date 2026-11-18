"""AB#432: the hotel name is not in the measured guest image; the link is per hotel.

Two hotels of one build and one link share one measurement. These tests run
the build's config, room.env and command line steps for two names and
compare every measured input. The name reaches the guest through fw_cfg and
lands in the attested binding. The host/guest IP pair and the guest MAC come
from sealed.env (one /30 per guest, several guests per host), so a hotel on its own pair has
its own measurement, stable at every rebuild.
"""
from __future__ import annotations

import hashlib
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
SEALED = KIT / "sealed"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")


def _measured_inputs(tmp_path: Path, name: str, **overrides: str) -> tuple[dict[str, str], str]:
    """Run the build steps that write the guest config; return file digests and the cmdline."""
    text = (SEALED / "build-guest.sh").read_text()
    top = text[text.index('log() { echo "[sealed-build] $*"; }'):text.index("B=$SEALED_DIR/build")]
    config = text[text.index("ln -sfn usr/lib/systemd"):text.index('cat > "$R/etc/modules-load.d/sealed.conf"')]
    guard = text[text.index("DEBUG=0; [ -n"):text.index('cat > "$R/etc/systemd/system/sealed-guard.service"')]
    env = text[text.index('cat > "$R/opt/room-kit/room.env" <<EOF'):text.index("# Units: no logins")]
    cmd = text[text.index("CMDLINE="):text.index('printf \'%s\' "$CMDLINE"')]
    root = tmp_path / f"root-{name}"
    for d in ("opt/room-kit", "etc/systemd/network"):
        (root / d).mkdir(parents=True)
    script = tmp_path / f"slice-{name}.sh"
    # Same order as the real scripts: sealed.env values first, then the image constants.
    script.write_text("set -euo pipefail\n" + top + f'source "{SEALED}/guest-constants.sh"\n'
                      + config + guard + env + cmd + 'printf "%s" "$CMDLINE" > "$R/../cmdline-$SEALED_NAME"\n')
    values = {"R": str(root), "SEALED_NAME": name, "SEALED_ROOM_MAX_SLOTS": "1000", "SEALED_ROOM_NETS": "10.214.0.0/22",
              "SEALED_DEBUG_SSH_PUBKEY": "", **overrides}
    proc = subprocess.run([BASH, str(script)], capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", **values})
    assert proc.returncode == 0, proc.stderr
    digests = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}
    return digests, (tmp_path / f"cmdline-{name}").read_text()


def test_two_hotel_names_give_the_same_measured_inputs(tmp_path: Path) -> None:
    # DNS left in an older sealed.env is still ignored; the name never reaches the image.
    a_files, a_cmd = _measured_inputs(tmp_path, "hotel-a")
    b_files, b_cmd = _measured_inputs(tmp_path, "hotel-b", SEALED_DNS="9.9.9.9")
    assert a_cmd == b_cmd
    assert "hotel-a" not in a_cmd and "cathedral.hotel" not in a_cmd
    assert a_files == b_files, "name or DNS changed a measured file"
    assert {"etc/hostname", "etc/resolv.conf", "etc/sealed-guard.nft", "opt/room-kit/room.env"} <= set(a_files)
    for rel in ("etc/hostname", "etc/resolv.conf", "etc/sealed-guard.nft", "opt/room-kit/room.env",
                "etc/systemd/network/10-uplink.network", "etc/systemd/network/10-uplink.link"):
        assert "hotel-a" not in (tmp_path / "root-hotel-a" / rel).read_text()


def test_the_default_link_unset_or_explicit_gives_the_same_measured_inputs(tmp_path: Path) -> None:
    a_files, _ = _measured_inputs(tmp_path, "hotel-a")
    b_files, _ = _measured_inputs(tmp_path, "hotel-b", SEALED_HOST_IP="10.215.0.1", SEALED_GUEST_IP="10.215.0.2",
                                  SEALED_GUEST_MAC="52:54:00:5e:a1:ed")
    assert a_files == b_files


def test_a_per_hotel_link_is_measured_and_stable_per_hotel(tmp_path: Path) -> None:
    # Frankfurt runs four guests on one host, one /30 each (AB#432): nc-sealed-2 keeps 10.215.0.5/.6.
    link = {"SEALED_HOST_IP": "10.215.0.5", "SEALED_GUEST_IP": "10.215.0.6", "SEALED_GUEST_MAC": "52:54:00:5e:a1:ee"}
    default, _ = _measured_inputs(tmp_path, "hotel-a")
    once, cmd1 = _measured_inputs(tmp_path, "nc-sealed-2", **link)
    again, cmd2 = _measured_inputs(tmp_path, "renamed", **link)
    assert once == again and cmd1 == cmd2, "same kit and same link must give the same measured inputs"
    assert once != default
    changed = {k for k in once if once[k] != default[k]}
    assert changed == {"etc/systemd/network/10-uplink.network", "etc/systemd/network/10-uplink.link",
                       "etc/sealed-guard.nft", "opt/room-kit/room.env"}
    root = tmp_path / "root-nc-sealed-2"
    net = (root / "etc/systemd/network/10-uplink.network").read_text()
    assert "Address=10.215.0.6/30" in net and "Gateway=10.215.0.5" in net
    assert "ip saddr 10.215.0.5 tcp dport 18090 accept" in (root / "etc/sealed-guard.nft").read_text()
    assert "ROOM_RECEIPTS_LISTEN=10.215.0.6:18090" in (root / "opt/room-kit/room.env").read_text()
    assert "MACAddress=52:54:00:5e:a1:ee" in (root / "etc/systemd/network/10-uplink.link").read_text()


def _source_constants(**env: str) -> subprocess.CompletedProcess[str]:
    script = f'set -euo pipefail\nsource "{SEALED}/guest-constants.sh"\necho "$SEALED_HOST_IP $SEALED_GUEST_IP $SEALED_GUEST_MAC"'
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", **env})


@pytest.mark.parametrize("host_ip,guest_ip,nets", [
    ("", "", ""), ("10.215.0.5", "10.215.0.6", ""), ("10.231.78.5", "10.231.78.6", "10.214.0.0/22 10.214.4.0/22"),
    ("172.31.255.253", "172.31.255.254", ""), ("192.168.7.9", "192.168.7.10", ""),
    ("10.215.0.5", "10.215.0.6", "auto"), ("10.215.0.5", "10.215.0.6", "none")])
def test_the_link_accepts_a_private_slash_30_pair(host_ip: str, guest_ip: str, nets: str) -> None:
    proc = _source_constants(SEALED_HOST_IP=host_ip, SEALED_GUEST_IP=guest_ip, SEALED_ROOM_NETS=nets)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ([host_ip, guest_ip] if host_ip else ["10.215.0.1", "10.215.0.2"]) + ["52:54:00:5e:a1:ed"]


def test_the_mac_follows_sealed_env_so_an_older_image_finds_its_uplink() -> None:
    # Live hotels before #467 took the MAC from sealed.env (nc-sealed-2 52:54:00:5e:a1:ee). A rollback
    # starts that image with the new launch-guest.sh, whose QEMU MAC must still match its .link file.
    proc = _source_constants(SEALED_HOST_IP="10.215.0.5", SEALED_GUEST_IP="10.215.0.6", SEALED_GUEST_MAC="52:54:00:5e:a1:ee")
    assert proc.returncode == 0 and proc.stdout.split()[2] == "52:54:00:5e:a1:ee"
    assert "mac=$SEALED_GUEST_MAC" in (SEALED / "launch-guest.sh").read_text()


@pytest.mark.parametrize("mac", ["52:54:00:5E:A1:EE", "53:54:00:5e:a1:ee", "52:54:00:5e:a1", "52-54-00-5e-a1-ee", "52:54:00:5e:a1:ee;x"])
def test_the_link_refuses_a_bad_mac(mac: str) -> None:
    proc = _source_constants(SEALED_GUEST_MAC=mac)
    assert proc.returncode == 1 and "SEALED_GUEST_MAC" in proc.stderr


@pytest.mark.parametrize("host_ip,guest_ip,nets,message", [
    ("10.215.0.5", "", "", "set both"),
    ("", "10.215.0.6", "", "set both"),
    ("10.215.0.4", "10.215.0.5", "", "one /30"),
    ("10.215.0.5", "10.215.0.7", "", "one /30"),
    ("10.215.0.6", "10.215.0.5", "", "one /30"),
    ("198.51.100.1", "198.51.100.2", "", "must be in 10.0.0.0/8"),
    ("172.32.0.1", "172.32.0.2", "", "must be in 10.0.0.0/8"),  # leak-guard: allow (first address past 172.16.0.0/12)
    ("10.213.1.1", "10.213.1.2", "", "overlaps 10.213.0.0/21"),
    ("10.201.0.1", "10.201.0.2", "", "overlaps 10.200.0.0/14"),
    ("10.214.4.5", "10.214.4.6", "10.214.0.0/22 10.214.4.0/22", "overlaps 10.214.4.0/22"),
    ("10.214.200.1", "10.214.200.2", "auto", "overlaps 10.214.0.0/16"),
    ("10.0.0.1", "10.0.0.2", "10.0.0.0/8", "overlaps 10.0.0.0/8"),
    ("10.215.0.256", "10.215.0.257", "", "IPv4 addresses"),
    ("010.215.0.5", "010.215.0.6", "", "IPv4 addresses"),
    ("10.215.0.5 ", "10.215.0.6", "", "IPv4 addresses"),
    ("10.215.0.5;x", "10.215.0.6", "", "IPv4 addresses"),
])
def test_the_link_refuses_a_bad_pair(host_ip: str, guest_ip: str, nets: str, message: str) -> None:
    proc = _source_constants(SEALED_HOST_IP=host_ip, SEALED_GUEST_IP=guest_ip, SEALED_ROOM_NETS=nets)
    assert proc.returncode == 1 and proc.stdout == ""
    assert message in proc.stderr


def test_image_constants_are_the_old_defaults() -> None:
    text = (SEALED / "guest-constants.sh").read_text()
    for line in ("SEALED_HOST_IP=${SEALED_HOST_IP:-10.215.0.1}", "SEALED_GUEST_IP=${SEALED_GUEST_IP:-10.215.0.2}",
                 "SEALED_GUEST_MAC=${SEALED_GUEST_MAC:-52:54:00:5e:a1:ed}", 'SEALED_DNS="1.1.1.1 8.8.8.8"'):
        assert line in text
    for script in ("build-guest.sh", "launch-guest.sh", "host-net.sh", "install-sealed.sh"):
        assert "guest-constants.sh" in (SEALED / script).read_text(), script
    example = (SEALED / "sealed.env.example").read_text()
    assert "\nSEALED_GUEST_IP=" not in example and "#SEALED_GUEST_IP=10.215.0.2" in example


def _manifest(tmp_path: Path, **link: str) -> dict:
    text = (SEALED / "build-guest.sh").read_text()
    py = text[text.index("<<'EOF'\nimport hashlib, json, os, sys") + len("<<'EOF'\n"):]
    py = py[:py.index("\nEOF\n")]
    out = tmp_path / ("img-" + "-".join(link.values()))
    out.mkdir()
    for f in ("OVMF.amdsev.fd", "vmlinuz", "initrd.cpio.zst"):
        (out / f).write_bytes(f.encode())
    (out / "cmdline").write_text("console=ttyS0")
    args = [str(out), "4", "EPYC-v4", "6.8", "0", "base", "0", "", "", "",
            link.get("host", "10.215.0.1"), link.get("guest", "10.215.0.2")]
    subprocess.run(["python3", "-c", py, *args], check=True, timeout=30)
    import json
    return json.loads((out / "manifest.json").read_text())


def test_the_manifest_names_only_a_per_hotel_link(tmp_path: Path) -> None:
    # A default hotel's manifest (its HOST_DATA) is unchanged; a per-hotel pair is named.
    assert "link" not in _manifest(tmp_path)
    assert _manifest(tmp_path, host="10.215.0.5", guest="10.215.0.6")["link"] == {"host_ip": "10.215.0.5", "guest_ip": "10.215.0.6"}


def test_manifest_has_no_hotel_name() -> None:
    text = (SEALED / "build-guest.sh").read_text()
    assert '"hotel": name' not in text and '"$SEALED_NAME"' not in text[text.index("python3 - "):]


def test_launch_passes_the_name_in_fw_cfg_and_checks_it() -> None:
    text = (SEALED / "launch-guest.sh").read_text()
    assert 'FW_CFG+=(-fw_cfg "name=opt/cathedral/hotel-name,string=$SEALED_NAME")' in text
    assert "SEALED_NAME must match" in text
    assert text.index("SEALED_NAME must match") < text.index("exec /usr/bin/qemu-system-x86_64")


def _read_hotel_name(tmp_path: Path, content: bytes | None) -> subprocess.CompletedProcess[str]:
    text = (SEALED / "guest-boot.sh").read_text()
    start = text.index("read_hotel_name() {")
    func = text[start:text.index("\n}\n", start) + 3]
    path = tmp_path / "hotel-name"
    path.unlink(missing_ok=True)
    if content is not None:
        path.write_bytes(content)
    script = f'log() {{ echo "$*" >&2; }}\nsleep() {{ :; }}\n{func}\nread_hotel_name "{path}"\n'
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30)


def test_guest_boot_reads_and_exports_the_name_before_install() -> None:
    text = (SEALED / "guest-boot.sh").read_text()
    assert "ROOM_HOTEL_NAME=$(read_hotel_name /sys/firmware/qemu_fw_cfg/by_name/opt/cathedral/hotel-name/raw)" in text
    assert text.index("export ROOM_HOTEL_NAME") < text.index("/opt/room-kit/install.sh /opt/room-kit/room.env")


@pytest.mark.parametrize("raw", [b"hotel-a", b"hotel-a\n", b"c46-sealed", b"a" * 59])
def test_guest_boot_accepts_a_valid_name(tmp_path: Path, raw: bytes) -> None:
    proc = _read_hotel_name(tmp_path, raw)
    assert proc.returncode == 0 and proc.stdout == raw.decode().strip()


@pytest.mark.parametrize("raw", [None, b"", b"Hotel", b"-a", b"a b", b"a;rm", b"a" * 60, b"a" * 64, b"a\nb"])
def test_guest_boot_fails_closed_without_a_valid_name(tmp_path: Path, raw: bytes | None) -> None:
    proc = _read_hotel_name(tmp_path, raw)
    assert proc.returncode == 1 and proc.stdout == ""
    assert "refusing to start" in proc.stderr


def test_the_name_lands_in_the_attested_binding(tmp_path: Path, monkeypatch) -> None:
    spec = importlib.util.spec_from_file_location("room_receipts_ab432", KIT / "room_receipts.py")
    rr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rr)
    import test_room_kit_dedicated_owner as owner  # fake SNP report helper

    machine = owner.Machine(tmp_path, monkeypatch, owner=False)
    monkeypatch.setattr(owner.rr, "snp_report", owner._fake_snp(machine.host_data))
    a = owner.rr.Ledger("hotel-a", str(tmp_path / "sa"))
    b = owner.rr.Ledger("hotel-b", str(tmp_path / "sb"))
    assert a.binding["hotel"] == "hotel-a" and b.binding["hotel"] == "hotel-b"
    assert a.binding["measurement"] == b.binding["measurement"]
    assert a.binding_sha256 != b.binding_sha256
    assert a.report[0x50:0x70] == bytes.fromhex(a.binding_sha256)


def _launch_name_check(name: str) -> subprocess.CompletedProcess[str]:
    line = next(l for l in (SEALED / "launch-guest.sh").read_text().splitlines() if l.startswith('[[ "${SEALED_NAME:-}"'))
    return subprocess.run([BASH, "-c", f"set -euo pipefail\nSEALED_NAME={name}\n{line}\necho ok"], capture_output=True, text=True, timeout=30)


def test_launch_accepts_a_59_byte_name_and_refuses_60() -> None:
    ok = _launch_name_check("a" * 59)
    assert ok.returncode == 0 and ok.stdout.strip() == "ok"
    bad = _launch_name_check("a" * 60)
    assert bad.returncode == 1 and "SEALED_NAME must match" in bad.stderr


def test_a_59_byte_name_gives_a_hostname_within_the_limit() -> None:
    assert len("room-" + "a" * 59) == 64


def test_install_checks_the_name_cap_before_the_build() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    assert "{0,58}$" in text and "{0,62}" not in text
    assert text.index("SEALED_NAME must match") < text.index("\"$KIT/sealed/build-guest.sh\"")
