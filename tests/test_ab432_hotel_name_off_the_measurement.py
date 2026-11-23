"""AB#432: no per-hotel setting is in the measured guest image.

Two hotels of one build share one measurement. These tests run the build's
config, guard, room.env and command line steps for two hotels and compare
every measured input. The name reaches the guest through fw_cfg and lands in
the attested binding. The host/guest IP pair (one /30 per guest, several guests
per host) reaches the guest through fw_cfg too (opt/cathedral/link); the guest
checks it with guest-constants.sh and writes the .network file, the guard and the
listen addresses under /run. The guest MAC is only on the QEMU command line.
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
    assert {"etc/hostname", "etc/resolv.conf", "etc/sealed-guard.nft", "opt/room-kit/room.env",
            "etc/systemd/network/10-uplink.link"} <= set(a_files)
    for rel in ("etc/hostname", "etc/resolv.conf", "etc/sealed-guard.nft", "opt/room-kit/room.env",
                "etc/systemd/network/10-uplink.link"):
        assert "hotel-a" not in (tmp_path / "root-hotel-a" / rel).read_text()


def test_the_default_link_unset_or_explicit_gives_the_same_measured_inputs(tmp_path: Path) -> None:
    a_files, _ = _measured_inputs(tmp_path, "hotel-a")
    b_files, _ = _measured_inputs(tmp_path, "hotel-b", SEALED_HOST_IP="10.215.0.1", SEALED_GUEST_IP="10.215.0.2",
                                  SEALED_GUEST_MAC="52:54:00:5e:a1:ed")
    assert a_files == b_files


NC2 = {"SEALED_HOST_IP": "10.215.0.5", "SEALED_GUEST_IP": "10.215.0.6", "SEALED_GUEST_MAC": "52:54:00:5e:a1:ee"}
NC3 = {"SEALED_HOST_IP": "10.215.0.9", "SEALED_GUEST_IP": "10.215.0.10", "SEALED_GUEST_MAC": "52:54:00:5e:a1:ef"}
INGRESS = {"SEALED_ROOM_GUEST_INGRESS": "1", "SEALED_INGRESS_ZONE": "rooms.example.com",
           "SEALED_INGRESS_BROKER_URL": "https://broker.example.com"}
MINER = {"SEALED_MINER": "1", "SEALED_HOTEL_KEY_INSTALL_SIGNERS": "A" * 43 + "="}


@pytest.mark.parametrize("extra", [{}, INGRESS, MINER, {**INGRESS, **MINER}], ids=["config", "ingress", "miner", "both"])
def test_two_hotels_on_one_host_with_their_own_links_share_the_measured_inputs(tmp_path: Path, extra: dict) -> None:
    # Frankfurt runs several guests on one host, one /30 each: nc-sealed-2 10.215.0.5/.6, nc-sealed-3 .9/.10.
    # Two ingress hotels on one host forward two public ports (nc-sealed-2 8444): per hotel too.
    port2 = {"SEALED_INGRESS_PUBLIC_PORT": "8444"} if extra.get("SEALED_INGRESS_ZONE") else {}
    port3 = {"SEALED_INGRESS_PUBLIC_PORT": "8445"} if extra.get("SEALED_INGRESS_ZONE") else {}
    nc2, cmd2 = _measured_inputs(tmp_path, "nc-sealed-2", **NC2, **extra, **port2)
    nc3, cmd3 = _measured_inputs(tmp_path, "nc-sealed-3", **NC3, **extra, **port3)
    default, cmd_default = _measured_inputs(tmp_path, "hotel-a", **extra)
    assert nc2 == nc3 == default and cmd2 == cmd3 == cmd_default, "a per-hotel link changed a measured file"
    for name in ("nc-sealed-2", "nc-sealed-3", "hotel-a"):
        root = tmp_path / f"root-{name}"
        text = "".join(p.read_text() for p in root.rglob("*") if p.is_file())
        for value in ("10.215.0.", "52:54:00", "8444", "8445", name):
            assert value not in text, f"{value} in the measured files of {name}"
    root = tmp_path / "root-nc-sealed-2"
    assert not (root / "etc/systemd/network/10-uplink.network").exists()
    assert "Driver=virtio_net" in (root / "etc/systemd/network/10-uplink.link").read_text()
    assert "ip saddr @SEALED_HOST_IP@ tcp dport 18090 accept" in (root / "etc/sealed-guard.nft").read_text()
    env = (root / "opt/room-kit/room.env").read_text()
    assert "ROOM_RECEIPTS_LISTEN=${SEALED_LINK_GUEST_IP:?}:18090\n" in env
    if extra.get("SEALED_INGRESS_ZONE"):
        assert "ROOM_INGRESS_TLS_LISTEN=${SEALED_LINK_GUEST_IP:?}:8443\n" in env
        assert "ROOM_INGRESS_PUBLIC_PORT=${SEALED_LINK_INGRESS_PUBLIC_PORT:?}\n" in env
    if extra.get("SEALED_MINER"):
        assert "ROOM_RECEIPTS_TLS_LISTEN=${SEALED_LINK_GUEST_IP:?}:18443\n" in env


def test_a_debug_build_takes_the_ssh_listen_address_from_the_link() -> None:
    text = (SEALED / "build-guest.sh").read_text()
    debug = text[text.index("if [ $DEBUG = 1 ]; then\n  install -d"):text.index("# Host keys made at build time")]
    assert "SEALED_GUEST_IP" not in debug and "ListenAddress" not in debug.split("# ListenAddress")[0]
    assert 'ln -sfn /run/sealed-link/sshd-listen.conf "$R/etc/ssh/sshd_config.d/11-sealed-listen.conf"' in debug


def _resolve_room_env(tmp_path: Path, guest_ip: str | None, **extra: str) -> subprocess.CompletedProcess[str]:
    _measured_inputs(tmp_path, "nc-sealed-3", **NC3, **extra)
    env = tmp_path / "root-nc-sealed-3/opt/room-kit/room.env"
    script = (f'set -euo pipefail\nsource "{env}"\n'
              'echo "$ROOM_RECEIPTS_LISTEN ${ROOM_INGRESS_TLS_LISTEN:-} ${ROOM_INGRESS_PUBLIC_PORT:-} ${ROOM_RECEIPTS_TLS_LISTEN:-}"')
    run_env = {"PATH": "/usr/bin:/bin", "SEALED_LINK_INGRESS_PUBLIC_PORT": "8445",
               **({"SEALED_LINK_GUEST_IP": guest_ip} if guest_ip else {})}
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30, env=run_env)


def test_the_measured_room_env_resolves_the_listen_addresses_from_the_link(tmp_path: Path) -> None:
    proc = _resolve_room_env(tmp_path, "10.215.0.10", **INGRESS, **MINER)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["10.215.0.10:18090", "10.215.0.10:8443", "8445", "10.215.0.10:18443"]


def test_the_measured_room_env_stops_the_install_without_a_link(tmp_path: Path) -> None:
    proc = _resolve_room_env(tmp_path, None)
    assert proc.returncode != 0 and "SEALED_LINK_GUEST_IP" in proc.stderr


def _guest_link(tmp_path: Path, raw: bytes | None, nets: str = "10.214.0.0/22", debug: bool = False,
                ingress: bool = False, port: bytes | None = None,
                nft_fails: bool = False) -> tuple[subprocess.CompletedProcess[str], Path]:
    extra = {"SEALED_DEBUG_SSH_PUBKEY": "ssh-ed25519 AAAA test"} if debug else {}
    if ingress:
        extra.update(INGRESS)
    _measured_inputs(tmp_path, "guest", SEALED_ROOM_NETS=nets, **extra)
    fw_port = tmp_path / "fw-port"
    if port is not None:
        fw_port.write_bytes(port)
    image = tmp_path / "root-guest"
    fw = tmp_path / "fw-link"
    if raw is not None:
        fw.write_bytes(raw)
    run = tmp_path / "run"
    nft = tmp_path / "nft"
    nft.write_text("#!/bin/bash\nexit 1\n" if nft_fails else f'#!/bin/bash\n[ "$1" = -f ] && cp "$2" "{tmp_path}/loaded.nft"\n')
    nft.chmod(0o755)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SEALED_LINK_FW_CFG": str(fw), "SEALED_LINK_FW_CFG_PORT": str(fw_port),
           "SEALED_LINK_GUARD": str(image / "etc/sealed-guard.nft"), "SEALED_LINK_ROOM_ENV": str(image / "opt/room-kit/room.env"),
           "SEALED_LINK_CONSTANTS": str(SEALED / "guest-constants.sh"), "SEALED_LINK_RUN": str(run), "SEALED_LINK_NFT": str(nft)}
    script = f'sleep() {{ :; }}\nexport -f sleep\nsource "{SEALED}/guest-link.sh"'
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=60, env=env), run


@pytest.mark.parametrize("raw,host,guest", [(b"10.215.0.9 10.215.0.10", "10.215.0.9", "10.215.0.10"),
                                            (b"10.215.0.9 10.215.0.10\n", "10.215.0.9", "10.215.0.10"),
                                            (b"10.215.0.1 10.215.0.2", "10.215.0.1", "10.215.0.2"),
                                            (b"192.168.7.9 192.168.7.10", "192.168.7.9", "192.168.7.10")])
def test_guest_link_writes_the_network_guard_and_listen_address(tmp_path: Path, raw: bytes, host: str, guest: str) -> None:
    proc, run = _guest_link(tmp_path, raw)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    net = (run / "systemd/network/10-uplink.network").read_text()
    assert f"Address={guest}/30\n" in net and f"Gateway={host}\n" in net and "Name=uplink" in net
    loaded = (tmp_path / "loaded.nft").read_text()
    assert f'iifname "uplink" ip saddr {host} tcp dport 18090 accept' in loaded and "@SEALED_HOST_IP@" not in loaded
    assert loaded.rstrip().endswith("}") and 'iifname "uplink" drop' in loaded
    assert (run / "sealed-link/link.env").read_text() == f"SEALED_LINK_HOST_IP={host}\nSEALED_LINK_GUEST_IP={guest}\n"
    assert (run / "sealed-link/sshd-listen.conf").read_text() == f"ListenAddress {guest}\n"


@pytest.mark.parametrize("ingress,port,want", [(True, b"8445", "8445"), (True, b"443\n", "443"), (False, b"8445", None),
                                               (False, None, None)])
def test_guest_link_passes_the_ingress_public_port_only_for_an_ingress_build(tmp_path: Path, ingress: bool,
                                                                             port: bytes | None, want: str | None) -> None:
    proc, run = _guest_link(tmp_path, b"10.215.0.9 10.215.0.10", ingress=ingress, port=port)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    env = (run / "sealed-link/link.env").read_text()
    if want:
        assert env.endswith(f"SEALED_LINK_INGRESS_PUBLIC_PORT={want}\n")
    else:
        assert "INGRESS" not in env


@pytest.mark.parametrize("port", [None, b"", b"0", b"65536", b"8445;x", b"08445", b"84 45"])
def test_guest_link_closes_the_uplink_on_a_bad_ingress_public_port(tmp_path: Path, port: bytes | None) -> None:
    proc, run = _guest_link(tmp_path, b"10.215.0.9 10.215.0.10", ingress=True, port=port)
    assert proc.returncode == 1 and "uplink stays closed" in proc.stdout
    assert "18090" not in (tmp_path / "loaded.nft").read_text()
    assert not (run / "sealed-link/link.env").exists()


def test_guest_link_fills_the_debug_ssh_rule(tmp_path: Path) -> None:
    proc, _ = _guest_link(tmp_path, b"10.215.0.9 10.215.0.10", debug=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert 'iifname "uplink" ip saddr 10.215.0.9 tcp dport 22 accept' in (tmp_path / "loaded.nft").read_text()


@pytest.mark.parametrize("raw,nets", [
    (None, "10.214.0.0/22"), (b"", "10.214.0.0/22"), (b"10.215.0.9", "10.214.0.0/22"),
    (b"10.215.0.9  10.215.0.10", "10.214.0.0/22"),
    (b"10.215.0.10 10.215.0.9", "10.214.0.0/22"), (b"10.215.0.8 10.215.0.9", "10.214.0.0/22"),
    (b"198.51.100.1 198.51.100.2", "10.214.0.0/22"), (b"10.213.1.1 10.213.1.2", "10.214.0.0/22"),
    (b"10.214.4.5 10.214.4.6", "10.214.0.0/22 10.214.4.0/22"), (b"10.214.200.1 10.214.200.2", "auto"),
    (b"10.215.0.256 10.215.0.257", "10.214.0.0/22"), (b"010.215.0.5 010.215.0.6", "10.214.0.0/22"),
    (b"10.215.0.9 10.215.0.10;x", "10.214.0.0/22"), (b"$(id) 10.215.0.10", "10.214.0.0/22")])
def test_guest_link_closes_the_uplink_on_a_missing_or_bad_link(tmp_path: Path, raw: bytes | None, nets: str) -> None:
    proc, run = _guest_link(tmp_path, raw, nets=nets)
    assert proc.returncode == 1 and "uplink stays closed" in proc.stdout
    loaded = (tmp_path / "loaded.nft").read_text()
    assert "18090" not in loaded and "@SEALED_HOST_IP@" not in loaded and 'iifname "uplink" drop' in loaded
    assert not (run / "systemd/network/10-uplink.network").exists()
    assert not (run / "sealed-link/link.env").exists()


def test_guest_link_writes_no_link_env_when_the_guard_does_not_load(tmp_path: Path) -> None:
    proc, run = _guest_link(tmp_path, b"10.215.0.9 10.215.0.10", nft_fails=True)
    assert proc.returncode != 0 and not (run / "sealed-link/link.env").exists()


def test_the_guard_unit_runs_guest_link_before_the_network() -> None:
    text = (SEALED / "build-guest.sh").read_text()
    unit = text[text.index('cat > "$R/etc/systemd/system/sealed-guard.service"'):]
    unit = unit[:unit.index("\nEOF\n")]
    assert "ExecStart=/usr/local/sbin/sealed-link.sh" in unit and "Before=network-pre.target" in unit
    assert 'install -m 0755 "$KIT/sealed/guest-link.sh" "$R/usr/local/sbin/sealed-link.sh"' in text


def test_launch_passes_the_link_in_fw_cfg() -> None:
    text = (SEALED / "launch-guest.sh").read_text()
    assert 'FW_CFG+=(-fw_cfg "name=opt/cathedral/link,string=$SEALED_HOST_IP $SEALED_GUEST_IP")' in text
    assert 'FW_CFG+=(-fw_cfg "name=opt/cathedral/ingress-public-port,string=$INGRESS_PUBLIC_PORT")' in text
    assert text.index("guest-constants.sh") < text.index("opt/cathedral/link")


def _guest_boot_link_gate(tmp_path: Path, content: str | None) -> subprocess.CompletedProcess[str]:
    text = (SEALED / "guest-boot.sh").read_text()
    gate = text[text.index("LINK_ENV=/run/sealed-link/link.env"):text.index('log "guest IP $SEALED_LINK_GUEST_IP"')]
    assert "SEALED_LINK_INGRESS_PUBLIC_PORT" in gate
    link = tmp_path / "link.env"
    if content is not None:
        link.write_text(content)
    gate = gate.replace("/run/sealed-link/link.env", str(link))
    script = f'set -euo pipefail\nlog() {{ echo "$*"; }}\n{gate}\nbash -c \'echo "child $SEALED_LINK_GUEST_IP ${{SEALED_LINK_INGRESS_PUBLIC_PORT:--}}"\''
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30)


def test_guest_boot_exports_the_checked_guest_ip_before_install(tmp_path: Path) -> None:
    proc = _guest_boot_link_gate(tmp_path, "SEALED_LINK_HOST_IP=10.215.0.9\nSEALED_LINK_GUEST_IP=10.215.0.10\n")
    assert proc.returncode == 0 and proc.stdout.strip() == "child 10.215.0.10 -"
    proc = _guest_boot_link_gate(tmp_path, "SEALED_LINK_HOST_IP=10.215.0.9\nSEALED_LINK_GUEST_IP=10.215.0.10\n"
                                           "SEALED_LINK_INGRESS_PUBLIC_PORT=8445\n")
    assert proc.returncode == 0 and proc.stdout.strip() == "child 10.215.0.10 8445"
    text = (SEALED / "guest-boot.sh").read_text()
    assert text.index("export SEALED_LINK_GUEST_IP") < text.index("/opt/room-kit/install.sh /opt/room-kit/room.env")


@pytest.mark.parametrize("content", [None, "", "SEALED_LINK_GUEST_IP=\n", "SEALED_LINK_GUEST_IP=10.215.0.10;id\n"])
def test_guest_boot_refuses_without_a_checked_link(tmp_path: Path, content: str | None) -> None:
    proc = _guest_boot_link_gate(tmp_path, content)
    assert proc.returncode == 1 and "refusing to start" in proc.stdout


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
    # Images before this change match their .link by MAC (nc-sealed-2 52:54:00:5e:a1:ee). A rollback
    # starts such an image with the new launch-guest.sh, whose QEMU MAC must still match it.
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


def _manifest(tmp_path: Path) -> dict:
    text = (SEALED / "build-guest.sh").read_text()
    py = text[text.index("<<'EOF'\nimport hashlib, json, os, sys") + len("<<'EOF'\n"):]
    py = py[:py.index("\nEOF\n")]
    out = tmp_path / "img"
    out.mkdir()
    for f in ("OVMF.amdsev.fd", "vmlinuz", "initrd.cpio.zst"):
        (out / f).write_bytes(f.encode())
    (out / "cmdline").write_text("console=ttyS0")
    args = [str(out), "4", "EPYC-v4", "6.8", "0", "base", "0", "", "", ""]
    subprocess.run(["python3", "-c", py, *args], check=True, timeout=30)
    import json
    return json.loads((out / "manifest.json").read_text())


def test_the_manifest_names_no_link(tmp_path: Path) -> None:
    # The link is not in the image, so the manifest (and HOST_DATA) is one per build.
    text = (SEALED / "build-guest.sh").read_text()
    assert "SEALED_HOST_IP" not in text[text.index("python3 - "):]
    assert "link" not in _manifest(tmp_path)


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
