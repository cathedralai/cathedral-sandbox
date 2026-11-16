"""AB#432: the hotel name and link settings are not in the measured guest image.

Two hotels of one build must share one measurement. These tests run the
build's config, room.env and command line steps for two names (and for
different host link values in sealed.env) and compare every measured input.
The name reaches the guest through fw_cfg and lands in the attested binding.
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
    a_files, a_cmd = _measured_inputs(tmp_path, "hotel-a")
    b_files, b_cmd = _measured_inputs(tmp_path, "hotel-b", SEALED_HOST_IP="10.9.9.1", SEALED_GUEST_IP="10.9.9.2",
                                      SEALED_GUEST_MAC="52:54:00:00:00:01", SEALED_DNS="9.9.9.9")
    assert a_cmd == b_cmd
    assert "hotel-a" not in a_cmd and "cathedral.hotel" not in a_cmd
    assert a_files == b_files, "name, IP, MAC or DNS changed a measured file"
    assert {"etc/hostname", "etc/resolv.conf", "etc/sealed-guard.nft", "opt/room-kit/room.env"} <= set(a_files)
    for rel in ("etc/hostname", "etc/resolv.conf", "etc/sealed-guard.nft", "opt/room-kit/room.env",
                "etc/systemd/network/10-uplink.network", "etc/systemd/network/10-uplink.link"):
        assert "hotel-a" not in (tmp_path / "root-hotel-a" / rel).read_text()


def test_image_constants_are_the_old_defaults() -> None:
    text = (SEALED / "guest-constants.sh").read_text()
    for line in ("SEALED_HOST_IP=10.215.0.1", "SEALED_GUEST_IP=10.215.0.2", "SEALED_GUEST_MAC=52:54:00:5e:a1:ed",
                 'SEALED_DNS="1.1.1.1 8.8.8.8"'):
        assert line in text
    for script in ("build-guest.sh", "launch-guest.sh", "host-net.sh", "install-sealed.sh"):
        assert "guest-constants.sh" in (SEALED / script).read_text(), script
    assert "SEALED_GUEST_IP=" not in (SEALED / "sealed.env.example").read_text()


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
