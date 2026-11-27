"""Sealed kit build and install scripts: checks that need no SNP host."""
from __future__ import annotations

import re
from pathlib import Path

SEALED = Path(__file__).resolve().parents[1] / "room-kit" / "sealed"


def test_debug_ssh_makes_host_keys_before_sshd_checks_them() -> None:
    # Ubuntu's ssh.service runs "sshd -t" first. The build removes host keys,
    # so the drop-in must reset ExecStartPre and make keys before the check.
    text = (SEALED / "build-guest.sh").read_text()
    m = re.search(r"printf '(\[Service\][^']*)' > \"\$R/etc/systemd/system/ssh\.service\.d/10-hostkeys\.conf\"", text)
    assert m, "no ssh host-key drop-in in build-guest.sh"
    pre = ["/usr/sbin/sshd -t"]  # the unit's own line
    for line in m.group(1).split("\\n"):
        if line == "ExecStartPre=":
            pre = []
        elif line.startswith("ExecStartPre="):
            pre.append(line.split("=", 1)[1])
    assert "/usr/bin/ssh-keygen -A" in pre and "/usr/sbin/sshd -t" in pre
    assert pre.index("/usr/bin/ssh-keygen -A") < pre.index("/usr/sbin/sshd -t")


def test_measurement_mismatch_fails_the_install() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    branch = text[text.index("MEASUREMENT DIFFERS"):text.index("MEASUREMENT DIFFERS") + 600]
    assert "exit 1" in branch


def test_sealed_install_refuses_a_restart_with_live_rooms() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    assert text.index("refuse_sealed_restart_with_rooms\n") < text.index('systemctl restart "$UNIT"')
    assert "SEALED_RESTART_WITH_ROOMS" in text


def test_a_measurement_mismatch_stops_the_guest_and_keeps_the_old_image() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    branch = text[text.index("MEASUREMENT DIFFERS"):]
    assert 'systemctl disable --now "$UNIT"' in branch and 'ln -sfn "$PREV_IMG"' in branch
    assert text.index("PREV_IMG=$(readlink") < text.index('"$KIT/sealed/build-guest.sh"')


def test_a_verified_guest_boots_again_at_the_next_host_start() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    match = text[text.index("measurement matches the build"):text.index("MEASUREMENT DIFFERS")]
    assert 'systemctl enable -q "$UNIT"' in match
    # Never before the check: a mismatched image must not be set to boot.
    assert text.index('systemctl enable -q "$UNIT"') > text.index('if [ "$GOT" = "$EXPECTED" ]')


def test_host_link_rules_are_checked_every_minute() -> None:
    text = (SEALED / "write-units.sh").read_text()
    assert "-net.timer" in text and "OnUnitActiveSec=1min" in text and "host-net.sh check" in text
    install = (SEALED / "install-sealed.sh").read_text()
    assert '"$KIT/sealed/write-units.sh" "$SEALED_DIR/sealed.env"' in install
    assert 'systemctl enable -q --now "${UNIT%.service}-net.timer"' in install
    net = (SEALED / "host-net.sh").read_text()
    assert "check)" in net and 'exec "$0" up "$2"' in net


def test_firmware_is_checked_before_the_long_build() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    assert text.index("apt-get install") < text.index('[ -f "$SEALED_OVMF" ] || { echo "no AmdSev firmware') < text.index('"$KIT/sealed/build-guest.sh"')


def test_the_measured_initrd_takes_tracked_kit_files_only() -> None:
    text = (SEALED / "build-guest.sh").read_text()
    assert "git -C \"$KIT\" ls-files -z" in text
    assert 'install -m 0644 "$KIT/$CATHEDRAL_TARBALL" "$R/opt/room-kit/dist/"' in text


def _write_units(tmp_path: Path) -> str:
    import subprocess
    env = tmp_path / "sealed.env"
    env.write_text("SEALED_NAME=nc-sealed-9\nSEALED_DIR=/srv/sealed-hotel-9\n")
    dest = tmp_path / "root"
    proc = subprocess.run(["bash", str(SEALED / "write-units.sh"), str(env)], capture_output=True, text=True,
                          env={"ROOM_DESTDIR": str(dest), "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 0, proc.stderr
    assert "no restart" in proc.stdout
    return (dest / "etc/systemd/system/room-sealed-nc-sealed-9.service").read_text()


def test_sealed_guest_restarts_after_a_failed_start(tmp_path: Path) -> None:
    # AB#824: 19 Nov 2026 the hotels stayed down after a host reboot (Restart=no, KVM late).
    unit = _write_units(tmp_path)
    assert "Restart=on-failure" in unit and "Restart=no" not in unit
    assert "RestartSec=15" in unit and "TimeoutStartSec=180" in unit
    head = unit.split("[Service]")[0]
    assert "StartLimitIntervalSec=900" in head and "StartLimitBurst=5" in head
    assert "After=network-online.target systemd-modules-load.service" in unit


def test_sealed_guest_waits_for_kvm_before_the_host_link_and_qemu(tmp_path: Path) -> None:
    unit = _write_units(tmp_path)
    pre = [line.split("=", 1)[1] for line in unit.splitlines() if line.startswith("ExecStartPre=")]
    # pre[0] is the custom guest hold guard (AB#1008; tests/test_custom_guest_kit_safety.py).
    assert "custom-guest.hold" in pre[0]
    assert pre[1] == "-/sbin/modprobe -q kvm_amd"
    # systemd turns $$ into a literal $ for the shell.
    assert "[ -c /dev/kvm ]" in pre[2] and "$$(seq 1 120)" in pre[2]
    assert pre[3] == "/srv/sealed-hotel-9/host-net.sh up /srv/sealed-hotel-9/sealed.env"
    assert "ExecStart=/srv/sealed-hotel-9/launch-guest.sh /srv/sealed-hotel-9/sealed.env" in unit


def test_write_units_never_starts_or_restarts_a_guest() -> None:
    text = (SEALED / "write-units.sh").read_text()
    for verb in ("restart", "start", "stop", "enable", "kill"):
        assert f"systemctl {verb}" not in text
