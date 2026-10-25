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
    text = (SEALED / "install-sealed.sh").read_text()
    assert "-net.timer" in text and "OnUnitActiveSec=1min" in text and "host-net.sh check" in text
    net = (SEALED / "host-net.sh").read_text()
    assert "check)" in net and 'exec "$0" up "$2"' in net


def test_firmware_is_checked_before_the_long_build() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    assert text.index("apt-get install") < text.index('[ -f "$SEALED_OVMF" ] || { echo "no AmdSev firmware') < text.index('"$KIT/sealed/build-guest.sh"')


def test_the_measured_initrd_takes_tracked_kit_files_only() -> None:
    text = (SEALED / "build-guest.sh").read_text()
    assert "git -C \"$KIT\" ls-files -z" in text
    assert 'install -m 0644 "$KIT/$CATHEDRAL_TARBALL" "$R/opt/room-kit/dist/"' in text
