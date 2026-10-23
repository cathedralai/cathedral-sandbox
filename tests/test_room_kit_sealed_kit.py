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
    line = next(l for l in text.splitlines() if "MEASUREMENT DIFFERS" in l)
    assert "exit 1" in line
