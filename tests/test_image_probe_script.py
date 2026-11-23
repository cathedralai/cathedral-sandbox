"""AB#732: the one-exec image probe gives the answers the single probes gave.

The script runs under the real /bin/sh with a PATH that holds only the tools
each case gives the image, so its checks are tested, not a fake's reading of them.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from cathedral.sandbox_guest import IMAGE_PROBE_SCRIPT, parse_image_probe

GNU_TIMEOUT = '#!/bin/sh\n[ "$1" = "-t" ] && exit 125\nshift\nexec "$@"\n'
BUSYBOX_TIMEOUT = '#!/bin/sh\n[ "$1" = "-t" ] || exit 1\nshift 2\nexec "$@"\n'


def _probe(tmp_path, *, bash: bool, timeout: str | None) -> tuple[int, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    os.symlink(shutil.which("true"), bin_dir / "true")
    if bash:
        os.symlink(shutil.which("bash"), bin_dir / "bash")
    if timeout is not None:
        tool = bin_dir / "timeout"
        tool.write_text(timeout)
        tool.chmod(0o755)
    r = subprocess.run(
        ["/bin/sh", "-c", IMAGE_PROBE_SCRIPT],
        env={"PATH": str(bin_dir)},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return r.returncode, r.stdout


@pytest.mark.parametrize("bash", [True, False])
@pytest.mark.parametrize(("timeout", "form"), [(GNU_TIMEOUT, "gnu"), (BUSYBOX_TIMEOUT, "busybox"), (None, "none")])
def test_probe_script_reports_bash_and_the_timeout_form(tmp_path, bash: bool, timeout: str | None, form: str) -> None:
    code, out = _probe(tmp_path, bash=bash, timeout=timeout)
    assert parse_image_probe(code, out) == (bash, form)


def test_a_timeout_that_takes_both_forms_reads_as_gnu(tmp_path) -> None:
    # As _timeout_form: the GNU form is tried first and kept when it runs.
    code, out = _probe(tmp_path, bash=True, timeout='#!/bin/sh\n[ "$1" = "-t" ] && shift\nshift\nexec "$@"\n')
    assert parse_image_probe(code, out) == (True, "gnu")


@pytest.mark.parametrize(
    ("code", "out"),
    [
        (127, 'exec: "sh": executable file not found in $PATH'),
        (0, ""),
        (0, "cathedral-image-probe bash=1 timeout=gnu\nextra"),
        (0, "cathedral-image-probe bash=2 timeout=gnu"),
        (0, "cathedral-image-probe bash=1 timeout=other"),
        (1, "cathedral-image-probe bash=1 timeout=gnu"),
    ],
)
def test_an_answer_that_is_not_the_probe_line_is_unreadable(code: int, out: str) -> None:
    assert parse_image_probe(code, out) is None
