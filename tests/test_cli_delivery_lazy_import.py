"""The CLI must start without the delivery contract package.

The SN94 miner images copy only ``cathedral/`` (``Dockerfile.sn94-audit-miner``,
``Dockerfile.sn94-snp-miner``), so ``cathedral_delivery`` from
``packages/delivery-contract`` is absent there while ``cathedral/delivery.py``
is present. Building the parser, and every command but the two delivery
commands, must work in that image.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cathedral import cli

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def no_delivery_contract(monkeypatch):
    """Make the import system behave as in a miner image without the package."""

    for name in ("cathedral_delivery", "cathedral_delivery.grants"):
        monkeypatch.setitem(sys.modules, name, None)  # import raises ModuleNotFoundError
    # cathedral/delivery.py is in the image; it fails only when imported.
    monkeypatch.delitem(sys.modules, "cathedral.delivery", raising=False)


def test_a_non_delivery_command_runs_without_the_delivery_contract(
    no_delivery_contract, tmp_path: Path, capsys
):
    parser = cli.build_parser()
    # The miner image entrypoints' commands still parse.
    assert parser.parse_args(["worker", "serve-snp", "--hotkey", "m"]).func is cli.cmd_worker_serve
    migrate = ["worker", "migrate", "--hotkey", "m", "--migration-mode", "public-legacy-audit"]
    assert parser.parse_args(migrate).func is cli.cmd_worker_serve

    assert cli.main(["work", "status", "--ledger-db", str(tmp_path / "ledger.sqlite")]) == 0
    status = json.loads(capsys.readouterr().out)
    assert isinstance(status, dict)
    with pytest.raises(ModuleNotFoundError):
        import cathedral_delivery  # noqa: F401 - the fixture really hides it


@pytest.mark.parametrize(
    "argv", [["delivery-receipt", "check"], ["executor", "check-grant"]]
)
def test_a_delivery_command_without_the_contract_says_what_is_missing(
    no_delivery_contract, argv, capsys
):
    assert cli.main(argv) == 2
    error = json.loads(capsys.readouterr().err)["error"]
    assert "cathedral-delivery package" in error


def test_importing_the_cli_and_building_the_parser_does_not_import_the_contract():
    # A fresh interpreter: no other test has imported the package already.
    code = (
        "import sys\n"
        "import cathedral.cli\n"
        "cathedral.cli.build_parser()\n"
        "loaded = sorted(m for m in sys.modules if m.split('.')[0] == 'cathedral_delivery'"
        " or m == 'cathedral.delivery')\n"
        "print(loaded)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"
