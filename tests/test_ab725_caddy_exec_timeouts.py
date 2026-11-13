"""AB#725: Caddy reverse_proxy timeouts must outlast the broker exec cap.

The broker caps one exec at 14400 s and keeps a 120 s margin. A read_timeout
or write_timeout below that cuts long held exec requests.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ROOT / "deploy" / "thin-broker-caddy" / "Caddyfile",
    ROOT / "room-kit" / "install.sh",
]
MIN_SECONDS = 14400 + 120
UNITS = {"s": 1, "m": 60, "h": 3600}


def parse_duration(text):
    parts = re.findall(r"(\d+)([smh])", text)
    assert parts and "".join(n + u for n, u in parts) == text, text
    return sum(int(n) * UNITS[u] for n, u in parts)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
@pytest.mark.parametrize("key", ["read_timeout", "write_timeout"])
def test_timeout_covers_exec_cap(path, key):
    text = path.read_text()
    assert "reverse_proxy" in text
    values = re.findall(rf"^\s*{key}\s+(\S+)\s*$", text, re.M)
    assert values, f"{path} has no {key}"
    for value in values:
        assert parse_duration(value) >= MIN_SECONDS, f"{path} {key} {value}"
