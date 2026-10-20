#!/usr/bin/env python3
"""Room kit: API launcher.

The sandbox API has a fixed create pace (100 creates per minute per key).
A room behind a broker gets bursts from one key, so the operator sets
ROOM_CREATES_PER_MINUTE. This launcher applies it, then runs the normal CLI:
python room_api.py sandbox serve ...
"""
from __future__ import annotations

import os
import sys


def main() -> int:
    from cathedral import sandbox_provider

    raw = os.environ.get("ROOM_CREATES_PER_MINUTE", "").strip()
    if raw:
        rate = int(raw)
        if rate < 1:
            raise SystemExit("ROOM_CREATES_PER_MINUTE must be 1 or more")
        defaults = sandbox_provider.InMemorySandboxProvider.__init__.__kwdefaults__
        defaults["creates_per_minute"] = rate
    from cathedral.cli import main as cli_main

    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
