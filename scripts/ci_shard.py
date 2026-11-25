#!/usr/bin/env python3
"""Print the test files for one CI shard: ci_shard.py <index 1..N> <N>.

Files under tests/ named test_*.py are split greedily by size (largest first,
each to the lightest shard), so the split is deterministic and roughly even.
Every file lands in exactly one shard.
"""
from __future__ import annotations

import sys
from pathlib import Path


def shards(root: Path, count: int) -> list[list[str]]:
    files = sorted(p for p in (root / "tests").rglob("test_*.py") if p.is_file())
    files.sort(key=lambda p: (-p.stat().st_size, p.as_posix()))
    buckets: list[list[str]] = [[] for _ in range(count)]
    loads = [0] * count
    for path in files:
        lightest = min(range(count), key=lambda i: (loads[i], i))
        buckets[lightest].append(path.relative_to(root).as_posix())
        loads[lightest] += path.stat().st_size
    return [sorted(b) for b in buckets]


def main(argv: list[str]) -> int:
    if len(argv) != 3 or not argv[1].isdigit() or not argv[2].isdigit():
        print("usage: ci_shard.py <index> <count>", file=sys.stderr)
        return 2
    index, count = int(argv[1]), int(argv[2])
    if not 1 <= index <= count:
        print("index must be between 1 and count", file=sys.stderr)
        return 2
    print("\n".join(shards(Path(__file__).resolve().parent.parent, count)[index - 1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
