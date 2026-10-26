"""Per-room start-up tunables on a hotel (room kit).

A create may carry ``"tunables"``: the same document the TEE box reads with
``--tee-box-tunables`` and the Escape challenge scores (``cathedral/tee_box/tunables.py``,
the same allowed set, bounds and sha256). On a shared hotel a tunable must act on
one room only, so the nine keys split in two:

Per room (applied to that room's container, nothing else):

- ``runsc.directfs``, ``runsc.overlay2``, ``runsc.net_channels``: the room starts
  under ``--runtime runsc-tun-<variant>``, one of the 16 runtimes the kit registers
  in the room daemon's ``daemon.json`` (``room-kit/lib/tunable_runtimes.py``). Each
  variant is the hotel's own runsc entry with exactly these three flags set
  explicitly. The hotel reads the daemon's runtimes and refuses a create whose
  variant is missing or differs from that rule (409 ``tunables_unavailable``).
- ``docker.log_driver``: ``docker run --log-driver`` for that container.
- ``image.prime``: ``page_cache`` reads the room's image once (``docker save`` to
  /dev/null) before that room starts. Its effect, a warm page cache, is shared with
  every room of the same image on the hotel; it changes speed, never behaviour.

Hotel-wide (no per-room meaning on a shared hotel): ``pool.*`` (the room kit has no
warm pool) and ``boot.create_concurrency``. A create that sets one away from its
default is refused (400 ``tunables_not_per_room``), so a room never claims a
tunable it did not run.

A create without ``"tunables"`` starts exactly as before.
"""

from __future__ import annotations

import json
from typing import Any, Iterator, Mapping

from cathedral.tee_box.tunables import (
    BY_KEY,
    DEFAULTS,
    TUNABLE_FLAG_PREFIXES,
    Tunables,
    TunablesError,
    parse_tunables,
)

PER_ROOM = ("runsc.directfs", "runsc.overlay2", "runsc.net_channels", "docker.log_driver", "image.prime")
HOTEL_WIDE = ("pool.warm_size", "pool.refill_parallelism", "pool.idle_seconds", "boot.create_concurrency")
RUNTIME_PREFIX = "runsc-tun"
VIEW_SCHEMA = "cathedral_room_tunables_v1"


class RoomTunablesError(ValueError):
    """A create's tunables cannot run on one room. ``code`` is the API error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def parse_room_tunables(doc: Any) -> Tunables:
    """The create's ``tunables`` object, validated by the TEE box parser, then the per-room rule."""

    if not isinstance(doc, dict):
        raise RoomTunablesError("invalid_tunables", 'tunables must be an object like {"schema": 1, ...}')
    try:
        # Re-encoded for the shared parser: a float (even 1.0) is refused there, as in a file.
        tunables = parse_tunables(json.dumps(doc, allow_nan=False))
    except (TunablesError, ValueError) as exc:
        raise RoomTunablesError("invalid_tunables", str(exc)) from None
    off = [key for key in HOTEL_WIDE if tunables[key] != DEFAULTS[key]]
    if off:
        raise RoomTunablesError(
            "tunables_not_per_room",
            f"{', '.join(off)} act on the whole hotel, not one room; a shared hotel runs them at their defaults",
        )
    return tunables


def runsc_flags(tunables: Tunables) -> list[str]:
    """The three tunable runsc flags, always explicit (the hotel's own runsc entry may set others)."""

    return [
        f"--directfs={str(tunables['runsc.directfs']).lower()}",
        f"--overlay2={tunables['runsc.overlay2']}",
        f"--num-network-channels={tunables['runsc.net_channels']}",
    ]


def runtime_name(tunables: Tunables) -> str:
    directfs = "d1" if tunables["runsc.directfs"] else "d0"
    overlay = str(tunables["runsc.overlay2"]).split(":", 1)[0]
    return f"{RUNTIME_PREFIX}-{directfs}-{overlay}-n{tunables['runsc.net_channels']}"


def _is_tunable_flag(arg: str) -> bool:
    return any(arg == p or arg.startswith(p + "=") for p in TUNABLE_FLAG_PREFIXES)


def variant_args(base_args: list[str], tunables: Tunables) -> list[str]:
    """The hotel's runsc args without the tunable flags, then the three explicit ones."""

    return [a for a in base_args if not _is_tunable_flag(a)] + runsc_flags(tunables)


def variants() -> Iterator[Tunables]:
    """Every runsc combination the kit registers (2 x 2 x 4 = 16)."""

    net = BY_KEY["runsc.net_channels"]
    for directfs in (True, False):
        for overlay in BY_KEY["runsc.overlay2"].choices:
            for channels in range(net.lo, net.hi + 1):
                yield parse_tunables(json.dumps(
                    {"schema": 1, "runsc": {"directfs": directfs, "overlay2": overlay, "net_channels": channels}}))


def check_runtime(runtimes: Mapping[str, Any], base_runtime: str, tunables: Tunables) -> list[str]:
    """The registered args of the room's runtime, after checking they are the hotel's own runsc
    entry with exactly the three tunable flags. Raises ``tunables_unavailable`` otherwise."""

    name = runtime_name(tunables)
    entry, base = runtimes.get(name), runtimes.get(base_runtime)
    if not isinstance(entry, Mapping) or not isinstance(base, Mapping):
        raise RoomTunablesError(
            "tunables_unavailable",
            f"this hotel's daemon has no runtime {name} (room kit without per-room tunables)",
        )
    args = [str(a) for a in (entry.get("runtimeArgs") or entry.get("args") or [])]
    base_args = [str(a) for a in (base.get("runtimeArgs") or base.get("args") or [])]
    if args != variant_args(base_args, tunables) or entry.get("path") != base.get("path"):
        raise RoomTunablesError(
            "tunables_unavailable",
            f"runtime {name} is not the hotel's {base_runtime} entry with {' '.join(runsc_flags(tunables))}",
        )
    return args


def docker_run_args(tunables: Tunables) -> list[str]:
    return ["--log-driver", str(tunables["docker.log_driver"])]


def room_view(tunables: Tunables, *, runtime: str, runtime_args: list[str], image_prime: str) -> dict:
    """What the room reports (create answer and GET) and the hotel receipt signs."""

    return {
        "schema": VIEW_SCHEMA,
        "status": "applied",
        "sha256": tunables.sha256,
        "values": tunables.nested(),
        "runtime": runtime,
        "runtime_args": list(runtime_args),
        "log_driver": str(tunables["docker.log_driver"]),
        "image_prime": image_prime,
    }
