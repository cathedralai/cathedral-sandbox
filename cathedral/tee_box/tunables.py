"""Start-up tunables for the TEE box: a validated settings file, nothing else.

``--tee-box-tunables PATH`` names a JSON file ``{"schema": 1, ...overrides}``. Every key
outside the nine below is refused, and nothing here can reach a pinned setting: the
runsc platform and network, the sandbox shape, ``no-new-privileges``, the network mode,
DNS, egress, the image and the entrypoint are fixed in ``executor.py``.

With no file (or an empty ``{"schema": 1}``) every value is its default and the box
behaves exactly as it did before this module existed. The challenge repo
``gt-challenge-sealed-sandbox`` uses the same table, so what it scores is what the box
accepts (``json_schema`` is compared byte for byte in both repos' tests).

runsc flags were checked against gVisor release-20260817.0 (``runsc/config/flags.go``):
``--directfs`` (bool, default true), ``--overlay2={root|all}:{self|memory}`` (default
``root:self``) and ``--num-network-channels`` (int, default 1). ``root:memory`` is not
offered: it would move sandbox writes out of the per-sandbox disk cap.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

SCHEMA_VERSION = 1
MAX_BYTES = 4096
DEFAULT_LOG_DRIVER = "json-file"
DEFAULT_OVERLAY2 = "root:self"
# Today's pinned runtimeArgs; the tunable flags are appended after them.
PINNED_RUNTIME_ARGS = ("--platform=systrap", "--network=sandbox")
# The flag names the tunables may add. The runtime check compares exactly these.
TUNABLE_FLAG_PREFIXES = ("--directfs", "--overlay2", "--num-network-channels")


class TunablesError(ValueError):
    """The settings file is not a valid tunables file."""


@dataclass(frozen=True)
class Field:
    key: str
    kind: str  # enum | bool | int
    default: object
    where: str
    doc: str
    choices: tuple[str, ...] = ()
    lo: int = 0
    hi: int = 0


FIELDS = (
    Field(
        "runsc.directfs",
        "bool",
        True,
        "daemon.json runtimeArgs",
        "runsc --directfs: the sandbox opens files through host file descriptors instead of "
        "the gofer round trip.",
    ),
    Field(
        "runsc.overlay2",
        "enum",
        DEFAULT_OVERLAY2,
        "daemon.json runtimeArgs",
        "runsc --overlay2: which mounts get the in-sandbox overlay. Both options keep writes "
        "in the sandbox own storage, so the disk cap still applies. (root:memory is not "
        "offered: it would move writes out of the disk cap.)",
        choices=("root:self", "all:self"),
    ),
    Field(
        "runsc.net_channels",
        "int",
        1,
        "daemon.json runtimeArgs",
        "runsc --num-network-channels: packet channels of the sandbox network stack.",
        lo=1,
        hi=4,
    ),
    Field(
        "docker.log_driver",
        "enum",
        DEFAULT_LOG_DRIVER,
        "create_argv",
        "docker run --log-driver. The sandbox command is `sleep infinity`; customer output "
        "is read through exec, not logs.",
        choices=("json-file", "local", "none"),
    ),
    Field(
        "image.prime",
        "enum",
        "none",
        "image import",
        "After an image is imported, read its layers once (docker save to /dev/null) so the "
        "first create does not pay for cold storage.",
        choices=("none", "page_cache"),
    ),
    Field(
        "pool.warm_size",
        "int",
        0,
        "warm pool",
        "Started, unclaimed deny_all sandboxes of the default shape kept ready for the most "
        "recently imported image, only while a customer holds the lease. They count against "
        "box capacity and are removed at hand-over.",
        lo=0,
        hi=16,
    ),
    Field(
        "pool.refill_parallelism",
        "int",
        1,
        "warm pool",
        "How many replacement warm sandboxes may start at once after one is claimed.",
        lo=1,
        hi=4,
    ),
    Field(
        "pool.idle_seconds",
        "int",
        300,
        "warm pool",
        "A warm sandbox unclaimed for this long is removed and replaced.",
        lo=30,
        hi=900,
    ),
    Field(
        "boot.create_concurrency",
        "int",
        1,
        "service",
        "How many sandbox creates one box runs at the same time. 1 is today's behaviour: "
        "creates one at a time.",
        lo=1,
        hi=16,
    ),
)

BY_KEY = {f.key: f for f in FIELDS}
DEFAULTS = {f.key: f.default for f in FIELDS}

# Not knobs. Each is enforced by the box, and a file that names one is refused.
PINNED = (
    "runsc --platform=systrap and --network=sandbox (`RunscExecutor.runtime_check` refuses "
    "anything else)",
    "sandbox shape: --cpus, --memory, --memory-swap, --pids-limit, --storage-opt size",
    "--security-opt no-new-privileges, the network mode, DNS and the egress rules",
    "the image: imported by digest, started by local image id with --pull never",
    "the entrypoint (`sleep infinity`), labels, container naming and cleanup",
    "MAX_SANDBOXES, the lease, receipts, and the measured boot of the confidential VM (RTMR3)",
)


@dataclass(frozen=True)
class Tunables:
    values: tuple[tuple[str, object], ...]

    def __getitem__(self, key: str) -> object:
        return dict(self.values)[key]

    def nested(self) -> dict:
        out: dict = {"schema": SCHEMA_VERSION}
        for key, value in self.values:
            section, name = key.split(".")
            out.setdefault(section, {})[name] = value
        return out

    def canonical(self) -> str:
        return json.dumps(self.nested(), sort_keys=True, separators=(",", ":"), allow_nan=False)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical().encode()).hexdigest()

    # -- what the box applies ----------------------------------------------

    def runtime_args(self) -> list[str]:
        """The daemon's runsc ``runtimeArgs``: the pinned two, then only non-default flags."""

        args = list(PINNED_RUNTIME_ARGS)
        if self["runsc.directfs"] is not DEFAULTS["runsc.directfs"]:
            args.append(f"--directfs={str(self['runsc.directfs']).lower()}")
        if self["runsc.overlay2"] != DEFAULT_OVERLAY2:
            args.append(f"--overlay2={self['runsc.overlay2']}")
        if self["runsc.net_channels"] != DEFAULTS["runsc.net_channels"]:
            args.append(f"--num-network-channels={self['runsc.net_channels']}")
        return args

    def docker_run_args(self) -> list[str]:
        driver = str(self["docker.log_driver"])
        return [] if driver == DEFAULT_LOG_DRIVER else ["--log-driver", driver]

    @property
    def prime_page_cache(self) -> bool:
        return self["image.prime"] == "page_cache"

    @property
    def warm_size(self) -> int:
        return int(self["pool.warm_size"])  # type: ignore[call-overload]

    @property
    def refill_parallelism(self) -> int:
        return int(self["pool.refill_parallelism"])  # type: ignore[call-overload]

    @property
    def idle_seconds(self) -> int:
        return int(self["pool.idle_seconds"])  # type: ignore[call-overload]

    @property
    def create_concurrency(self) -> int:
        return int(self["boot.create_concurrency"])  # type: ignore[call-overload]


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise TunablesError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_float(text: str) -> float:
    raise TunablesError(f"floats are not allowed: {text}")


def _check(field: Field, value: object) -> object:
    if field.kind == "bool":
        if type(value) is not bool:
            raise TunablesError(f"{field.key} must be true or false")
    elif field.kind == "int":
        if type(value) is not int:
            raise TunablesError(f"{field.key} must be an integer")
        if not field.lo <= value <= field.hi:
            raise TunablesError(f"{field.key} must be in {field.lo}..{field.hi}")
    elif type(value) is not str or value not in field.choices:
        raise TunablesError(f"{field.key} must be one of {', '.join(field.choices)}")
    return value


def parse_tunables(data: bytes | str) -> Tunables:
    """Overrides on the defaults. Unknown keys, wrong types, out-of-range values and
    duplicate keys are errors."""

    raw = data.encode() if isinstance(data, str) else data
    if len(raw) > MAX_BYTES:
        raise TunablesError(f"tunables file is over {MAX_BYTES} bytes")
    try:
        doc = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_float=_reject_float
        )
    except (ValueError, RecursionError) as exc:
        raise TunablesError(f"unreadable tunables file: {type(exc).__name__}") from exc
    if (
        not isinstance(doc, dict)
        or type(doc.get("schema")) is not int
        or doc["schema"] != SCHEMA_VERSION
    ):
        raise TunablesError(f'tunables file must be an object with "schema": {SCHEMA_VERSION}')
    values = dict(DEFAULTS)
    sections = {f.key.split(".")[0] for f in FIELDS}
    for section, body in doc.items():
        if section == "schema":
            continue
        if section not in sections or not isinstance(body, dict):
            raise TunablesError(f"unknown section {section!r}")
        for name, value in body.items():
            field = BY_KEY.get(f"{section}.{name}")
            if field is None:
                raise TunablesError(f"unknown tunable {section}.{name}")
            values[field.key] = _check(field, value)
    return Tunables(tuple(sorted(values.items())))


def default_tunables() -> Tunables:
    return parse_tunables('{"schema": 1}')


def load_tunables_file(path: str) -> Tunables:
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        raise TunablesError(f"cannot read the tunables file: {type(exc).__name__}") from exc
    return parse_tunables(data)


def json_schema() -> dict:
    """The JSON Schema of the file. Published as docs/tee_box_tunables.schema.json."""

    props: dict = {}
    for f in FIELDS:
        section, name = f.key.split(".")
        if f.kind == "bool":
            body: dict = {"type": "boolean"}
        elif f.kind == "int":
            body = {"type": "integer", "minimum": f.lo, "maximum": f.hi}
        else:
            body = {"enum": list(f.choices)}
        body["default"] = f.default
        body["description"] = f.doc
        props.setdefault(
            section, {"type": "object", "additionalProperties": False, "properties": {}}
        )
        props[section]["properties"][name] = body
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "tee-box tunables",
        "type": "object",
        "required": ["schema"],
        "additionalProperties": False,
        "properties": {"schema": {"const": SCHEMA_VERSION}, **props},
    }
