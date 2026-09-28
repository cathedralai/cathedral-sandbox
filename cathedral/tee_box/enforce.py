"""Apply and verify the egress policy for ``internet`` sandboxes (T6b1).

This runs inside the confidential VM, next to the Docker daemon that starts
the runsc sandboxes. It is used only when an operator enables the TEE box.

Attachment point:

- Every ``internet`` sandbox joins one dedicated Docker bridge network. The
  network and its Linux bridge share one name, ``EgressPolicy.bridge``
  (default ``cathsbx0``), set with ``com.docker.network.bridge.name``.
  Inter-container traffic on it is off (``enable_icc=false``).
- The nft table ``inet cathedral_tee_box_egress`` matches ``iifname`` on
  that bridge. It is box-wide, applied once, and read back with
  ``nft --json list table`` and compared with the policy before every
  ``internet`` create.
- The bandwidth cap is per sandbox, on the host side of the sandbox's veth.
  The veth is found from the container's network namespace: Docker's
  ``SandboxKey`` names it, ``eth0@ifN`` inside it gives the peer index N,
  and the bridge port with index N is the veth. The ``tc`` qdiscs are read
  back before the sandbox counts as enforced, and are removed on delete.

Fail closed: until the table is applied and verified, ``active`` is false,
the executor offers no ``internet`` mode, and ``status()`` reports the
error. Every command is an argv list with no shell and a bounded timeout.
Every address rendered into a rule comes from an ``ipaddress`` object.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from cathedral.tee_box.egress import EgressPolicy, EgressPolicyError, _check_interface

NFT_FAMILY = "inet"
NFT_TABLE = "cathedral_tee_box_egress"
NETWORK_LABEL = "org.cathedral.tee-box.network"
COMMAND_TIMEOUT_SECONDS = 15.0
RETRY_SECONDS = 60.0
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
DEFAULT_NFT = "/usr/sbin/nft"
DEFAULT_TC = "/usr/sbin/tc"
DEFAULT_IP = "/usr/sbin/ip"
DEFAULT_NSENTER = "/usr/bin/nsenter"
_SANDBOX_KEY_RE = re.compile(r"^/(?:var/)?run/docker/netns/[A-Za-z0-9_-]{1,64}$")
_CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PEER_RE = re.compile(r"^\d+:\s+eth0@if(\d+):", re.MULTILINE)
_LINK_RE = re.compile(r"^(\d+):\s+([A-Za-z0-9_.-]{1,15})(?:@[A-Za-z0-9_.-]+)?:", re.MULTILINE)
_POLICE_RE = re.compile(r"\bpolice\s+0x[0-9a-f]+\s+rate\s+(\d+(?:\.\d+)?)([KMGT]?)bit\b")
# tc's answers when the device or qdisc no longer exists: nothing to remove.
_ALREADY_GONE = (b"Cannot find device", b"Invalid handle", b"No such file or directory")
_UNITS = {"": 1, "K": 10**3, "M": 10**6, "G": 10**9, "T": 10**12}

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class EgressEnforcementError(Exception):
    """The egress rules could not be applied or verified."""


@dataclass(frozen=True)
class SandboxEgress:
    """One sandbox whose bandwidth cap is applied and verified."""

    container: str
    veth: str


def _networks(values: Iterable[object]) -> tuple[Network, ...]:
    """Refuse anything that is not an ``ipaddress`` network object."""

    result = []
    for value in values:
        if not isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            raise EgressEnforcementError("policy addresses must be ipaddress networks")
        result.append(value)
    return tuple(result)


def checked_policy(policy: EgressPolicy) -> EgressPolicy:
    """Check that every value rendered into nft or tc is typed and bounded."""

    if not isinstance(policy, EgressPolicy):
        raise EgressEnforcementError("an EgressPolicy is required")
    _networks(policy.denied)
    _networks(policy.box_addresses)
    if not set(policy.box_addresses) <= set(policy.denied):
        raise EgressEnforcementError("the box's own addresses must be denied")
    try:
        _check_interface(policy.bridge)
    except EgressPolicyError as exc:
        raise EgressEnforcementError("bridge name is invalid") from exc
    if isinstance(policy.bandwidth_mbit, bool) or not isinstance(policy.bandwidth_mbit, int):
        raise EgressEnforcementError("bandwidth cap is invalid")
    return policy


def detect_box_addresses(
    *,
    ip: str = DEFAULT_IP,
    extra: Sequence[str] = (),
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Every address on the box's interfaces, plus ``extra``, as ``ipaddress`` objects.

    Reads ``ip -json address show``. Any value that does not parse as an IP
    address refuses the whole detection, so nothing but a parsed address can
    reach the policy.
    """

    try:
        result = runner(
            [ip, "-json", "address", "show"],
            capture_output=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EgressEnforcementError("address detection failed") from exc
    if result.returncode != 0 or len(result.stdout or b"") > MAX_COMMAND_OUTPUT:
        raise EgressEnforcementError("address detection failed")
    try:
        links = json.loads(result.stdout or b"[]")
    except (UnicodeDecodeError, ValueError) as exc:
        raise EgressEnforcementError("address listing is invalid") from exc
    found: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    raw_values: list[object] = list(extra)
    if not isinstance(links, list):
        raise EgressEnforcementError("address listing is invalid")
    for link in links:
        if not isinstance(link, dict) or not isinstance(link.get("addr_info", []), list):
            raise EgressEnforcementError("address listing is invalid")
        for info in link.get("addr_info", []):
            if not isinstance(info, dict) or "local" not in info:
                raise EgressEnforcementError("address listing is invalid")
            raw_values.append(info["local"])
    for raw in raw_values:
        if not isinstance(raw, str) or len(raw) > 64:
            raise EgressEnforcementError("detected address is invalid")
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise EgressEnforcementError("detected address is invalid") from exc
        if address not in found:
            found.append(address)
    if not found:
        raise EgressEnforcementError("no box address was detected")
    return tuple(found)


def _expected_elements(networks: Iterable[Network]) -> frozenset[Network]:
    return frozenset(ipaddress.collapse_addresses(networks))


def _element(value: object) -> list[Network]:
    """One nft JSON set element as networks; raises on anything unexpected."""

    if isinstance(value, dict) and set(value) == {"elem"}:
        inner = value["elem"]
        if not isinstance(inner, dict) or "val" not in inner:
            raise ValueError("element")
        value = inner["val"]
    if isinstance(value, str):
        return [ipaddress.ip_network(value)]
    if isinstance(value, dict) and set(value) == {"prefix"}:
        prefix = value["prefix"]
        if not isinstance(prefix, dict) or set(prefix) != {"addr", "len"}:
            raise ValueError("element")
        length = prefix["len"]
        if isinstance(length, bool) or not isinstance(length, int):
            raise ValueError("element")
        return [ipaddress.ip_network(f"{ipaddress.ip_address(prefix['addr'])}/{length}")]
    if isinstance(value, dict) and set(value) == {"range"}:
        low, high = value["range"]
        return list(
            ipaddress.summarize_address_range(ipaddress.ip_address(low), ipaddress.ip_address(high))
        )
    raise ValueError("element")


def _rule_terms(expressions: object) -> tuple[tuple[str, ...], ...]:
    if not isinstance(expressions, list):
        raise ValueError("rule")
    terms: list[tuple[str, ...]] = []
    for expression in expressions:
        if not isinstance(expression, dict) or len(expression) != 1:
            raise ValueError("rule")
        ((kind, body),) = expression.items()
        if kind == "counter":
            terms.append(("counter",))
        elif kind == "drop" and body is None:
            terms.append(("drop",))
        elif kind == "match" and isinstance(body, dict) and body.get("op") in ("==", "in"):
            left, right = body.get("left"), body.get("right")
            if left == {"meta": {"key": "iifname"}} and isinstance(right, str):
                terms.append(("iifname", right))
            elif (
                isinstance(left, dict)
                and set(left) == {"payload"}
                and left["payload"]
                in ({"protocol": "ip", "field": "daddr"}, {"protocol": "ip6", "field": "daddr"})
                and isinstance(right, str)
            ):
                terms.append((left["payload"]["protocol"] + " daddr", right))
            else:
                raise ValueError("rule")
        else:
            raise ValueError("rule")
    return tuple(terms)


def table_matches(policy: EgressPolicy, listing: bytes) -> bool:
    """True when ``nft --json list table`` output is exactly the policy's table.

    Sets, chains and rules are compared as parsed values: the same deny
    ranges, the same hooks and priorities, the same rules in order, and
    nothing else in the table.
    """

    bridge = policy.bridge
    expected_sets = {
        "deny4": ("ipv4_addr", _expected_elements(policy.denied_ipv4)),
        "deny6": ("ipv6_addr", _expected_elements(policy.denied_ipv6)),
    }
    expected_chains = {
        "forward": ("filter", "forward", -1, "accept"),
        "input": ("filter", "input", -1, "accept"),
    }
    expected_rules = {
        "forward": [
            (("iifname", bridge), ("ip daddr", "@deny4"), ("counter",), ("drop",)),
            (("iifname", bridge), ("ip6 daddr", "@deny6"), ("counter",), ("drop",)),
        ],
        "input": [(("iifname", bridge), ("counter",), ("drop",))],
    }
    try:
        document = json.loads(listing)
        entries = document["nftables"]
        if not isinstance(entries, list):
            return False
        tables, sets, chains = 0, {}, {}
        rules: dict[str, list[tuple[tuple[str, ...], ...]]] = {}
        for entry in entries:
            if not isinstance(entry, dict) or len(entry) != 1:
                return False
            ((kind, body),) = entry.items()
            if kind == "metainfo":
                continue
            if not isinstance(body, dict) or body.get("family") != NFT_FAMILY:
                return False
            if kind == "table":
                if body.get("name") != NFT_TABLE:
                    return False
                tables += 1
                continue
            if body.get("table") != NFT_TABLE:
                return False
            if kind == "set":
                elements: list[Network] = []
                for value in body.get("elem", []):
                    elements.extend(_element(value))
                if body.get("flags") != ["interval"]:
                    return False
                sets[body.get("name")] = (body.get("type"), _expected_elements(elements))
            elif kind == "chain":
                chains[body.get("name")] = (
                    body.get("type"),
                    body.get("hook"),
                    body.get("prio"),
                    body.get("policy"),
                )
            elif kind == "rule":
                rules.setdefault(body.get("chain"), []).append(_rule_terms(body.get("expr")))
            else:
                return False
    except (KeyError, TypeError, ValueError, UnicodeDecodeError):
        return False
    return (
        tables == 1
        and sets == expected_sets
        and chains == expected_chains
        and rules == expected_rules
    )


def _bits(number: str, unit: str) -> float:
    return float(number) * _UNITS[unit]


class EgressEnforcer:
    """Apply the nft table and per-sandbox ``tc`` caps; report what is verified."""

    def __init__(
        self,
        policy: EgressPolicy,
        *,
        docker: str = "/usr/bin/docker",
        nft: str = DEFAULT_NFT,
        tc: str = DEFAULT_TC,
        ip: str = DEFAULT_IP,
        nsenter: str = DEFAULT_NSENTER,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        timeout: float = COMMAND_TIMEOUT_SECONDS,
        retry_seconds: float = RETRY_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = checked_policy(policy)
        for path in (docker, nft, tc, ip, nsenter):
            if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
                raise ValueError("tool paths must be absolute")
        if not 0 < timeout <= 120:
            raise ValueError("command timeout must be 0 to 120 seconds")
        self.docker, self.nft, self.tc, self.ip, self.nsenter = docker, nft, tc, ip, nsenter
        self._runner = runner
        self._timeout = timeout
        self._retry_seconds = retry_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._active = False
        self._error: str | None = "egress rules not applied yet"
        self._last_attempt: float | None = None
        self._lapses = 0
        self._sandboxes: dict[str, SandboxEgress] = {}

    # -- state -----------------------------------------------------------

    @property
    def active(self) -> bool:
        with self._lock:
            return self._active

    @property
    def lapses(self) -> int:
        """How many times enforcement went from active to inactive."""

        with self._lock:
            return self._lapses

    def status(self) -> dict[str, object]:
        with self._lock:
            return {
                "enforced": self._active,
                "error": self._error,
                "lapses": self._lapses,
                "bridge": self.policy.bridge,
                "nft_table": f"{NFT_FAMILY} {NFT_TABLE}",
                "capped_sandboxes": len(self._sandboxes),
            }

    def _fail(self, message: str) -> bool:
        with self._lock:
            if self._active:
                self._lapses += 1
            self._active = False
            self._error = message
        return False

    def is_enforced(self, container: str) -> bool:
        with self._lock:
            return self._active and container in self._sandboxes

    # -- commands --------------------------------------------------------

    def _run(self, argv: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess:
        if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise EgressEnforcementError("argument is invalid")
        try:
            result = self._runner(
                argv,
                input=stdin,
                capture_output=True,
                timeout=self._timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise EgressEnforcementError(f"{argv[0].rsplit('/', 1)[-1]} failed to run") from exc
        if len(result.stdout or b"") > MAX_COMMAND_OUTPUT:
            raise EgressEnforcementError("command output is too large")
        return result

    def _ok(self, argv: list[str], what: str, *, stdin: bytes | None = None) -> bytes:
        result = self._run(argv, stdin=stdin)
        if result.returncode != 0:
            raise EgressEnforcementError(f"{what} failed")
        return result.stdout or b""

    # -- argv (pure) -----------------------------------------------------

    def network_inspect_argv(self) -> list[str]:
        return [self.docker, "network", "inspect", "--format", "{{json .}}", self.policy.bridge]

    def network_create_argv(self) -> list[str]:
        bridge = self.policy.bridge
        return [
            self.docker,
            "network",
            "create",
            "--driver",
            "bridge",
            "--opt",
            f"com.docker.network.bridge.name={bridge}",
            "--opt",
            "com.docker.network.bridge.enable_icc=false",
            "--label",
            f"{NETWORK_LABEL}=egress",
            bridge,
        ]

    def nft_apply_argv(self) -> list[str]:
        return [self.nft, "-f", "-"]

    def nft_ruleset(self) -> bytes:
        """The table, replaced atomically: declare, delete, then define it again."""

        head = f"table {NFT_FAMILY} {NFT_TABLE}\ndelete table {NFT_FAMILY} {NFT_TABLE}\n"
        return (head + self.policy.render_nft()).encode("ascii")

    def nft_list_argv(self) -> list[str]:
        return [self.nft, "--json", "list", "table", NFT_FAMILY, NFT_TABLE]

    def tc_commands(self, veth: str) -> list[list[str]]:
        return [[self.tc, *command[1:]] for command in self.policy.bandwidth_commands(veth)]

    def tc_remove_commands(self, veth: str) -> list[list[str]]:
        _check_interface(veth)
        return [
            [self.tc, "qdisc", "del", "dev", veth, "root"],
            [self.tc, "qdisc", "del", "dev", veth, "ingress"],
        ]

    # -- the box-wide table ----------------------------------------------

    def _ensure_network(self) -> None:
        result = self._run(self.network_inspect_argv())
        if result.returncode != 0:
            if b"not found" not in (result.stderr or b"").lower():
                raise EgressEnforcementError("docker network inspect failed")
            self._ok(self.network_create_argv(), "docker network create")
            result = self._run(self.network_inspect_argv())
            if result.returncode != 0:
                raise EgressEnforcementError("docker network inspect failed")
        try:
            network = json.loads(result.stdout or b"")
            options = network.get("Options") or {}
            driver = network.get("Driver")
        except (AttributeError, UnicodeDecodeError, ValueError) as exc:
            raise EgressEnforcementError("docker network listing is invalid") from exc
        if (
            driver != "bridge"
            or options.get("com.docker.network.bridge.name") != self.policy.bridge
            or options.get("com.docker.network.bridge.enable_icc") != "false"
        ):
            raise EgressEnforcementError(
                f"docker network {self.policy.bridge} exists with other settings; remove it"
            )

    def apply(self) -> bool:
        """Create the network, replace the nft table, and verify it. True when active."""

        with self._lock:
            self._last_attempt = self._clock()
        try:
            self._ensure_network()
            self._ok(self.nft_apply_argv(), "nft apply", stdin=self.nft_ruleset())
        except EgressEnforcementError as exc:
            return self._fail(str(exc))
        return self.verify()

    def verify(self) -> bool:
        """Read the table back and compare it; any difference turns enforcement off."""

        try:
            listing = self._ok(self.nft_list_argv(), "nft list")
        except EgressEnforcementError as exc:
            return self._fail(str(exc))
        if not table_matches(self.policy, listing):
            return self._fail("the nft table does not match the egress policy")
        with self._lock:
            self._active = True
            self._error = None
        return True

    def maintain(self) -> None:
        """Re-check the table on every reaper tick, and re-apply it when it is not active.

        An active table is read back each tick. When that fails, enforcement
        turns off (``lapses`` grows, so the executor ends its ``internet``
        sandboxes) and the table is re-applied at once. A table that stays
        inactive is re-applied at most every ``retry_seconds``.
        """

        with self._lock:
            active = self._active
            last = self._last_attempt
        if active:
            if not self.verify():
                self.apply()
            return
        if last is None or self._clock() - last >= self._retry_seconds:
            self.apply()

    # -- per-sandbox caps ------------------------------------------------

    def find_veth(self, container: str) -> str:
        """The host-side veth of ``container``'s ``eth0``, which must be a bridge port."""

        if not isinstance(container, str) or _CONTAINER_RE.fullmatch(container) is None:
            raise EgressEnforcementError("container name is invalid")
        key = (
            self._ok(
                [
                    self.docker,
                    "container",
                    "inspect",
                    "--format",
                    "{{.NetworkSettings.SandboxKey}}",
                    container,
                ],
                "docker inspect",
            )
            .decode("ascii", "replace")
            .strip()
        )
        if _SANDBOX_KEY_RE.fullmatch(key) is None:
            raise EgressEnforcementError("the sandbox network namespace is unknown")
        inside = self._ok(
            [self.nsenter, f"--net={key}", self.ip, "-o", "link", "show", "dev", "eth0"],
            "reading the sandbox link",
        ).decode("ascii", "replace")
        peer = _PEER_RE.search(inside)
        if peer is None:
            raise EgressEnforcementError("the sandbox has no veth")
        ports = self._ok(
            [self.ip, "-o", "link", "show", "master", self.policy.bridge], "listing bridge ports"
        ).decode("ascii", "replace")
        for index, name in _LINK_RE.findall(ports):
            if index == peer.group(1):
                return _check_interface(name)
        raise EgressEnforcementError("the sandbox veth is not on the egress bridge")

    def _tc_verified(self, veth: str) -> bool:
        qdiscs = json.loads(self._ok([self.tc, "-json", "qdisc", "show", "dev", veth], "tc show"))
        rate = self.policy.bandwidth_mbit * 1_000_000 // 8
        shaped = any(
            isinstance(item, dict)
            and item.get("kind") == "tbf"
            and item.get("root") is True
            and isinstance(item.get("options"), dict)
            and item["options"].get("rate") == rate
            for item in qdiscs
        )
        ingress = any(
            isinstance(item, dict)
            and item.get("kind") == "ingress"
            and item.get("handle") == "ffff:"
            for item in qdiscs
        )
        filters = self._ok(
            [self.tc, "filter", "show", "dev", veth, "ingress"], "tc filter show"
        ).decode("ascii", "replace")
        police = _POLICE_RE.search(filters)
        policed = (
            "matchall" in filters
            and "action drop" in filters
            and police is not None
            and _bits(*police.groups()) == self.policy.bandwidth_mbit * 1_000_000
        )
        return shaped and ingress and policed

    def attach(self, container: str) -> SandboxEgress:
        """Cap one new sandbox and verify it. Raises unless the table is active too."""

        if not self.verify():
            raise EgressEnforcementError("the egress table is not active")
        veth = self.find_veth(container)
        for argv in self.tc_commands(veth):
            self._ok(argv, "tc apply")
        try:
            verified = self._tc_verified(veth)
        except (TypeError, ValueError) as exc:
            raise EgressEnforcementError("tc listing is invalid") from exc
        if not verified:
            raise EgressEnforcementError("the bandwidth cap did not verify")
        attached = SandboxEgress(container, veth)
        with self._lock:
            self._sandboxes[container] = attached
        return attached

    def detach(self, container: str) -> bool:
        """Remove ``container``'s ``tc`` qdiscs. True when removed or the veth is gone."""

        with self._lock:
            attached = self._sandboxes.pop(container, None)
        if attached is None:
            return True
        removed = True
        for argv in self.tc_remove_commands(attached.veth):
            try:
                result = self._run(argv)
            except EgressEnforcementError:
                removed = False
                continue
            stderr = result.stderr or b""
            if result.returncode != 0 and not any(gone in stderr for gone in _ALREADY_GONE):
                removed = False
        return removed
