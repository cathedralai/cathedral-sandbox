"""Egress policy for ``internet`` sandboxes on a TEE box.

Owner decision 6 (v1): an ``internet`` sandbox reaches the public internet
only. It may not reach private, link-local, loopback, multicast or reserved
ranges, cloud metadata services, or the box's own addresses, and each sandbox
has a bandwidth cap. A ``deny_all`` sandbox has no network at all.

This module only computes and renders the policy as text and argv lists. It
never applies a rule. Applying the rendered nft ruleset and ``tc`` commands on
a live box is not done yet (docs/TEE_BOX_SERVICE.md).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

DEFAULT_BANDWIDTH_MBIT = 100
MAX_BANDWIDTH_MBIT = 100_000
MAX_BOX_ADDRESSES = 64
DEFAULT_BRIDGE = "cathsbx0"
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")

# Ranges no internet sandbox may reach. Every row is non-global by IANA, or a
# transition prefix that can embed a non-global IPv4 address.
DENIED_IPV4: tuple[str, ...] = (
    "0.0.0.0/8",  # "this network"
    "10.0.0.0/8",  # RFC 1918
    "100.64.0.0/10",  # CGNAT, RFC 6598 (holds Alibaba metadata 100.100.100.200)
    "127.0.0.0/8",  # loopback
    "169.254.0.0/16",  # link-local (holds 169.254.169.254 metadata)
    "172.16.0.0/12",  # RFC 1918
    "192.0.0.0/24",  # IETF protocol assignments (holds Oracle 192.0.0.192)
    "192.0.2.0/24",  # TEST-NET-1
    "192.88.99.0/24",  # deprecated 6to4 relay anycast
    "192.168.0.0/16",  # RFC 1918
    "198.18.0.0/15",  # benchmarking
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",  # TEST-NET-3
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved, includes 255.255.255.255
)
DENIED_IPV6: tuple[str, ...] = (
    "::/128",  # unspecified
    "::1/128",  # loopback
    "::ffff:0:0/96",  # IPv4-mapped
    "64:ff9b::/96",  # NAT64 well-known (can embed a private IPv4)
    "64:ff9b:1::/48",  # NAT64 local use
    "100::/64",  # discard-only
    "2001::/32",  # Teredo
    "2001:db8::/32",  # documentation
    "2002::/16",  # 6to4 (can embed a private IPv4)
    "fc00::/7",  # unique local (holds AWS IMDS fd00:ec2::254)
    "fe80::/10",  # link-local
    "fec0::/10",  # deprecated site-local
    "ff00::/8",  # multicast
)
# Cloud metadata and host-agent endpoints, listed on their own so the policy
# still names them if a range above is ever narrowed. Azure's WireServer is a
# public address that only the host answers, so no range covers it.
METADATA_ADDRESSES: tuple[str, ...] = (
    "169.254.169.254/32",  # AWS, GCP, Azure, OCI, DigitalOcean IMDS
    "169.254.170.2/32",  # AWS ECS task metadata
    "100.100.100.200/32",  # Alibaba Cloud
    "168.63.129.16/32",  # Azure WireServer
    "192.0.0.192/32",  # Oracle Cloud legacy metadata
    "fd00:ec2::254/128",  # AWS IMDS over IPv6
)


class EgressPolicyError(ValueError):
    """The egress policy inputs are invalid."""


@dataclass(frozen=True)
class EgressPolicy:
    """The deny list and per-sandbox cap for ``internet`` sandboxes."""

    denied: tuple[IPNetwork, ...]
    box_addresses: tuple[IPNetwork, ...]
    bandwidth_mbit: int
    bridge: str

    @property
    def denied_ipv4(self) -> tuple[ipaddress.IPv4Network, ...]:
        return tuple(net for net in self.denied if net.version == 4)

    @property
    def denied_ipv6(self) -> tuple[ipaddress.IPv6Network, ...]:
        return tuple(net for net in self.denied if net.version == 6)

    def denies(self, address: str) -> bool:
        """True when a sandbox may not reach ``address`` under this policy."""

        ip = ipaddress.ip_address(address)
        return any(ip.version == net.version and ip in net for net in self.denied)

    def render_nft(self) -> str:
        """Render an ``nft -f`` ruleset for the sandbox bridge.

        Forwarded packets from the bridge to a denied destination are dropped.
        Every packet from the bridge addressed to the box itself (the worker
        port, the executor, guest services) arrives on the input hook and is
        dropped there, whatever its destination address.
        """

        def elements(networks: Iterable[IPNetwork]) -> str:
            # nft refuses overlapping interval elements, so render the
            # collapsed ranges. The metadata /32s sit inside wider ranges.
            return ", ".join(str(net) for net in ipaddress.collapse_addresses(networks))

        bridge = self.bridge
        return (
            "table inet cathedral_tee_box_egress {\n"
            "  set deny4 {\n"
            "    type ipv4_addr; flags interval;\n"
            f"    elements = {{ {elements(self.denied_ipv4)} }}\n"
            "  }\n"
            "  set deny6 {\n"
            "    type ipv6_addr; flags interval;\n"
            f"    elements = {{ {elements(self.denied_ipv6)} }}\n"
            "  }\n"
            "  chain forward {\n"
            "    type filter hook forward priority -1; policy accept;\n"
            f'    iifname "{bridge}" ip daddr @deny4 counter drop\n'
            f'    iifname "{bridge}" ip6 daddr @deny6 counter drop\n'
            "  }\n"
            "  chain input {\n"
            "    type filter hook input priority -1; policy accept;\n"
            f'    iifname "{bridge}" counter drop\n'
            "  }\n"
            "}\n"
        )

    def bandwidth_commands(self, interface: str) -> tuple[tuple[str, ...], ...]:
        """Return ``tc`` argv lists capping one sandbox's host-side veth.

        The root token bucket caps traffic toward the sandbox; the ingress
        policer caps traffic the sandbox sends. Nothing here runs them.
        """

        _check_interface(interface)
        rate = f"{self.bandwidth_mbit}mbit"
        # Burst of about 10 ms at the capped rate, at least 32 KiB.
        burst = f"{max(32 * 1024, self.bandwidth_mbit * 1_000_000 // 8 // 100)}b"
        return (
            (
                "tc",
                "qdisc",
                "replace",
                "dev",
                interface,
                "root",
                "tbf",
                "rate",
                rate,
                "burst",
                burst,
                "latency",
                "50ms",
            ),
            ("tc", "qdisc", "replace", "dev", interface, "handle", "ffff:", "ingress"),
            (
                "tc",
                "filter",
                "replace",
                "dev",
                interface,
                "parent",
                "ffff:",
                "matchall",
                "action",
                "police",
                "rate",
                rate,
                "burst",
                burst,
                "drop",
            ),
        )

    def docker_network_args(self, network: str) -> tuple[str, ...]:
        """Docker ``run`` options that select the sandbox's network."""

        if network == "deny_all":
            return ("--network", "none")
        if network == "internet":
            return ("--network", self.bridge)
        raise EgressPolicyError("network must be internet or deny_all")

    def describe(self) -> dict[str, object]:
        return {
            "denied": [str(net) for net in self.denied],
            "bandwidth_mbit": self.bandwidth_mbit,
        }


def _check_interface(name: object) -> str:
    if not isinstance(name, str) or _INTERFACE_RE.fullmatch(name) is None:
        raise EgressPolicyError("interface name is invalid")
    return name


def build_egress_policy(
    box_addresses: Iterable[str],
    *,
    bandwidth_mbit: int = DEFAULT_BANDWIDTH_MBIT,
    bridge: str = DEFAULT_BRIDGE,
) -> EgressPolicy:
    """Build the v1 policy: fixed deny ranges, metadata, and the box's own addresses."""

    if isinstance(box_addresses, (str, bytes)):
        raise EgressPolicyError("box addresses must be a list")
    if (
        isinstance(bandwidth_mbit, bool)
        or not isinstance(bandwidth_mbit, int)
        or not 1 <= bandwidth_mbit <= MAX_BANDWIDTH_MBIT
    ):
        raise EgressPolicyError("bandwidth cap must be 1 to 100000 Mbit/s")
    _check_interface(bridge)
    own: list[IPNetwork] = []
    for raw in box_addresses:
        if not isinstance(raw, str) or len(raw) > 64:
            raise EgressPolicyError("box address is invalid")
        try:
            own.append(ipaddress.ip_network(raw, strict=True))
        except ValueError as exc:
            raise EgressPolicyError("box address is invalid") from exc
        if len(own) > MAX_BOX_ADDRESSES:
            raise EgressPolicyError("too many box addresses")
    if not own:
        raise EgressPolicyError("the box's own addresses are required")
    denied: list[IPNetwork] = []
    for text in (*DENIED_IPV4, *DENIED_IPV6, *METADATA_ADDRESSES):
        denied.append(ipaddress.ip_network(text))
    denied.extend(own)
    unique = sorted(set(denied), key=lambda net: (net.version, net.network_address, net.prefixlen))
    return EgressPolicy(
        denied=tuple(unique),
        box_addresses=tuple(own),
        bandwidth_mbit=bandwidth_mbit,
        bridge=bridge,
    )
