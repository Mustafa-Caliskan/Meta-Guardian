"""Address classification shared by the gateway and the MCP tools.

A blocklist is an attacker list. It must never contain infrastructure, or the
defence takes itself down. Documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) are deliberately **not** protected: they are the synthetic
attacker addresses the demo uses, and they are not routable infrastructure.
"""

from __future__ import annotations

import ipaddress

INFRA_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def parse_address(value: object) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def is_protected_address(value: object) -> bool:
    """True for loopback, unspecified, multicast and private infrastructure."""
    address = parse_address(value)
    if address is None:
        return False
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
    ):
        return True
    return any(
        address in network
        for network in INFRA_NETWORKS
        if network.version == address.version
    )


__all__ = ["INFRA_NETWORKS", "is_protected_address", "parse_address"]
