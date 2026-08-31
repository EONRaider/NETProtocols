"""Port-based application-protocol dispatch for the transport layer.

Unlike the EtherType and IP-protocol registries — where a single
authoritative field names what follows — application protocols are
identified by *port*, which is a heuristic: any service may run on any
port, and the discriminator is split across two fields (source and
destination). Dispatch therefore checks the destination port first (a
request targets the server's well-known port) and then the source port
(a response comes from it), and the resulting class is expected to
validate strictly on decode so that a wrong guess degrades to the
library's ordinary malformed-frame path rather than yielding garbage.

Only UDP is wired this round. TCP application protocols (DNS over TCP
carries a 2-byte length prefix, RFC 1035 §4.2.2) need their own
handling and are left for later.
"""

from __future__ import annotations

from netprotocols._base import Protocol

__all__ = ["udp_app_class"]


def udp_app_class(src_port: int, dst_port: int) -> type[Protocol] | None:
    """The class that decodes a UDP payload, chosen by well-known port.

    Returns ``None`` when neither port names a known application
    protocol — the common case, where the chain ends at UDP.
    """
    from netprotocols.layer7.dhcp import DHCP
    from netprotocols.layer7.dns import DNS

    registry: dict[int, type[Protocol]] = {53: DNS, 67: DHCP, 68: DHCP}
    return registry.get(dst_port) or registry.get(src_port)
