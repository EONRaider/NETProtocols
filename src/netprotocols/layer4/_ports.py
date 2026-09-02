"""Port-based application-protocol dispatch for the transport layer.

Unlike the EtherType and IP-protocol tables — where a single
authoritative field names what follows — application protocols are
identified by *port*, which is a heuristic: any service may run on any
port, and the discriminator is split across two fields (source and
destination). Dispatch therefore checks the destination port first (a
request targets the server's well-known port) and then the source port
(a response comes from it), and the resulting class is expected to
validate strictly on decode so that a wrong guess degrades to the
library's ordinary malformed-frame path rather than yielding garbage.

DNS over TCP carries a 2-byte length prefix (RFC 1035 §4.2.2), so the
TCP table names a small length-prefix shim (``DNSOverTCP``) rather than
``DNS`` directly; the shim consumes the prefix and then chains to the
DNS message, keeping the chain walk uniform.
"""

from __future__ import annotations

from netprotocols._base import Protocol
from netprotocols.registry import DEFAULT, TABLE_TCP_PORT, TABLE_UDP_PORT

__all__ = ["tcp_app_class", "udp_app_class"]

#: The flat ``udp.port`` and ``tcp.port`` dispatch tables of the default
#: registry, bound once at import. Registering a decoder mutates these
#: dicts in place rather than replacing them, so the references stay
#: live and a lookup stays a bare ``dict.get`` — see
#: :mod:`netprotocols.registry`.
_UDP_APP_CLASSES: dict[int, type[Protocol]] = DEFAULT.table(TABLE_UDP_PORT)
_TCP_APP_CLASSES: dict[int, type[Protocol]] = DEFAULT.table(TABLE_TCP_PORT)


def udp_app_class(src_port: int, dst_port: int) -> type[Protocol] | None:
    """The class that decodes a UDP payload, chosen by well-known port.

    Returns ``None`` when neither port names a known application
    protocol — the common case, where the chain ends at UDP.
    """
    return _UDP_APP_CLASSES.get(dst_port) or _UDP_APP_CLASSES.get(src_port)


def tcp_app_class(src_port: int, dst_port: int) -> type[Protocol] | None:
    """The class that decodes a TCP payload, chosen by well-known port.

    DNS over TCP is length-prefixed (RFC 1035 §4.2.2), so port 53 names
    :class:`~netprotocols.DNSOverTCP` — a 2-byte length shim that then
    chains to the DNS message. Returns ``None`` when neither port names a
    known application protocol (the common case, where the chain ends at
    TCP).
    """
    return _TCP_APP_CLASSES.get(dst_port) or _TCP_APP_CLASSES.get(src_port)
