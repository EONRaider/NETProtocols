"""Canonical, direction-independent flow identification.

:func:`flow_key` folds a TCP/UDP segment and its enclosing IPv4/IPv6
header into a :class:`FlowKey` that is identical for both directions of
one conversation — a request and its reply produce the same key,
regardless of which one you feed in, because the two ``(address,
port)`` endpoints are always emitted in the same (lexicographically
smaller first) order::

    >>> flow_key(tcp_syn, ip=ip_header) == flow_key(tcp_syn_ack, ip=ip_header)
    True

There is no port-slot convention invented for protocols that don't have
ports: a transport layer other than TCP/UDP (ICMP, for instance) has no
flow to key, so both :func:`flow_key` and :meth:`Packet.flow_key
<netprotocols.packet.Packet.flow_key>` return ``None`` for it rather
than raising or stuffing type/code into a port field — the same
"``None``, not an exception" contract this library already uses for an
accessor that doesn't apply (the NDP accessors in
:mod:`netprotocols.layer3.icmp`, ``Packet.get``).
"""

from __future__ import annotations

from typing import NamedTuple

from netprotocols._base import Protocol
from netprotocols.layer3.ip import IPv4, IPv6
from netprotocols.layer4.tcp import TCP
from netprotocols.layer4.udp import UDP
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["FlowKey", "flow_key"]


class FlowKey(NamedTuple):
    """A hashable, direction-independent identifier for one flow.

    Comparing the two ``(address, port)`` endpoints needs ordinary
    ``<=`` — which a plain tuple already gives for free — so this is a
    :class:`typing.NamedTuple` rather than a frozen dataclass; every
    other frozen dataclass in this codebase models a wire format
    (``decode()`` / ``__bytes__`` / ``_struct``), and a derived key
    isn't one.

    :param addr_a: The lexicographically smaller of the two endpoint
        addresses.
    :param addr_b: The other endpoint address.
    :param port_a: The port paired with ``addr_a``.
    :param port_b: The port paired with ``addr_b``.
    :param protocol: The IP protocol number (``IPv4.protocol`` /
        ``IPv6.next_header``) of the transport layer, e.g. ``6`` for
        TCP.
    """

    addr_a: str
    addr_b: str
    port_a: int | None
    port_b: int | None
    protocol: int


def flow_key(
    layer: Protocol, *, ip: IPv4 | IPv6 | None = None
) -> FlowKey | None:
    """The canonical :class:`FlowKey` for a TCP/UDP segment.

    :param layer: The transport layer. Anything other than
        :class:`~netprotocols.TCP` / :class:`~netprotocols.UDP` (an
        ICMP message, for instance) has no ports to key on and returns
        ``None`` — this is not an error, just a layer this function
        does not apply to.
    :param ip: The enclosing :class:`~netprotocols.IPv4` /
        :class:`~netprotocols.IPv6` header, keyword-only. Required
        when ``layer`` is TCP/UDP, since the addresses come from it —
        ``IPv4.protocol`` and ``IPv6.next_header`` are the same
        semantic field under different names, so this reads whichever
        one ``ip`` actually has.
    :raises InvalidFieldError: ``layer`` is TCP/UDP but ``ip`` is
        ``None``.
    """
    if not isinstance(layer, (TCP, UDP)):
        return None
    if ip is None:
        raise InvalidFieldError(
            f"Computing a flow key for {type(layer).__name__} requires "
            f"the enclosing IPv4/IPv6 layer (its addresses are half the "
            f"key)",
            protocol=type(layer),
            field="ip",
        )
    protocol_number = ip.protocol if isinstance(ip, IPv4) else ip.next_header
    a = (ip.src, layer.src_port)
    b = (ip.dst, layer.dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return FlowKey(lo[0], hi[0], lo[1], hi[1], protocol_number)
