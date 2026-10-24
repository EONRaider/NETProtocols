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

import typing
from typing import NamedTuple

from netprotocols._base import Protocol
from netprotocols._enums import IPProtocol
from netprotocols.layer3.ip import IPv4, IPv6
from netprotocols.layer4.tcp import TCP
from netprotocols.layer4.udp import UDP
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["FlowKey", "flow_key"]


class _PortedLayer(typing.Protocol):
    """What :func:`flow_key` reads from a transport layer."""

    @property
    def src_port(self) -> int: ...

    @property
    def dst_port(self) -> int: ...


#: The transport layers :func:`flow_key` keys on, each with the IP
#: protocol number that names it — one entry per transport, read by
#: :meth:`Packet.flow_key <netprotocols.packet.Packet.flow_key>` too.
#: The number comes from here, not from the enclosing IP header: that
#: header's ``protocol`` / ``next_header`` names whatever directly
#: follows it, which may be an IPv6 extension header or IPsec AH.
_TRANSPORT_PROTOCOLS: dict[type[_PortedLayer], int] = {
    TCP: IPProtocol.TCP.value,
    UDP: IPProtocol.UDP.value,
}
_TRANSPORTS = tuple(_TRANSPORT_PROTOCOLS)


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
    :param protocol: The IP protocol number of the transport layer:
        ``6`` for TCP, ``17`` for UDP. It names the transport itself,
        so it is the same whether the segment follows its IP header
        directly or behind IPv6 extension headers or IPsec AH, where
        the IP header's own ``protocol`` / ``next_header`` names the
        first of those instead.
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
        when ``layer`` is TCP/UDP, since the addresses come from it.
        Only its addresses are read: the protocol number is
        ``layer``'s own, so headers between ``ip`` and ``layer`` (IPv6
        extension headers, AH) do not change the key.
    :raises InvalidFieldError: ``layer`` is TCP/UDP but ``ip`` is
        ``None``.
    """
    if not isinstance(layer, _TRANSPORTS):
        return None
    if ip is None:
        raise InvalidFieldError(
            f"Computing a flow key for {type(layer).__name__} requires "
            f"the enclosing IPv4/IPv6 layer (its addresses are half the "
            f"key)",
            protocol=type(layer),
            field="ip",
        )
    protocol_number = next(
        number
        for transport, number in _TRANSPORT_PROTOCOLS.items()
        if isinstance(layer, transport)
    )
    a = (ip.src, layer.src_port)
    b = (ip.dst, layer.dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return FlowKey(lo[0], hi[0], lo[1], hi[1], protocol_number)
