"""The dispatch registry: the tables that map a wire value to a decoder.

A header names the class that decodes what it carries through these
tables, and third parties add their own decoders to them.

A ``next_protocol()`` that dispatches on a wire field is a lookup in
one of seven tables, each named after that field. A few return a fixed
successor instead (VXLAN, ``DNSOverTCP``, BGP), and MPLS, whose label
stack names no payload protocol, looks up the ``ethertype`` table at
0x0800 or 0x86DD by convention (see :mod:`netprotocols.layer2.mpls`).

===============  =========================================================
``ethertype``    Ethernet II EtherType; VLAN tags and GRE chain here too,
                 and SNAP under OUI 00-00-00 or 00-00-F8; MPLS by
                 convention
``llc.dsap``     IEEE 802.2 LLC DSAP, after an 802.3 Length
``llc.snap``     SNAP protocol under any other OUI, keyed
                 ``(oui << 16) | pid``
``ip.proto``     IPv4 ``protocol``
``ip.proto.v6``  IPv6 ``next_header`` — inherits ``ip.proto``
``udp.port``     UDP well-known port (best-effort; see below)
``tcp.port``     TCP well-known port (best-effort; see below)
===============  =========================================================

An eighth table is read by an accessor, never by ``next_protocol()``:

===============  =========================================================
``sctp.ppid``    SCTP Payload Protocol Identifier, read by
                 :meth:`~netprotocols.SCTPChunk.decode_user_data` for an
                 unfragmented DATA or I-DATA chunk; empty by default
===============  =========================================================

The library registers no decoder in ``sctp.ppid``. A walk ends at SCTP,
so ``decode_as`` accepts the table's name but no walk reads it; pass a
registry to :meth:`~netprotocols.SCTPChunk.decode_user_data` instead::

    reg = Registry.from_defaults()
    reg.register("sctp.ppid", 46, Diameter)
    message = chunk.decode_user_data(reg)

Registering a decoder is how you extend the frame walk without editing
library source::

    from netprotocols import Protocol
    from netprotocols.registry import register

    # 0x88B5 is IEEE 802's Local Experimental EtherType, so no
    # built-in decoder holds it
    @register("ethertype", 0x88B5)
    class Telemetry(Protocol):
        ...

    # or, for a class you did not write (253 is reserved for
    # experimentation, RFC 3692, so no built-in decoder holds it)
    register("ip.proto", 253, Experiment)

The decorator returns the class unchanged, so it stacks with
``@dataclass`` and never interferes with the type.

Key ranges
----------

Three tables reject a key their wire field cannot carry, raising
:class:`InvalidRegistryKeyError` at registration (never on a lookup):

* ``llc.dsap`` takes 0-0xFF, the width of the DSAP octet.
* ``llc.snap`` takes 0 to 2**40 - 1: a 24-bit OUI and a 16-bit PID.
* ``sctp.ppid`` takes 0 to 2**32 - 1, the width of the PPID field.

The other tables accept any key, ``ethertype`` among them. An Ethernet
or VLAN header never consults ``ethertype`` for a type/length value of
1500 or less, which IEEE 802.3 §3.2.6 makes a frame Length
followed by an 802.2 LLC header, nor for the undefined 1501-1535.
But a GRE Protocol Type, and a SNAP PID under OUI 00-00-00 or
00-00-F8, are looked up there whatever their value, and GRE has low
values assigned: RFC 1701's "Current List of Protocol Types"
assigns SNA 0x0004, OSI network layer 0x00FE and PUP 0x0200 ("The
following table of values MUST be used to identify the following
protocols"). A decoder registered at ``ethertype`` 0x00FE is reached
from a GRE Protocol Type or a SNAP PID of 0x00FE, and never from an
Ethernet or VLAN header.

Table inheritance
-----------------

``ip.proto.v6`` inherits ``ip.proto``. IPv4's ``protocol`` and IPv6's
``next_header`` share one number space, but not one table: the four
IPv6 extension headers must be reachable only inside an IPv6 chain, or
a garbage IPv4 packet with ``protocol=0`` would conjure a Hop-by-Hop
layer. So the shared entries are registered once in ``ip.proto`` and
inherited, while the extension headers are registered directly in
``ip.proto.v6`` and stay there. A direct registration in the child
also shadows an inherited key: protocol 51 is ``AH`` in ``ip.proto``
but ``AHv6`` in ``ip.proto.v6``, so that what follows AH dispatches in
its own family's table, and protocol 112 is ``VRRP`` and ``VRRPv6``, so
that each reads its virtual addresses at its own family's width.

A child can also own a key with no class at all: the defaults withhold
protocol 89 from ``ip.proto.v6``, because IPv4's protocol 89 is OSPFv2
and IPv6's is OSPFv3, a different wire format, so ``OSPF`` is
registered in ``ip.proto`` and an IPv6 packet with next header 89 ends
its walk at the IPv6 header. A withheld key behaves like an override
that maps to nothing: a write to the parent does not reach it, and a
registration made directly in the child fills it as usual.

Inheritance is resolved **when you register, not when you look up**: a
write to a parent table is copied into every child that has not
overridden the key. Dispatch is therefore a single ``dict.get`` on a
flat table.

Withholding
-----------

:data:`WITHHELD` in place of a class withholds a key. It reads the same
on the global registry and for one walk::

    from netprotocols import decode_frame
    from netprotocols.registry import WITHHELD, register

    register("udp.port", 1812, WITHHELD, override=True)  # every walk
    decode_frame(frame, decode_as={"udp.port": {1812: WITHHELD}})

A withheld key dispatches to nothing, exactly like a key that was never
registered: the walk ends at the header that named it, with the payload
left undecoded, and a port table still tries the other port of the
pair. Withholding in a parent table reaches every child that inherits
the key, as a registration does. Withholding is idempotent, and it never
undoes a class registered directly in the same table unless it is
passed ``override=True``, which ``decode_as`` and :meth:`Registry.derive`
always pass; a key inherited from a parent is withheld either way. A
later registration of a class directly in the same table fills a withheld
key without ``override=True``, a global withhold included.
``None`` is not a decoder and is refused with :class:`TypeError`.

Global and isolated registries
------------------------------

:data:`DEFAULT` is the process-wide registry, and it is what
``next_protocol()`` reads when it is given no registry, as in a
:func:`~netprotocols.decode_frame` call without ``registry=`` or
``decode_as=``.

When you need registrations that do *not* leak into the rest of the
process — you are embedding this library, or you are testing a decoder —
build your own and hand it to the frame walker instead::

    reg = Registry.from_defaults()
    reg.register("udp.port", 6969, DNS)

:meth:`Registry.derive` makes a cheap copy-on-write child, which is how
a per-call decoder override is expressed without touching global state.

Best-effort tables
------------------

``udp.port`` and ``tcp.port`` differ from the other five tables a walk
reads in kind, not just in name. An EtherType or IP protocol number is
authoritative: the field exists to say what follows (MPLS, which looks
up the ``ethertype`` table by convention, is the exception described
above). A port is a *guess* — any service may run on any port, and the
discriminator is split across two fields.
Dispatch on those tables checks the destination port first (a request
targets the server's well-known port) and then the source port (a
response comes from it). The class it names validates on decode, but
can only reject what its format tells apart from noise: a wrong guess
that it rejects takes the ordinary malformed-frame path, and one it
accepts decodes cleanly into a wrong layer. DNS and DHCP accept almost
any datagram long enough for their fixed headers. A caller who knows
what a port carries says so with :meth:`Registry.derive` or
``decode_frame(..., decode_as=...)`` rather than trusting the guess.
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Iterable, Mapping
from typing import TYPE_CHECKING, Final, TypeVar, overload

from netprotocols.utils.exceptions import ProtocolError

if TYPE_CHECKING:
    from netprotocols._base import Protocol

__all__ = [
    "DEFAULT",
    "TABLES",
    "TABLE_ETHERTYPE",
    "TABLE_IP_PROTO",
    "TABLE_IP_PROTO_V6",
    "TABLE_LLC_DSAP",
    "TABLE_LLC_SNAP",
    "TABLE_SCTP_PPID",
    "TABLE_TCP_PORT",
    "TABLE_UDP_PORT",
    "WITHHELD",
    "InvalidRegistryKeyError",
    "Registry",
    "RegistryConflictError",
    "UnknownTableError",
    "WithheldType",
    "register",
    "register_all",
]

TABLE_ETHERTYPE = "ethertype"
TABLE_LLC_DSAP = "llc.dsap"
TABLE_LLC_SNAP = "llc.snap"
TABLE_IP_PROTO = "ip.proto"
TABLE_IP_PROTO_V6 = "ip.proto.v6"
TABLE_UDP_PORT = "udp.port"
TABLE_TCP_PORT = "tcp.port"
TABLE_SCTP_PPID = "sctp.ppid"

#: Every dispatch table, mapped to the table it inherits from (``None``
#: for a root table). Adding an entry here is all it takes to give a new
#: dispatch point a name third parties can register against.
TABLES: Mapping[str, str | None] = {
    TABLE_ETHERTYPE: None,
    TABLE_LLC_DSAP: None,
    TABLE_LLC_SNAP: None,
    TABLE_IP_PROTO: None,
    TABLE_IP_PROTO_V6: TABLE_IP_PROTO,
    TABLE_UDP_PORT: None,
    TABLE_TCP_PORT: None,
    TABLE_SCTP_PPID: None,
}

#: The inverse of :data:`TABLES`, precomputed: which tables inherit from
#: each one. Consulted on every registration, never on a lookup.
_CHILDREN: Mapping[str, tuple[str, ...]] = {
    parent: tuple(name for name, of in TABLES.items() if of == parent)
    for parent in TABLES
}

#: The keys a table accepts, for the tables whose wire field bounds
#: them (see "Key ranges" in the module docstring). Checked when a key is
#: registered, never on a lookup.
_KEY_RANGES: Mapping[str, range] = {
    TABLE_LLC_DSAP: range(0x100),
    TABLE_LLC_SNAP: range(1 << 40),
    TABLE_SCTP_PPID: range(1 << 32),
}

_C = TypeVar("_C", bound="type[Protocol]")


class WithheldType(enum.Enum):
    """The type of :data:`WITHHELD`, whose only member it is."""

    WITHHELD = "WITHHELD"

    def __repr__(self) -> str:
        return "WITHHELD"


#: The value registered in place of a class to withhold a key: a
#: withheld key dispatches to nothing (see "Withholding" in the module
#: docstring).
WITHHELD: Final = WithheldType.WITHHELD


class UnknownTableError(ProtocolError):
    """A registration or lookup named a table that does not exist.

    Raised at once, with the valid names listed, so a typo in a table
    name never registers a decoder that nothing consults.
    """


class InvalidRegistryKeyError(ProtocolError):
    """A registration named a key its table's wire field cannot carry.

    Raised for an ``llc.dsap`` key outside 0-0xFF, an ``llc.snap`` key
    outside 0 to 2**40 - 1 and an ``sctp.ppid`` key outside 0 to
    2**32 - 1 (a negative key included), the values the fields they are
    read from can carry. No other table raises it.
    See "Key ranges" in the module docstring.
    """


class RegistryConflictError(ProtocolError):
    """A key in a dispatch table is already held by another class.

    Registering over an existing entry requires ``override=True``, so
    that two packages claiming the same port cannot silently resolve by
    import order. Re-registering the *same* class to the same key is a
    no-op, not an error, so a decorator that re-runs when its module is
    re-executed does not raise.
    """


class Registry:
    """A set of dispatch tables mapping a wire value to a decoder.

    Most callers want :data:`DEFAULT`, through the module-level
    :func:`register`, and never construct one of these. Build your own
    when registrations must not escape into the rest of the process:
    :meth:`from_defaults` starts from the built-in decoders, plain
    ``Registry()`` starts empty.
    """

    __slots__ = ("_own", "_tables")

    def __init__(self) -> None:
        #: Flattened lookup tables — inherited entries already merged in.
        #: This is what dispatch reads, and the layer modules hold these
        #: dict objects directly, so they are mutated in place and never
        #: rebound. A withheld key is absent from them.
        self._tables: dict[str, dict[int, type[Protocol]]] = {
            name: {} for name in TABLES
        }
        #: Registrations made *directly* on each table, as opposed to
        #: inherited into it, so that a later write to a parent
        #: cannot clobber an override in a child. A withheld key maps to
        #: :data:`WITHHELD`.
        self._own: dict[str, dict[int, type[Protocol] | WithheldType]] = {
            name: {} for name in TABLES
        }

    @classmethod
    def from_defaults(cls) -> Registry:
        """Return a registry seeded with this library's built-in decoders.

        The copy is independent: registering on it leaves :data:`DEFAULT`
        — and therefore ``next_protocol()`` — untouched.
        """
        return DEFAULT.derive()

    def table(self, name: str) -> dict[int, type[Protocol]]:
        """Return the flattened lookup table ``name``.

        Inherited entries are included and withheld keys are absent. This
        is the live dict the registry dispatches through, not a copy: the
        layer modules bind it once at import so that a lookup is a bare
        ``dict.get``. Treat it as read-only and go through
        :meth:`register` to change it.
        """
        try:
            return self._tables[name]
        except KeyError:
            raise _unknown_table(name) from None

    def get(self, table: str, key: int) -> type[Protocol] | None:
        """Return the class registered for ``key`` in ``table``, or ``None``.

        ``None`` is an ordinary answer rather than an error: the chain
        ends here, either because nothing is encapsulated, because
        this library does not implement what is, or because the key is
        withheld.
        """
        return self.table(table).get(key)

    def get_port(
        self, table: str, src_port: int, dst_port: int
    ) -> type[Protocol] | None:
        """Return the class for a port pair, destination tried first.

        A request targets the server's well-known port and a response
        comes from it, so the destination is the better guess of the two
        (see "Best-effort tables" in the module docstring).
        """
        entries = self.table(table)
        return entries.get(dst_port) or entries.get(src_port)

    def register(
        self,
        table: str,
        key: int,
        protocol: type[Protocol] | WithheldType,
        *,
        override: bool = False,
    ) -> None:
        """Register ``protocol`` as the decoder for ``key`` in ``table``.

        :data:`WITHHELD` in place of a class withholds ``key``: it
        dispatches to nothing, and a later write to a parent table does
        not reach it (see "Withholding" in the module docstring).

        :param table: The dispatch table's name, one of :data:`TABLES`.
        :param key: The wire value to dispatch on.
        :param protocol: The class that decodes what that value names, or
            :data:`WITHHELD`.
        :param override: Replace a different class already holding
            ``key``, instead of raising. With :data:`WITHHELD`, replace a
            class registered directly in ``table``, instead of leaving it
            in place.
        :raises UnknownTableError: if ``table`` is not one of
            :data:`TABLES`.
        :raises InvalidRegistryKeyError: if ``table`` is ``llc.dsap``,
            ``llc.snap`` or ``sctp.ppid`` and ``key`` is outside the range
            it accepts (see "Key ranges" in the module docstring).
        :raises TypeError: if ``protocol`` is ``None``.
        :raises RegistryConflictError: if ``key`` is held by a different
            class and ``override`` is false. Re-registering the same
            class to the same key succeeds and changes nothing, and so
            does withholding a key that is withheld already or that
            holds a class registered directly in ``table``.
        """
        entries = self.table(table)
        _check_key(table, key)
        own = self._own[table]
        if protocol is WITHHELD:
            if key in own and not override:
                return
        elif protocol is None:
            raise TypeError(
                f"{table} {key!r} maps to None, which is not a decoder; "
                f"use netprotocols.registry.WITHHELD to make the key "
                f"dispatch to nothing"
            )
        else:
            incumbent = entries.get(key)
            if (
                incumbent is not None
                and incumbent is not protocol
                and not override
            ):
                raise RegistryConflictError(
                    f"{table} {key!r} is already registered to "
                    f"{_qualname(incumbent)}; pass override=True to "
                    f"replace it with {_qualname(protocol)}"
                )
        own[key] = protocol
        self._publish(table, key, protocol)

    def _publish(
        self, table: str, key: int, protocol: type[Protocol] | WithheldType
    ) -> None:
        """Write an entry into ``table`` and every child not overriding it.

        :data:`WITHHELD` removes the entry instead. A child that holds
        ``key`` itself, or withholds it, is skipped.

        Entries are written in place rather than rebuilt, so the flat
        dicts the layer modules hold stay valid and are never observed
        empty by a concurrent reader.
        """
        if protocol is WITHHELD:
            self._tables[table].pop(key, None)
        else:
            self._tables[table][key] = protocol
        for child in _CHILDREN[table]:
            if key not in self._own[child]:
                self._publish(child, key, protocol)

    def derive(
        self,
        overrides: Mapping[str, Mapping[int, type[Protocol] | WithheldType]]
        | None = None,
    ) -> Registry:
        """Return a child registry: this one's entries, plus ``overrides``.

        Copy-on-write and independent in both directions — later changes
        to either registry do not reach the other. This is the primitive
        behind a per-call decoder override ("Decode As"), where a caller
        wants DNS read on port 6969 for one capture without changing how
        the rest of the process decodes::

            reg = DEFAULT.derive({"udp.port": {6969: DNS}})

        Overrides replace whatever they land on, so no conflict is
        raised. :data:`WITHHELD` as an override withholds the key in the
        child, whatever this registry holds there, and a class as an
        override fills a key this registry withholds.

        :param overrides: Entries to register on the child with
            ``override=True``, keyed by table name and then by key.
        :raises UnknownTableError: if an override names a table that is
            not one of :data:`TABLES`.
        :raises InvalidRegistryKeyError: if an override names an
            ``llc.dsap``, ``llc.snap`` or ``sctp.ppid`` key outside the
            range that table accepts (see "Key ranges" in the module
            docstring).
        :raises TypeError: if an override maps a key to ``None``.
        """
        child = Registry()
        for name in TABLES:
            child._tables[name] = dict(self._tables[name])
            child._own[name] = dict(self._own[name])
        for table, entries in (overrides or {}).items():
            for key, protocol in entries.items():
                child.register(table, key, protocol, override=True)
        return child

    def __repr__(self) -> str:
        sizes = ", ".join(
            f"{name}={len(entries)}" for name, entries in self._tables.items()
        )
        return f"<{type(self).__name__} {sizes}>"


def _check_key(table: str, key: int) -> None:
    """Refuse a key outside the range ``table`` accepts.

    :param table: The dispatch table's name.
    :param key: The key to check.
    :raises InvalidRegistryKeyError: if ``key`` is outside that range.
    """
    accepted = _KEY_RANGES.get(table)
    if accepted is not None and key not in accepted:
        raise InvalidRegistryKeyError(
            f"{table} key {key!r} is outside {accepted.start:#x}-"
            f"{accepted.stop - 1:#x}, the values that table dispatches"
        )


def _qualname(protocol: type[Protocol]) -> str:
    return f"{protocol.__module__}.{protocol.__qualname__}"


def _unknown_table(name: str) -> UnknownTableError:
    known = ", ".join(sorted(TABLES))
    return UnknownTableError(f"no such dispatch table {name!r}; known: {known}")


#: The process-wide registry, populated with the built-in decoders when
#: ``netprotocols`` is imported. ``next_protocol()`` dispatches through
#: it, so registering here changes decoding for the whole process —
#: which is what an application wants and what a library should avoid.
#: See :meth:`Registry.from_defaults` for the isolated form.
DEFAULT = Registry()


@overload
def register(
    table: str,
    key: int,
    protocol: None = ...,
    *,
    override: bool = ...,
    registry: Registry | None = ...,
) -> Callable[[_C], _C]: ...


@overload
def register(
    table: str,
    key: int,
    protocol: type[Protocol] | WithheldType,
    *,
    override: bool = ...,
    registry: Registry | None = ...,
) -> None: ...


def register(
    table: str,
    key: int,
    protocol: type[Protocol] | WithheldType | None = None,
    *,
    override: bool = False,
    registry: Registry | None = None,
) -> Callable[[_C], _C] | None:
    """Register a decoder, as a decorator or as a direct call.

    Used as a decorator, the class is returned unchanged::

        @register("ethertype", 0x88B5)
        class Telemetry(Protocol):
            ...

    Used directly, ``protocol`` names a class you did not write::

        register("ip.proto", 253, Experiment)

    or is :data:`WITHHELD`, to make the key dispatch to nothing::

        register("udp.port", 1812, WITHHELD, override=True)

    Registrations land in :data:`DEFAULT` — process-wide — unless
    ``registry`` names another. See :meth:`Registry.register` for the
    conflict rules and for withholding.
    """
    target = DEFAULT if registry is None else registry
    if protocol is not None:
        target.register(table, key, protocol, override=override)
        return None

    def decorate(cls: _C) -> _C:
        target.register(table, key, cls, override=override)
        return cls

    return decorate


def register_all(
    table: str,
    keys: Iterable[int],
    protocol: type[Protocol] | WithheldType,
    *,
    override: bool = False,
    registry: Registry | None = None,
) -> None:
    """Register one class against several keys of the same table.

    For protocols that a single value cannot describe: a VLAN tag is any
    of three EtherTypes, DHCP answers on two ports.

    The keys are registered one at a time, in order, and not atomically:
    when one raises, as :meth:`Registry.register` describes, the keys
    before it stay registered and the ones after it are not tried.

    :param table: The dispatch table's name, one of :data:`TABLES`.
    :param keys: The wire values to register ``protocol`` against.
    :param protocol: The class that decodes what those values name, or
        :data:`WITHHELD` to withhold every key.
    :param override: Replace a different class already holding a key,
        instead of raising; with :data:`WITHHELD`, as
        :meth:`Registry.register` describes.
    :param registry: The registry to register on; :data:`DEFAULT` when
        ``None``.
    :raises UnknownTableError: if ``table`` is not one of
        :data:`TABLES`.
    :raises InvalidRegistryKeyError: if ``table`` is ``llc.dsap``,
        ``llc.snap`` or ``sctp.ppid`` and a key is outside the range it
        accepts (see "Key ranges" in the module docstring).
    :raises TypeError: if ``protocol`` is ``None`` and ``keys`` is not
        empty.
    :raises RegistryConflictError: if a key is held by a different
        class and ``override`` is false.
    """
    target = DEFAULT if registry is None else registry
    for key in keys:
        target.register(table, key, protocol, override=override)
