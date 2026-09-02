"""The dispatch registry: how a header names the class that decodes
what it carries, and how third parties add their own.

Every ``next_protocol()`` in this library is a lookup in one of five
tables, each named after the wire field it dispatches on:

===============  =======================================================
``ethertype``    Ethernet II EtherType; VLAN tags and GRE chain here too
``ip.proto``     IPv4 ``protocol``
``ip.proto.v6``  IPv6 ``next_header`` — inherits ``ip.proto``
``udp.port``     UDP well-known port (best-effort; see below)
``tcp.port``     TCP well-known port (best-effort; see below)
===============  =======================================================

Registering a decoder is how you extend the frame walk without editing
library source::

    from netprotocols import Protocol
    from netprotocols.registry import register

    @register("ethertype", 0x8847)
    class MPLS(Protocol):
        ...

    # or, for a class you did not write
    register("ip.proto", 132, SCTP)

The decorator returns the class unchanged, so it stacks with
``@dataclass`` and never interferes with the type.

Table inheritance
-----------------

``ip.proto.v6`` inherits ``ip.proto``. IPv4's ``protocol`` and IPv6's
``next_header`` share one number space, but not one table: the four
IPv6 extension headers must be reachable only inside an IPv6 chain, or
a garbage IPv4 packet with ``protocol=0`` would conjure a Hop-by-Hop
layer. So the shared entries are registered once in ``ip.proto`` and
inherited, while the extension headers are registered directly in
``ip.proto.v6`` and stay there.

Inheritance is resolved **when you register, not when you look up**: a
write to a parent table is copied into every child that has not
overridden the key. Dispatch therefore stays a single ``dict.get`` on a
flat table, which is what keeps it cheap enough for the hot path.

Global and isolated registries
------------------------------

:data:`DEFAULT` is the process-wide registry, and it is what
``next_protocol()`` reads — that method takes no arguments and is called
once per layer per frame, so there is nowhere to thread a registry
through it and no budget for indirection if there were.

When you need registrations that do *not* leak into the rest of the
process — you are embedding this library, or you are testing a decoder —
build your own and hand it to the frame walker instead::

    reg = Registry.from_defaults()
    reg.register("udp.port", 6969, DNS)

:meth:`Registry.derive` makes a cheap copy-on-write child, which is how
a per-call decoder override is expressed without touching global state.

Best-effort tables
------------------

``udp.port`` and ``tcp.port`` differ from the other three in kind, not
just in name. An EtherType or IP protocol number is authoritative: the
field exists to say what follows. A port is a *guess* — any service may
run on any port, and the discriminator is split across two fields.
Dispatch on those tables checks the destination port first (a request
targets the server's well-known port) and then the source port (a
response comes from it), and the class it names is expected to validate
strictly on decode, so a wrong guess degrades to the library's ordinary
malformed-frame path rather than to silent garbage.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import TYPE_CHECKING, TypeVar, overload

from netprotocols.utils.exceptions import ProtocolError

if TYPE_CHECKING:
    from netprotocols._base import Protocol

__all__ = [
    "DEFAULT",
    "TABLES",
    "TABLE_ETHERTYPE",
    "TABLE_IP_PROTO",
    "TABLE_IP_PROTO_V6",
    "TABLE_TCP_PORT",
    "TABLE_UDP_PORT",
    "Registry",
    "RegistryConflictError",
    "UnknownTableError",
    "register",
    "register_all",
]

TABLE_ETHERTYPE = "ethertype"
TABLE_IP_PROTO = "ip.proto"
TABLE_IP_PROTO_V6 = "ip.proto.v6"
TABLE_UDP_PORT = "udp.port"
TABLE_TCP_PORT = "tcp.port"

#: Every dispatch table, mapped to the table it inherits from (``None``
#: for a root table). Adding an entry here is all it takes to give a new
#: dispatch point a name third parties can register against.
TABLES: Mapping[str, str | None] = {
    TABLE_ETHERTYPE: None,
    TABLE_IP_PROTO: None,
    TABLE_IP_PROTO_V6: TABLE_IP_PROTO,
    TABLE_UDP_PORT: None,
    TABLE_TCP_PORT: None,
}

#: The inverse of :data:`TABLES`, precomputed: which tables inherit from
#: each one. Consulted on every registration, never on a lookup.
_CHILDREN: Mapping[str, tuple[str, ...]] = {
    parent: tuple(name for name, of in TABLES.items() if of == parent)
    for parent in TABLES
}

_C = TypeVar("_C", bound="type[Protocol]")


class UnknownTableError(ProtocolError):
    """A registration or lookup named a table that does not exist.

    Raised eagerly, with the valid names listed, because a typo in a
    table name would otherwise register a decoder that nothing ever
    consults.
    """


class RegistryConflictError(ProtocolError):
    """A key in a dispatch table is already held by another class.

    Registering over an existing entry requires ``override=True``, so
    that two packages claiming the same port cannot silently resolve by
    import order. Re-registering the *same* class to the same key is a
    no-op rather than an error — a decorator re-runs whenever its module
    is re-executed.
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
        #: rebound.
        self._tables: dict[str, dict[int, type[Protocol]]] = {
            name: {} for name in TABLES
        }
        #: Registrations made *directly* on each table, as opposed to
        #: inherited into it. Kept so that a later write to a parent
        #: cannot clobber a deliberate override in a child.
        self._own: dict[str, dict[int, type[Protocol]]] = {
            name: {} for name in TABLES
        }

    @classmethod
    def from_defaults(cls) -> Registry:
        """A registry seeded with this library's built-in decoders.

        The copy is independent: registering on it leaves :data:`DEFAULT`
        — and therefore ``next_protocol()`` — untouched.
        """
        return DEFAULT.derive()

    def table(self, name: str) -> dict[int, type[Protocol]]:
        """The flattened lookup table ``name``, inherited entries
        included.

        This is the live dict the registry dispatches through, not a
        copy: the layer modules bind it once at import so that a lookup
        is a bare ``dict.get``. Treat it as read-only and go through
        :meth:`register` to change it.
        """
        try:
            return self._tables[name]
        except KeyError:
            raise _unknown_table(name) from None

    def get(self, table: str, key: int) -> type[Protocol] | None:
        """The class registered for ``key`` in ``table``, or ``None``.

        ``None`` is an ordinary answer rather than an error: the chain
        ends here, either because nothing is encapsulated or because
        this library does not implement what is.
        """
        return self.table(table).get(key)

    def get_port(
        self, table: str, src_port: int, dst_port: int
    ) -> type[Protocol] | None:
        """The class for a port pair, destination tried first.

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
        protocol: type[Protocol],
        *,
        override: bool = False,
    ) -> None:
        """Register ``protocol`` as the decoder for ``key`` in ``table``.

        :raises UnknownTableError: ``table`` is not one of :data:`TABLES`.
        :raises RegistryConflictError: ``key`` is held by a different
            class and ``override`` is false. Re-registering the same
            class to the same key succeeds and changes nothing.
        """
        entries = self.table(table)
        incumbent = entries.get(key)
        if incumbent is not None and incumbent is not protocol and not override:
            raise RegistryConflictError(
                f"{table} {key!r} is already registered to "
                f"{_qualname(incumbent)}; pass override=True to replace it "
                f"with {_qualname(protocol)}"
            )
        self._own[table][key] = protocol
        self._publish(table, key, protocol)

    def _publish(self, table: str, key: int, protocol: type[Protocol]) -> None:
        """Write an entry into ``table`` and into every child that has
        not overridden the key.

        Entries are written in place rather than rebuilt, so the flat
        dicts the layer modules hold stay valid and are never observed
        empty by a concurrent reader.
        """
        self._tables[table][key] = protocol
        for child in _CHILDREN[table]:
            if key not in self._own[child]:
                self._publish(child, key, protocol)

    def derive(
        self,
        overrides: Mapping[str, Mapping[int, type[Protocol]]] | None = None,
    ) -> Registry:
        """A child registry: this one's entries, plus ``overrides``.

        Copy-on-write and independent in both directions — later changes
        to either registry do not reach the other. This is the primitive
        behind a per-call decoder override ("Decode As"), where a caller
        wants DNS read on port 6969 for one capture without changing how
        the rest of the process decodes::

            reg = DEFAULT.derive({"udp.port": {6969: DNS}})

        Overrides replace whatever they land on, so nothing here can
        raise a conflict: naming a key that is already taken is the
        point.
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
    protocol: type[Protocol],
    *,
    override: bool = ...,
    registry: Registry | None = ...,
) -> None: ...


def register(
    table: str,
    key: int,
    protocol: type[Protocol] | None = None,
    *,
    override: bool = False,
    registry: Registry | None = None,
) -> Callable[[_C], _C] | None:
    """Register a decoder, as a decorator or as a direct call.

    Used as a decorator, the class is returned unchanged::

        @register("ethertype", 0x8847)
        class MPLS(Protocol):
            ...

    Used directly, ``protocol`` names a class you did not write::

        register("ip.proto", 132, SCTP)

    Registrations land in :data:`DEFAULT` — process-wide — unless
    ``registry`` names another. See :meth:`Registry.register` for the
    conflict rules.
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
    protocol: type[Protocol],
    *,
    override: bool = False,
    registry: Registry | None = None,
) -> None:
    """Register one class against several keys of the same table.

    For protocols that a single value cannot describe: a VLAN tag is any
    of three EtherTypes, DHCP answers on two ports.
    """
    target = DEFAULT if registry is None else registry
    for key in keys:
        target.register(table, key, protocol, override=override)
