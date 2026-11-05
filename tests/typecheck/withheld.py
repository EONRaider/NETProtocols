"""Call sites of :data:`~netprotocols.registry.WITHHELD` for mypy.

``mypy --strict`` checks this module (see ``[tool.mypy]`` in
pyproject.toml). The functions are never called: each statement is a
call site that must type-check, and the one marked ``type: ignore``
must keep failing, or the ignore is reported as unused.
"""

from typing import Literal, assert_type

from netprotocols import DNS, decode_frame
from netprotocols.registry import (
    WITHHELD,
    Registry,
    WithheldType,
    register,
    register_all,
)


def accepted(frame: bytes, registry: Registry) -> None:
    """Withhold a key in every way the registry offers."""
    assert_type(WITHHELD, Literal[WithheldType.WITHHELD])
    decode_frame(frame, decode_as={"udp.port": {1812: WITHHELD}})
    decode_frame(frame, decode_as={"udp.port": {1812: WITHHELD, 6969: DNS}})
    registry.derive({"udp.port": {1812: WITHHELD}})
    registry.register("udp.port", 1812, WITHHELD, override=True)
    assert_type(register("udp.port", 1812, WITHHELD), None)
    register_all("udp.port", (1812, 1813), WITHHELD, registry=registry)


def rejected(frame: bytes) -> None:
    """Pass ``None`` where a class or :data:`WITHHELD` belongs."""
    decode_frame(
        frame,
        decode_as={"udp.port": {1812: None}},  # type: ignore[dict-item]
    )
