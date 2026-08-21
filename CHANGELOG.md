# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-21

Complete rewrite. The public API is new; see the README and
ARCHITECTURE.md for the current usage.

### Changed
- The parsing core moved from `ctypes.BigEndianStructure` subclasses to
  frozen, slotted dataclasses parsed with `struct.Struct`. Decoded and
  constructed instances are now identical in type and compare equal
  field-by-field.
- `next_protocol()` (returning the class that decodes the payload, or
  `None`) replaces the stringly-typed `encapsulated_proto` chain.
  Protocol number registries are exposed as `EtherType`, `IPProtocol`,
  and `ARPOperation` enums.
- `header_len` is now an instance property: IPv4 honors IHL and TCP
  honors the data offset, and both expose their raw `options` bytes.
- Field names modernized (`ethertype`, `src_port`, `total_length`,
  `checksum`, ...); display helpers are properties such as
  `protocol_name`, `flags_str`, and `checksum_hex_str`.
- Packaging moved to PEP 621 (`hatchling` + `uv`), src layout, Python
  3.12+, MIT license, `py.typed` (mypy strict clean).
- Validators are plain functions (`validate_mac_addr`,
  `validate_ipv4_addr`) raising exceptions rooted at `ProtocolError`.

### Fixed
- `TCP.header_len` was hardcoded to 32 bytes; the base header is 20 and
  the real length follows the data offset.
- Decoding ignored IPv4 IHL and TCP data offset, so headers carrying
  options were mis-sliced.
- Serialization returned a zeroed buffer (`Protocol.__str__`);
  `bytes(header)` now re-emits the exact on-wire form, options included.
- `Packet` rejected instances of indirect `Protocol` subclasses
  (e.g. `IPv4`, `ICMPv4`) due to validation against direct subclasses
  only; membership is now checked with `isinstance`.
- Malformed input (truncated buffers, lying IHL/data-offset values) now
  raises typed exceptions (`TruncatedHeaderError`, `InvalidFieldError`)
  instead of arbitrary `ValueError`/`struct.error` leaks.

### Removed
- The `Validator` descriptor infrastructure (it stored state on the
  descriptor itself — class-shared — and was never wired into any
  protocol class).
- Poetry manifests and the `setup.py`-era metadata.

## [0.8.0] - 2022-08-19

Last release of the ctypes-based implementation, published to PyPI in
2022. The repository had drifted behind the published releases; the
0.8.0 sources were recovered from the PyPI sdist and committed (tagged
`v0.8.0`) before the 1.0.0 rewrite. Releases 0.4.4 through 0.8.0 exist
on PyPI only; their individual histories were not preserved.
