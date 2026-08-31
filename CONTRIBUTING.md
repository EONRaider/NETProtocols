# Contributing to netprotocols

Thanks for your interest in contributing. This library decodes and
builds low-level network protocol headers; correctness against real
traffic is the whole point, so the bar for changes is a green QA ladder
and a fixture that proves the change against real bytes.

Start with [ARCHITECTURE.md](ARCHITECTURE.md) for the design and the
add-a-protocol cookbook; this file covers the mechanics.

## Development setup

Development uses [uv](https://docs.astral.sh/uv/) and targets Python
3.12+ (CI runs 3.12, 3.13, and 3.14).

```bash
uv sync          # create the virtualenv and install dev dependencies
```

## The QA ladder

These four checks are enforced by CI on every push and pull request.
Run them locally before you push — one validated push beats three
red ones:

```bash
uv run ruff check           # lint
uv run ruff format --check  # formatting (drop --check to apply)
uv run mypy                 # type checking, strict
uv run pytest               # the full suite
```

CI additionally builds the wheel and imports it. `ruff`'s line length
is 80; Markdown is excluded from linting.

## Project layout

```
src/netprotocols/
  _base.py        the Protocol base class and the decode contract
  _enums.py       EtherType / IPProtocol / ARP* registries + display names
  checksum.py     RFC 1071 internet checksum, compute()/verify()
  packet.py       Packet: an ordered stack of headers, with_checksums()
  layer2/         Ethernet, VLAN, ARP
  layer3/         IPv4, IPv6, IPv6 extension headers, ICMPv4/v6, IGMP
  layer4/         TCP, UDP (+ port-based dispatch)
  layer7/         DNS
  utils/          exceptions, MAC/IPv4 helpers
tests/            unit tests, corpus invariants, fuzzing, fixtures/
scripts/          fixture capture + validation
```

## The decode contract

Every protocol is a frozen, slotted dataclass whose fields mirror the
on-wire header. `decode(data)` receives the entire remaining buffer and
must parse its fixed portion, tolerate trailing bytes, and raise a
subclass of `ProtocolError` (never a bare `struct.error` or
`ValueError`) on malformed input. The authoritative description lives in
the module docstring of
[`src/netprotocols/_base.py`](src/netprotocols/_base.py) — read it
before adding a protocol.

## Adding a protocol

Follow the six-step cookbook in [ARCHITECTURE.md](ARCHITECTURE.md)
("Cookbook: adding a protocol"). In short:

1. Model the fixed header as a frozen, slotted dataclass with a
   class-level `struct.Struct`; split wire bitfields into semantic
   fields (as `IPv6` does with `version`/`traffic_class`/`flow_label`),
   validating ranges in `__post_init__` with `InvalidFieldError`.
2. Implement `decode()` and `__bytes__()` so `bytes(decode(x)) == x`
   holds for well-formed input.
3. Wire the chain: the layer below returns your class from
   `next_protocol()`. For a new `EtherType` or IP protocol number, add
   the value to `_enums.py` **with its display name in lockstep** — a
   completeness test enforces this — and one mapping entry in the
   dispatcher, using a deferred import.
4. Add display helpers that degrade gracefully on unknown values
   (return `"unknown (47)"`, never raise from a display property).
5. Export the class from the package `__init__.py` and the layer
   `__init__.py`.

Two enforcement points that are easy to miss:

- **Fuzz registration.** Add the class to `ALL_PROTOCOLS` in
  [`tests/test_fuzz.py`](tests/test_fuzz.py) so the "decode never
  escapes `ProtocolError`" property covers it.
- **Enum lockstep.** The display-name completeness tests live in
  `tests/test_ipv6_ext.py`; new enum members must have display names.

## Tests and the fixture corpus

The suite is anchored by a corpus of real captured traffic under
[`tests/fixtures/`](tests/fixtures/), described frame by frame in
[`tests/fixtures/MANIFEST.md`](tests/fixtures/MANIFEST.md). The
corpus-wide invariants and the checksum recompute run over every frame
automatically, so **dropping a `.pcap` into the corpus is often most of
the test coverage for a new protocol.**

Fixtures are captured and validated with the scripts under
[`scripts/`](scripts/):

- `capture_fixtures*.sh` — capture a scenario with `tcpdump` into
  `tests/fixtures/staging/`, then validate it.
- `check_fixtures.py` — a standalone (stdlib-only) checksum validator.
  **Every committed fixture must pass it**:

  ```bash
  python3 scripts/check_fixtures.py tests/fixtures/staging
  ```

Prefer a real capture, and build the conditions for one where a
protocol won't appear in a normal environment. VLAN tags, for instance,
are stripped by a switch on an access port, so
`scripts/capture_fixtures_vlan.sh` stands up real 802.1Q / 802.1ad vlan
devices over a veth pair and captures the kernel-tagged frames on the
parent device. Only where even that isn't possible — a kernel without
the `8021q` driver — may a fixture be derived from a real capture, and
only if the derivation is byte-faithful to the wire and the provenance
is recorded in the MANIFEST; that script's synthesis fallback (splicing
tag shims over a real untagged capture) is the worked example.

## Changelog

This project keeps a [Keep a Changelog](https://keepachangelog.com/)
file. Add an entry under `## [Unreleased]` in
[`CHANGELOG.md`](CHANGELOG.md): user-facing changes under `### Added` /
`### Changed` / `### Fixed`, test-and-tooling changes under
`### Development`.

## Pull requests

- Keep changes focused; don't widen a PR beyond what it needs.
- Fill in the pull-request template and keep the QA ladder green.
- CI on a first-time fork PR waits for a maintainer to approve the run —
  that's expected, not a failure on your end.
- Commits and PRs describe the change and the reasoning; the diff shows
  the *what*, the message explains the *why*.

By contributing, you agree that your contributions are licensed under
the project's [MIT license](LICENSE).
