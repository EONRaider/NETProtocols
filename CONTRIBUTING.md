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

These seven checks are enforced by CI on every push and pull request.
Run them locally before you push — one validated push beats three
red ones:

```bash
uv run ruff check                # lint, docstring layout included
uv run ruff format --check       # formatting (drop --check to apply)
uv run flake8 src                # docstring fields (pydoclint)
uv run mypy                      # type checking, strict
uv run pytest                    # the full suite and the doctests in src/
python3 scripts/check_markers.py # no work markers (offline)
uv run sphinx-build -W -n -b dummy docs "$(mktemp -d)"
                                 # docstring cross-references resolve
```

The Sphinx build fetches the Python standard library's inventory from
docs.python.org, so it needs network access; see "Cross-reference
check" below.

CI additionally builds the wheel and imports it. `ruff`'s line length
is 80; Markdown is excluded from linting.

## Project layout

```
src/netprotocols/
  _base.py        the Protocol base class and the decode contract
  _enums.py       EtherType / IPProtocol / LLCSAP / ARP* registries +
                  display names
  checksum.py     RFC 1071 internet checksum, SCTP's CRC32c, the
                  Fletcher checksum of OSPF's LSAs, compute()/verify()
                  (CDP's odd-byte variant and STUN's FINGERPRINT among
                  them)
  packet.py       Packet: an ordered stack of headers, with_checksums()
  layer2/         Ethernet, VLAN, ARP, LLC + SNAP (802.2), STP (802.1D),
                  LLDP, MPLS, CDP
  layer3/         IPv4, IPv6, IPv6 extension headers, ICMPv4/v6, IGMP,
                  GRE, IPsec ESP and AH, VRRP, OSPFv2, PIM
  layer4/         TCP, UDP, SCTP (+ port-based dispatch)
  layer7/         DNS, DHCP, HTTP, VXLAN, RIP, BGP, TFTP, RADIUS, STUN, NTP,
                  HSRP, TLS
  utils/          exceptions, MAC/IPv4 helpers
tests/            unit tests, corpus invariants, fuzzing, fixtures/
scripts/          fixture capture + validation
```

## The decode contract

Every protocol is a frozen, slotted dataclass whose fields mirror the
on-wire header. `decode(data)` receives the entire remaining buffer and
must parse its fixed portion, tolerate trailing bytes, and raise a
subclass of `ProtocolError` (never a bare `struct.error` or
`ValueError`) on malformed input. (SCTP, which has no length field
and a CRC32c that trailing zeros change, finds its own extent instead:
it leaves only zero padding after it undecoded, and keeps any other
trailing or unparseable bytes in its `chunks` rather than raising.
PIM, which has no length field either, ends a message where its own
structure does and keeps a body it cannot parse whole, likewise.)
The authoritative description lives in the module docstring of
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
  `tests/test_enums.py`; new enum members must have display names.

## Docstrings and comments

Docstrings follow [PEP 257](https://peps.python.org/pep-0257/) and
document with Sphinx's
[reST field lists](https://www.sphinx-doc.org/en/master/usage/domains/python.html#info-field-lists).
Two tools check them over `src/`: ruff's pydocstyle rules, under the
`pep257` convention (`pyproject.toml`), and
[pydoclint](https://jsh9.github.io/pydoclint/), run as a flake8 plugin
because only flake8 can switch a single pydoclint code off for the
whole tree (`.flake8`). `tests/` and `scripts/` are exempt from both.

**Layout.**

- Every public module, package `__init__.py`, class, function and
  method has a docstring.
- The first line is a one-line summary ending in a period, followed by
  a blank line and then the body. A multi-line docstring's closing
  quotes go on a line of their own.
- A function's or method's summary is in the imperative mood:
  "Decode a TCP header." rather than "Decodes ..." or "The ...". A
  `@property` is exempt and names what it returns: "The MAC of ...".

**Fields.**

- `:param name:` documents a parameter. A docstring with no fields at
  all is prose only and may describe its parameters in that prose. Once
  it has any field (`:param:`, `:raises:`, `:returns:`, `:ivar:`), its
  `:param:` fields cover every parameter in the signature, in order,
  private helpers included.
- No types in docstrings: no `:type:`, no `:rtype:`, no
  `:param int x:`. The annotations hold the types and `mypy --strict`
  checks them.
- `:returns:` and `:yields:` are not required; the summary says what
  comes back. Add a `:returns:` field only where the value needs more
  than the summary, such as a tuple whose items need naming.
- `:raises ExcType: if ...` documents each exception a caller can see
  and the condition that raises it, whether the function raises it
  itself or a callee does.
- `:ivar name:` documents an exception's attributes (see
  `utils/exceptions.py`); a `#:` comment above a module-level constant
  or an instance attribute documents it.
- Cross-references use Sphinx roles (`:class:`, `:meth:`, `:attr:`,
  `:func:`, `:mod:`, `:data:`), with `~` for the short form:
  ``:class:`~netprotocols.TCP` ``.

**Cross-reference check.** CI's lint job runs
`sphinx-build -W -n -b dummy docs`: `docs/conf.py` renders every
docstring in `src/` through autodoc with `nitpicky = True`, and `-W`
turns every warning into a failure, so a role that names no documented
object, a standard-library role of the wrong kind (`:func:` on
`str`), and malformed reST such as an unclosed `*` all fail CI. Sphinx
does not check the kind of a role that names a documented
`netprotocols` object: ``:func:`~netprotocols.TCP` `` resolves. The
dummy builder writes no output; the check is the build itself.

- Every module is documented, private ones (`_base`, `_tlv`, ...) and
  private and undocumented members included, each object once, under
  the module that defines it. A role resolves against those entries.
- A reference spelt through a module that imports the object, such as
  ``:class:`~netprotocols.TCP` `` for `netprotocols.layer4.tcp.TCP`,
  resolves to the defining module: `docs/conf.py`'s `resolve_import`
  follows the import and hands the defining name back to the Python
  domain, so it resolves only if that object is documented. A name
  that does not exist still fails. It follows classes and functions
  only, so a module-level constant is referenced under its defining
  module: ``:data:`~netprotocols.walk.MAX_DEPTH` ``.
- An inherited member is documented only on the class that defines
  it. Reference it there:
  ``:attr:`~netprotocols.layer3.ah.AH.icv` `` from `AHv6`, or with an
  explicit title,
  ``:attr:`HSRP.header_len <netprotocols._base.Protocol.header_len>` ``.
- Special methods (`__eq__`, `__getitem__`, ...) are not documented, so
  write them as literals: ``` ``__eq__`` ```.
- A role must not wrap across a line break: write
  ``:attr:`STUN.message_type` `` on one line.
- Standard-library references (``:class:`ipaddress.IPv4Address` ``,
  ``:func:`dataclasses.replace` ``) resolve through intersphinx against
  the inventory of Python 3.12, the oldest version `requires-python`
  admits. The build fetches it from docs.python.org, with a 30-second
  timeout; a failed fetch is a warning, so it fails the build rather
  than letting the standard-library references go unchecked. Nothing is
  suppressed: `docs/conf.py` has no `nitpick_ignore`,
  `nitpick_ignore_regex` or `suppress_warnings`, and
  `tests/test_workflows.py` fails if it gains any of the three, so adding
  one, even a single `nitpick_ignore` entry, means changing that test
  too.
  Intersphinx checks that each standard-library target exists and has
  the role's kind; an ignore list would accept whatever it names.

**`decode()`.** Every public `decode()` has a docstring listing, with
`:raises:`, each `ProtocolError` subclass it can raise and when:
`:raises TruncatedHeaderError: if data is shorter than the 20-byte
header.` A protocol that decodes everything past a fixed portion says
so in the docstring: "Past the 12-byte common header, this never
raises."

**Accessors.** There are two kinds, and the docstring states which
one it is:

- Display helpers (`*_name`, `*_str`) and typed views of a field (an
  enum-or-`None`, a decoded option value) never raise. On a value they
  cannot interpret they return `"unknown (n)"` or `None`, and the
  docstring says so, in the form "``None`` for ... (degrades, never
  raises)". One that names every value it can be given says it never
  raises.
- Any accessor that parses a raw `bytes` attribute on demand, a
  `*_name` among them (`parsed_options`, `parsed_chunks`,
  `parsed_attributes`, `DHCP.message_type_name`, ...), can raise a
  `ProtocolError`. It lists it with `:raises:`, and the error's
  `offset` counts from the start of that attribute.

**Spec citations.** Cite the section that defines the behaviour, with
the section sign: `RFC 791 §3.1`, `RFC 2328 §A.3.1`,
`IEEE 802.1AB §8`. In running prose put it in parentheses,
"(RFC 8200 §8.1)", and separate several with commas,
"(RFC 2865 §5, RFC 2866 §5)". Never write "Section 3.1" or "sec. 3.1".

**Examples.** A `>>>` example in `src/` is a doctest, and the test job
runs it: `pyproject.toml` gives pytest `--doctest-modules` and the
`src` test path, so `uv run pytest` collects them. Keep each example
self-contained, building its input inline (`bytes.fromhex(...)`).
Write an example that cannot run as a literal block (`::`) without
`>>>` prompts.

**What comments and docstrings say.** Every comment and every
docstring states only what the code is or does: its behaviour, its
invariants, its preconditions and postconditions, and the spec
sections it implements. It never gives:

- history: what the code used to be, which issue or PR changed it,
  "was", "previously", "now", "no longer", "used to", dates;
- decision-making: why one approach was chosen over another, which
  alternatives were rejected, who found what.

That material belongs in [`CHANGELOG.md`](CHANGELOG.md) and nowhere
else. An issue or PR number counts as history.

`TODO`, `FIXME`, `XXX` and `HACK` markers are not used: work still to
do is filed as an issue, or not done. `scripts/check_markers.py` fails
CI on any of them; CI's lint job runs it and the QA ladder above
includes it. It runs offline over the files `git ls-files` lists.
Everywhere, in prose, strings and docstrings alike, it matches the
four words in capitals, alone or with a plural `s` or an `_suffix`;
in a comment it also matches them in any case. A comment is a Python
`#` comment; a `#` at the start of a line or after whitespace in a
shell, YAML, TOML, `.cfg`, `.flake8`, `.gitignore`, `.gitattributes`,
`CODEOWNERS` or `Dockerfile` file; a `//` the same way in a `.js` or
`.mjs` file; a `;` or `#` line in an `.ini` file; and a `..` explicit
markup line in an `.rst` file. It skips anything that is not a regular
file (a symlink, a submodule), files holding a NUL byte, the root
`CHANGELOG.md`, and in Markdown the text of inline code spans.

**Configured exceptions.** Each one is set in `pyproject.toml`,
`.flake8` or `docs/conf.py`:

| Exception | Where | Why |
|---|---|---|
| ruff `D105`: magic methods need no docstring | `pyproject.toml` | Their contract is Python's data model; the class docstring and the decode contract cover what is specific to a class, such as what `__bytes__` encodes. |
| ruff `D107`: `__init__` needs no docstring | `pyproject.toml` | The class docstring documents construction, and dataclasses generate their own `__init__`. |
| ruff `D` in `tests/` and `scripts/` | `pyproject.toml` | Tests are named for what they check; `scripts/` is maintainer tooling, not the shipped package. |
| pydoclint `DOC201`, `DOC402`: no `:returns:` or `:yields:` required | `.flake8` | The summary says what comes back, and the annotation gives its type. |
| pydoclint `DOC502`, `DOC503`: `:raises:` may name exceptions the body does not raise itself | `.flake8` | `decode()` documents what its callees raise (`_unpack_fixed`, a `raise _malformed(...)` factory), which pydoclint cannot see. `DOC501` still requires a `:raises:` field when the body raises. |
| pydoclint `arg-type-hints-in-docstring`, `check-return-types`, `check-yield-types` off | `.flake8` | Types live in the annotations only. |
| pydoclint `skip-checking-short-docstrings` on | `.flake8` | A docstring with no fields at all is not checked against the signature. |
| pydoclint `check-class-attributes` off | `.flake8` | A class docstring describes its dataclass fields in prose, not as one field per attribute. |
| Sphinx renders signatures without annotations (`autodoc_typehints = "none"`) | `docs/conf.py` | The cross-reference check covers the roles written in docstrings; `mypy --strict` checks the annotations. |

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

`tests/fixtures/staging/` is an untracked, git-ignored workspace: capture
there, validate with `check_fixtures.py`, then copy the validated pcap
and any other files the capture script names into `tests/fixtures/` or
the subdirectory it names, and commit only those:
`capture_fixtures_http.sh`, for instance, has both `staging/http.pcap`
and the per-connection stream files it writes under `staging/http/`
folded into `tests/fixtures/http/`. Nothing under `staging/` is
committed.

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

## Mutation testing

`.github/workflows/mutation.yml` runs a scoped
[mutmut](https://github.com/boxed/mutmut) audit every night; the scope
and its reasoning live in `pyproject.toml`'s `[tool.mutmut]` table.
`mutmut run` itself exits 0 however many mutants survive, so the job's
final step,
[`scripts/check_mutmut_survivors.py`](scripts/check_mutmut_survivors.py),
is what fails it — on any undetected mutant not accepted in
[`scripts/mutmut_survivors.txt`](scripts/mutmut_survivors.txt). To
reproduce locally:

```bash
uv run mutmut run 'netprotocols.checksum.*' 'netprotocols._tlv.*' \
    'netprotocols.layer7.dns.x__read_name*' \
    'netprotocols.layer7.dns.x__labels*' \
    'netprotocols.layer7.http.x__*'
uv run mutmut results --all true > mutmut-results.txt
python3 scripts/check_mutmut_survivors.py mutmut-results.txt
```

A survivor a test *could* kill gets that test. Only a true no-op, or one
out of any test's reach, goes in the triage record, under a comment
saying why. Two properties of the setup are easy to trip over:

- mutmut never mutates a decorated function (other than a lone
  `@staticmethod`/`@classmethod`) — an `@lru_cache`'d parser, say — so
  logic meant to be audited belongs in undecorated functions. (Methods
  of a decorated class such as a `@dataclass` are mutated, as of
  mutmut 3.8.0.)
- `tests/conftest.py` clears every package-level `functools` cache
  before each test, so a result cached by the original code can't hide
  a mutant.

## Releasing

Releases follow [RELEASE.md](RELEASE.md), from the preconditions to the
post-release checks. Its step 7 holds the pre-tag gates: `release.yml`
gates publishing on the CI ladder only, so the nightly fuzz and mutation
workflows are dispatched by hand on `master` at the commit to be
tagged, and the tag is pushed only once both are green.

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
- PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/)
  shape — a `type:` prefix such as `feat:`, `fix:`, `docs:`, or `chore:`
  (optionally scoped, e.g. `feat(layer4):`) — checked automatically by
  `.github/workflows/pr-title-lint.yml`. This governs only the PR title
  itself; it says nothing about the shape of commit messages within the
  PR — the *what*/*why* guidance just above is unaffected and still
  applies to those.

By contributing, you agree that your contributions are licensed under
the project's [MIT license](LICENSE).
