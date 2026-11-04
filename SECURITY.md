# Security Policy

## Supported Versions

Only the latest released version of netprotocols receives security
fixes. Older versions are not backported.

## Reporting a Vulnerability

Please report security vulnerabilities privately rather than opening a
public issue.

- Preferred: use GitHub's [private vulnerability
  reporting](https://github.com/EONRaider/NETProtocols/security/advisories/new)
  for this repository.
- Alternative: email eonraider@protonmail.com with a description
  of the vulnerability, the affected version, and steps to reproduce
  it.

You should expect an initial response within 5 business days. We aim
to confirm the vulnerability, assess its severity, and agree on a
disclosure timeline with you within that window.

We follow coordinated disclosure: once a fix is available, we will
credit reporters (unless anonymity is requested) in the release notes
and CHANGELOG.md. We ask that you not publicly disclose the
vulnerability until a fixed version has been released, and in any case
not before 90 days have elapsed since your initial report, whichever
comes first.

## Scope

netprotocols is a pure decoding/encoding library for network protocol
headers. Of particular interest are:

- Crashes, hangs, or excessive resource consumption when decoding
  untrusted, malformed, or adversarial byte sequences (e.g. via
  `decode_frame`).
- Any deviation from documented behavior that could mislead a caller
  about the contents of a decoded packet.
- For `HTTP`: a message whose boundary differs from the one RFC 9112
  defines, or a framing ambiguity (Content-Length against
  Transfer-Encoding, bare LF, obs-fold, chunk-line oddities, Host
  disagreements) that decodes without the `HTTPAnomaly` documenting
  it. Anomalies are evidence, not verdicts: they say where an
  implementation could read the message differently, not that one
  did.

What `HTTP` cannot see, by design, is not a vulnerability in it: it
decodes one message from bytes the caller reassembled, so TCP
reassembly and segment-overlap tricks are the caller's; a response's
framing depends on the `request_method` and `closed` the caller passes;
and it never pairs a request with its response, so desyncs that need
both — an early response, or `Expect: 100-continue` — are out of reach
until request/response pairing exists.

`BGP` is port-dispatched and decodes the messages one TCP segment
holds; reassembling the stream, and the segment-overlap tricks that
come with it, are the caller's in the same way.

`TLS` is port-dispatched the same way and decodes the records one
segment holds; a ClientHello that spans segments is read only from a
stream the caller reassembled. It decrypts and verifies nothing: the
SNI it reports is what the client sent in the clear (under Encrypted
Client Hello, the outer ClientHello's public name), which identifies
nothing on its own.

`MPLS` names the packet under its label stack by convention, since
nothing in the stack names it: an Explicit NULL bottom label, or else
the first nibble after the stack read as an IP version. A pseudowire
sent without a control word can therefore decode as IPv4 or IPv6 (RFC
4928 describes the same misreading in routers); that guess is
documented behaviour, not a vulnerability, and the module docstring
says how to walk such a payload explicitly.

Vulnerabilities in third-party tooling used only in CI (linters, type
checkers, the build backend) are out of scope for this policy --
please report those upstream instead.
