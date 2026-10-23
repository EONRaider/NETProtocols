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

Vulnerabilities in third-party tooling used only in CI (linters, type
checkers, the build backend) are out of scope for this policy --
please report those upstream instead.
