# logfence + rsyslog + mmhashchainsigs + RELP vs. JALoP

This document compares two ways to meet the "cryptographic integrity of
stored audit records" requirements from NIST SP 800-92, DoD, and IC
standards:

1. **The rsyslog stack** — `logfence` in front of `rsyslog`, with
   `mmhashchainsigs` adding a per-message hash chain and periodic
   Ed25519 signatures, and `RELP` transporting the enriched messages
   between hosts.
2. **JALoP** — the Journal, Audit, and Logging Protocol, and the C/C++
   [JALoP Reference Implementation](https://github.com/JALoP/JALoP)
   maintained at `github.com/JALoP/JALoP`. Branch 1.x runs over BEEP;
   branch 2.x runs over HTTP/1.1.

The intended use case for both is the same: durable, tamper-evident
audit and log capture across hosts, where the receiver must be able to
prove what the sender emitted.

## Architecture at a glance

| Layer | rsyslog stack | JALoP |
|---|---|---|
| Schema enforcement | `logfence` validates RFC 5424 fields and a JSON Schema (draft 7 / 2019-09) per message before rsyslog sees it | None in the protocol; producers call the JPL API directly |
| Local relay | `rsyslogd` with `imuxsock` / `imptcp` / `imrelp` inputs | `jal-local-store` (LMDB-backed) |
| Integrity-at-rest | `mmhashchainsigs` adds SHA-256 hash chain + Ed25519 signature SD elements | XML record + detached XML-DSig signature in LMDB |
| Wire transport | `omrelp` over RELP/TLS | BEEP (v1) or HTTP/1.1 + TLS (v2) |
| Storage | Plain files via `omfile` with `sd-preserve` template | LMDB database files (default 200 MB cap) |
| Verification | Standalone `mmhashchainsigs-verify` CLI, reads the file | LMDB inspection plus XML-DSig validation against a stored cert |
| Languages on the wire | RFC 5424 text + RFC 5424 structured data | XML records, XML-DSig, XML manifests |

The rsyslog stack keeps the message in RFC 5424 form end to end and
adds two structured-data elements per message; JALoP wraps each record
in XML metadata, transports the wrapper, and stores the wrapper plus
its signature in LMDB.

## Performance

**Measured rsyslog stack.** `docs/BENCHMARK.md` records the
`mmhashchainsigs` overhead on a 9-core / 8 GB aarch64 Linux VM with
rsyslog 8.2312 and OpenSSL 3.0.13:

| Pipeline | Throughput |
|---|---|
| baseline `omfile` | ~376,000 msg/s |
| `mmhashchainsigs` + `omfile`, `signinterval=1024` | ~343,000 msg/s |
| `mmhashchainsigs-verify` | ~578,000 lines/s |

Signing cost is ~9% throughput. The dominant per-message work is one
SHA-256 chain update plus one `[mmhashchainsigs-hdr@32473 ...]` SD
element; Ed25519 signing fires once per 1024 messages.

`logfence` is the schema-validation chokepoint in front of rsyslog.
Its README reports 401–636 Kelem/s on the same class of host with
schema validation enabled, depending on connection count. Even on a
single connection logfence keeps up with rsyslog at the numbers above,
so the stack remains rsyslog-bound rather than logfence-bound.

**JALoP.** The reference implementation does not publish throughput
numbers. The per-record work is structurally heavier than the rsyslog
stack:

- Each record is wrapped in an XML application metadata document.
- XML-DSig signs each record (or each batch) — XML canonicalisation,
  digest, and RSA/ECDSA signing per record.
- Records are stored in LMDB with the wrapper and signature, not as
  free-form text.

The rsyslog stack does one SHA-256 update per message and one Ed25519
signature per 1024 messages; JALoP signs each record (or batch) using
XML-DSig, which is markedly more expensive per signature both for CPU
and for output size. The CLAUDE.md project framing — "Other high
assurance audit and log systems like JALoP provide digest/hash
chaining and signatures to meet these requirements, but performance
is terrible" — is consistent with the structure of the JALoP record
path: XML serialisation and per-record XML-DSig dwarf the SHA-256
chain update used by `mmhashchainsigs`.

**On-disk size.** `mmhashchainsigs` files are ~2.3× the
`RSYSLOG_TraditionalFileFormat` baseline because every line carries
the chain metadata SD element (~95 B / ~290 B at signature points)
plus the captured-header SD element (~120 B). JALoP stores each
record as an XML document plus a detached XML-DSig blob in LMDB; the
XML envelope alone is typically several hundred bytes per record
before any payload, and LMDB page-aligns its entries. The rsyslog
stack will be smaller per record in all realistic configurations.

## Stability

**rsyslog stack.**

- `rsyslogd` itself is a long-running production daemon with a large
  deployed base; `mmhashchainsigs` plugs into it as a
  message-modification module and is rejected if a second worker is
  spawned (the chain is sequential by construction).
- `mmhashchainsigs` is C with one direct dependency (OpenSSL ≥ 3.0).
  Cryptographic failures suspend the action so rsyslog retries
  instead of dropping messages; the module is documented to never
  crash on error.
- Graceful shutdown writes a state file (atomic `rename(2)`) so that
  the first message after restart signs the unsigned tail of the old
  chain before starting a new one. Crash loss is bounded by the
  `signinterval` — at most 1024 messages lose signature coverage,
  but the chain itself still verifies up to the crash point.
- `logfence` is Rust on Tokio with no `unsafe` code, hot reload via
  `SIGHUP`, and OS-level socket directionality enforcement; it
  isolates the schema policy from rsyslog.
- RELP is a mature reliable-delivery protocol with TLS and
  acknowledged framing.

**JALoP reference implementation.**

- The reference implementation is C/C++17 with a much larger
  dependency surface: `libcurl`, `libxml2`, `libxmlsec1`, OpenSSL,
  LMDB, and `libmicrohttpd`. The README itself notes that the
  `libmicrohttpd` shipped in some enterprise distributions is
  insufficient.
- The README lists known limitations: "potential record loss with
  duplicate identifiers, temporary transmission of outdated records
  under certain conditions, and challenges with subscriber
  interruption under high volume scenarios." These are
  reference-implementation defects rather than protocol-level
  guarantees, but they bear on stability in deployment.
- Local store has a default 200 MB cap; operators are responsible
  for rotation and offload to network stores.

The rsyslog stack inherits rsyslog's operational track record and
keeps `mmhashchainsigs`'s code surface small (C, one crypto
dependency, single output module). The JALoP reference
implementation is a heavier and less battle-tested codebase to keep
running.

## Tamper resistance

**rsyslog stack (`mmhashchainsigs`).**

- Per-message hash chain: `H(n) = SHA-256(H(n-1) || seq_be64 || payload(n))`.
- `payload(n) = hdr_SD(n) || cleaned_client_SD(n) || MSG(n)` —
  captured RFC 5424 header fields, any non-self client structured
  data, and the message body are all under the chain.
- Periodic Ed25519 signature over the current chain hash (default
  every 1024 messages) plus a final signature on graceful shutdown.
- Asymmetric: only the signing host holds the Ed25519 private key.
  The verifier only needs the public key.
- Detected by `mmhashchainsigs-verify`: modification, deletion,
  insertion, reorder, splice from a different chain (public-key
  fingerprint travels in the INIT element), and — in
  `--strict` mode — unsigned tail and unsigned segments between
  INIT records.
- Captures the syslog header at signing time and protects it inside
  `[mmhashchainsigs-hdr@32473 ...]`, so a downstream relay that
  rewrites the on-the-wire header does not invalidate the chain but
  also cannot forge the captured fields.

**JALoP.**

- Each record carries its own XML-DSig signature. Modification of a
  stored record is detectable record-by-record.
- The reference implementation does not chain digests across records
  in the on-disk store the way `mmhashchainsigs` does. Detection of
  deletion or reordering relies on the receiver tracking record
  identifiers and sequencing externally; a record removed from the
  LMDB store leaves no cryptographic trace in the *remaining*
  records.
- Asymmetric: the signer's private key is held only by the producer
  (or the local store, depending on deployment); verifiers use the
  certificate.

**The chain-vs-per-record distinction is the load-bearing difference.**
With per-message hash chaining, an attacker who deletes a message
must rewrite every subsequent signature to hide it; with per-record
signatures only, deleting an entire signed record is detectable only
if the verifier independently knows the record was supposed to be
there. `mmhashchainsigs`'s `--strict` mode additionally flags an
unsigned tail, so a truncation at the end of the file is detected
even though those tail messages were never signed.

In the other direction, JALoP's XML-DSig binds each record to a
certificate chain and supports the full X.509 trust model out of the
box. `mmhashchainsigs` uses raw Ed25519 keys distributed by
fingerprint; if you need PKI-anchored signer identity beyond a
fingerprint pinned by the verifier, that is on the operator to layer
on.

## Security

**Schema validation and ingress control.** `logfence` is the only
piece of either stack that enforces message-shape validation before
the signing step. Compromised producers can still emit any bytes,
but they cannot inject malformed RFC 5424 or off-schema JSON
payloads through logfence's chokepoint without being dropped (strict
mode) or flagged (warn mode). JALoP has no equivalent — the JPL
producer library is an in-process API, so anything that calls it
gets to write whatever it wants into the local store.

**Key handling.**

- `mmhashchainsigs` refuses to start if the private key file is
  world-readable, holds key material in memory only as needed, and
  cleanses it with `OPENSSL_cleanse` on shutdown.
- JALoP's key handling depends on `libxmlsec1` and the operator's
  certificate provisioning. The reference implementation does not
  enforce file-mode checks on the private key.

**Attack surface.**

- The rsyslog stack: rsyslog itself, plus OpenSSL inside
  `mmhashchainsigs`, plus Rust + Tokio in `logfence`. RELP/TLS is
  rsyslog's existing transport.
- JALoP: `libxml2`, `libxmlsec1`, `libcurl`, `libmicrohttpd`,
  OpenSSL, LMDB, plus the BEEP or HTTP server in the local/network
  stores. XML signing is historically a source of canonicalisation
  and signature-wrapping vulnerabilities (XSW); `libxmlsec1` exposes
  the full XML-DSig surface.

**Transport security.** RELP supports TLS with mutual
authentication. JALoP v2 uses HTTPS; JALoP v1 uses BEEP with TLS
profiles. Both meet the in-transit requirement; the difference is
operational (RELP is a syslog-native protocol, JALoP v1 BEEP is rare
in modern deployments, JALoP v2 HTTP is standard but has its own
record-batching semantics).

## Ease of integration

**rsyslog stack.**

- No application changes. Anything that already speaks syslog —
  `journald`, `auditd`, libc `syslog(3)`, any application logging
  framework with a syslog backend — flows through unmodified.
- `auditd` integration is a configuration line (`audisp-syslog` or
  the equivalent), not a code change.
- The on-wire and on-disk format is RFC 5424. Existing tooling that
  reads syslog files keeps working; verification is a separate
  offline step.
- Configuration is rsyslog `.conf` plus one rsyslog action stanza for
  `mmhashchainsigs`. The keygen script and the verifier are small
  standalone tools.
- `logfence` integration for applications that want pre-validation
  is a Unix-socket client library (`logfence-client`, with a C
  wrapper); applications that don't care can keep using `syslog(3)`
  to `imuxsock`.

**JALoP.**

- Applications integrate by linking against the JALoP Producer
  Library (JPL) and calling its API (e.g. `jalp_journal_fd` for
  large records). Existing syslog producers need a translation
  layer.
- A dedicated `JALoP-Auditd-Plugin` exists to forward `auditd`
  records into the JALoP local store; this is the standard path for
  Linux audit subsystem integration.
- The local store and network stores are separate daemons with
  their own configuration, deployment, and operational footprint.
- The data format is XML; downstream consumers (SIEMs,
  log-aggregation pipelines) need to parse JALoP XML rather than
  syslog, which means more integration glue per consumer.

The CLAUDE.md framing — "JALoP's non-syslog-compliant approach has a
heavy development burden for applications and integrators" — matches
the integration surface: JALoP requires application-level API
adoption (or an `auditd`-class shim) and consumers that understand
its XML record format.

## Operational and ecosystem considerations

- **Tooling.** rsyslog has years of operator-facing tooling
  (templates, queues, action filters, ruleset isolation). JALoP
  tooling is narrower and largely tied to the reference
  implementation.
- **Compliance reporting.** Both can produce evidence for SP 800-92
  / DoD / IC controls covering integrity of stored records. The
  rsyslog stack's verifier emits a deterministic pass/fail with
  line-level error reporting suitable for inclusion in audit
  reports; JALoP's evidence is per-record XML-DSig validation
  records held in the local store.
- **Distribution.** RHEL 10 and Ubuntu 24.04 LTS ship rsyslog;
  `mmhashchainsigs` builds against `rsyslog-dev` headers on both.
  The JALoP reference implementation is not packaged in either
  distribution and has to be built from source against multiple
  libraries.
- **Format longevity.** RFC 5424 plus a vendor SD-ID
  (`mmhashchainsigs@32473`) is a stable text format that survives
  log rotation, `grep`, `journalctl --output=cat`, and SIEM
  ingestion unchanged. LMDB files are not directly readable without
  the JALoP tools, so off-system inspection always goes through a
  JALoP-aware reader.

## When the rsyslog stack is the better fit

- The producers already speak syslog (most Linux audit and
  application logging).
- Operators want existing rsyslog operational knowledge to carry
  over.
- The compliance requirement is "tamper-evident audit at rest" and
  per-message chain + periodic signature is sufficient (most
  NIST/DoD/IC controls are satisfied by detection of modification,
  deletion, insertion, and reorder, which is exactly what
  `mmhashchainsigs` provides).
- Throughput matters — the measured ~9% overhead at ~343k msg/s
  with verification at ~578k lines/s is a known good operating
  point.

## When JALoP may still be the better fit

- A procurement explicitly mandates "JALoP-conformant" audit
  exchange (some government contracts do).
- The consumer side is already JALoP-native and expects XML records
  with detached XML-DSig.
- Per-record X.509 / PKI-anchored signer identity is required by
  policy and a fingerprint-pinned Ed25519 key won't satisfy the
  auditor.

## Summary

For the stated goal — meeting NIST SP 800-92, DoD, and IC
"integrity of stored audit records" requirements on RHEL 10 and
Ubuntu 24.04 LTS — the `logfence` + `rsyslog` + `mmhashchainsigs` +
RELP stack provides:

- Stronger tamper-evidence semantics than per-record signing alone
  (hash chain detects deletion and reorder without external
  bookkeeping).
- Measured single-digit percent performance overhead at
  hundreds-of-thousands of messages per second.
- A much smaller integration surface (no application changes; one
  rsyslog action; standard RFC 5424 files on disk).
- Smaller and better-known dependency footprint (OpenSSL,
  rsyslog-dev, plus Rust crates for logfence) than the JALoP
  reference implementation's libxml2/libxmlsec1/libmicrohttpd/LMDB
  chain.
- Schema enforcement at the ingress, which JALoP does not provide
  at the protocol level.

JALoP retains an edge where contracts require its specific record
format or where per-record X.509-anchored signer identity is
non-negotiable. In every other dimension considered here —
performance, stability, tamper resistance, security, ease of
integration — the rsyslog stack is the lower-risk choice for new
deployments.

## References

- [mmhashchainsigs README](../README.md)
- [mmhashchainsigs benchmark methodology and numbers](BENCHMARK.md)
- [logfence](https://github.com/hildstrom/logfence)
- [JALoP Reference Implementation](https://github.com/JALoP/JALoP)
- [JALoP Auditd Plugin](https://github.com/JALoP/JALoP-Auditd-Plugin)
- [jJALoP (Java implementation)](https://github.com/JALoP/jJALoP)
- NIST SP 800-92, *Guide to Computer Security Log Management*
