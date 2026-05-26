# mmhashchainsigs

Cryptographic integrity for syslog records carried over RELP.

`mmhashchainsigs` is an rsyslog message-modification module that attaches
a SHA-256 hash chain and periodic signatures (Ed25519 or ECDSA P-256) to
every message as RFC 5424 structured data. Keys may be supplied as raw
PEM or wrapped in an X.509 certificate. The receiver stores the messages
as delivered and uses the companion `mmhashchainsigs-verify` tool to
detect tampering, deletion, insertion, or reordering of records.

See [docs/STRUCTURE.md](docs/STRUCTURE.md) for the source layout,
[docs/BENCHMARK.md](docs/BENCHMARK.md) for throughput numbers, and
[docs/diagrams/](docs/diagrams/) for PlantUML architecture and sequence
diagrams.

## Motivation

Syslog implementations like rsyslog handle unstructured and structured
audit messages well. Features like RELP provide cryptographic integrity for
data *in transit*. However, none of these provide cryptographic integrity
of *stored* audit records, which is required by NIST SP 800-92, DoD, and IC
standards.

Existing solutions like JALoP address this gap but suffer from poor
performance and heavy integration burden due to non-syslog-compliant
protocols.

mmhashchainsigs solves this by working within the rsyslog ecosystem as a
native message modification module, keeping the familiar syslog pipeline
while adding verifiable integrity at rest.

### Why not `mmrfc5424addhmac`?

rsyslog already ships a `mmrfc5424addhmac` module that adds a per-message
HMAC structured data element. It does not meet the requirements that
mmhashchainsigs targets:

- **Shared secret keys.** HMAC is symmetric. The verifier holds the same
  key as the signer, so any party that can verify a log can also forge one.
  Authenticity is lost as soon as the key leaves the originating host.
- **No hash chain.** Each message is hashed independently. The HMAC over
  message `N` does not depend on message `N-1`, so removing, reordering, or
  splicing messages is undetectable as long as each HMAC remains valid for
  its own message.
- **No deletion or insertion detection.** Because there is no sequence
  binding between messages, a missing message leaves no trace, and a
  message lifted from one log and dropped into another still verifies.
- **No replay detection.** A valid message can be duplicated or replayed
  without breaking the per-message HMAC.
- **Key distribution problem.** Every receiver needs the secret key, which
  multiplies the attack surface and makes key rotation expensive.

mmhashchainsigs uses Ed25519 (asymmetric) signatures so only the signing host
holds the private key, chains messages with SHA-256 so any modification,
deletion, insertion, or reorder breaks the chain at the point of damage,
and uses sequence numbers so gaps and replays are explicit.

## Trust Modes

Three ways to convey signer identity to the verifier:

| Mode | Signer config | Verifier flag | When to use |
|------|---------------|---------------|-------------|
| Raw key | `privatekey=key.pem` | `--publickey pub.pem` | Fastest, smallest log overhead. Distribute the public key out of band. |
| Pinned X.509 cert | `privatekey=key.pem` `certificate=cert.pem` | `--cert cert.pem` | You want an X.509 envelope (audit policy, future PKI rollout) but no chain validation. Verifier pins the leaf. Cert validity dates are not enforced. |
| CA-validated cert | `privatekey=key.pem` `certificate=cert.pem` `embedcert=on` | `--ca-bundle ca.pem` [`--crl-file crl.pem`] | Standard PKI deployment. Operators rotate certs through their CA; verifiers only need the CA bundle. Cert chain is validated on every chain INIT line. |

Ed25519 and ECDSA P-256 are interchangeable across all three modes — pick
one per signing host. See [docs/X509.md](docs/X509.md) for the full design.

## How It Works

1. **Hash chaining** -- Each message is chained:
   `H(n) = SHA-256(H(n-1) || sequence_number || message)`.
   Modifying, removing, or reordering any message breaks the chain for all
   subsequent messages.

2. **Periodic signing** -- Every N messages (default 1024), mmhashchainsigs signs
   the current chain hash with Ed25519 and embeds the signature in the
   structured data of that message.

3. **Verification** -- `mmhashchainsigs-verify` reads the stored log file,
   reconstructs the chain by hashing each message's payload (with the
   structured data element stripped), and checks every signature against
   the public key.

## Target Platforms

- RHEL 10
- Ubuntu 24.04 LTS

## Dependencies

- OpenSSL >= 3.0 (libcrypto) -- SHA-256 and Ed25519
- rsyslog development headers -- only needed to build the module
- GCC, GNU Make, pkg-config

## Quick Start

### Build

```sh
# Build the verification tool (no rsyslog headers needed)
make

# Build everything including the rsyslog module (requires rsyslog-dev)
make all

# Run the unit test suite
make test

# Run integration tests (requires rsyslog)
make test-integration

# Run benchmarks (requires rsyslog)
make bench
```

### Generate Keys

Raw key pair (default — fastest, smallest log overhead):

```sh
mkdir -p /etc/rsyslog.d
tools/mmhashchainsigs-keygen.sh keygen --outdir /etc/rsyslog.d
```

Produces:
- `mmhashchainsigs-private.pem` -- deploy to the signing host (mode 0600)
- `mmhashchainsigs-public.pem` -- distribute to verifiers

X.509 self-signed certificate (use with `--cert` at the verifier):

```sh
tools/mmhashchainsigs-keygen.sh selfsign --alg ed25519 \
    --cn my-host.example.com --days 365 --outdir /etc/rsyslog.d
```

X.509 CSR for an external CA to sign:

```sh
tools/mmhashchainsigs-keygen.sh csr --alg ecdsa-p256 \
    --cn my-host.example.com --outdir /etc/rsyslog.d
# Submit mmhashchainsigs.csr to your CA, install the issued cert as
# /etc/rsyslog.d/mmhashchainsigs-cert.pem
```

Supported algorithms: `ed25519` (default) and `ecdsa-p256`.

### Configure rsyslog

```
module(load="mmhashchainsigs")

template(name="sd-preserve" type="string"
    string="%STRUCTURED-DATA%%msg%\n")

*.* {
    action(
        type="mmhashchainsigs"
        privatekey="/etc/rsyslog.d/mmhashchainsigs-private.pem"
        signinterval="1024"
        statefiledir="/var/lib/mmhashchainsigs"
    )
    action(type="omrelp" target="logserver" port="514")
    action(
        type="omfile"
        file="/var/log/secure-audit.log"
        template="sd-preserve"
        filecreatemode="0600"
    )
}
```

See `conf/mmhashchainsigs.conf.example` for a complete example.

### Verify a Log File

```sh
mmhashchainsigs-verify -k /path/to/mmhashchainsigs-public.pem /var/log/secure-audit.log
```

Output:
```
PASS: 10240 messages verified, 10 signature blocks
```

Or on failure:
```
FAIL: 1 error(s) detected
  line 4127: chain hash mismatch at seq 4097
```

### CLI Options

```
mmhashchainsigs-verify (-k <pubkey.pem> | -c <cert.pem> | -C <ca.pem>) \
                      [OPTIONS] <logfile>

Trust anchor (exactly one is required):
  -k, --publickey <path>  Raw PEM public key (Ed25519 or ECDSA P-256)
  -c, --cert <path>       Pinned X.509 leaf certificate PEM
  -C, --ca-bundle <path>  PEM bundle of CA certificates; the signer's
                          cert must be embedded in the log (embedcert=on)
                          and chain to a CA in this bundle
      --crl-file <path>   Optional CRL file (only with --ca-bundle)

Options:
  -v, --verbose           Print per-block verification details
  -q, --quiet             Only output final pass/fail
  -s, --strict            Fail if the file does not end with a signature
  -h, --help              Show usage

Exit codes:
  0  All signatures valid, chain intact
  1  Verification failure (integrity violation detected)
  2  Usage error or file not found
  3  Public key fingerprint mismatch
  4  Certificate chain validation failure
```

### Install

```sh
# Install mmhashchainsigs-verify to /usr/local/bin
sudo make install-verify

# Install mmhashchainsigs.so to the rsyslog module directory
sudo make install-module

# Or install both
sudo make install
```

## Log File Format

mmhashchainsigs prepends **two** RFC 5424 structured data elements to every
message:

1. `[mmhashchainsigs@32473 ...]` — the chain metadata (sequence, chain
   hash, and on every Nth message the Ed25519 signature). The verifier
   *strips* this element before reconstructing the chain.
2. `[mmhashchainsigs-hdr@32473 ...]` — a snapshot of the six syslog
   header fields captured at signing time. This element is part of the
   integrity-protected payload (the verifier hashes it just like any
   other byte after the leading mmhashchainsigs element).

### Chain metadata element shapes

| Shape | When | Fields |
|-------|------|--------|
| INIT  | First message of a chain | `t="I"`, `q` (seq), `h` (chain hash), `f` (pubkey fingerprint) |
| MSG   | Ordinary message         | `q`, `h` |
| SIG   | Every `signinterval` messages, and on graceful shutdown | `t="S"`, `q`, `h`, `qf` (first signed seq), `qt` (last signed seq), `s` (Ed25519 signature, base64) |

### Header capture element

| Param | Source |
|-------|--------|
| `pri`    | `(facility << 3) \| severity`, as a decimal integer |
| `ts`     | Reported timestamp formatted as RFC 3339 |
| `host`   | HOSTNAME (RFC 5424) / hostname (RFC 3164) |
| `app`    | APP-NAME / TAG |
| `procid` | PROCID / PID |
| `msgid`  | MSGID (5424 only; `-` for 3164) |

All six parameters are always emitted in this fixed order, with empty
values rendered as `""` and parameter values escaped per RFC 5424
§6.3.3 (`"`, `\`, `]` → `\"`, `\\`, `\]`).

When mmhashchainsigs is paired with `omfile` and a template such as
`string="%STRUCTURED-DATA%%msg%\n"`, the stored file looks like:

```
[mmhashchainsigs@32473 t="I" q="1" h="e6dcb9c1...37d3" f="d1737047...471d"][mmhashchainsigs-hdr@32473 pri="13" ts="2026-05-22T10:00:00Z" host="myhost" app="myapp" procid="1234" msgid="-"]starting up
[mmhashchainsigs@32473 q="2" h="a3f2b1c8...9e04"][mmhashchainsigs-hdr@32473 pri="13" ts="2026-05-22T10:00:01Z" host="myhost" app="myapp" procid="1234" msgid="-"]listening on port 8080
...
[mmhashchainsigs@32473 t="S" q="1024" h="b2e58f4a...c911" qf="1" qt="1024" s="MEUCIQD...base64..."][mmhashchainsigs-hdr@32473 pri="13" ts="2026-05-22T10:05:00Z" host="myhost" app="myapp" procid="1234" msgid="-"]scheduled task ran
```

When mmhashchainsigs runs ahead of `omrelp`, both elements travel with
the message; the receiver's `omfile` writes them to disk in the same
form using the `sd-preserve` template above.

`mmhashchainsigs-verify` reconstructs the chain by stripping the leading
`[mmhashchainsigs@32473 ...]` element from each line, hashing the
remaining payload (which includes the `[mmhashchainsigs-hdr@32473 ...]`
element and any client SD), and comparing against `h`. Signature
elements additionally verify the embedded Ed25519 signature against
the public key.

## RELP Signing Pipeline

A typical deployment uses `mmhashchainsigs` at the origin and `omrelp`
to ship the enriched messages to a receiver:

```
+---------------+        +----------------------+        +------------------+
|  application  |  log   |  rsyslog (origin)    |  RELP  |  rsyslog (recv)  |
|               +--------> mmhashchainsigs       +--------> omfile           |
|               |        |   + omrelp           |        |   sd-preserve    |
+---------------+        +----------------------+        +------------------+
                                                                  |
                                                                  v
                                                         /var/log/host1.log
                                                                  |
                                                                  v
                                                  mmhashchainsigs-verify -k pub.pem
```

Because the chain metadata is in-band on each message, the receiver does
not need to know the sign interval and does not need any state beyond the
public key.

## mmhashchainsigs Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `privatekey` | string | (required) | Path to private key PEM (Ed25519 or ECDSA P-256) |
| `certificate` | string | (none) | Optional X.509 cert PEM matching the private key. When set, the cert's public key drives the on-wire fingerprint. |
| `embedcert` | binary | off | Emit the X.509 cert in `[mmhashchainsigs-cert@32473 ...]` on chain INIT lines so verifiers in CA-bundle mode can chain-validate without out-of-band cert distribution. Requires `certificate=`. |
| `template` | string | rsyslog default | Rsyslog template for hash input |
| `signinterval` | integer | 1024 | Sign every N messages |
| `statefiledir` | string | (none) | Directory for shutdown state file; enables final signature on graceful restart |

**Single worker thread required.** The hash chain is inherently sequential
-- each message's hash depends on the previous one. If rsyslog's action
queue creates multiple worker threads, messages are distributed across
workers non-deterministically, producing interleaved independent chains
that the verifier cannot reconstruct. The module rejects a second worker
at startup with an error message. Do not set `queue.workerThreads` >1 on
the mmhashchainsigs action (the default of 1 is correct).

## Module Interface

The rsyslog documentation for [Message Modification
Modules](https://docs.rsyslog.com/doc/configuration/modules/idx_messagemod.html) states
that an `mm*` module can be implemented using either the output module
interface or the parser module interface.

**mmhashchainsigs uses the output module interface.** Specifically it declares
itself with `MODULE_TYPE_OUTPUT` and implements the action-style entry
points (`BEGINdoAction_NoStrings`, `BEGINcreateWrkrInstance`, etc.). The
output module interface fits the rsyslog "action" model that mmhashchainsigs
needs: an instance per `action()` block, a worker per processing thread, a
single in-place modification per message, and clean integration with the
RuleEngine so the modification happens before subsequent `omrelp` /
`omfile` actions in the same rule.

The parser interface is intended for modules that convert raw octet
streams into parsed `smsg_t` structures during ingest, which is a poor fit
for adding signature metadata to messages that are already parsed.

## Shutdown and Crash Behavior

### Graceful shutdown with `statefiledir`

When `statefiledir` is configured, mmhashchainsigs saves the hash chain
state (current hash, sequence number, signing range, and public key
fingerprint) to a file on graceful shutdown. On the next startup, the
module reads the state file and uses it to sign the first arriving message
through the **restored old chain** before starting a new chain. This means:

- The first message after restart carries a SIG SD element that covers all
  previously unsigned messages from the old chain, plus the message itself.
- The second message carries a normal INIT SD element for the new chain.
- No messages are sacrificed -- every message's content is
  integrity-protected.
- The state file is deleted after it is consumed.
- The verifier sees a seamless transition: the old chain is fully signed,
  and the new chain begins immediately after.

The state file is written atomically (write to temp file, then `rename(2)`)
to the configured directory as `mmhashchainsigs.state`.

If the private key changed between restarts, the saved state's public key
fingerprint will not match the new key. In that case, the state file is
discarded and the first message starts a fresh chain with INIT as usual.

If `statefiledir` is not configured, no state is saved and the module
behaves as if there was no previous chain -- the first message after
restart always gets a new INIT.

### Crash or hard poweroff

If rsyslog is killed (`SIGKILL`), the system loses power, or the process
crashes, no state file is written. The consequences:

- **Hash chain integrity is preserved.** Every message in the audit log
  carries its own `q=` (sequence) and `h=` (chain hash) in the structured
  data. The verifier can reconstruct and validate the hash chain for all
  stored messages, detecting any tampering, deletion, or reordering.
- **Signature coverage has a gap.** Messages after the last periodic
  signature lack cryptographic non-repudiation. At most `signinterval`
  messages (default 1024) are unsigned.
- **A new chain starts on restart.** When rsyslog restarts, the module
  initializes a fresh hash chain with a new INIT record (`t="I"`). The
  verifier handles this: it accepts multiple segments in a single log file,
  each starting with an INIT record.
- **Detection in strict mode.** Running `mmhashchainsigs-verify --strict`
  reports the unsigned tail: `"N messages at tail are unsigned"` for the
  segment that ended without a final signature, and
  `"N messages unsigned before new segment"` when a new INIT follows an
  unsigned tail.

To minimize the window of unsigned messages after a crash, reduce
`signinterval`. A value of 1 signs every message (no unsigned tail) at the
cost of one Ed25519 signature per message instead of one per N messages.

## Security Properties

**What is detected:**
- Modified messages (any byte change breaks the hash chain)
- Deleted messages (sequence gap and chain hash mismatch)
- Inserted messages (chain hash mismatch)
- Reordered messages (chain hash mismatch)
- Truncated logs (unsigned tail detected in `--strict` mode)
- Spliced messages from a different chain (fingerprint or chain mismatch)

**Key management:**
- The module refuses to start if the private key file is world-readable
- Key material is cleansed from memory on shutdown (`OPENSSL_cleanse`)
- Only the public key fingerprint travels in the log stream

**Operational safety:**
- Cryptographic failures cause the module to suspend (rsyslog retries)
  rather than silently passing unsigned messages downstream
- The module never crashes on error -- audit systems must not lose data

## Input Formats

mmhashchainsigs works with both RFC 3164 (BSD syslog) and RFC 5424 input.
For RFC 5424 messages that already carry their own structured data, the
output SD section becomes
`[mmhashchainsigs@32473 ...][mmhashchainsigs-hdr@32473 ...][client@... ...]`
followed by the MSG body. The hash chain covers
`hdr_SD || cleaned_client_SD || MSG`, so the captured header values and
any non-self client SD elements are integrity-protected together with
the message body.

**SD-ID collision.** If an incoming message already contains an SD
element with the `mmhashchainsigs@32473` SD-ID or the
`mmhashchainsigs-hdr@32473` SD-ID (whether by misconfiguration or
intentional spoofing), mmhashchainsigs removes the offending elements
before adding its own. mmhashchainsigs is the trusted signer, and a
client-supplied element with one of these SD-IDs is not authoritative.
Per RFC 5424 §6.3.2 SD-IDs must be unique within a message, so the
alternative -- emitting two elements with the same SD-ID -- would
produce malformed output and break verification. The message is not
dropped; the collision is silently rectified so that an attacker
cannot deny audit logging by injecting a poisoned SD-ID.

## Hashing Details

The chain hash recurrence is:

```
H(n) = SHA-256( H(n-1) || seq(n) || payload(n) )
```

where `seq(n)` is the 64-bit big-endian sequence number and
`payload(n)` is the bytes mmhashchainsigs feeds into SHA-256 for
message `n`. `payload(n)` is constructed in mmhashchainsigs's
`doAction` from the parsed message fields, *before* the message
reaches the output template. The verifier reconstructs the same bytes
from each stored line by stripping the leading
`[mmhashchainsigs@32473 ...]` element.

Across every input format,

```
payload(n) = hdr_SD(n) || cleaned_client_SD(n) || MSG(n)
```

where `hdr_SD(n)` is the `[mmhashchainsigs-hdr@32473 ...]` element
mmhashchainsigs emits (carrying the six captured header values),
`cleaned_client_SD(n)` is the SD section the input arrived with after
any `mmhashchainsigs@32473` or `mmhashchainsigs-hdr@32473` elements
have been stripped, and `MSG(n)` is the parsed `%msg%` field.

The syslog header values themselves are captured at signing time and
travel inside `hdr_SD(n)` — so they are part of the protected payload
even if a downstream relay rewrites the on-the-wire syslog header
later. The on-the-wire header (PRI, timestamp, hostname, app-name,
procid, msgid as they appear in the rsyslog template output) is **not**
hashed; only the snapshot captured into the hdr SD is.

### RFC 3164 input

Input form (one octet stream per message):

```
<PRI>MMM DD HH:MM:SS HOST TAG[PID]: BODY
```

rsyslog's parser populates:
- `%msg%` = the message body (typically with a leading space carried
  over from the `: ` separator)
- `%STRUCTURED-DATA%` = `-` (RFC 3164 has no SD section)

mmhashchainsigs hashes:

```
payload = hdr_SD(pri, ts, host, app=TAG, procid=PID, msgid="-") || MSG
```

- **Hashed:** the captured header values inside `hdr_SD`, and the
  message body as rsyslog parsed it.
- **Not hashed:** the on-the-wire syslog header bytes (only the
  *captured snapshot* inside `hdr_SD` is integrity-protected).

### RFC 5424 input without structured data

Input form (the trailing `-` indicates "no SD"):

```
<PRI>1 TIMESTAMP HOST APP PROCID MSGID - MSG
```

rsyslog's parser populates:
- `%msg%` = MSG
- `%STRUCTURED-DATA%` = `-`

mmhashchainsigs hashes:

```
payload = hdr_SD(pri, ts, host, app, procid, msgid) || MSG
```

- **Hashed:** the captured header values inside `hdr_SD` and the
  message body.
- **Not hashed:** the on-the-wire syslog header bytes.

### RFC 5424 input with structured data

Input form:

```
<PRI>1 TIMESTAMP HOST APP PROCID MSGID [client@9999 k="v"][other@123 x="y"] MSG
```

rsyslog's parser populates:
- `%msg%` = MSG
- `%STRUCTURED-DATA%` = the entire SD section, for example
  `[client@9999 k="v"][other@123 x="y"]`

mmhashchainsigs first strips any `[mmhashchainsigs@32473 ...]` and
`[mmhashchainsigs-hdr@32473 ...]` elements from the SD section
(collision policy above), producing `cleaned_client_SD`. Then:

```
payload = hdr_SD(pri, ts, host, app, procid, msgid)
       || cleaned_client_SD || MSG
```

- **Hashed:** the captured header values, every non-self SD element
  (with its SD-ID, parameter names, and parameter values), and the
  message body. Modifying a client SD parameter, adding or removing
  any non-self SD element, or rewriting a captured header field all
  break the chain.
- **Not hashed:** the on-the-wire syslog header bytes, and the
  `[mmhashchainsigs@32473 ...]` element itself — it is the metadata
  that lets the verifier recompute the chain rather than part of the
  protected payload.

### Storage template requirement

For verification to succeed, the file written by `omfile` (or the
analogous storage downstream of RELP) must use a template that places
`%STRUCTURED-DATA%` immediately before `%msg%` with nothing between
them except an optional trailing newline. The example `sd-preserve`
template:

```
template(name="sd-preserve" type="string"
    string="%STRUCTURED-DATA%%msg%\n")
```

produces lines of the form
`[mmhashchainsigs@32473 ...][cleaned_client_SD]MSG\n`. The verifier strips the
leading mmhashchainsigs element and hashes everything between that point and
the end of the line, which is exactly `payload(n)`.

## Performance

On a 9-core, 8 GB Apple Container Linux VM (Apple M4 Max host), a
1,000,000-message run through `imuxsock` + `omfile`:

| Pipeline | Throughput |
|----------|------------|
| baseline omfile (no signing) | ~376,000 msg/s |
| mmhashchainsigs + omfile (signinterval=1024) | ~343,000 msg/s |
| `mmhashchainsigs-verify` over the signed log | ~578,000 lines/s |

Signing costs roughly **9% throughput** and emits two SD elements per
message (chain metadata + captured headers), so the on-disk file is
~2.3× larger than plain `RSYSLOG_TraditionalFileFormat` output.
Verification stays faster than signing, so a single verifier can keep
up with logs from many signing hosts. See [docs/BENCHMARK.md](docs/BENCHMARK.md)
for the methodology, full per-run numbers, and reproduction instructions.

## License

See [LICENSE](LICENSE) file.
