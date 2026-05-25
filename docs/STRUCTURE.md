# Project Structure

## Directory Layout

```
.
├── Makefile                              Top-level build system
├── README.md                             Project overview and usage guide
├── CLAUDE.md                             AI assistant project instructions
├── LICENSE                               Apache 2.0
├── docs/
│   ├── STRUCTURE.md                      This file
│   ├── DEVENV.md                         Development environment setup
│   ├── BENCHMARK.md                      Benchmark methodology and results
│   └── diagrams/                         PlantUML diagrams (see below)
├── conf/
│   └── mmhashchainsigs.conf.example      Example rsyslog configuration
├── src/
│   ├── common/                           Shared library (used by module and verifier)
│   │   ├── hcs_crypto.{c,h}              Crypto API: SHA-256, Ed25519, key loading
│   │   └── hcs_format.{c,h}              SD element format and helpers
│   ├── mmhashchainsigs/                  Rsyslog message modification module
│   │   ├── mmhashchainsigs.{c,h}         Core hash/sign/SD logic + rsyslog boilerplate
│   │   ├── hashchain.{c,h}               Hash chain state management API
│   │   └── signer.{c,h}                  Ed25519 signer lifecycle
│   └── verify/                           Verification CLI tool
│       ├── verifier.{c,h}                Verification engine and state machine
│       └── mmhashchainsigs_verify.c      CLI entry point
├── tests/
│   ├── test_signer.c                     Crypto primitives
│   ├── test_format.c                     SD record format + strip helpers
│   ├── test_hashchain.c                  Hash chain semantics
│   ├── test_mmhashchainsigs.c            mmhashchainsigs + verifier integration
│   └── integration/                      Scripts driving a real rsyslog
│       ├── send_syslog.c                 Bulk unix-domain syslog sender (C helper)
│       ├── run.sh                        Functional tests
│       └── bench.sh                      Throughput benchmark
├── tools/
│   └── mmhashchainsigs-keygen.sh         Ed25519 key pair generation script
└── build/                                Build output (gitignored)
    ├── common/                           Compiled common objects
    ├── mmhashchainsigs/                  Compiled module objects
    ├── verify/                           Compiled verifier objects
    ├── tests/                            Test binaries
    ├── integration/
    │   └── send_syslog                   Compiled sender helper
    ├── mmhashchainsigs-verify            Verification CLI binary
    └── mmhashchainsigs.so                Rsyslog mm module (when rsyslog-dev present)
```

## Source Components

### `src/common/` -- Shared Cryptographic Library

Code shared between the rsyslog module and the verification tool. Has no
rsyslog dependency -- only OpenSSL.

**hcs_crypto.{c,h}**

Core cryptographic operations using OpenSSL 3.0+ EVP API:
- `hcs_sha256()` -- Single-shot SHA-256 digest
- `hcs_sha256_chain()` -- Chain hash: `SHA-256(prev || seq_be64 || msg)`
- `hcs_load_private_key()` / `hcs_load_public_key()` -- PEM key loading with Ed25519 type validation
- `hcs_ed25519_sign()` / `hcs_ed25519_verify()` -- Single-shot Ed25519 sign/verify
- `hcs_pubkey_fingerprint()` -- SHA-256 of raw public key bytes

**hcs_format.{c,h}**

RFC 5424 structured data record format -- the contract between writer and verifier:
- `hcs_chain_init_hash()` -- Well-known initialization vector: `SHA-256("MMHASHCHAINSIGS_CHAIN_INIT_V1")`
- `hcs_format_sd_init()` / `hcs_format_sd_msg()` / `hcs_format_sd_sig()` / `hcs_format_sd_continue()` -- Format chain-metadata SD elements
- `hcs_format_sd_hdr()` -- Format the `[mmhashchainsigs-hdr@32473 ...]` element carrying the six captured syslog header fields (`pri`, `ts`, `host`, `app`, `procid`, `msgid`) with RFC 5424 PARAM-VALUE escaping
- `hcs_parse_sd()` -- Parse a single `[mmhashchainsigs@32473 ...]` chain-metadata element into fields
- `hcs_strip_sd_from_line()` -- Find and strip the (leading) chain-metadata SD element from a log line
- `hcs_strip_all_sd()` -- Remove every element with a given SD-ID from an SD-section string (used by mmhashchainsigs to discard client-supplied `mmhashchainsigs@32473` or `mmhashchainsigs-hdr@32473` collision elements before signing)
- Hex and base64 encode/decode utilities

### `src/mmhashchainsigs/` -- Rsyslog Message Modification Module

**hashchain.{c,h}**

Hash chain state management:
- `hashchain_init()` -- Initialize with well-known IV, seq=1
- `hashchain_update()` -- Add message to chain, increment sequence and count
- `hashchain_reset_count()` -- Reset message count after signing (chain continues)
- `hashchain_reset()` -- Full reset for log rotation (new chain)

**signer.{c,h}**

Ed25519 signer lifecycle:
- `signer_init()` -- Load private key from PEM, compute public key fingerprint, reject world-readable keys
- `signer_sign()` -- Sign data with Ed25519
- `signer_free()` -- Free key and cleanse memory with `OPENSSL_cleanse()`

**mmhashchainsigs.{c,h}**

Message modification module for RELP transmission signing:

1. **Standalone core** (always compiled) -- Hash/sign/SD logic:
   - `mmhashchainsigs_init()` -- Load private key, init hash chain
   - `mmhashchainsigs_process_msg()` -- Hash `payload` into the chain, produce RFC 5424 SD element (INIT, MSG, or SIG). If a `pending_state` is loaded from a previous shutdown, the first call routes through `process_final` instead.
   - `mmhashchainsigs_final_sign()` -- Extend the chain with an empty payload and sign (standalone final signature for callers that manage their own output)
   - `mmhashchainsigs_process_final()` -- Restore a saved chain, hash the real message through it, sign, emit SIG, then reinitialize for a new chain
   - `mmhashchainsigs_save_state()` -- Atomically write chain state (hash, seq, sig_seq_from, pubkey fingerprint) to a file for recovery on next startup
   - `mmhashchainsigs_load_state()` -- Read and parse a saved state file
   - `mmhashchainsigs_delete_state()` -- Remove the state file after consumption
   - `mmhashchainsigs_free()` -- Free signer resources and any unconsumed pending state

2. **Rsyslog boilerplate** (compiled only without `MMHASHCHAINSIGS_STANDALONE`) -- Module API:
   - Declared via `MODULE_TYPE_OUTPUT` (rsyslog's output module interface)
   - Configuration parameter parsing (`privatekey`, `signinterval`, `template`, `statefiledir`)
   - `createWrkrInstance`: rejects a second worker (hash chain requires sequential processing); loads saved state from `statefiledir` if present
   - `doAction` handler: capture six header fields from `pMsg`, format the `[mmhashchainsigs-hdr@32473 ...]` element, strip client `mmhashchainsigs@32473` and `mmhashchainsigs-hdr@32473` SDs if any, hash `hdr_SD || cleaned_client_SD || MSG`, prepend the chain-metadata SD element
   - `freeWrkrInstance`: saves chain state to `statefiledir` if unsigned messages remain

### `src/verify/` -- Verification Tool

**verifier.{c,h}**

Verification state machine for SD-formatted logs:
- States: `EXPECT_INIT` -> `PROCESSING` -> `DONE` (or `ERROR`)
- `verifier_init()` -- Load public key, compute fingerprint
- `verifier_process_line()` -- Strip leading `[mmhashchainsigs@32473 ...]` element, hash the remainder, verify chain
- `verifier_finalize()` -- Check for unsigned tail in strict mode
- Tracks up to 64 errors with line numbers and descriptive messages

**mmhashchainsigs_verify.c**

CLI entry point:
- `getopt_long` argument parsing
- Line-by-line file reading with `getline()`
- Exit code mapping: 0=pass, 1=integrity failure, 2=usage, 3=key mismatch
- Verbose and quiet output modes

## Test Suites

| File | Tests | What It Covers |
|------|-------|----------------|
| `test_signer.c` | 4 | SHA-256 known vector, chain hash, Ed25519 sign/verify roundtrip, fingerprint |
| `test_format.c` | 20 | Hex, base64, SD INIT/MSG/SIG/CONTINUE roundtrip, SD strip, bad input rejection, `hcs_strip_all_sd` (empty/none/single/multiple/quoted-bracket/out-too-small/hdr-id/in-place), `hcs_format_sd_hdr` (basic/empty-fields/escaping/buf-too-small) |
| `test_hashchain.c` | 6 | Chain init IV, update, determinism, ordering, count reset, full reset |
| `test_mmhashchainsigs.c` | 17 | SD chain verify, tamper detect, multi-segment, single message, `mmhashchainsigs_process_msg`, sign-interval=1, RFC 5424 with client SD, RFC 5424 collision (poisoned `mmhashchainsigs@32473`), hdr chain verify, hdr tamper detect, hdr collision (poisoned `mmhashchainsigs-hdr@32473`), `final_sign` (covers tail, no unsigned, uninitialized), state save/load roundtrip, state inject+verify (full shutdown/restart flow), state no-unsigned |

All tests generate temporary Ed25519 key pairs at runtime. No test fixtures are
checked in.

### Integration and Benchmark Tests

Located in `tests/integration/`, these drive a real `rsyslogd` reading from
unix sockets inside a temp directory, so no root privileges or TCP ports are
required. They are not part of `make test` (which runs unit tests only).

| Script / source | What It Covers |
|-----------------|----------------|
| `send_syslog.c` | Opens the unix datagram socket once and sends N RFC 3164 messages -- avoids the cost of forking `logger` per message |
| `run.sh` | 8 tests: `imuxsock`-based write+verify and tamper detection; `imptcp` + `rsyslog.rfc5424` parser tests for RFC 5424 with client SD, SD-ID collision, distinct-per-message header capture, and header-value tamper detection; `statefiledir` shutdown+restart (state file written, consumed on restart, strict verification passes); no-statefiledir strict-mode unsigned-tail detection |
| `bench.sh` | Throughput comparison: baseline omfile vs `mmhashchainsigs` + omfile. Also measures `mmhashchainsigs-verify` throughput |

Both scripts run the sender, sleep briefly so rsyslog can drain the socket
receive buffer, then `SIGTERM` rsyslog and wait for it to flush its action
queues before reading the log file. This avoids the polling loop that
otherwise capped time resolution at one second.

Run with `make test-integration` or `make bench` (both require rsyslog).

## Diagrams

PlantUML sources live in `docs/diagrams/`:

| File | What it shows |
|------|---------------|
| `architecture.puml` | Component view: rsyslog, mmhashchainsigs, hashchain, signer, hcs library, verifier |
| `pipeline.puml` | Deployment view: signing origin → RELP → receiving rsyslog → omfile → mmhashchainsigs-verify |
| `message-processing.puml` | End-to-end sequence diagram for one message through `doAction` and onto disk |
| `verification.puml` | Sequence diagram for `mmhashchainsigs-verify` reading and validating a log file |
| `verifier-state-machine.puml` | State diagram for `verifier_ctx_t` (`EXPECT_INIT` → `PROCESSING` → `DONE`/`ERROR`) |

Render with `plantuml docs/diagrams/*.puml` or any PlantUML-aware viewer.

## Build Targets

| Target | Command | Output | Requires |
|--------|---------|--------|----------|
| Verify tool | `make` or `make verify-tool` | `build/mmhashchainsigs-verify` | OpenSSL |
| Rsyslog module | `make module` | `build/mmhashchainsigs.so` | OpenSSL + rsyslog-dev |
| Unit tests | `make test` | `build/tests/test_*` (47 tests) | OpenSSL |
| Integration tests | `make test-integration` | Runs `tests/integration/run.sh` | OpenSSL + rsyslog |
| Benchmarks | `make bench` | Runs `tests/integration/bench.sh` | OpenSSL + rsyslog |
| Install | `make install` | Installs to `$PREFIX` | varies |
| Clean | `make clean` | Removes `build/` | -- |
