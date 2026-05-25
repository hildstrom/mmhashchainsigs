# Benchmark Results

This document describes the `tests/integration/bench.sh` methodology and
records throughput numbers for the mmhashchainsigs reference environment.

## Test System

| | |
|---|---|
| Host hardware | Apple MacBook Pro, M4 Max, 128 GB RAM |
| Container runtime | Apple Container (Apple's lightweight Linux VM for macOS) |
| Allocated CPUs | 9 cores |
| Allocated memory | 8 GB |
| Guest OS | Ubuntu 24.04.4 LTS (aarch64) |
| Kernel | Linux 6.18.5 |
| rsyslogd | 8.2312.0 |
| OpenSSL | 3.0.13 |
| Compiler | gcc 13.3.0 |
| CFLAGS | `-Wall -Wextra -Werror -pedantic -std=c11 -O2 -fPIC -D_POSIX_C_SOURCE=200809L` |

All file I/O lands on the container's writable layer, which is
backed by an APFS image on the M4 Max's internal NVMe.

## Methodology

### Pipeline under test

`bench.sh` runs rsyslog with `imuxsock` reading from a unix domain socket
inside a temp directory (no root, no TCP ports). Two rsyslog
configurations are exercised back to back, each as its own rsyslog
process so neither can warm caches for the other:

1. **baseline (omfile)** -- plain `omfile` with
   `RSYSLOG_TraditionalFileFormat`. No mmhashchainsigs code involved.
2. **mmhashchainsigs + omfile** -- `mmhashchainsigs` action followed by `omfile` with
   the `sd-preserve` template
   (`string="%STRUCTURED-DATA%%msg%\n"`). `mmhashchainsigs` is configured with
   `signinterval="1024"`, so it produces one Ed25519 signature per 1024
   messages.

The third measurement -- **verification throughput** -- runs
`mmhashchainsigs-verify -q` over the mmhashchainsigs log file produced above.

### Message source

The legacy bash benchmark called `logger -u SOCK ...` once per message,
which forked and exec'd `logger` a million times. This dominated wall
time and made the rsyslog throughput numbers meaningless. The new
benchmark uses `build/integration/send_syslog`, a small C helper that:

- Opens the unix datagram socket once.
- Builds an RFC 3164 message in a fixed buffer
  (`<13>Mmm DD HH:MM:SS host tag[pid]: prefix N of count`).
- Calls `sendto()` in a tight loop, with `nanosleep(1 ms)` backoff if the
  kernel returns `ENOBUFS` / `EAGAIN`.

### Timing flow

For each rsyslog configuration, one round is:

1. `start_rsyslog` -- launch rsyslogd; wait for the socket file to appear.
2. `t0 = date +%s%N`
3. Run `send_syslog SOCK tag count` (synchronous; returns after the final
   `sendto`).
4. `sleep "$DRAIN_PAUSE"` (default 0.2 s) so rsyslog's imuxsock worker
   can drain whatever datagrams are still in the kernel socket receive
   buffer.
5. `kill -TERM "$RSYSLOG_PID"; wait "$RSYSLOG_PID"`. rsyslog flushes its
   action queues during shutdown, so when `wait` returns the log file
   contains every message that was successfully delivered.
6. `t1 = date +%s%N`. Throughput is reported as
   `lines * 1000 / ((t1 - t0) / 1e6)` msg/s.
7. `wc -l "$logfile"` and warn if the count does not match `count`.

This replaces the previous `wait_for_lines` polling loop, which had a
one-second sleep between checks and called `wc -l` on the whole file
every iteration. The new flow gives nanosecond-resolution start/end
timestamps, doesn't waste time polling, and uses rsyslog's own
shutdown-drain as the natural "all done" event.

Verification timing is identical in spirit: `t0` before `mmhashchainsigs-verify`,
`t1` after it returns.

## Results

Default invocation (`tests/integration/bench.sh` with the script's
1,000,000-message default). Three back-to-back runs:

### Run 1
```
baseline (omfile)             1000000 msgs      2659 ms    376081 msg/s  141 MB
mmhashchainsigs + omfile      1000000 msgs      2919 ms    342583 msg/s  327 MB
  verification: PASS

Verification throughput:
  mmhashchainsigs             1000000 lines      1711 ms    584453 lines/s
```

### Run 2
```
baseline (omfile)             1000000 msgs      2676 ms    373692 msg/s  141 MB
mmhashchainsigs + omfile      1000000 msgs      2955 ms    338409 msg/s  327 MB
  verification: PASS

Verification throughput:
  mmhashchainsigs             1000000 lines      1737 ms    575705 lines/s
```

### Run 3
```
baseline (omfile)             1000000 msgs      2643 ms    378357 msg/s  141 MB
mmhashchainsigs + omfile      1000000 msgs      2860 ms    349650 msg/s  327 MB
  verification: PASS

Verification throughput:
  mmhashchainsigs             1000000 lines      1740 ms    574712 lines/s
```

### Summary

| Stage | Mean elapsed | Mean throughput |
|-------|--------------|-----------------|
| baseline omfile | 2659 ms | ~376,000 msg/s |
| mmhashchainsigs + omfile | 2911 ms | ~343,000 msg/s |
| mmhashchainsigs-verify | 1729 ms | ~578,000 lines/s |

| Comparison | Value |
|------------|-------|
| Signing overhead (latency) | (2911 − 2659) / 2659 ≈ **+9.5%** |
| Signing overhead (throughput) | (376k − 343k) / 376k ≈ **−8.8%** |
| File size | 327 MB vs 141 MB baseline (**~2.3× larger**) |

`mmhashchainsigs` keeps up with rsyslog's omfile output and pays
roughly **nine percent throughput** for per-message SHA-256 chaining,
one Ed25519 signature per 1024 messages, and the captured-header SD
element on every line.

`mmhashchainsigs-verify` is comfortably faster than the producer side
-- in this configuration it processes ~578k lines per second,
replaying the chain and checking ~1000 signatures along the way.
Verification stays well ahead of any plausible signing-side
throughput, so a single verifier can keep up with logs from many
signing hosts.

### Note on file size

The file is ~2.3× larger than the plain-omfile baseline because every
line carries:
- the `[mmhashchainsigs@32473 ...]` chain-metadata element
  (~95 bytes for an ordinary message, ~290 for a signature message),
- the `[mmhashchainsigs-hdr@32473 ...]` element with all six captured
  header fields (typically ~120 bytes), and
- the original message body.

The captured-header element is the dominant addition. Operators who do
not need cryptographic header protection can remove this overhead in a
future tunable, but for the current build it is unconditional because
the security guarantee depends on it. The baseline file uses
`RSYSLOG_TraditionalFileFormat` (a short header line); a fairer
"what-if" comparison would use `sd-preserve` for both, in which case
the ratio drops considerably -- the absolute numbers here include the
template-shape difference and should be read as an upper bound on the
storage cost.

## Reproducing

```sh
# Build everything (verify tool, integration helper, rsyslog module)
make all RSYSLOG_SRC=/path/to/rsyslog-source

# Default: 1,000,000 messages
tests/integration/bench.sh

# Custom message count
tests/integration/bench.sh 5000000

# Override the drain pause if your host is much slower
DRAIN_PAUSE=0.5 tests/integration/bench.sh
```

The script exits non-zero if any benchmark round delivers fewer lines
than were sent.

## Caveats

- This is a single-host, in-memory pipeline. RELP transport, network
  latency, and disk fsync on a real audit host will dominate the wire-time
  budget and shrink the relative cost of mmhashchainsigs further.
- The message body is fixed-size and small (~90 bytes). Larger messages
  reduce mmhashchainsigs's relative cost because the SHA-256 update is the same
  size class as the rest of rsyslog's per-message work.
- The sign interval (1024) is the default. Lowering it produces more
  Ed25519 signatures per second; raising it produces fewer. Ed25519 sign
  cost is small compared to the per-message SHA-256 chain update, so
  this knob has a modest effect.
- Apple Container is a recent macOS feature; absolute numbers will shift
  on bare metal Linux. The *relative* overhead between baseline and
  mmhashchainsigs is the load-bearing measurement here.
