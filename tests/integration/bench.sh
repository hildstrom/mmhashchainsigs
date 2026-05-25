#!/bin/bash
set -euo pipefail

# Benchmark tests for mmhashchainsigs.
# Measures throughput with and without mmhashchainsigs to show overhead.
# Uses imuxsock with a unix domain socket in a temp directory,
# so no root privileges or TCP ports are required.
#
# Requires: rsyslog, modules built (make module),
#           and build/integration/send_syslog helper.
#
# Usage: tests/integration/bench.sh [message_count]
#
# Default: 1000000 messages per test.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERIFY="$PROJECT_DIR/build/mmhashchainsigs-verify"
MMHASHCHAINSIGS_SO="$PROJECT_DIR/build/mmhashchainsigs.so"
SENDER="$PROJECT_DIR/build/integration/send_syslog"

MSG_COUNT="${1:-1000000}"
# Drain pause: brief sleep after the sender finishes so rsyslog can pull
# the last datagrams out of the socket receive buffer before we SIGTERM it.
DRAIN_PAUSE="${DRAIN_PAUSE:-0.2}"
TMPDIR_BASE=""
RSYSLOG_PID=""
SOCK=""

cleanup() {
    if [ -n "$RSYSLOG_PID" ] && kill -0 "$RSYSLOG_PID" 2>/dev/null; then
        kill "$RSYSLOG_PID" 2>/dev/null || true
        wait "$RSYSLOG_PID" 2>/dev/null || true
    fi
    if [ -n "$TMPDIR_BASE" ] && [ -d "$TMPDIR_BASE" ]; then
        rm -rf "$TMPDIR_BASE"
    fi
}
trap cleanup EXIT

die() {
    echo "FATAL: $*" >&2
    exit 2
}

preflight() {
    [ -x "$VERIFY" ] || die "mmhashchainsigs-verify not built: $VERIFY"
    [ -f "$MMHASHCHAINSIGS_SO" ] || die "mmhashchainsigs.so not built: $MMHASHCHAINSIGS_SO"
    [ -x "$SENDER" ] || die "send_syslog not built: $SENDER"
    command -v rsyslogd >/dev/null || die "rsyslogd not found"
}

setup() {
    TMPDIR_BASE="$(mktemp -d /tmp/mmhcs-bench.XXXXXX)"
    SOCK="$TMPDIR_BASE/syslog.sock"
    openssl genpkey -algorithm Ed25519 \
        -out "$TMPDIR_BASE/privkey.pem" 2>/dev/null
    chmod 600 "$TMPDIR_BASE/privkey.pem"
    openssl pkey -in "$TMPDIR_BASE/privkey.pem" -pubout \
        -out "$TMPDIR_BASE/pubkey.pem" 2>/dev/null
}

start_rsyslog() {
    local conf="$1"
    rsyslogd -f "$conf" \
        -i "$TMPDIR_BASE/rsyslog.pid" \
        -n 2>"$TMPDIR_BASE/rsyslog.err" &
    RSYSLOG_PID=$!
    local elapsed=0
    while [ "$elapsed" -lt 10 ]; do
        if [ -S "$SOCK" ]; then
            return 0
        fi
        if ! kill -0 "$RSYSLOG_PID" 2>/dev/null; then
            echo "rsyslogd stderr:" >&2
            cat "$TMPDIR_BASE/rsyslog.err" >&2
            die "rsyslogd exited unexpectedly"
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    die "rsyslogd did not create socket $SOCK"
}

# SIGTERM rsyslog and wait for it to flush+exit.
# Rsyslog drains its action queues before exit, so when wait returns
# the log file contains every message that was successfully processed.
stop_rsyslog() {
    if [ -n "$RSYSLOG_PID" ] && kill -0 "$RSYSLOG_PID" 2>/dev/null; then
        kill -TERM "$RSYSLOG_PID" 2>/dev/null || true
        wait "$RSYSLOG_PID" 2>/dev/null || true
        RSYSLOG_PID=""
    fi
}

# Run one benchmark round end-to-end: send, drain, stop, measure.
# Echoes "<elapsed_ms> <line_count>" on stdout.
# Elapsed time is t0 (start of send) to t1 (rsyslog exited after flush).
run_round() {
    local logfile="$1"
    local count="$2"
    local tag="${3:-bench}"
    local t0 t1

    t0="$(date +%s%N)"
    "$SENDER" "$SOCK" "$tag" "$count"
    sleep "$DRAIN_PAUSE"
    stop_rsyslog
    t1="$(date +%s%N)"

    local elapsed_ms=$(( (t1 - t0) / 1000000 ))
    local lines
    lines="$(wc -l < "$logfile" 2>/dev/null || echo 0)"
    if [ "$lines" -ne "$count" ]; then
        echo "WARNING: expected $count lines, got $lines in $logfile" >&2
    fi
    echo "$elapsed_ms $lines"
}

file_size_human() {
    local size
    size="$(stat -c%s "$1" 2>/dev/null || echo 0)"
    if [ "$size" -ge 1048576 ]; then
        echo "$((size / 1048576)) MB"
    elif [ "$size" -ge 1024 ]; then
        echo "$((size / 1024)) KB"
    else
        echo "$size B"
    fi
}

print_result() {
    local label="$1"
    local lines="$2"
    local elapsed_ms="$3"
    local logfile="$4"
    local rate=0
    if [ "$elapsed_ms" -gt 0 ]; then
        rate=$(( lines * 1000 / elapsed_ms ))
    fi
    printf "  %-28s %8d msgs  %8d ms  %8d msg/s  %s\n" \
        "$label" "$lines" "$elapsed_ms" "$rate" \
        "$(file_size_human "$logfile")"
}

# --- Baseline: plain omfile, no mmhashchainsigs ---
bench_baseline() {
    local logfile="$TMPDIR_BASE/baseline.log"
    local conf="$TMPDIR_BASE/baseline.conf"

    cat > "$conf" <<EOF
global(workDirectory="$TMPDIR_BASE")

module(load="imuxsock" SysSock.Use="off")
input(type="imuxsock" Socket="$SOCK")

*.* action(
    type="omfile"
    file="$logfile"
    template="RSYSLOG_TraditionalFileFormat"
)
EOF

    start_rsyslog "$conf"
    read -r elapsed_ms lines < <(run_round "$logfile" "$MSG_COUNT")
    print_result "baseline (omfile)" "$lines" "$elapsed_ms" "$logfile"
}

# --- mmhashchainsigs + omfile ---
bench_mmhashchainsigs() {
    local logfile="$TMPDIR_BASE/mmhashchainsigs.log"
    local conf="$TMPDIR_BASE/mmhashchainsigs.conf"

    cat > "$conf" <<EOF
global(workDirectory="$TMPDIR_BASE")

module(load="imuxsock" SysSock.Use="off")
input(type="imuxsock" Socket="$SOCK")
module(load="$MMHASHCHAINSIGS_SO")

template(name="sd-preserve" type="string"
    string="%STRUCTURED-DATA%%msg%\n")

*.* {
    action(
        type="mmhashchainsigs"
        privatekey="$TMPDIR_BASE/privkey.pem"
        signinterval="1024"
        template="RSYSLOG_TraditionalFileFormat"
    )
    action(
        type="omfile"
        file="$logfile"
        template="sd-preserve"
    )
}
EOF

    start_rsyslog "$conf"
    read -r elapsed_ms lines < <(run_round "$logfile" "$MSG_COUNT")
    print_result "mmhashchainsigs + omfile" "$lines" "$elapsed_ms" "$logfile"

    if "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" -q "$logfile" >/dev/null 2>&1; then
        echo "    verification: PASS"
    else
        echo "    verification: FAIL"
    fi
}

# --- Verification throughput ---
bench_verify() {
    echo ""
    echo "  Verification throughput:"

    local logfile="$TMPDIR_BASE/mmhashchainsigs.log"
    if [ ! -f "$logfile" ]; then
        return
    fi
    local lines
    lines="$(wc -l < "$logfile")"
    local t0 t1
    t0="$(date +%s%N)"
    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" -q "$logfile" >/dev/null 2>&1 || true
    t1="$(date +%s%N)"
    local elapsed_ms=$(( (t1 - t0) / 1000000 ))
    local rate=0
    if [ "$elapsed_ms" -gt 0 ]; then
        rate=$(( lines * 1000 / elapsed_ms ))
    fi
    printf "    %-26s %8d lines  %8d ms  %8d lines/s\n" \
        "mmhashchainsigs" "$lines" "$elapsed_ms" "$rate"
}

# --- Main ---
main() {
    echo "=== mmhashchainsigs benchmark ==="
    echo "  Message count: $MSG_COUNT"
    echo ""

    preflight
    setup

    bench_baseline
    bench_mmhashchainsigs
    bench_verify

    echo ""
    echo "=== Benchmark complete ==="
}

main "$@"
