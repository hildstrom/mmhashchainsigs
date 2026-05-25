#!/bin/bash
set -euo pipefail

# Integration tests for mmhashchainsigs.
# Uses imuxsock with a unix domain socket in a temp directory,
# so no root privileges or TCP ports are required.
#
# Requires: rsyslog, modules built (make module),
#           and build/integration/send_syslog helper.
#
# Usage: tests/integration/run.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERIFY="$PROJECT_DIR/build/mmhashchainsigs-verify"
MMHASHCHAINSIGS_SO="$PROJECT_DIR/build/mmhashchainsigs.so"
SENDER="$PROJECT_DIR/build/integration/send_syslog"

DRAIN_PAUSE="${DRAIN_PAUSE:-0.2}"
TMPDIR_BASE=""
RSYSLOG_PID=""
SOCK=""
PASS=0
FAIL=0

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

setup_tmpdir() {
    TMPDIR_BASE="$(mktemp -d /tmp/mmhcs-integ.XXXXXX)"
    SOCK="$TMPDIR_BASE/syslog.sock"
}

generate_keys() {
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
stop_rsyslog() {
    if [ -n "$RSYSLOG_PID" ] && kill -0 "$RSYSLOG_PID" 2>/dev/null; then
        kill -TERM "$RSYSLOG_PID" 2>/dev/null || true
        wait "$RSYSLOG_PID" 2>/dev/null || true
        RSYSLOG_PID=""
    fi
}

# Send <count> messages, give rsyslog a moment to drain the socket,
# then stop it and wait for the queue flush.
send_and_drain() {
    local count="$1"
    local tag="${2:-mmhcs-test}"
    "$SENDER" "$SOCK" "$tag" "$count"
    sleep "$DRAIN_PAUSE"
    stop_rsyslog
}

report() {
    local name="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name"
        FAIL=$((FAIL + 1))
    fi
}

# --- Test: mmhashchainsigs write and verify ---
test_mmhashchainsigs_basic() {
    local logfile="$TMPDIR_BASE/mmhashchainsigs-basic.log"
    local conf="$TMPDIR_BASE/mmhashchainsigs-basic.conf"

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
        signinterval="10"
    )
    action(
        type="omfile"
        file="$logfile"
        template="sd-preserve"
    )
}
EOF

    start_rsyslog "$conf"
    send_and_drain 25

    if [ ! -f "$logfile" ]; then
        echo "    logfile not created" >&2
        cat "$TMPDIR_BASE/rsyslog.err" >&2
        report "mmhashchainsigs_basic" 1
        return
    fi

    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" >/dev/null 2>&1
    report "mmhashchainsigs_basic" $?
}

# --- Test: mmhashchainsigs tamper detection ---
test_mmhashchainsigs_tamper() {
    local logfile="$TMPDIR_BASE/mmhashchainsigs-tamper.log"
    local conf="$TMPDIR_BASE/mmhashchainsigs-tamper.conf"

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
        signinterval="5"
    )
    action(
        type="omfile"
        file="$logfile"
        template="sd-preserve"
    )
}
EOF

    start_rsyslog "$conf"
    send_and_drain 15

    if [ ! -f "$logfile" ]; then
        report "mmhashchainsigs_tamper" 1
        return
    fi

    local pre post
    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1 && pre=0 || pre=$?

    sed -i '3s/message/TAMPERED/' "$logfile"

    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1 && post=0 || post=$?

    if [ "$pre" -eq 0 ] && [ "$post" -ne 0 ]; then
        report "mmhashchainsigs_tamper" 0
    else
        echo "    pre-tamper=$pre post-tamper=$post (expected 0,1)" >&2
        report "mmhashchainsigs_tamper" 1
    fi
}

# Send raw RFC 5424 messages over the imptcp stream socket.
# Stdin is the message body (one message per line).
send_5424() {
    local sock="$1"
    socat - UNIX-CONNECT:"$sock"
}

# --- Test: RFC 5424 input with a non-mmhashchainsigs client SD element ---
test_rfc5424_client_sd() {
    local logfile="$TMPDIR_BASE/mmhashchainsigs-5424client.log"
    local conf="$TMPDIR_BASE/mmhashchainsigs-5424client.conf"
    local sock="$TMPDIR_BASE/5424client.sock"

    cat > "$conf" <<EOF
global(workDirectory="$TMPDIR_BASE")

module(load="imptcp")
module(load="$MMHASHCHAINSIGS_SO")

template(name="sd-preserve" type="string"
    string="%STRUCTURED-DATA%%msg%\n")

ruleset(name="r5424" parser=["rsyslog.rfc5424"]) {
    action(
        type="mmhashchainsigs"
        privatekey="$TMPDIR_BASE/privkey.pem"
        signinterval="3"
    )
    action(
        type="omfile"
        file="$logfile"
        template="sd-preserve"
    )
}

input(type="imptcp" path="$sock" ruleset="r5424")
EOF

    start_rsyslog_no_unix_sock "$conf" "$sock"

    {
        for i in $(seq 1 9); do
            printf '<13>1 2026-05-25T12:00:%02dZ host app 1 - [client@9999 trace="t%d"] message %d\n' \
                "$i" "$i" "$i"
        done
    } | send_5424 "$sock"

    sleep "$DRAIN_PAUSE"
    stop_rsyslog

    if [ ! -f "$logfile" ]; then
        echo "    logfile not created" >&2
        cat "$TMPDIR_BASE/rsyslog.err" >&2
        report "rfc5424_client_sd" 1
        return
    fi

    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" >/dev/null 2>&1
    report "rfc5424_client_sd" $?
}

# --- Test: RFC 5424 input with poisoned mmhashchainsigs SD (collision) ---
test_rfc5424_collision() {
    local logfile="$TMPDIR_BASE/mmhashchainsigs-collision.log"
    local conf="$TMPDIR_BASE/mmhashchainsigs-collision.conf"
    local sock="$TMPDIR_BASE/collision.sock"

    cat > "$conf" <<EOF
global(workDirectory="$TMPDIR_BASE")

module(load="imptcp")
module(load="$MMHASHCHAINSIGS_SO")

template(name="sd-preserve" type="string"
    string="%STRUCTURED-DATA%%msg%\n")

ruleset(name="r5424" parser=["rsyslog.rfc5424"]) {
    action(
        type="mmhashchainsigs"
        privatekey="$TMPDIR_BASE/privkey.pem"
        signinterval="3"
    )
    action(
        type="omfile"
        file="$logfile"
        template="sd-preserve"
    )
}

input(type="imptcp" path="$sock" ruleset="r5424")
EOF

    start_rsyslog_no_unix_sock "$conf" "$sock"

    {
        for i in $(seq 1 6); do
            printf '<13>1 2026-05-25T12:00:%02dZ host app 1 - [mmhashchainsigs@32473 fake="poison%d"][client@9999 trace="t%d"] message %d\n' \
                "$i" "$i" "$i" "$i"
        done
    } | send_5424 "$sock"

    sleep "$DRAIN_PAUSE"
    stop_rsyslog

    if [ ! -f "$logfile" ]; then
        report "rfc5424_collision" 1
        return
    fi

    # Each output line must contain exactly one [mmhashchainsigs@32473 ...]
    # element. Anything else means the client's poisoned SD survived.
    local max
    max="$(awk -F'\\[mmhashchainsigs@32473 ' '{print NF-1}' "$logfile" \
        | sort -nr | head -1)"
    if [ "$max" -ne 1 ]; then
        echo "    multiple mmhashchainsigs SDs on one line (max=$max)" >&2
        report "rfc5424_collision" 1
        return
    fi

    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" >/dev/null 2>&1
    report "rfc5424_collision" $?
}

# --- Test: header capture (RFC 5424 distinct headers per message) ---
test_rfc5424_header_capture() {
    local logfile="$TMPDIR_BASE/mmhcs-hdr.log"
    local conf="$TMPDIR_BASE/mmhcs-hdr.conf"
    local sock="$TMPDIR_BASE/hdr.sock"

    cat > "$conf" <<EOF
global(workDirectory="$TMPDIR_BASE")

module(load="imptcp")
module(load="$MMHASHCHAINSIGS_SO")

template(name="sd-preserve" type="string"
    string="%STRUCTURED-DATA%%msg%\n")

ruleset(name="r5424" parser=["rsyslog.rfc5424"]) {
    action(
        type="mmhashchainsigs"
        privatekey="$TMPDIR_BASE/privkey.pem"
        signinterval="3"
    )
    action(
        type="omfile"
        file="$logfile"
        template="sd-preserve"
    )
}

input(type="imptcp" path="$sock" ruleset="r5424")
EOF

    start_rsyslog_no_unix_sock "$conf" "$sock"

    {
        for i in $(seq 1 9); do
            printf '<13>1 2026-05-25T12:00:%02dZ host%d app%d %d MID%d - body %d\n' \
                "$i" "$i" "$i" "$i" "$i" "$i"
        done
    } | send_5424 "$sock"

    sleep "$DRAIN_PAUSE"
    stop_rsyslog

    if [ ! -f "$logfile" ]; then
        report "rfc5424_header_capture" 1
        return
    fi

    # Each line must carry the per-message hdr SD element with the
    # right host/app/procid/msgid values baked in.
    local i ok=1
    for i in $(seq 1 9); do
        if ! grep -q "host=\"host${i}\".*app=\"app${i}\".*procid=\"${i}\".*msgid=\"MID${i}\"" "$logfile"; then
            echo "    missing hdr fields for message $i" >&2
            ok=0
        fi
    done
    if [ "$ok" -ne 1 ]; then
        report "rfc5424_header_capture" 1
        return
    fi

    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" >/dev/null 2>&1
    report "rfc5424_header_capture" $?
}

# --- Test: tampered header value breaks the chain ---
test_rfc5424_header_tamper() {
    local logfile="$TMPDIR_BASE/mmhcs-hdrtamp.log"
    local conf="$TMPDIR_BASE/mmhcs-hdrtamp.conf"
    local sock="$TMPDIR_BASE/hdrtamp.sock"

    cat > "$conf" <<EOF
global(workDirectory="$TMPDIR_BASE")

module(load="imptcp")
module(load="$MMHASHCHAINSIGS_SO")

template(name="sd-preserve" type="string"
    string="%STRUCTURED-DATA%%msg%\n")

ruleset(name="r5424" parser=["rsyslog.rfc5424"]) {
    action(
        type="mmhashchainsigs"
        privatekey="$TMPDIR_BASE/privkey.pem"
        signinterval="3"
    )
    action(
        type="omfile"
        file="$logfile"
        template="sd-preserve"
    )
}

input(type="imptcp" path="$sock" ruleset="r5424")
EOF

    start_rsyslog_no_unix_sock "$conf" "$sock"
    {
        for i in $(seq 1 6); do
            printf '<13>1 2026-05-25T12:00:%02dZ originhost myapp %d MID%d - body %d\n' \
                "$i" "$i" "$i" "$i"
        done
    } | send_5424 "$sock"
    sleep "$DRAIN_PAUSE"
    stop_rsyslog

    if [ ! -f "$logfile" ]; then
        report "rfc5424_header_tamper" 1
        return
    fi

    local pre post
    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1 && pre=0 || pre=$?

    # Forge the host on line 2 from "originhost" to "ATTACKER!!"
    # (10 chars in, 10 chars out, preserves all surrounding bytes).
    sed -i '2s/host="originhost"/host="ATTACKER!!"/' "$logfile"

    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1 && post=0 || post=$?

    if [ "$pre" -eq 0 ] && [ "$post" -ne 0 ]; then
        report "rfc5424_header_tamper" 0
    else
        echo "    pre=$pre post=$post (expected 0, !0)" >&2
        report "rfc5424_header_tamper" 1
    fi
}

# Same as start_rsyslog but waits for an arbitrary socket path
# (used by imptcp tests that don't create $SOCK).
start_rsyslog_no_unix_sock() {
    local conf="$1"
    local wait_path="$2"
    rsyslogd -f "$conf" \
        -i "$TMPDIR_BASE/rsyslog.pid" \
        -n 2>"$TMPDIR_BASE/rsyslog.err" &
    RSYSLOG_PID=$!
    local elapsed=0
    while [ "$elapsed" -lt 10 ]; do
        if [ -S "$wait_path" ]; then
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
    die "rsyslogd did not create socket $wait_path"
}

# --- Main ---
main() {
    echo "=== mmhashchainsigs integration tests ==="
    preflight
    setup_tmpdir
    generate_keys

    test_mmhashchainsigs_basic
    test_mmhashchainsigs_tamper
    test_rfc5424_client_sd
    test_rfc5424_collision
    test_rfc5424_header_capture
    test_rfc5424_header_tamper

    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    [ "$FAIL" -eq 0 ]
}

main "$@"
