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

generate_ecdsa_curve_keys() {
    local curve="$1"
    local tag="$2"
    openssl genpkey -algorithm EC \
        -pkeyopt "ec_paramgen_curve:$curve" \
        -out "$TMPDIR_BASE/privkey-${tag}.pem" 2>/dev/null
    chmod 600 "$TMPDIR_BASE/privkey-${tag}.pem"
    openssl pkey -in "$TMPDIR_BASE/privkey-${tag}.pem" -pubout \
        -out "$TMPDIR_BASE/pubkey-${tag}.pem" 2>/dev/null
}

# Generate ECDSA key pairs for each supported NIST curve.
generate_ecdsa_keys() {
    generate_ecdsa_curve_keys P-256 ec
    generate_ecdsa_curve_keys P-384 ec384
    generate_ecdsa_curve_keys P-521 ec521
}

# Generate a self-signed leaf cert from $TMPDIR_BASE/privkey.pem.
generate_selfsigned_cert() {
    openssl req -new -x509 -key "$TMPDIR_BASE/privkey.pem" \
        -days 1 -subj "/CN=mmhcs-integ-leaf" \
        -out "$TMPDIR_BASE/cert.pem" 2>/dev/null
}

# Generate a CA + leaf cert chain. Outputs:
#   $TMPDIR_BASE/ca.pem        (CA cert PEM, also used as --ca-bundle)
#   $TMPDIR_BASE/leaf.pem      (leaf cert PEM, CA-signed)
#   privkey.pem already exists; the leaf is bound to it.
generate_ca_and_leaf() {
    # CA key + self-signed CA cert with CA:TRUE.
    openssl genpkey -algorithm Ed25519 \
        -out "$TMPDIR_BASE/ca-priv.pem" 2>/dev/null
    chmod 600 "$TMPDIR_BASE/ca-priv.pem"

    cat > "$TMPDIR_BASE/ca.cnf" <<EOF
[req]
distinguished_name = req_dn
prompt             = no
x509_extensions    = v3_ca
[req_dn]
CN = mmhcs-integ-CA
[v3_ca]
basicConstraints   = critical,CA:TRUE
keyUsage           = critical,keyCertSign
EOF

    openssl req -new -x509 -key "$TMPDIR_BASE/ca-priv.pem" \
        -days 1 -config "$TMPDIR_BASE/ca.cnf" \
        -out "$TMPDIR_BASE/ca.pem" 2>/dev/null

    # Leaf CSR signed by the CA. The leaf shares the existing privkey.pem.
    openssl req -new -key "$TMPDIR_BASE/privkey.pem" \
        -subj "/CN=mmhcs-integ-leaf" \
        -out "$TMPDIR_BASE/leaf.csr" 2>/dev/null

    openssl x509 -req -in "$TMPDIR_BASE/leaf.csr" \
        -CA "$TMPDIR_BASE/ca.pem" -CAkey "$TMPDIR_BASE/ca-priv.pem" \
        -CAcreateserial -days 1 \
        -out "$TMPDIR_BASE/leaf.pem" 2>/dev/null
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

# --- Test: statefiledir shutdown+restart produces final signature ---
test_statefiledir_restart() {
    local logfile="$TMPDIR_BASE/statefiledir-restart.log"
    local statedir="$TMPDIR_BASE/statefiledir-restart"
    local conf="$TMPDIR_BASE/statefiledir-restart.conf"
    mkdir -p "$statedir"

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
        statefiledir="$statedir"
    )
    action(
        type="omfile"
        file="$logfile"
        template="sd-preserve"
    )
}
EOF

    # Phase 1: send 15 messages (SIG at 10, leaves 5 unsigned),
    # then gracefully stop rsyslog.
    start_rsyslog "$conf"
    "$SENDER" "$SOCK" "mmhcs-state" 15
    sleep "$DRAIN_PAUSE"
    stop_rsyslog

    if [ ! -f "$logfile" ]; then
        echo "    logfile not created after phase 1" >&2
        cat "$TMPDIR_BASE/rsyslog.err" >&2
        report "statefiledir_restart" 1
        return
    fi

    # State file must exist after graceful shutdown.
    if [ ! -f "$statedir/mmhashchainsigs.state" ]; then
        echo "    state file not written on shutdown" >&2
        report "statefiledir_restart" 1
        return
    fi

    # Phase 2: restart rsyslog with the same config and log file.
    # The first message consumes the state file (final SIG for the
    # old chain), so send signinterval+1 = 11 messages: 1 for the
    # final SIG + 10 for the new chain's periodic SIG.
    start_rsyslog "$conf"
    "$SENDER" "$SOCK" "mmhcs-state2" 11
    sleep "$DRAIN_PAUSE"
    stop_rsyslog

    # State file should have been consumed (deleted) on startup.
    # A new one may exist if the second run has an unsigned tail,
    # but verify the OLD one was consumed by checking the log.

    # The full log must pass strict verification: the final
    # signature from the old chain covered the unsigned tail,
    # and the new chain's periodic SIG covers its messages.
    local out
    out=$("$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" -s "$logfile" 2>&1) \
        && report "statefiledir_restart" 0 \
        || { echo "    verify failed: $out" >&2
             report "statefiledir_restart" 1; }
}

# --- Test: without statefiledir, strict mode detects unsigned tail ---
test_no_statefiledir_strict() {
    local logfile="$TMPDIR_BASE/no-statefiledir.log"
    local conf="$TMPDIR_BASE/no-statefiledir.conf"

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

    # Phase 1: send 15 messages (SIG at 10, 5 unsigned), stop.
    start_rsyslog "$conf"
    "$SENDER" "$SOCK" "mmhcs-nostate" 15
    sleep "$DRAIN_PAUSE"
    stop_rsyslog

    if [ ! -f "$logfile" ]; then
        report "no_statefiledir_strict" 1
        return
    fi

    # Phase 2: restart and send 10 more.
    start_rsyslog "$conf"
    "$SENDER" "$SOCK" "mmhcs-nostate2" 10
    sleep "$DRAIN_PAUSE"
    stop_rsyslog

    # Non-strict should pass (chain integrity is intact).
    local non_strict
    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1 && non_strict=0 || non_strict=$?

    # Strict should FAIL (unsigned tail from phase 1).
    local strict
    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" -s "$logfile" \
        >/dev/null 2>&1 && strict=0 || strict=$?

    if [ "$non_strict" -eq 0 ] && [ "$strict" -ne 0 ]; then
        report "no_statefiledir_strict" 0
    else
        echo "    non-strict=$non_strict strict=$strict" \
             "(expected 0, !0)" >&2
        report "no_statefiledir_strict" 1
    fi
}

# --- Test: X.509 pinned-leaf — sign with certificate=, verify with --cert ---
test_x509_pinned_cert() {
    local logfile="$TMPDIR_BASE/x509-pinned.log"
    local conf="$TMPDIR_BASE/x509-pinned.conf"

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
        certificate="$TMPDIR_BASE/cert.pem"
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
    send_and_drain 12 "mmhcs-x509pin"

    if [ ! -f "$logfile" ]; then
        echo "    logfile not created" >&2
        cat "$TMPDIR_BASE/rsyslog.err" >&2
        report "x509_pinned_cert" 1
        return
    fi

    # Verify with --cert (pinned leaf).
    local pin pub
    "$VERIFY" --cert "$TMPDIR_BASE/cert.pem" "$logfile" \
        >/dev/null 2>&1 && pin=0 || pin=$?

    # Also verify with --publickey using the same key's PEM — the
    # fingerprint must match because both forms wrap the same key.
    "$VERIFY" --publickey "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1 && pub=0 || pub=$?

    if [ "$pin" -eq 0 ] && [ "$pub" -eq 0 ]; then
        report "x509_pinned_cert" 0
    else
        echo "    pin=$pin pub=$pub (expected 0,0)" >&2
        report "x509_pinned_cert" 1
    fi
}

# --- Test: ECDSA key end-to-end, parameterized by curve tag ---
# tag = "ec" (P-256) / "ec384" (P-384) / "ec521" (P-521)
test_x509_ecdsa_curve() {
    local tag="$1"
    local label="$2"
    local logfile="$TMPDIR_BASE/x509-${tag}.log"
    local conf="$TMPDIR_BASE/x509-${tag}.conf"

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
        privatekey="$TMPDIR_BASE/privkey-${tag}.pem"
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
    send_and_drain 12 "mmhcs-${tag}"

    if [ ! -f "$logfile" ]; then
        echo "    logfile not created" >&2
        cat "$TMPDIR_BASE/rsyslog.err" >&2
        report "x509_ecdsa_${label}" 1
        return
    fi

    "$VERIFY" --publickey "$TMPDIR_BASE/pubkey-${tag}.pem" "$logfile" \
        >/dev/null 2>&1
    report "x509_ecdsa_${label}" $?
}

test_x509_ecdsa_p256() { test_x509_ecdsa_curve "ec"    "p256"; }
test_x509_ecdsa_p384() { test_x509_ecdsa_curve "ec384" "p384"; }
test_x509_ecdsa_p521() { test_x509_ecdsa_curve "ec521" "p521"; }

# --- Test: CA-bundle mode with embedcert=on ---
test_x509_ca_bundle() {
    local logfile="$TMPDIR_BASE/x509-cabundle.log"
    local conf="$TMPDIR_BASE/x509-cabundle.conf"

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
        certificate="$TMPDIR_BASE/leaf.pem"
        embedcert="on"
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
    send_and_drain 12 "mmhcs-ca"

    if [ ! -f "$logfile" ]; then
        echo "    logfile not created" >&2
        cat "$TMPDIR_BASE/rsyslog.err" >&2
        report "x509_ca_bundle" 1
        return
    fi

    # The first line (INIT) must contain the embedded cert SD.
    if ! head -1 "$logfile" | grep -q 'mmhashchainsigs-cert@32473 cert="'; then
        echo "    INIT line missing embedded cert SD" >&2
        head -1 "$logfile" >&2
        report "x509_ca_bundle" 1
        return
    fi

    # Positive case: verify with the real CA bundle.
    local good bad
    "$VERIFY" --ca-bundle "$TMPDIR_BASE/ca.pem" "$logfile" \
        >/dev/null 2>&1 && good=0 || good=$?

    # Negative case: verify with a different CA — must fail with exit 4
    # (chain validation failure).
    openssl genpkey -algorithm Ed25519 \
        -out "$TMPDIR_BASE/badca-priv.pem" 2>/dev/null
    openssl req -new -x509 -key "$TMPDIR_BASE/badca-priv.pem" \
        -days 1 -subj "/CN=mmhcs-bad-CA" \
        -out "$TMPDIR_BASE/badca.pem" 2>/dev/null

    "$VERIFY" --ca-bundle "$TMPDIR_BASE/badca.pem" "$logfile" \
        >/dev/null 2>&1 && bad=0 || bad=$?

    if [ "$good" -eq 0 ] && [ "$bad" -eq 4 ]; then
        report "x509_ca_bundle" 0
    else
        echo "    good=$good bad=$bad (expected 0, 4)" >&2
        report "x509_ca_bundle" 1
    fi
}

# --- Test: SHA-512 chain mode ---
test_sha512_chain() {
    local logfile="$TMPDIR_BASE/sha512.log"
    local conf="$TMPDIR_BASE/sha512.conf"

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
        hashalgo="sha512"
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
    send_and_drain 12 "mmhcs-sha512"

    if [ ! -f "$logfile" ]; then
        echo "    logfile not created" >&2
        cat "$TMPDIR_BASE/rsyslog.err" >&2
        report "sha512_chain" 1
        return
    fi

    # Every line must carry h="<128 hex>" — SHA-512 produces a 64-byte
    # hash that the formatter renders as 128 hex chars. SHA-256 would
    # render as 64 hex chars, so this check distinguishes the two.
    local sha256_lines sha512_lines
    sha256_lines=$(grep -c 'h="[0-9a-f]\{64\}"' "$logfile" || true)
    sha512_lines=$(grep -c 'h="[0-9a-f]\{128\}"' "$logfile" || true)
    if [ "$sha256_lines" -ne 0 ] || [ "$sha512_lines" -eq 0 ]; then
        echo "    expected only SHA-512 lines, got sha256=$sha256_lines sha512=$sha512_lines" >&2
        report "sha512_chain" 1
        return
    fi

    # Verifier auto-detects from h= width.
    "$VERIFY" --publickey "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1
    report "sha512_chain" $?
}

# --- Test: SHA-384 chain mode ---
test_sha384_chain() {
    local logfile="$TMPDIR_BASE/sha384.log"
    local conf="$TMPDIR_BASE/sha384.conf"

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
        hashalgo="sha384"
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
    send_and_drain 12 "mmhcs-sha384"

    if [ ! -f "$logfile" ]; then
        echo "    logfile not created" >&2
        cat "$TMPDIR_BASE/rsyslog.err" >&2
        report "sha384_chain" 1
        return
    fi

    # Every line must carry h="<96 hex>" (SHA-384 is a 48-byte digest).
    local sha256_lines sha384_lines sha512_lines
    sha256_lines=$(grep -c 'h="[0-9a-f]\{64\}"' "$logfile" || true)
    sha384_lines=$(grep -c 'h="[0-9a-f]\{96\}"' "$logfile" || true)
    sha512_lines=$(grep -c 'h="[0-9a-f]\{128\}"' "$logfile" || true)
    if [ "$sha256_lines" -ne 0 ] || [ "$sha512_lines" -ne 0 ] \
       || [ "$sha384_lines" -eq 0 ]; then
        echo "    expected only SHA-384 lines, got 256=$sha256_lines 384=$sha384_lines 512=$sha512_lines" >&2
        report "sha384_chain" 1
        return
    fi

    "$VERIFY" --publickey "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1
    report "sha384_chain" $?
}

# --- Test: SHA-512 tamper detection (chain works the same way) ---
test_sha512_tamper() {
    local logfile="$TMPDIR_BASE/sha512-tamp.log"
    local conf="$TMPDIR_BASE/sha512-tamp.conf"

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
        hashalgo="sha512"
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
    send_and_drain 15 "mmhcs-sha512-tamp"

    if [ ! -f "$logfile" ]; then
        report "sha512_tamper" 1
        return
    fi

    local pre post
    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1 && pre=0 || pre=$?
    sed -i '3s/message/TAMPERED/' "$logfile"
    "$VERIFY" -k "$TMPDIR_BASE/pubkey.pem" "$logfile" \
        >/dev/null 2>&1 && post=0 || post=$?

    if [ "$pre" -eq 0 ] && [ "$post" -ne 0 ]; then
        report "sha512_tamper" 0
    else
        echo "    pre=$pre post=$post (expected 0, !0)" >&2
        report "sha512_tamper" 1
    fi
}

# --- Test: rsyslog rejects unknown hashalgo ---
test_invalid_hashalgo() {
    local conf="$TMPDIR_BASE/bad-alg.conf"
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
        hashalgo="md5"
        signinterval="5"
    )
}
EOF

    rsyslogd -f "$conf" -i "$TMPDIR_BASE/bad.pid" -n \
        > "$TMPDIR_BASE/bad.out" 2> "$TMPDIR_BASE/bad.err" &
    local pid=$!
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        # rsyslog tolerates a config-rejected action by entering a
        # suspended state rather than refusing to start. Look for the
        # diagnostic in stderr.
        if grep -q "unknown hashalgo" "$TMPDIR_BASE/bad.err"; then
            report "invalid_hashalgo" 0
        else
            echo "    expected 'unknown hashalgo' diagnostic; got:" >&2
            cat "$TMPDIR_BASE/bad.err" >&2
            report "invalid_hashalgo" 1
        fi
    else
        wait "$pid" 2>/dev/null || true
        if grep -q "unknown hashalgo" "$TMPDIR_BASE/bad.err"; then
            report "invalid_hashalgo" 0
        else
            echo "    rsyslog exited but no expected diagnostic" >&2
            cat "$TMPDIR_BASE/bad.err" >&2
            report "invalid_hashalgo" 1
        fi
    fi
}

# --- Test: CA-bundle without embedcert must fail clearly ---
test_x509_ca_bundle_requires_embed() {
    local logfile="$TMPDIR_BASE/x509-noembed.log"
    local conf="$TMPDIR_BASE/x509-noembed.conf"

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
        certificate="$TMPDIR_BASE/leaf.pem"
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
    send_and_drain 6 "mmhcs-noembed"

    if [ ! -f "$logfile" ]; then
        report "x509_ca_bundle_requires_embed" 1
        return
    fi

    # CA-bundle verification must fail because the signer didn't embed
    # the cert. The error message should mention embedded certificate.
    local out status
    out=$("$VERIFY" --ca-bundle "$TMPDIR_BASE/ca.pem" "$logfile" 2>&1) \
        && status=0 || status=$?

    if [ "$status" -ne 0 ] && echo "$out" \
            | grep -q "requires an embedded certificate"; then
        report "x509_ca_bundle_requires_embed" 0
    else
        echo "    unexpected status=$status output: $out" >&2
        report "x509_ca_bundle_requires_embed" 1
    fi
}

# --- Main ---
main() {
    echo "=== mmhashchainsigs integration tests ==="
    preflight
    setup_tmpdir
    generate_keys
    generate_ecdsa_keys
    generate_selfsigned_cert
    generate_ca_and_leaf

    test_mmhashchainsigs_basic
    test_mmhashchainsigs_tamper
    test_rfc5424_client_sd
    test_rfc5424_collision
    test_rfc5424_header_capture
    test_rfc5424_header_tamper
    test_statefiledir_restart
    test_no_statefiledir_strict
    test_x509_pinned_cert
    test_x509_ecdsa_p256
    test_x509_ecdsa_p384
    test_x509_ecdsa_p521
    test_x509_ca_bundle
    test_x509_ca_bundle_requires_embed
    test_sha384_chain
    test_sha512_chain
    test_sha512_tamper
    test_invalid_hashalgo

    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    [ "$FAIL" -eq 0 ]
}

main "$@"
