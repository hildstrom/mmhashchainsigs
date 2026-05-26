#!/bin/bash
set -euo pipefail

# Key/cert generation for mmhashchainsigs.
#
# Modes:
#   keygen    Generate a raw key pair (default, original behavior).
#   selfsign  Generate a key pair AND a self-signed X.509 certificate.
#             Useful when you want the X.509 envelope without operating
#             a full PKI (pin the leaf cert at each verifier).
#   csr       Generate a key and a CSR for an external CA to sign.
#
# Algorithms (--alg): ed25519 (default), ecdsa-p256, ecdsa-p384, ecdsa-p521.

usage() {
    cat >&2 <<EOF
Usage:
  $0 [keygen]  [--alg ed25519|ecdsa-p256|ecdsa-p384|ecdsa-p521]
               [--outdir DIR]
  $0 selfsign  [--alg ed25519|ecdsa-p256|ecdsa-p384|ecdsa-p521]
               [--outdir DIR] [--cn NAME] [--days N]
  $0 csr       [--alg ed25519|ecdsa-p256|ecdsa-p384|ecdsa-p521]
               [--outdir DIR] [--cn NAME]

Outputs are written under DIR (default: current directory):
  mmhashchainsigs-private.pem  (mode 0600)
  mmhashchainsigs-public.pem   (mode 0644, keygen only)
  mmhashchainsigs-cert.pem     (mode 0644, selfsign only)
  mmhashchainsigs.csr          (mode 0644, csr only)
EOF
    exit 2
}

MODE="keygen"
case "${1:-}" in
    keygen|selfsign|csr) MODE="$1"; shift ;;
    -*|"") ;;
    *) usage ;;
esac

ALG="ed25519"
OUTDIR="."
CN="mmhashchainsigs"
DAYS="365"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --alg)    ALG="$2"; shift 2 ;;
        --outdir) OUTDIR="$2"; shift 2 ;;
        --cn)     CN="$2"; shift 2 ;;
        --days)   DAYS="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

case "$ALG" in
    ed25519)    GENPKEY_ARGS=(-algorithm Ed25519) ;;
    ecdsa-p256) GENPKEY_ARGS=(-algorithm EC -pkeyopt ec_paramgen_curve:P-256) ;;
    ecdsa-p384) GENPKEY_ARGS=(-algorithm EC -pkeyopt ec_paramgen_curve:P-384) ;;
    ecdsa-p521) GENPKEY_ARGS=(-algorithm EC -pkeyopt ec_paramgen_curve:P-521) ;;
    *) echo "Unsupported --alg: $ALG (use ed25519, ecdsa-p256, ecdsa-p384, or ecdsa-p521)" >&2; exit 2 ;;
esac

mkdir -p "$OUTDIR"
PRIVKEY="${OUTDIR}/mmhashchainsigs-private.pem"
PUBKEY="${OUTDIR}/mmhashchainsigs-public.pem"
CERT="${OUTDIR}/mmhashchainsigs-cert.pem"
CSR="${OUTDIR}/mmhashchainsigs.csr"

if [[ -f "$PRIVKEY" ]]; then
    echo "Error: $PRIVKEY already exists" >&2
    exit 1
fi

openssl genpkey "${GENPKEY_ARGS[@]}" -out "$PRIVKEY"
chmod 600 "$PRIVKEY"
echo "Private key: $PRIVKEY (keep secure, deploy to rsyslog host)"

case "$MODE" in
    keygen)
        openssl pkey -in "$PRIVKEY" -pubout -out "$PUBKEY"
        chmod 644 "$PUBKEY"
        echo "Public key:  $PUBKEY (distribute to verifiers)"
        ;;
    selfsign)
        # Self-signed: subject == issuer. Verifiers pin this leaf cert.
        openssl req -new -x509 -key "$PRIVKEY" \
            -days "$DAYS" -subj "/CN=$CN" -out "$CERT"
        chmod 644 "$CERT"
        echo "Certificate: $CERT (distribute to verifiers — pin with --cert)"
        ;;
    csr)
        openssl req -new -key "$PRIVKEY" -subj "/CN=$CN" -out "$CSR"
        chmod 644 "$CSR"
        echo "CSR:         $CSR (submit to your CA; install the issued cert)"
        ;;
esac
