#!/bin/bash
set -euo pipefail

# Generate Ed25519 key pair for mmhashchainsigs
# Usage: mmhashchainsigs-keygen.sh [output-dir]

OUTDIR="${1:-.}"

PRIVKEY="${OUTDIR}/mmhashchainsigs-private.pem"
PUBKEY="${OUTDIR}/mmhashchainsigs-public.pem"

if [ -f "${PRIVKEY}" ]; then
    echo "Error: ${PRIVKEY} already exists" >&2
    exit 1
fi

openssl genpkey -algorithm Ed25519 -out "${PRIVKEY}"
chmod 600 "${PRIVKEY}"

openssl pkey -in "${PRIVKEY}" -pubout -out "${PUBKEY}"
chmod 644 "${PUBKEY}"

echo "Private key: ${PRIVKEY} (keep secure, deploy to rsyslog host)"
echo "Public key:  ${PUBKEY} (distribute to verifiers)"
