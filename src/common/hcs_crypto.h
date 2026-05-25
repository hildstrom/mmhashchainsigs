/*
 * hcs_crypto.h - Cryptographic primitives for mmhashchainsigs
 *
 * SHA-256 hash chaining and Ed25519 signing/verification
 * using OpenSSL 3.0+ EVP API.
 */
#ifndef HCS_CRYPTO_H
#define HCS_CRYPTO_H

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

#define HCS_HASH_LEN    32  /* SHA-256 digest length */
#define HCS_SIG_MAX_LEN 64  /* Ed25519 signature length */

/* SHA-256 of arbitrary data. Returns 0 on success, -1 on error. */
int hcs_sha256(
    const void *data, size_t len,
    unsigned char out[HCS_HASH_LEN]);

/*
 * Chain hash: SHA-256(prev_hash || seq_be64 || msg).
 * Returns 0 on success, -1 on error.
 */
int hcs_sha256_chain(
    const unsigned char prev[HCS_HASH_LEN],
    uint64_t seq,
    const void *msg, size_t msg_len,
    unsigned char out[HCS_HASH_LEN]);

/* Load Ed25519 private key from PEM file. Caller owns *out. */
int hcs_load_private_key(const char *path, EVP_PKEY **out);

/* Load Ed25519 public key from PEM file. Caller owns *out. */
int hcs_load_public_key(const char *path, EVP_PKEY **out);

/*
 * Sign data with Ed25519 (single-shot).
 * sig_out must be at least HCS_SIG_MAX_LEN bytes.
 * *sig_len is set to actual signature length on success.
 * Returns 0 on success, -1 on error.
 */
int hcs_ed25519_sign(
    EVP_PKEY *key,
    const void *data, size_t data_len,
    unsigned char *sig_out, size_t *sig_len);

/*
 * Verify Ed25519 signature (single-shot).
 * Returns 0 if valid, 1 if invalid, -1 on error.
 */
int hcs_ed25519_verify(
    EVP_PKEY *key,
    const void *data, size_t data_len,
    const unsigned char *sig, size_t sig_len);

/*
 * Compute public key fingerprint: SHA-256 of raw public key bytes.
 * Returns 0 on success, -1 on error.
 */
int hcs_pubkey_fingerprint(
    EVP_PKEY *key,
    unsigned char out[HCS_HASH_LEN]);

#endif /* HCS_CRYPTO_H */
