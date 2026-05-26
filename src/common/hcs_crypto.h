/*
 * hcs_crypto.h - Cryptographic primitives for mmhashchainsigs
 *
 * SHA-256 hash chaining and signature operations using OpenSSL 3.0+
 * EVP API. Supports Ed25519 (PureEdDSA) and ECDSA P-256 (with SHA-256).
 * Both key types may be supplied as raw PEM keys or via X.509 certs.
 */
#ifndef HCS_CRYPTO_H
#define HCS_CRYPTO_H

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HCS_HASH_LEN    32  /* SHA-256 digest length */
/* Max signature length across supported algorithms:
 *   Ed25519: 64 bytes
 *   ECDSA P-256 (DER): up to ~72 bytes (two 32B integers + ASN.1 overhead)
 * 80 bytes accommodates both with margin. */
#define HCS_SIG_MAX_LEN 80

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

/*
 * Load private key from PEM file. Accepts Ed25519 or ECDSA P-256.
 * Caller owns *out. Returns 0 on success, -1 on error.
 */
int hcs_load_private_key(const char *path, EVP_PKEY **out);

/*
 * Load public key from PEM SubjectPublicKeyInfo file. Accepts Ed25519
 * or ECDSA P-256. Caller owns *out. Returns 0 on success, -1 on error.
 */
int hcs_load_public_key(const char *path, EVP_PKEY **out);

/*
 * Load an X.509 certificate from a PEM file. Caller owns *out and must
 * free with X509_free(). Returns 0 on success, -1 on error.
 */
int hcs_load_x509_cert(const char *path, X509 **out);

/*
 * Extract the public key from an X.509 certificate. The pubkey must be
 * Ed25519 or ECDSA P-256; otherwise this fails. Caller owns *out.
 * Returns 0 on success, -1 on error.
 */
int hcs_x509_get_pubkey(X509 *cert, EVP_PKEY **out);

/*
 * Verify that a certificate's public key matches a loaded private key.
 * Returns 0 on match, -1 on mismatch or error.
 */
int hcs_x509_check_keypair(X509 *cert, EVP_PKEY *privkey);

/*
 * Serialize a certificate to DER. *out is allocated by OpenSSL and must
 * be freed with OPENSSL_free(). Returns DER length on success, -1 on error.
 */
int hcs_x509_to_der(X509 *cert, unsigned char **out);

/*
 * Parse an X.509 certificate from DER bytes. Caller owns *out.
 * Returns 0 on success, -1 on error.
 */
int hcs_x509_from_der(const unsigned char *der, size_t der_len, X509 **out);

/*
 * Sign data using the algorithm appropriate to the key type:
 *   Ed25519     -> PureEdDSA (no separate hash)
 *   ECDSA P-256 -> ECDSA over SHA-256
 * sig_out must be at least HCS_SIG_MAX_LEN bytes.
 * *sig_len is set to the actual signature length on success.
 * Returns 0 on success, -1 on error.
 */
int hcs_sign(
    EVP_PKEY *key,
    const void *data, size_t data_len,
    unsigned char *sig_out, size_t *sig_len);

/*
 * Verify a signature produced by hcs_sign() with the matching key type.
 * Returns 0 if valid, 1 if invalid, -1 on error.
 */
int hcs_verify(
    EVP_PKEY *key,
    const void *data, size_t data_len,
    const unsigned char *sig, size_t sig_len);

/*
 * Compute public key fingerprint: SHA-256 of the raw public key bytes.
 *   Ed25519:     SHA-256 of the 32-byte raw public key
 *   ECDSA P-256: SHA-256 of the 65-byte uncompressed point (0x04 || X || Y)
 * The fingerprint encoding is stable across Ed25519 history (unchanged
 * since v1) and well-defined for ECDSA. Returns 0 on success, -1 on error.
 */
int hcs_pubkey_fingerprint(
    EVP_PKEY *key,
    unsigned char out[HCS_HASH_LEN]);

#endif /* HCS_CRYPTO_H */
