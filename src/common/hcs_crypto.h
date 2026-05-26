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

/*
 * Pubkey fingerprint length: SHA-256 of raw pubkey bytes, fixed for all
 * key types. The fingerprint is a key identifier and never changes,
 * even when the chain hash algorithm is SHA-512.
 */
#define HCS_HASH_LEN    32

/*
 * Maximum chain-hash length across supported algorithms.
 *   SHA-256: 32 bytes
 *   SHA-384: 48 bytes
 *   SHA-512: 64 bytes
 * Use this for buffers and arrays that may hold any of these sizes;
 * the actual length in use is tracked by the surrounding context.
 */
#define HCS_HASH_MAX_LEN 64

/* Max signature length across supported algorithms:
 *   Ed25519:           64 bytes
 *   ECDSA P-256 (DER): up to ~72 bytes
 *   ECDSA P-384 (DER): up to ~104 bytes
 *   ECDSA P-521 (DER): up to ~139 bytes (two 66-byte ints + ASN.1 overhead)
 * 144 bytes accommodates all with margin. */
#define HCS_SIG_MAX_LEN 144

/*
 * Hash algorithm for the chain (sequence-protective hash).
 * The fingerprint always uses SHA-256.
 */
typedef enum {
    HCS_HASH_SHA256 = 0,
    HCS_HASH_SHA384 = 2,
    HCS_HASH_SHA512 = 1
} hcs_hash_alg_t;

/* Bytes produced by hcs_hash_alg_t (32 or 64). 0 on bad alg. */
size_t hcs_hash_len(hcs_hash_alg_t alg);

/* "sha256" / "sha512" string for config files and logs. */
const char *hcs_hash_name(hcs_hash_alg_t alg);

/*
 * Parse "sha256" / "sha512" (case-insensitive) into an algorithm.
 * Returns 0 on success, -1 on unknown name.
 */
int hcs_hash_from_name(const char *name, hcs_hash_alg_t *out);

/*
 * Map a hex-encoded chain-hash length back to its algorithm:
 *   64 hex chars  (32 bytes) -> SHA-256
 *   96 hex chars  (48 bytes) -> SHA-384
 *   128 hex chars (64 bytes) -> SHA-512
 * Returns 0 on success, -1 if the length matches no supported algorithm.
 */
int hcs_hash_alg_from_hex_len(size_t hex_len, hcs_hash_alg_t *out);

/* SHA-256 of arbitrary data. Returns 0 on success, -1 on error. */
int hcs_sha256(
    const void *data, size_t len,
    unsigned char out[HCS_HASH_LEN]);

/*
 * Chain hash: H(prev_hash || seq_be64 || msg) for the chosen algorithm.
 * `prev` and `out` must both be at least hcs_hash_len(alg) bytes.
 * Returns 0 on success, -1 on error.
 */
int hcs_hash_chain(
    hcs_hash_alg_t alg,
    const unsigned char *prev,
    uint64_t seq,
    const void *msg, size_t msg_len,
    unsigned char *out);

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
