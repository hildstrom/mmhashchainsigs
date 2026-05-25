/*
 * signer.h - Ed25519 signer lifecycle for mmhashchainsigs
 */
#ifndef HCS_SIGNER_H
#define HCS_SIGNER_H

#include "hcs_crypto.h"

#include <stddef.h>

typedef struct {
    EVP_PKEY *privkey;
    unsigned char pubkey_fp[HCS_HASH_LEN];
} signer_ctx_t;

/*
 * Initialize signer from a PEM private key file.
 * Computes the public key fingerprint.
 * Returns 0 on success, -1 on error.
 */
int signer_init(signer_ctx_t *ctx, const char *privkey_path);

/*
 * Sign data with Ed25519.
 * sig_out must be at least HCS_SIG_MAX_LEN bytes.
 * Returns 0 on success, -1 on error.
 */
int signer_sign(
    signer_ctx_t *ctx,
    const void *data, size_t data_len,
    unsigned char *sig_out, size_t *sig_len);

/*
 * Get the public key fingerprint (read-only pointer).
 */
const unsigned char *signer_pubkey_fp(const signer_ctx_t *ctx);

/*
 * Free signer resources. Cleanses key material.
 */
void signer_free(signer_ctx_t *ctx);

#endif /* HCS_SIGNER_H */
