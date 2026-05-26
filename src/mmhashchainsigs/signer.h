/*
 * signer.h - Signer lifecycle for mmhashchainsigs
 *
 * Wraps an Ed25519 or ECDSA P-256 private key. Optionally pairs the key
 * with an X.509 certificate that callers can publish in-band when they
 * want verifiers to chain-validate against a CA.
 */
#ifndef HCS_SIGNER_H
#define HCS_SIGNER_H

#include "hcs_crypto.h"

#include <stddef.h>

typedef struct {
    EVP_PKEY *privkey;
    X509 *cert;              /* NULL when running in raw-PEM mode */
    unsigned char *cert_der; /* lazily filled by signer_get_cert_der */
    int cert_der_len;
    unsigned char pubkey_fp[HCS_HASH_LEN];
} signer_ctx_t;

/*
 * Initialize signer from a PEM private key file.
 * Refuses world-readable key files. Computes the public key fingerprint.
 * Returns 0 on success, -1 on error.
 */
int signer_init(signer_ctx_t *ctx, const char *privkey_path);

/*
 * Initialize signer from a PEM private key file and a PEM X.509
 * certificate file. Verifies that the cert's public key matches the
 * private key and that the algorithm/curve is supported.
 * Returns 0 on success, -1 on error.
 */
int signer_init_x509(
    signer_ctx_t *ctx,
    const char *privkey_path,
    const char *cert_path);

/*
 * Sign data with the configured key (Ed25519 PureEdDSA or ECDSA P-256
 * with SHA-256, depending on the loaded key type).
 * sig_out must be at least HCS_SIG_MAX_LEN bytes.
 * Returns 0 on success, -1 on error.
 */
int signer_sign(
    signer_ctx_t *ctx,
    const void *data, size_t data_len,
    unsigned char *sig_out, size_t *sig_len);

/* Get the public key fingerprint (read-only pointer). */
const unsigned char *signer_pubkey_fp(const signer_ctx_t *ctx);

/*
 * Return the DER encoding of the loaded certificate (cached after first
 * call). Returns 0 on success with der/der_len populated, or -1 if no
 * cert is loaded or serialization fails. The pointer is owned by the
 * signer; callers must not free it.
 */
int signer_get_cert_der(
    signer_ctx_t *ctx,
    const unsigned char **der, int *der_len);

/* Free signer resources. Cleanses key material. */
void signer_free(signer_ctx_t *ctx);

#endif /* HCS_SIGNER_H */
