/*
 * verifier.h - Log verification engine for mmhashchainsigs SD-mode logs
 */
#ifndef HCS_VERIFIER_H
#define HCS_VERIFIER_H

#include "hcs_crypto.h"
#include "hcs_format.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    VSTATE_EXPECT_INIT,
    VSTATE_PROCESSING,
    VSTATE_DONE,
    VSTATE_ERROR
} verifier_state_t;

typedef struct {
    const char *file;
    uint64_t line_num;
    char message[256];
} verifier_error_t;

#define VERIFIER_MAX_ERRORS 64

/*
 * Trust model: exactly one of pubkey_path, cert_path, or ca_bundle_path
 * must be set.
 *
 *   pubkey_path     -- raw PEM SubjectPublicKeyInfo
 *   cert_path       -- pinned X.509 leaf certificate PEM (validity period
 *                      not enforced; the cert just supplies the pubkey)
 *   ca_bundle_path  -- PEM bundle of trust anchors; the verifier accepts
 *                      any in-band certificate that chains to the bundle
 *   crl_file        -- optional CRL file used only with ca_bundle_path
 */
typedef struct {
    const char *pubkey_path;
    const char *cert_path;
    const char *ca_bundle_path;
    const char *crl_file;
    bool strict;
} verifier_opts_t;

typedef struct {
    verifier_state_t state;
    EVP_PKEY *pubkey;
    unsigned char pubkey_fp[HCS_HASH_LEN];
    bool have_pubkey;        /* false in ca_bundle mode until first cert seen */
    X509_STORE *trust_store; /* non-NULL only in ca_bundle mode */
    unsigned char chain_hash[HCS_HASH_LEN];
    uint64_t next_seq;
    uint64_t msg_count;
    uint64_t sig_count;
    uint64_t last_signed_seq;
    uint64_t segment_count;
    bool strict;
    verifier_error_t errors[VERIFIER_MAX_ERRORS];
    int error_count;
} verifier_ctx_t;

/*
 * Initialize the verifier. Exactly one of opts->pubkey_path,
 * opts->cert_path, or opts->ca_bundle_path must be set.
 * Returns 0 on success, -1 on error.
 */
int verifier_init(verifier_ctx_t *ctx, const verifier_opts_t *opts);

/*
 * Process one line from the log file.
 * line should NOT include the trailing newline.
 * Returns 0 on success (even if errors are recorded),
 * -1 on unrecoverable error.
 */
int verifier_process_line(
    verifier_ctx_t *ctx,
    const char *line, size_t len,
    uint64_t line_num);

/*
 * Finalize verification after all lines have been processed.
 * Checks for unsigned tail in strict mode.
 * Returns 0 on success, -1 on error.
 */
int verifier_finalize(verifier_ctx_t *ctx);

/* Returns true if verification passed (no errors). */
bool verifier_passed(const verifier_ctx_t *ctx);

/* Free verifier resources. */
void verifier_free(verifier_ctx_t *ctx);

#endif /* HCS_VERIFIER_H */
