/*
 * verifier.h - Log verification engine for mmhashchainsigs SD-mode logs
 */
#ifndef HCS_VERIFIER_H
#define HCS_VERIFIER_H

#include "hcs_crypto.h"
#include "hcs_format.h"

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

typedef struct {
    verifier_state_t state;
    EVP_PKEY *pubkey;
    unsigned char pubkey_fp[HCS_HASH_LEN];
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
 * Initialize verifier with a public key PEM file.
 * Returns 0 on success, -1 on error.
 */
int verifier_init(
    verifier_ctx_t *ctx,
    const char *pubkey_path,
    bool strict);

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

/*
 * Returns true if verification passed (no errors).
 */
bool verifier_passed(const verifier_ctx_t *ctx);

/* Free verifier resources. */
void verifier_free(verifier_ctx_t *ctx);

#endif /* HCS_VERIFIER_H */
