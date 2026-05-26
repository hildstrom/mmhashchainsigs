/*
 * hashchain.h - Hash chain state for mmhashchainsigs
 */
#ifndef HCS_HASHCHAIN_H
#define HCS_HASHCHAIN_H

#include "hcs_crypto.h"

#include <stdint.h>

typedef struct {
    hcs_hash_alg_t alg;
    size_t hash_len;     /* cached hcs_hash_len(alg) */
    unsigned char current[HCS_HASH_MAX_LEN];
    uint64_t seq;        /* next sequence number to assign */
    uint64_t msg_count;  /* messages since last signature */
} hashchain_ctx_t;

/*
 * Initialize chain with the well-known IV for `alg`.
 * Sets seq=1, msg_count=0.
 * Returns 0 on success, -1 on error.
 */
int hashchain_init(hashchain_ctx_t *ctx, hcs_hash_alg_t alg);

/*
 * Add a message to the chain.
 * Updates ctx->current, increments seq and msg_count.
 * Returns 0 on success, -1 on error.
 */
int hashchain_update(
    hashchain_ctx_t *ctx,
    const void *msg, size_t msg_len);

/* Get the current chain hash (read-only pointer). */
const unsigned char *hashchain_get_current(const hashchain_ctx_t *ctx);

/* Reset msg_count to 0 (called after signing). Hash chain itself unchanged. */
void hashchain_reset_count(hashchain_ctx_t *ctx);

/* Fully reset the chain (new IV, seq=1, msg_count=0). */
int hashchain_reset(hashchain_ctx_t *ctx);

#endif /* HCS_HASHCHAIN_H */
