/*
 * hashchain.c - Hash chain state for mmhashchainsigs
 */
#include "hashchain.h"
#include "hcs_format.h"

#include <string.h>

int hashchain_init(hashchain_ctx_t *ctx, hcs_hash_alg_t alg)
{
    size_t hlen = hcs_hash_len(alg);
    if (hlen == 0) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->alg = alg;
    ctx->hash_len = hlen;
    ctx->seq = 1;
    ctx->msg_count = 0;
    return hcs_chain_init_hash(alg, ctx->current);
}

int hashchain_update(
    hashchain_ctx_t *ctx,
    const void *msg, size_t msg_len)
{
    unsigned char next[HCS_HASH_MAX_LEN];

    if (hcs_hash_chain(ctx->alg, ctx->current, ctx->seq,
                       msg, msg_len, next) != 0) {
        return -1;
    }

    memcpy(ctx->current, next, ctx->hash_len);
    ctx->seq++;
    ctx->msg_count++;
    return 0;
}

const unsigned char *hashchain_get_current(const hashchain_ctx_t *ctx)
{
    return ctx->current;
}

void hashchain_reset_count(hashchain_ctx_t *ctx)
{
    ctx->msg_count = 0;
}

int hashchain_reset(hashchain_ctx_t *ctx)
{
    return hashchain_init(ctx, ctx->alg);
}
