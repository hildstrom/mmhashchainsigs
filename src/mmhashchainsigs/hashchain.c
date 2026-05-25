/*
 * hashchain.c - Hash chain state for mmhashchainsigs
 */
#include "hashchain.h"
#include "hcs_format.h"

#include <string.h>

int hashchain_init(hashchain_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->seq = 1;
    ctx->msg_count = 0;
    return hcs_chain_init_hash(ctx->current);
}

int hashchain_update(
    hashchain_ctx_t *ctx,
    const void *msg, size_t msg_len)
{
    unsigned char next[HCS_HASH_LEN];

    if (hcs_sha256_chain(ctx->current, ctx->seq,
                            msg, msg_len, next) != 0) {
        return -1;
    }

    memcpy(ctx->current, next, HCS_HASH_LEN);
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
    return hashchain_init(ctx);
}
