/*
 * signer.c - Ed25519 signer lifecycle for mmhashchainsigs
 */
#include "signer.h"

#include <openssl/crypto.h>
#include <string.h>
#include <sys/stat.h>

int signer_init(signer_ctx_t *ctx, const char *privkey_path)
{
    memset(ctx, 0, sizeof(*ctx));

    /* Refuse to use a world-readable private key */
    struct stat st;
    if (stat(privkey_path, &st) != 0) {
        return -1;
    }
    if (st.st_mode & S_IROTH) {
        return -1;
    }

    if (hcs_load_private_key(privkey_path, &ctx->privkey) != 0) {
        return -1;
    }

    if (hcs_pubkey_fingerprint(ctx->privkey, ctx->pubkey_fp) != 0) {
        EVP_PKEY_free(ctx->privkey);
        ctx->privkey = NULL;
        return -1;
    }

    return 0;
}

int signer_sign(
    signer_ctx_t *ctx,
    const void *data, size_t data_len,
    unsigned char *sig_out, size_t *sig_len)
{
    return hcs_ed25519_sign(
        ctx->privkey, data, data_len, sig_out, sig_len);
}

const unsigned char *signer_pubkey_fp(const signer_ctx_t *ctx)
{
    return ctx->pubkey_fp;
}

void signer_free(signer_ctx_t *ctx)
{
    if (ctx->privkey) {
        EVP_PKEY_free(ctx->privkey);
        ctx->privkey = NULL;
    }
    OPENSSL_cleanse(ctx, sizeof(*ctx));
}
