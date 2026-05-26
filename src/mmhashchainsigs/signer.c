/*
 * signer.c - Signer lifecycle for mmhashchainsigs
 */
#include "signer.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <string.h>
#include <sys/stat.h>

static int check_privkey_perms(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    if (st.st_mode & S_IROTH) {
        return -1;
    }
    return 0;
}

int signer_init(signer_ctx_t *ctx, const char *privkey_path)
{
    memset(ctx, 0, sizeof(*ctx));

    if (check_privkey_perms(privkey_path) != 0) {
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

int signer_init_x509(
    signer_ctx_t *ctx,
    const char *privkey_path,
    const char *cert_path)
{
    memset(ctx, 0, sizeof(*ctx));

    if (check_privkey_perms(privkey_path) != 0) {
        return -1;
    }

    if (hcs_load_private_key(privkey_path, &ctx->privkey) != 0) {
        return -1;
    }

    if (hcs_load_x509_cert(cert_path, &ctx->cert) != 0) {
        goto fail;
    }

    /* Reject a cert whose pubkey is the wrong algorithm/curve before
     * checking the keypair, so the error message is clear. */
    EVP_PKEY *cert_pub = NULL;
    if (hcs_x509_get_pubkey(ctx->cert, &cert_pub) != 0) {
        goto fail;
    }
    EVP_PKEY_free(cert_pub);

    if (hcs_x509_check_keypair(ctx->cert, ctx->privkey) != 0) {
        goto fail;
    }

    if (hcs_pubkey_fingerprint(ctx->privkey, ctx->pubkey_fp) != 0) {
        goto fail;
    }

    return 0;

fail:
    if (ctx->cert) {
        X509_free(ctx->cert);
        ctx->cert = NULL;
    }
    if (ctx->privkey) {
        EVP_PKEY_free(ctx->privkey);
        ctx->privkey = NULL;
    }
    return -1;
}

int signer_sign(
    signer_ctx_t *ctx,
    const void *data, size_t data_len,
    unsigned char *sig_out, size_t *sig_len)
{
    return hcs_sign(
        ctx->privkey, data, data_len, sig_out, sig_len);
}

const unsigned char *signer_pubkey_fp(const signer_ctx_t *ctx)
{
    return ctx->pubkey_fp;
}

int signer_get_cert_der(
    signer_ctx_t *ctx,
    const unsigned char **der, int *der_len)
{
    if (!ctx->cert) {
        return -1;
    }
    if (!ctx->cert_der) {
        int n = hcs_x509_to_der(ctx->cert, &ctx->cert_der);
        if (n <= 0) {
            ctx->cert_der = NULL;
            return -1;
        }
        ctx->cert_der_len = n;
    }
    *der = ctx->cert_der;
    *der_len = ctx->cert_der_len;
    return 0;
}

void signer_free(signer_ctx_t *ctx)
{
    if (ctx->privkey) {
        EVP_PKEY_free(ctx->privkey);
        ctx->privkey = NULL;
    }
    if (ctx->cert) {
        X509_free(ctx->cert);
        ctx->cert = NULL;
    }
    if (ctx->cert_der) {
        OPENSSL_free(ctx->cert_der);
        ctx->cert_der = NULL;
    }
    OPENSSL_cleanse(ctx, sizeof(*ctx));
}
