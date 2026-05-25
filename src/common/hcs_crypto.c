/*
 * hcs_crypto.c - Cryptographic primitives for mmhashchainsigs
 */
#include "hcs_crypto.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>

int hcs_sha256(
    const void *data, size_t len,
    unsigned char out[HCS_HASH_LEN])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    unsigned int md_len = HCS_HASH_LEN;
    int rc = -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto done;
    }
    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        goto done;
    }
    if (EVP_DigestFinal_ex(ctx, out, &md_len) != 1) {
        goto done;
    }
    rc = 0;

done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

static void uint64_to_be(uint64_t val, unsigned char buf[8])
{
    buf[0] = (unsigned char)(val >> 56);
    buf[1] = (unsigned char)(val >> 48);
    buf[2] = (unsigned char)(val >> 40);
    buf[3] = (unsigned char)(val >> 32);
    buf[4] = (unsigned char)(val >> 24);
    buf[5] = (unsigned char)(val >> 16);
    buf[6] = (unsigned char)(val >> 8);
    buf[7] = (unsigned char)(val);
}

int hcs_sha256_chain(
    const unsigned char prev[HCS_HASH_LEN],
    uint64_t seq,
    const void *msg, size_t msg_len,
    unsigned char out[HCS_HASH_LEN])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    unsigned char seq_buf[8];
    uint64_to_be(seq, seq_buf);

    unsigned int md_len = HCS_HASH_LEN;
    int rc = -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto done;
    }
    if (EVP_DigestUpdate(ctx, prev, HCS_HASH_LEN) != 1) {
        goto done;
    }
    if (EVP_DigestUpdate(ctx, seq_buf, sizeof(seq_buf)) != 1) {
        goto done;
    }
    if (EVP_DigestUpdate(ctx, msg, msg_len) != 1) {
        goto done;
    }
    if (EVP_DigestFinal_ex(ctx, out, &md_len) != 1) {
        goto done;
    }
    rc = 0;

done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

int hcs_load_private_key(const char *path, EVP_PKEY **out)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    *out = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!*out) {
        return -1;
    }

    if (EVP_PKEY_id(*out) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(*out);
        *out = NULL;
        return -1;
    }

    return 0;
}

int hcs_load_public_key(const char *path, EVP_PKEY **out)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    *out = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!*out) {
        return -1;
    }

    if (EVP_PKEY_id(*out) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(*out);
        *out = NULL;
        return -1;
    }

    return 0;
}

int hcs_ed25519_sign(
    EVP_PKEY *key,
    const void *data, size_t data_len,
    unsigned char *sig_out, size_t *sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    int rc = -1;

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1) {
        goto done;
    }
    /* First call: get required signature length */
    if (EVP_DigestSign(ctx, NULL, sig_len, data, data_len) != 1) {
        goto done;
    }
    /* Second call: produce signature */
    if (EVP_DigestSign(ctx, sig_out, sig_len, data, data_len) != 1) {
        goto done;
    }
    rc = 0;

done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

int hcs_ed25519_verify(
    EVP_PKEY *key,
    const void *data, size_t data_len,
    const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    int rc = -1;

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != 1) {
        goto done;
    }

    int vr = EVP_DigestVerify(ctx, sig, sig_len, data, data_len);
    if (vr == 1) {
        rc = 0;  /* valid */
    } else if (vr == 0) {
        rc = 1;  /* invalid signature */
    }
    /* vr < 0 => error, rc stays -1 */

done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

int hcs_pubkey_fingerprint(
    EVP_PKEY *key,
    unsigned char out[HCS_HASH_LEN])
{
    unsigned char raw[32];
    size_t raw_len = sizeof(raw);

    if (EVP_PKEY_get_raw_public_key(key, raw, &raw_len) != 1) {
        return -1;
    }

    return hcs_sha256(raw, raw_len, out);
}
