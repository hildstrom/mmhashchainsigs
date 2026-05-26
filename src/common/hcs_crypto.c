/*
 * hcs_crypto.c - Cryptographic primitives for mmhashchainsigs
 */
#include "hcs_crypto.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
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

/*
 * Return true if `key` is one of the supported algorithm/curve combos:
 *   Ed25519
 *   ECDSA on the NIST P-256 curve (prime256v1 / secp256r1)
 */
static bool key_is_supported(EVP_PKEY *key)
{
    int id = EVP_PKEY_id(key);
    if (id == EVP_PKEY_ED25519) {
        return true;
    }
    if (id == EVP_PKEY_EC) {
        char group[64] = {0};
        size_t glen = 0;
        if (EVP_PKEY_get_group_name(key, group, sizeof(group), &glen) != 1) {
            return false;
        }
        return strcmp(group, "prime256v1") == 0
            || strcmp(group, "P-256") == 0
            || strcmp(group, "secp256r1") == 0;
    }
    return false;
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

    if (!key_is_supported(*out)) {
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

    if (!key_is_supported(*out)) {
        EVP_PKEY_free(*out);
        *out = NULL;
        return -1;
    }

    return 0;
}

int hcs_load_x509_cert(const char *path, X509 **out)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    *out = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return *out ? 0 : -1;
}

int hcs_x509_get_pubkey(X509 *cert, EVP_PKEY **out)
{
    EVP_PKEY *pk = X509_get_pubkey(cert);
    if (!pk) {
        return -1;
    }
    if (!key_is_supported(pk)) {
        EVP_PKEY_free(pk);
        return -1;
    }
    *out = pk;
    return 0;
}

int hcs_x509_check_keypair(X509 *cert, EVP_PKEY *privkey)
{
    return X509_check_private_key(cert, privkey) == 1 ? 0 : -1;
}

int hcs_x509_to_der(X509 *cert, unsigned char **out)
{
    *out = NULL;
    int len = i2d_X509(cert, out);
    return len > 0 ? len : -1;
}

int hcs_x509_from_der(const unsigned char *der, size_t der_len, X509 **out)
{
    const unsigned char *p = der;
    *out = d2i_X509(NULL, &p, (long)der_len);
    return *out ? 0 : -1;
}

/*
 * Pick the digest to pair with EVP_DigestSign/Verify for this key:
 *   Ed25519     -> NULL (PureEdDSA, single-shot, no pre-hash)
 *   ECDSA P-256 -> SHA-256
 * Returns NULL for both cases (callers must check the key type to
 * distinguish error from valid-NULL); we instead use a bool out param.
 */
static int pick_md(EVP_PKEY *key, const EVP_MD **md_out)
{
    int id = EVP_PKEY_id(key);
    if (id == EVP_PKEY_ED25519) {
        *md_out = NULL;
        return 0;
    }
    if (id == EVP_PKEY_EC) {
        *md_out = EVP_sha256();
        return 0;
    }
    return -1;
}

int hcs_sign(
    EVP_PKEY *key,
    const void *data, size_t data_len,
    unsigned char *sig_out, size_t *sig_len)
{
    const EVP_MD *md = NULL;
    if (pick_md(key, &md) != 0) {
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    int rc = -1;

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key) != 1) {
        goto done;
    }

    if (md == NULL) {
        /* PureEdDSA requires the single-shot EVP_DigestSign API. */
        if (EVP_DigestSign(ctx, NULL, sig_len, data, data_len) != 1) {
            goto done;
        }
        if (EVP_DigestSign(ctx, sig_out, sig_len, data, data_len) != 1) {
            goto done;
        }
    } else {
        if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) {
            goto done;
        }
        if (EVP_DigestSignFinal(ctx, NULL, sig_len) != 1) {
            goto done;
        }
        if (EVP_DigestSignFinal(ctx, sig_out, sig_len) != 1) {
            goto done;
        }
    }
    rc = 0;

done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

int hcs_verify(
    EVP_PKEY *key,
    const void *data, size_t data_len,
    const unsigned char *sig, size_t sig_len)
{
    const EVP_MD *md = NULL;
    if (pick_md(key, &md) != 0) {
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    int rc = -1;
    int vr;

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, key) != 1) {
        goto done;
    }

    if (md == NULL) {
        vr = EVP_DigestVerify(ctx, sig, sig_len, data, data_len);
    } else {
        if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
            goto done;
        }
        vr = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    }

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
    int id = EVP_PKEY_id(key);

    if (id == EVP_PKEY_ED25519) {
        unsigned char raw[32];
        size_t raw_len = sizeof(raw);
        if (EVP_PKEY_get_raw_public_key(key, raw, &raw_len) != 1) {
            return -1;
        }
        return hcs_sha256(raw, raw_len, out);
    }

    if (id == EVP_PKEY_EC) {
        /* OSSL_PKEY_PARAM_PUB_KEY returns the uncompressed point form
         * (0x04 || X || Y) which is 65 bytes for P-256. */
        unsigned char raw[128];
        size_t raw_len = 0;
        if (EVP_PKEY_get_octet_string_param(
                key, OSSL_PKEY_PARAM_PUB_KEY,
                raw, sizeof(raw), &raw_len) != 1) {
            return -1;
        }
        return hcs_sha256(raw, raw_len, out);
    }

    return -1;
}
