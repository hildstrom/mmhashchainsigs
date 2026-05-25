/*
 * test_signer.c - Unit tests for crypto and signing
 */
#include "hcs_crypto.h"

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char privkey_path[256];
static char pubkey_path[256];

static void setup_test_keys(void)
{
    /* Generate a temporary Ed25519 key pair */
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    assert(ctx != NULL);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_keygen(ctx, &pkey) == 1);
    EVP_PKEY_CTX_free(ctx);

    snprintf(privkey_path, sizeof(privkey_path),
             "/tmp/hcs_test_priv_XXXXXX");
    int fd = mkstemp(privkey_path);
    assert(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert(fp != NULL);
    assert(PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0,
                                NULL, NULL) == 1);
    fclose(fp);
    chmod(privkey_path, 0600);

    snprintf(pubkey_path, sizeof(pubkey_path),
             "/tmp/hcs_test_pub_XXXXXX");
    fd = mkstemp(pubkey_path);
    assert(fd >= 0);
    fp = fdopen(fd, "w");
    assert(fp != NULL);
    assert(PEM_write_PUBKEY(fp, pkey) == 1);
    fclose(fp);

    EVP_PKEY_free(pkey);
}

static void cleanup_test_keys(void)
{
    unlink(privkey_path);
    unlink(pubkey_path);
}

static void test_sha256(void)
{
    unsigned char out[HCS_HASH_LEN];
    assert(hcs_sha256("hello", 5, out) == 0);

    /* Known SHA-256 of "hello" */
    const char *expected =
        "2cf24dba5fb0a30e26e83b2ac5b9e29e"
        "1b161e5c1fa7425e73043362938b9824";
    char hex[HCS_HASH_LEN * 2 + 1];
    for (int i = 0; i < HCS_HASH_LEN; i++) {
        sprintf(&hex[i * 2], "%02x", out[i]);
    }
    assert(strcmp(hex, expected) == 0);

    printf("  PASS: test_sha256\n");
}

static void test_sha256_chain(void)
{
    unsigned char prev[HCS_HASH_LEN];
    unsigned char out1[HCS_HASH_LEN];
    unsigned char out2[HCS_HASH_LEN];

    memset(prev, 0xaa, HCS_HASH_LEN);

    assert(hcs_sha256_chain(prev, 1, "msg", 3, out1) == 0);
    assert(hcs_sha256_chain(prev, 1, "msg", 3, out2) == 0);
    assert(memcmp(out1, out2, HCS_HASH_LEN) == 0);

    /* Different seq should produce different hash */
    assert(hcs_sha256_chain(prev, 2, "msg", 3, out2) == 0);
    assert(memcmp(out1, out2, HCS_HASH_LEN) != 0);

    printf("  PASS: test_sha256_chain\n");
}

static void test_sign_verify_roundtrip(void)
{
    EVP_PKEY *privkey = NULL;
    EVP_PKEY *pubkey = NULL;

    assert(hcs_load_private_key(privkey_path, &privkey) == 0);
    assert(hcs_load_public_key(pubkey_path, &pubkey) == 0);

    const char *data = "test data to sign";
    unsigned char sig[HCS_SIG_MAX_LEN];
    size_t sig_len = sizeof(sig);

    assert(hcs_ed25519_sign(privkey, data, strlen(data),
                               sig, &sig_len) == 0);
    assert(sig_len == 64);

    /* Valid signature */
    assert(hcs_ed25519_verify(pubkey, data, strlen(data),
                                 sig, sig_len) == 0);

    /* Tampered data */
    assert(hcs_ed25519_verify(pubkey, "tampered", 8,
                                 sig, sig_len) == 1);

    /* Tampered signature */
    sig[0] ^= 0xff;
    assert(hcs_ed25519_verify(pubkey, data, strlen(data),
                                 sig, sig_len) == 1);

    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);

    printf("  PASS: test_sign_verify_roundtrip\n");
}

static void test_pubkey_fingerprint(void)
{
    EVP_PKEY *privkey = NULL;
    EVP_PKEY *pubkey = NULL;

    assert(hcs_load_private_key(privkey_path, &privkey) == 0);
    assert(hcs_load_public_key(pubkey_path, &pubkey) == 0);

    unsigned char fp1[HCS_HASH_LEN];
    unsigned char fp2[HCS_HASH_LEN];

    assert(hcs_pubkey_fingerprint(privkey, fp1) == 0);
    assert(hcs_pubkey_fingerprint(pubkey, fp2) == 0);

    /* Fingerprints from private and public key should match */
    assert(memcmp(fp1, fp2, HCS_HASH_LEN) == 0);

    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);

    printf("  PASS: test_pubkey_fingerprint\n");
}

int main(void)
{
    printf("test_signer:\n");

    setup_test_keys();

    test_sha256();
    test_sha256_chain();
    test_sign_verify_roundtrip();
    test_pubkey_fingerprint();

    cleanup_test_keys();

    printf("All signer tests passed.\n");
    return 0;
}
