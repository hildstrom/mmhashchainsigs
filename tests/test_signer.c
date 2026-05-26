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

static char ed_privkey_path[256];
static char ed_pubkey_path[256];
static char ec_privkey_path[256];
static char ec_pubkey_path[256];

static void write_pem_keypair(
    EVP_PKEY *pkey, char *privkey_path, char *pubkey_path)
{
    int fd = mkstemp(privkey_path);
    assert(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert(fp != NULL);
    assert(PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0,
                                NULL, NULL) == 1);
    fclose(fp);
    chmod(privkey_path, 0600);

    fd = mkstemp(pubkey_path);
    assert(fd >= 0);
    fp = fdopen(fd, "w");
    assert(fp != NULL);
    assert(PEM_write_PUBKEY(fp, pkey) == 1);
    fclose(fp);
}

static EVP_PKEY *gen_ed25519(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    assert(ctx != NULL);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_keygen(ctx, &pkey) == 1);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *gen_ecdsa_p256(void)
{
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    assert(pkey != NULL);
    return pkey;
}

static void setup_test_keys(void)
{
    EVP_PKEY *ed = gen_ed25519();
    snprintf(ed_privkey_path, sizeof(ed_privkey_path),
             "/tmp/hcs_test_ed_priv_XXXXXX");
    snprintf(ed_pubkey_path, sizeof(ed_pubkey_path),
             "/tmp/hcs_test_ed_pub_XXXXXX");
    write_pem_keypair(ed, ed_privkey_path, ed_pubkey_path);
    EVP_PKEY_free(ed);

    EVP_PKEY *ec = gen_ecdsa_p256();
    snprintf(ec_privkey_path, sizeof(ec_privkey_path),
             "/tmp/hcs_test_ec_priv_XXXXXX");
    snprintf(ec_pubkey_path, sizeof(ec_pubkey_path),
             "/tmp/hcs_test_ec_pub_XXXXXX");
    write_pem_keypair(ec, ec_privkey_path, ec_pubkey_path);
    EVP_PKEY_free(ec);
}

static void cleanup_test_keys(void)
{
    unlink(ed_privkey_path);
    unlink(ed_pubkey_path);
    unlink(ec_privkey_path);
    unlink(ec_pubkey_path);
}

static void test_sha256(void)
{
    unsigned char out[HCS_HASH_LEN];
    assert(hcs_sha256("hello", 5, out) == 0);

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

    assert(hcs_sha256_chain(prev, 2, "msg", 3, out2) == 0);
    assert(memcmp(out1, out2, HCS_HASH_LEN) != 0);

    printf("  PASS: test_sha256_chain\n");
}

static void sign_verify_roundtrip_for_keys(
    const char *priv_path, const char *pub_path,
    size_t expected_min_sig_len, size_t expected_max_sig_len,
    const char *label)
{
    EVP_PKEY *privkey = NULL;
    EVP_PKEY *pubkey = NULL;

    assert(hcs_load_private_key(priv_path, &privkey) == 0);
    assert(hcs_load_public_key(pub_path, &pubkey) == 0);

    const char *data = "test data to sign";
    unsigned char sig[HCS_SIG_MAX_LEN];
    size_t sig_len = sizeof(sig);

    assert(hcs_sign(privkey, data, strlen(data), sig, &sig_len) == 0);
    assert(sig_len >= expected_min_sig_len);
    assert(sig_len <= expected_max_sig_len);

    assert(hcs_verify(pubkey, data, strlen(data), sig, sig_len) == 0);
    assert(hcs_verify(pubkey, "tampered", 8, sig, sig_len) == 1);
    /* Tamper a byte deep in the signature payload. For ECDSA P-256
     * the leading bytes are ASN.1 DER framing; flipping them yields a
     * parser error (return -1) rather than an invalid-signature result.
     * Byte sig_len/2 always lands in an integer value field. */
    sig[sig_len / 2] ^= 0x55;
    int vr = hcs_verify(pubkey, data, strlen(data), sig, sig_len);
    assert(vr == 1 || vr == -1);

    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);

    printf("  PASS: test_sign_verify_roundtrip[%s]\n", label);
}

static void test_sign_verify_roundtrip(void)
{
    /* Ed25519: fixed 64-byte signature. */
    sign_verify_roundtrip_for_keys(
        ed_privkey_path, ed_pubkey_path, 64, 64, "ed25519");
    /* ECDSA P-256: DER signature is variable, typically 70–72 bytes. */
    sign_verify_roundtrip_for_keys(
        ec_privkey_path, ec_pubkey_path, 8, HCS_SIG_MAX_LEN, "ecdsa-p256");
}

static void fingerprint_priv_pub_match(
    const char *priv_path, const char *pub_path, const char *label)
{
    EVP_PKEY *privkey = NULL;
    EVP_PKEY *pubkey = NULL;
    assert(hcs_load_private_key(priv_path, &privkey) == 0);
    assert(hcs_load_public_key(pub_path, &pubkey) == 0);

    unsigned char fp1[HCS_HASH_LEN];
    unsigned char fp2[HCS_HASH_LEN];
    assert(hcs_pubkey_fingerprint(privkey, fp1) == 0);
    assert(hcs_pubkey_fingerprint(pubkey, fp2) == 0);
    assert(memcmp(fp1, fp2, HCS_HASH_LEN) == 0);

    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
    printf("  PASS: test_pubkey_fingerprint[%s]\n", label);
}

static void test_pubkey_fingerprint(void)
{
    fingerprint_priv_pub_match(
        ed_privkey_path, ed_pubkey_path, "ed25519");
    fingerprint_priv_pub_match(
        ec_privkey_path, ec_pubkey_path, "ecdsa-p256");
}

static void test_reject_unsupported_key(void)
{
    /* RSA 2048 key — must be rejected by hcs_load_private_key. */
    EVP_PKEY *rsa = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    assert(ctx != NULL);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
    assert(EVP_PKEY_keygen(ctx, &rsa) == 1);
    EVP_PKEY_CTX_free(ctx);

    char path[256];
    snprintf(path, sizeof(path), "/tmp/hcs_test_rsa_XXXXXX");
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert(PEM_write_PrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(fp);
    chmod(path, 0600);
    EVP_PKEY_free(rsa);

    EVP_PKEY *loaded = NULL;
    assert(hcs_load_private_key(path, &loaded) == -1);
    assert(loaded == NULL);

    unlink(path);
    printf("  PASS: test_reject_unsupported_key\n");
}

int main(void)
{
    printf("test_signer:\n");

    setup_test_keys();

    test_sha256();
    test_sha256_chain();
    test_sign_verify_roundtrip();
    test_pubkey_fingerprint();
    test_reject_unsupported_key();

    cleanup_test_keys();

    printf("All signer tests passed.\n");
    return 0;
}
