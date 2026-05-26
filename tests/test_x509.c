/*
 * test_x509.c - Unit tests for X.509 cert support in mmhashchainsigs
 *
 * Covers:
 *   - hcs_load_x509_cert / hcs_x509_get_pubkey / hcs_x509_check_keypair
 *   - signer_init_x509: happy path, key/cert mismatch, RSA cert rejection
 *   - end-to-end sign with cert + verify with pinned leaf cert
 */
#include "hcs_crypto.h"
#include "hcs_format.h"
#include "hashchain.h"
#include "mmhashchainsigs.h"
#include "signer.h"
#include "verifier.h"

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- key/cert generation helpers ------------------------------------ */

static EVP_PKEY *gen_ed25519(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    assert(ctx);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_keygen(ctx, &pkey) == 1);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *gen_ecdsa_p256(void)
{
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    assert(pkey);
    return pkey;
}

static EVP_PKEY *gen_rsa(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    assert(ctx);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
    assert(EVP_PKEY_keygen(ctx, &pkey) == 1);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/*
 * Build a certificate for `subject_key` with CN `cn`, signed by
 * `issuer_key`. If `issuer_cert` is non-NULL, that cert's subject is
 * used as our issuer name (so the chain links up). If NULL, the cert
 * is self-signed.
 */
static X509 *make_cert(
    EVP_PKEY *subject_key, EVP_PKEY *issuer_key, X509 *issuer_cert,
    const char *cn, long not_before_off, long not_after_off)
{
    X509 *cert = X509_new();
    assert(cert);
    assert(X509_set_version(cert, 2) == 1);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), not_before_off);
    X509_gmtime_adj(X509_getm_notAfter(cert), not_after_off);
    assert(X509_set_pubkey(cert, subject_key) == 1);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    if (issuer_cert) {
        assert(X509_set_issuer_name(
            cert, X509_get_subject_name(issuer_cert)) == 1);
    } else {
        assert(X509_set_issuer_name(cert, name) == 1);
        /* Self-signed certs in this helper double as CA certs — add
         * basicConstraints CA:TRUE so OpenSSL's chain validator accepts
         * them as trust anchors for leaf certs we issue below. */
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(
            NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
        assert(ext);
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    int id = EVP_PKEY_id(issuer_key);
    const EVP_MD *md = (id == EVP_PKEY_ED25519) ? NULL : EVP_sha256();
    assert(X509_sign(cert, issuer_key, md) > 0);
    return cert;
}

static void write_privkey_pem(EVP_PKEY *key, char *path)
{
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert(fp);
    assert(PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) == 1);
    fclose(fp);
    chmod(path, 0600);
}

static void write_cert_pem(X509 *cert, char *path)
{
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert(fp);
    assert(PEM_write_X509(fp, cert) == 1);
    fclose(fp);
}

/* ---- tests ---------------------------------------------------------- */

static void test_load_cert_and_extract_pubkey(void)
{
    EVP_PKEY *key = gen_ed25519();
    X509 *cert = make_cert(key, key, NULL, "test-ed25519", 0, 3600);

    char cert_path[256] = "/tmp/hcs_test_cert_XXXXXX";
    write_cert_pem(cert, cert_path);

    X509 *loaded = NULL;
    assert(hcs_load_x509_cert(cert_path, &loaded) == 0);

    EVP_PKEY *cert_pub = NULL;
    assert(hcs_x509_get_pubkey(loaded, &cert_pub) == 0);

    unsigned char fp_orig[HCS_HASH_LEN];
    unsigned char fp_cert[HCS_HASH_LEN];
    assert(hcs_pubkey_fingerprint(key, fp_orig) == 0);
    assert(hcs_pubkey_fingerprint(cert_pub, fp_cert) == 0);
    assert(memcmp(fp_orig, fp_cert, HCS_HASH_LEN) == 0);

    EVP_PKEY_free(cert_pub);
    X509_free(loaded);
    X509_free(cert);
    EVP_PKEY_free(key);
    unlink(cert_path);
    printf("  PASS: test_load_cert_and_extract_pubkey\n");
}

static void test_reject_rsa_cert(void)
{
    EVP_PKEY *rsa = gen_rsa();
    X509 *cert = make_cert(rsa, rsa, NULL, "test-rsa", 0, 3600);

    char cert_path[256] = "/tmp/hcs_test_rsa_cert_XXXXXX";
    write_cert_pem(cert, cert_path);

    X509 *loaded = NULL;
    assert(hcs_load_x509_cert(cert_path, &loaded) == 0);

    EVP_PKEY *pub = NULL;
    /* RSA pubkeys must be rejected by hcs_x509_get_pubkey. */
    assert(hcs_x509_get_pubkey(loaded, &pub) == -1);

    X509_free(loaded);
    X509_free(cert);
    EVP_PKEY_free(rsa);
    unlink(cert_path);
    printf("  PASS: test_reject_rsa_cert\n");
}

static void test_signer_init_x509_happy(void)
{
    EVP_PKEY *key = gen_ed25519();
    X509 *cert = make_cert(key, key, NULL, "happy-path", 0, 3600);

    char priv_path[256] = "/tmp/hcs_test_priv_XXXXXX";
    char cert_path[256] = "/tmp/hcs_test_cert_XXXXXX";
    write_privkey_pem(key, priv_path);
    write_cert_pem(cert, cert_path);

    signer_ctx_t signer;
    assert(signer_init_x509(&signer, priv_path, cert_path) == 0);

    unsigned char data[] = "x509 sign me";
    unsigned char sig[HCS_SIG_MAX_LEN];
    size_t sig_len = sizeof(sig);
    assert(signer_sign(&signer, data, sizeof(data),
                       sig, &sig_len) == 0);

    /* Verify directly with the cert's pubkey. */
    EVP_PKEY *cert_pub = NULL;
    assert(hcs_x509_get_pubkey(signer.cert, &cert_pub) == 0);
    assert(hcs_verify(cert_pub, data, sizeof(data), sig, sig_len) == 0);

    EVP_PKEY_free(cert_pub);
    signer_free(&signer);
    X509_free(cert);
    EVP_PKEY_free(key);
    unlink(priv_path);
    unlink(cert_path);
    printf("  PASS: test_signer_init_x509_happy\n");
}

static void test_signer_init_x509_mismatch(void)
{
    EVP_PKEY *key_a = gen_ed25519();
    EVP_PKEY *key_b = gen_ed25519();
    X509 *cert_b = make_cert(key_b, key_b, NULL, "wrong-key", 0, 3600);

    char priv_path[256] = "/tmp/hcs_test_priv_XXXXXX";
    char cert_path[256] = "/tmp/hcs_test_cert_XXXXXX";
    write_privkey_pem(key_a, priv_path);
    write_cert_pem(cert_b, cert_path);

    signer_ctx_t signer;
    assert(signer_init_x509(&signer, priv_path, cert_path) == -1);

    X509_free(cert_b);
    EVP_PKEY_free(key_a);
    EVP_PKEY_free(key_b);
    unlink(priv_path);
    unlink(cert_path);
    printf("  PASS: test_signer_init_x509_mismatch\n");
}

static void test_signer_init_x509_rsa_rejected(void)
{
    EVP_PKEY *rsa = gen_rsa();
    /* RSA isn't loadable as a signing key in the first place — the
     * private-key load must fail before we even reach the cert check. */
    char priv_path[256] = "/tmp/hcs_test_rsa_priv_XXXXXX";
    char cert_path[256] = "/tmp/hcs_test_rsa_cert_XXXXXX";
    write_privkey_pem(rsa, priv_path);
    X509 *cert = make_cert(rsa, rsa, NULL, "rsa", 0, 3600);
    write_cert_pem(cert, cert_path);

    signer_ctx_t signer;
    assert(signer_init_x509(&signer, priv_path, cert_path) == -1);

    X509_free(cert);
    EVP_PKEY_free(rsa);
    unlink(priv_path);
    unlink(cert_path);
    printf("  PASS: test_signer_init_x509_rsa_rejected\n");
}

/* End-to-end: sign a chain with signer_init_x509, verify with --cert
 * (pinned leaf). Uses ECDSA P-256 to exercise both new code paths. */
static void test_e2e_sign_with_cert_verify_with_pinned_cert(void)
{
    EVP_PKEY *key = gen_ecdsa_p256();
    X509 *cert = make_cert(key, key, NULL, "e2e-ecdsa", 0, 3600);

    char priv_path[256] = "/tmp/hcs_test_e2e_priv_XXXXXX";
    char cert_path[256] = "/tmp/hcs_test_e2e_cert_XXXXXX";
    write_privkey_pem(key, priv_path);
    write_cert_pem(cert, cert_path);

    /* Build a worker manually (skip the rsyslog path). */
    mmhashchainsigs_instance_t inst = {0};
    inst.privkey_path = priv_path;
    inst.cert_path = cert_path;
    inst.sign_interval = 4;

    mmhashchainsigs_worker_t wrkr = {0};
    wrkr.inst = &inst;
    assert(mmhashchainsigs_init(&wrkr) == 0);

    FILE *fp = tmpfile();
    assert(fp);

    /* Produce 8 messages (sign_interval=4 → two SIG blocks). */
    for (int i = 0; i < 8; i++) {
        char msg[64];
        int mlen = snprintf(msg, sizeof(msg), "msg-%d", i);
        char sd[HCS_SD_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
        assert(sd_len > 0);
        fprintf(fp, "%s%s\n", sd, msg);
    }
    mmhashchainsigs_free(&wrkr);

    rewind(fp);

    verifier_ctx_t vctx;
    verifier_opts_t opts = {.cert_path = cert_path, .strict = false};
    assert(verifier_init(&vctx, &opts) == 0);

    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    uint64_t n = 0;
    while ((len = getline(&line, &cap, fp)) != -1) {
        n++;
        while (len > 0
               && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            len--;
        }
        assert(verifier_process_line(
            &vctx, line, (size_t)len, n) == 0);
    }
    free(line);
    verifier_finalize(&vctx);
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 8);
    assert(vctx.sig_count >= 2);

    verifier_free(&vctx);
    fclose(fp);
    X509_free(cert);
    EVP_PKEY_free(key);
    unlink(priv_path);
    unlink(cert_path);
    printf("  PASS: test_e2e_sign_with_cert_verify_with_pinned_cert\n");
}

/* End-to-end with CA bundle:
 *   1. CA key + self-signed CA cert
 *   2. Leaf key + cert signed by the CA
 *   3. Sign a chain with embedcert=on
 *   4. Verify with --ca-bundle pointing at the CA cert
 *   5. Verify also fails when the CA bundle has the wrong CA
 */
static void test_e2e_ca_bundle(void)
{
    /* CA */
    EVP_PKEY *ca_key = gen_ed25519();
    X509 *ca_cert = make_cert(ca_key, ca_key, NULL, "test-CA", 0, 7 * 24 * 3600);

    /* Leaf */
    EVP_PKEY *leaf_key = gen_ed25519();
    X509 *leaf_cert = make_cert(leaf_key, ca_key, ca_cert, "test-leaf", 0, 3600);

    char ca_path[256] = "/tmp/hcs_test_ca_XXXXXX";
    char leaf_priv_path[256] = "/tmp/hcs_test_leaf_priv_XXXXXX";
    char leaf_cert_path[256] = "/tmp/hcs_test_leaf_cert_XXXXXX";
    write_cert_pem(ca_cert, ca_path);
    write_privkey_pem(leaf_key, leaf_priv_path);
    write_cert_pem(leaf_cert, leaf_cert_path);

    /* A wrong CA (different key) for the negative case. */
    EVP_PKEY *bad_ca_key = gen_ed25519();
    X509 *bad_ca_cert = make_cert(bad_ca_key, bad_ca_key, NULL, "bad-CA", 0, 7 * 24 * 3600);
    char bad_ca_path[256] = "/tmp/hcs_test_bad_ca_XXXXXX";
    write_cert_pem(bad_ca_cert, bad_ca_path);

    /* Sign a chain with embedcert=on. */
    mmhashchainsigs_instance_t inst = {0};
    inst.privkey_path = leaf_priv_path;
    inst.cert_path = leaf_cert_path;
    inst.sign_interval = 4;
    inst.embedcert = 1;

    mmhashchainsigs_worker_t wrkr = {0};
    wrkr.inst = &inst;
    assert(mmhashchainsigs_init(&wrkr) == 0);

    FILE *fp = tmpfile();
    assert(fp);
    for (int i = 0; i < 8; i++) {
        char msg[64];
        int mlen = snprintf(msg, sizeof(msg), "msg-%d", i);
        char sd[HCS_SD_WITH_CERT_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
        assert(sd_len > 0);
        fprintf(fp, "%s%s\n", sd, msg);
    }
    mmhashchainsigs_free(&wrkr);

    /* Positive: verify with the real CA bundle. */
    rewind(fp);
    verifier_ctx_t vctx;
    verifier_opts_t opts = {.ca_bundle_path = ca_path, .strict = false};
    assert(verifier_init(&vctx, &opts) == 0);

    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    uint64_t n = 0;
    while ((len = getline(&line, &cap, fp)) != -1) {
        n++;
        while (len > 0
               && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            len--;
        }
        assert(verifier_process_line(
            &vctx, line, (size_t)len, n) == 0);
    }
    verifier_finalize(&vctx);
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 8);
    assert(vctx.have_pubkey);
    verifier_free(&vctx);

    /* Negative: verify with the wrong CA bundle. */
    rewind(fp);
    verifier_opts_t bad_opts = {
        .ca_bundle_path = bad_ca_path, .strict = false};
    assert(verifier_init(&vctx, &bad_opts) == 0);
    n = 0;
    while ((len = getline(&line, &cap, fp)) != -1) {
        n++;
        while (len > 0
               && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            len--;
        }
        if (verifier_process_line(
                &vctx, line, (size_t)len, n) != 0) {
            break;
        }
    }
    verifier_finalize(&vctx);
    assert(!verifier_passed(&vctx));
    /* Must specifically be a chain-validation failure. */
    bool found_chain_err = false;
    for (int i = 0; i < vctx.error_count; i++) {
        if (strstr(vctx.errors[i].message,
                   "chain validation failed")) {
            found_chain_err = true;
            break;
        }
    }
    assert(found_chain_err);
    verifier_free(&vctx);
    free(line);

    fclose(fp);
    X509_free(leaf_cert);
    X509_free(ca_cert);
    X509_free(bad_ca_cert);
    EVP_PKEY_free(leaf_key);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(bad_ca_key);
    unlink(ca_path);
    unlink(leaf_priv_path);
    unlink(leaf_cert_path);
    unlink(bad_ca_path);
    printf("  PASS: test_e2e_ca_bundle\n");
}

/* CA-bundle mode must fail clearly when the signer did not embed a cert. */
static void test_ca_bundle_requires_embedcert(void)
{
    EVP_PKEY *ca_key = gen_ed25519();
    X509 *ca_cert = make_cert(ca_key, ca_key, NULL, "test-CA", 0, 7 * 24 * 3600);
    EVP_PKEY *leaf_key = gen_ed25519();
    X509 *leaf_cert = make_cert(leaf_key, ca_key, ca_cert, "test-leaf", 0, 3600);

    char ca_path[256] = "/tmp/hcs_test_ca_XXXXXX";
    char leaf_priv_path[256] = "/tmp/hcs_test_leaf_priv_XXXXXX";
    char leaf_cert_path[256] = "/tmp/hcs_test_leaf_cert_XXXXXX";
    write_cert_pem(ca_cert, ca_path);
    write_privkey_pem(leaf_key, leaf_priv_path);
    write_cert_pem(leaf_cert, leaf_cert_path);

    /* embedcert deliberately off. */
    mmhashchainsigs_instance_t inst = {0};
    inst.privkey_path = leaf_priv_path;
    inst.cert_path = leaf_cert_path;
    inst.sign_interval = 4;
    inst.embedcert = 0;

    mmhashchainsigs_worker_t wrkr = {0};
    wrkr.inst = &inst;
    assert(mmhashchainsigs_init(&wrkr) == 0);

    FILE *fp = tmpfile();
    char msg[] = "hello";
    char sd[HCS_SD_WITH_CERT_MAX_LEN];
    int sd_len = mmhashchainsigs_process_msg(
        &wrkr, msg, sizeof(msg) - 1, sd, sizeof(sd));
    assert(sd_len > 0);
    fprintf(fp, "%s%s\n", sd, msg);
    mmhashchainsigs_free(&wrkr);

    rewind(fp);
    verifier_ctx_t vctx;
    verifier_opts_t opts = {.ca_bundle_path = ca_path};
    assert(verifier_init(&vctx, &opts) == 0);

    char *line = NULL;
    size_t cap = 0;
    ssize_t len = getline(&line, &cap, fp);
    assert(len > 0);
    while (len > 0
           && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        len--;
    }
    verifier_process_line(&vctx, line, (size_t)len, 1);
    verifier_finalize(&vctx);
    assert(!verifier_passed(&vctx));
    bool found_embed_err = false;
    for (int i = 0; i < vctx.error_count; i++) {
        if (strstr(vctx.errors[i].message,
                   "requires an embedded certificate")) {
            found_embed_err = true;
            break;
        }
    }
    assert(found_embed_err);
    verifier_free(&vctx);
    free(line);
    fclose(fp);
    X509_free(leaf_cert);
    X509_free(ca_cert);
    EVP_PKEY_free(leaf_key);
    EVP_PKEY_free(ca_key);
    unlink(ca_path);
    unlink(leaf_priv_path);
    unlink(leaf_cert_path);
    printf("  PASS: test_ca_bundle_requires_embedcert\n");
}

int main(void)
{
    printf("test_x509:\n");
    test_load_cert_and_extract_pubkey();
    test_reject_rsa_cert();
    test_signer_init_x509_happy();
    test_signer_init_x509_mismatch();
    test_signer_init_x509_rsa_rejected();
    test_e2e_sign_with_cert_verify_with_pinned_cert();
    test_e2e_ca_bundle();
    test_ca_bundle_requires_embedcert();
    printf("All x509 tests passed.\n");
    return 0;
}
