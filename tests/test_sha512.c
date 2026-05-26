/*
 * test_sha512.c - End-to-end tests for SHA-512 chain mode
 *
 * The hashchain unit tests already loop over both algorithms; this
 * file focuses on full sign/verify flows with hashalgo=sha512 and the
 * SD format / verifier auto-detect path.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char privkey_path[256];
static char pubkey_path[256];

static void setup_keys(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_keygen(ctx, &pkey) == 1);
    EVP_PKEY_CTX_free(ctx);

    snprintf(privkey_path, sizeof(privkey_path),
             "/tmp/hcs_sha512_priv_XXXXXX");
    int fd = mkstemp(privkey_path);
    FILE *fp = fdopen(fd, "w");
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    chmod(privkey_path, 0600);

    snprintf(pubkey_path, sizeof(pubkey_path),
             "/tmp/hcs_sha512_pub_XXXXXX");
    fd = mkstemp(pubkey_path);
    fp = fdopen(fd, "w");
    PEM_write_PUBKEY(fp, pkey);
    fclose(fp);

    EVP_PKEY_free(pkey);
}

static void teardown_keys(void)
{
    unlink(privkey_path);
    unlink(pubkey_path);
}

/* Configure & run a sign/verify cycle with the given algorithm, then
 * assert the on-wire `h="..."` width matches expectations. */
static void test_e2e_for_alg(hcs_hash_alg_t alg, size_t expected_hex)
{
    mmhashchainsigs_instance_t inst = {0};
    inst.privkey_path = privkey_path;
    inst.sign_interval = 4;
    inst.hash_alg = alg;

    mmhashchainsigs_worker_t wrkr = {0};
    wrkr.inst = &inst;
    assert(mmhashchainsigs_init(&wrkr) == 0);
    assert(wrkr.chain.alg == alg);
    assert(wrkr.chain.hash_len == hcs_hash_len(alg));

    FILE *fp = tmpfile();
    assert(fp);

    for (int i = 0; i < 12; i++) {
        char msg[64];
        int mlen = snprintf(msg, sizeof(msg), "msg-%d", i);
        char sd[HCS_SD_WITH_CERT_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
        assert(sd_len > 0);
        fprintf(fp, "%s%s\n", sd, msg);
    }
    mmhashchainsigs_free(&wrkr);

    /* Walk the file and confirm every line has h="..." of the expected
     * hex width — this exercises the SD format's hash-length plumbing. */
    rewind(fp);
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int line_count = 0;
    while ((len = getline(&line, &cap, fp)) != -1) {
        const char *h = strstr(line, " h=\"");
        assert(h != NULL);
        const char *hend = strchr(h + 4, '"');
        assert(hend != NULL);
        size_t hex_len = (size_t)(hend - (h + 4));
        if (hex_len != expected_hex) {
            fprintf(stderr,
                "    alg=%s line=%d h hex width=%zu, expected %zu\n",
                hcs_hash_name(alg), line_count, hex_len, expected_hex);
            assert(0);
        }
        line_count++;
    }
    assert(line_count == 12);

    /* Verify auto-detect picks up the right algorithm. */
    rewind(fp);
    verifier_ctx_t vctx;
    verifier_opts_t opts = {.pubkey_path = pubkey_path};
    assert(verifier_init(&vctx, &opts) == 0);

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
    assert(vctx.hash_alg == alg);
    assert(vctx.hash_len == hcs_hash_len(alg));
    assert(vctx.msg_count == 12);
    assert(vctx.sig_count >= 2);

    verifier_free(&vctx);
    free(line);
    fclose(fp);

    printf("  PASS: test_e2e[%s]\n", hcs_hash_name(alg));
}

static void test_e2e_sha256(void)
{
    test_e2e_for_alg(HCS_HASH_SHA256, 64);
}

static void test_e2e_sha384(void)
{
    test_e2e_for_alg(HCS_HASH_SHA384, 96);
}

static void test_e2e_sha512(void)
{
    test_e2e_for_alg(HCS_HASH_SHA512, 128);
}

/* SHA-256 and SHA-512 chains over the same messages produce distinct
 * chain hashes and signatures. Mixing algorithms in one file must be
 * detected (verifier locks alg at INIT). */
static void test_alg_mismatch_detected(void)
{
    mmhashchainsigs_instance_t inst_a = {
        .privkey_path = privkey_path, .sign_interval = 4,
        .hash_alg = HCS_HASH_SHA256
    };
    mmhashchainsigs_instance_t inst_b = {
        .privkey_path = privkey_path, .sign_interval = 4,
        .hash_alg = HCS_HASH_SHA512
    };

    mmhashchainsigs_worker_t wa = {.inst = &inst_a};
    mmhashchainsigs_worker_t wb = {.inst = &inst_b};
    assert(mmhashchainsigs_init(&wa) == 0);
    assert(mmhashchainsigs_init(&wb) == 0);

    FILE *fp = tmpfile();
    /* One SHA-256 INIT line, one SHA-512 INIT line afterwards. */
    for (mmhashchainsigs_worker_t *w = &wa; w; w = (w == &wa ? &wb : NULL)) {
        char msg[] = "hello";
        char sd[HCS_SD_WITH_CERT_MAX_LEN];
        int n = mmhashchainsigs_process_msg(w, msg, sizeof(msg) - 1,
                                            sd, sizeof(sd));
        assert(n > 0);
        fprintf(fp, "%s%s\n", sd, msg);
    }
    mmhashchainsigs_free(&wa);
    mmhashchainsigs_free(&wb);

    rewind(fp);
    verifier_ctx_t vctx;
    verifier_opts_t opts = {.pubkey_path = pubkey_path};
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
        verifier_process_line(&vctx, line, (size_t)len, n);
    }
    verifier_finalize(&vctx);
    assert(!verifier_passed(&vctx));
    bool saw_mismatch = false;
    for (int i = 0; i < vctx.error_count; i++) {
        if (strstr(vctx.errors[i].message, "hash algorithm changed")) {
            saw_mismatch = true;
            break;
        }
    }
    assert(saw_mismatch);
    verifier_free(&vctx);
    free(line);
    fclose(fp);
    printf("  PASS: test_alg_mismatch_detected\n");
}

/* Save SHA-512 state, then load it back and confirm the algorithm
 * round-trips through the state file. */
static void test_state_roundtrip_sha512(void)
{
    char dir[256] = "/tmp/hcs_sha512_state_XXXXXX";
    assert(mkdtemp(dir) != NULL);

    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .statefiledir = dir,
        .sign_interval = 100,
        .hash_alg = HCS_HASH_SHA512
    };
    mmhashchainsigs_worker_t wrkr = {.inst = &inst};
    assert(mmhashchainsigs_init(&wrkr) == 0);

    /* Generate one message so msg_count > 0 and the state writes. */
    char sd[HCS_SD_WITH_CERT_MAX_LEN];
    assert(mmhashchainsigs_process_msg(&wrkr, "x", 1, sd, sizeof(sd)) > 0);

    assert(mmhashchainsigs_save_state(&wrkr, dir) == 1);
    mmhashchainsigs_free(&wrkr);

    mmhashchainsigs_saved_state_t *st = mmhashchainsigs_load_state(dir);
    assert(st != NULL);
    assert(st->hash_alg == HCS_HASH_SHA512);
    assert(st->hash_len == 64);
    free(st);

    mmhashchainsigs_delete_state(dir);
    rmdir(dir);
    printf("  PASS: test_state_roundtrip_sha512\n");
}

int main(void)
{
    printf("test_sha512:\n");
    setup_keys();
    test_e2e_sha256();
    test_e2e_sha384();
    test_e2e_sha512();
    test_alg_mismatch_detected();
    test_state_roundtrip_sha512();
    teardown_keys();
    printf("All sha512 tests passed.\n");
    return 0;
}
