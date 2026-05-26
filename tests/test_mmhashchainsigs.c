/*
 * test_mmhashchainsigs.c - Tests for mmhashchainsigs module and SD-mode verification
 */
#include "hashchain.h"
#include "mmhashchainsigs.h"
#include "hcs_crypto.h"
#include "hcs_format.h"
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

static void create_test_keys(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    assert(ctx != NULL);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_keygen(ctx, &pkey) == 1);
    EVP_PKEY_CTX_free(ctx);

    snprintf(privkey_path, sizeof(privkey_path),
             "/tmp/hcs_sd_priv_XXXXXX");
    int fd = mkstemp(privkey_path);
    assert(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    assert(fp != NULL);
    assert(PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0,
                                NULL, NULL) == 1);
    fclose(fp);
    chmod(privkey_path, 0600);

    snprintf(pubkey_path, sizeof(pubkey_path),
             "/tmp/hcs_sd_pub_XXXXXX");
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

typedef struct {
    hashchain_ctx_t chain;
    signer_ctx_t signer;
    uint64_t sig_seq_from;
    int sign_interval;
    int is_first;
} sd_builder_t;

static void builder_init(sd_builder_t *b, int sign_interval)
{
    hashchain_init(&b->chain, HCS_HASH_SHA256);
    assert(signer_init(&b->signer, privkey_path) == 0);
    b->sig_seq_from = 1;
    b->sign_interval = sign_interval;
    b->is_first = 1;
}

static void builder_free(sd_builder_t *b)
{
    signer_free(&b->signer);
}

enum { SD_LINE_INIT, SD_LINE_MSG, SD_LINE_SIG, SD_LINE_CONTINUE };

static int builder_add_msg(
    sd_builder_t *b,
    const char *msg, size_t msg_len,
    int sd_type,
    char *line_buf, size_t line_buf_len)
{
    hashchain_update(&b->chain, msg, msg_len);
    uint64_t seq = b->chain.seq - 1;

    char sd[HCS_SD_MAX_LEN];
    int sd_len;

    size_t hlen = b->chain.hash_len;
    switch (sd_type) {
    case SD_LINE_INIT:
        sd_len = hcs_format_sd_init(
            seq, b->chain.current, hlen, b->signer.pubkey_fp,
            sd, sizeof(sd));
        break;
    case SD_LINE_SIG: {
        unsigned char sig_buf[HCS_SIG_MAX_LEN];
        size_t slen = sizeof(sig_buf);
        assert(hcs_sign(
            b->signer.privkey, b->chain.current,
            b->chain.hash_len, sig_buf, &slen) == 0);
        sd_len = hcs_format_sd_sig(
            seq, b->chain.current, hlen,
            b->sig_seq_from, seq,
            sig_buf, slen, sd, sizeof(sd));
        b->sig_seq_from = seq + 1;
        hashchain_reset_count(&b->chain);
        break;
    }
    case SD_LINE_CONTINUE:
        sd_len = hcs_format_sd_continue(
            seq, b->chain.current, hlen, b->signer.pubkey_fp,
            sd, sizeof(sd));
        break;
    default:
        sd_len = hcs_format_sd_msg(
            seq, b->chain.current, hlen, sd, sizeof(sd));
        break;
    }

    if (sd_len < 0) return -1;

    int n = snprintf(line_buf, line_buf_len, "%s%s", sd, msg);
    if (n < 0 || (size_t)n >= line_buf_len) return -1;
    return n;
}

static void test_sd_chain_verify(void)
{
    sd_builder_t b;
    builder_init(&b, 4);

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    for (int i = 0; i < 12; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "msg %d", i);

        int sd_type = SD_LINE_MSG;
        if (i == 0) {
            sd_type = SD_LINE_INIT;
        } else if (b.chain.msg_count + 1 == 4) {
            sd_type = SD_LINE_SIG;
        }

        char line[8192];
        int llen = builder_add_msg(
            &b, msg, (size_t)mlen, sd_type,
            line, sizeof(line));
        assert(llen > 0);

        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)(i + 1)) == 0);
    }

    verifier_finalize(&vctx);

    if (!verifier_passed(&vctx)) {
        for (int i = 0; i < vctx.error_count; i++) {
            fprintf(stderr, "  error: %s\n",
                    vctx.errors[i].message);
        }
    }
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 12);
    assert(vctx.sig_count == 3);
    assert(vctx.segment_count == 1);

    verifier_free(&vctx);
    builder_free(&b);
    printf("  PASS: test_sd_chain_verify\n");
}

static void test_sd_tamper_detect(void)
{
    sd_builder_t b;
    builder_init(&b, 4);

    char lines[4][8192];
    size_t line_lens[4];

    for (int i = 0; i < 4; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "msg %d", i);

        int sd_type = SD_LINE_MSG;
        if (i == 0) sd_type = SD_LINE_INIT;
        else if (i == 3) sd_type = SD_LINE_SIG;

        int llen = builder_add_msg(
            &b, msg, (size_t)mlen, sd_type,
            lines[i], sizeof(lines[i]));
        assert(llen > 0);
        line_lens[i] = (size_t)llen;
    }
    builder_free(&b);

    /* Tamper with message content in line 1 */
    char *closing = strchr(lines[1], ']');
    assert(closing != NULL);
    closing[1] = 'X';

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=0}) == 0);

    for (int i = 0; i < 4; i++) {
        verifier_process_line(&vctx, lines[i], line_lens[i],
                              (uint64_t)(i + 1));
    }
    verifier_finalize(&vctx);
    assert(!verifier_passed(&vctx));

    verifier_free(&vctx);
    printf("  PASS: test_sd_tamper_detect\n");
}

static void test_sd_multi_segment(void)
{
    sd_builder_t b;
    builder_init(&b, 100);

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    int line_num = 0;

    /* Segment 1: INIT + 3 MSG, SIG at last */
    for (int i = 0; i < 4; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "s1 msg %d", i);

        int sd_type = SD_LINE_MSG;
        if (i == 0) sd_type = SD_LINE_INIT;
        if (i == 3) sd_type = SD_LINE_SIG;

        char line[8192];
        int llen = builder_add_msg(
            &b, msg, (size_t)mlen, sd_type,
            line, sizeof(line));
        assert(llen > 0);
        line_num++;
        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)line_num) == 0);
    }

    /* Segment 2: CONTINUE + 3 MSG, SIG at last */
    for (int i = 0; i < 4; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "s2 msg %d", i);

        int sd_type = SD_LINE_MSG;
        if (i == 0) sd_type = SD_LINE_CONTINUE;
        if (i == 3) sd_type = SD_LINE_SIG;

        char line[8192];
        int llen = builder_add_msg(
            &b, msg, (size_t)mlen, sd_type,
            line, sizeof(line));
        assert(llen > 0);
        line_num++;
        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)line_num) == 0);
    }

    verifier_finalize(&vctx);

    if (!verifier_passed(&vctx)) {
        for (int i = 0; i < vctx.error_count; i++) {
            fprintf(stderr, "  error: %s\n",
                    vctx.errors[i].message);
        }
    }
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 8);
    assert(vctx.sig_count == 2);
    assert(vctx.segment_count == 2);

    verifier_free(&vctx);
    builder_free(&b);
    printf("  PASS: test_sd_multi_segment\n");
}

static void test_sd_single_message(void)
{
    sd_builder_t b;
    builder_init(&b, 1);

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    /* Single message that is both INIT and SIG */
    char msg[] = "only message";

    /* INIT first, then immediately sign */
    hashchain_update(&b.chain, msg, strlen(msg));
    uint64_t seq = b.chain.seq - 1;

    unsigned char sig_buf[HCS_SIG_MAX_LEN];
    size_t slen = sizeof(sig_buf);
    assert(hcs_sign(
        b.signer.privkey, b.chain.current,
        b.chain.hash_len, sig_buf, &slen) == 0);

    /*
     * First message must be INIT. We can't combine INIT+SIG in one
     * SD element. So use two messages: INIT then SIG.
     */
    char sd[HCS_SD_MAX_LEN];
    int sd_len = hcs_format_sd_init(
        seq, b.chain.current, b.chain.hash_len, b.signer.pubkey_fp,
        sd, sizeof(sd));
    assert(sd_len > 0);

    char line[8192];
    int llen = snprintf(line, sizeof(line), "%s%s", sd, msg);

    assert(verifier_process_line(
        &vctx, line, (size_t)llen, 1) == 0);

    /* Second message with SIG */
    char msg2[] = "signed message";
    hashchain_update(&b.chain, msg2, strlen(msg2));
    seq = b.chain.seq - 1;
    slen = sizeof(sig_buf);
    assert(hcs_sign(
        b.signer.privkey, b.chain.current,
        b.chain.hash_len, sig_buf, &slen) == 0);

    sd_len = hcs_format_sd_sig(
        seq, b.chain.current, b.chain.hash_len, 1, seq,
        sig_buf, slen, sd, sizeof(sd));
    assert(sd_len > 0);

    llen = snprintf(line, sizeof(line), "%s%s", sd, msg2);
    assert(verifier_process_line(
        &vctx, line, (size_t)llen, 2) == 0);

    verifier_finalize(&vctx);
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 2);
    assert(vctx.sig_count == 1);

    verifier_free(&vctx);
    builder_free(&b);
    printf("  PASS: test_sd_single_message\n");
}

static void test_mmhashchainsigs_process(void)
{
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 4,
    };
    mmhashchainsigs_worker_t wrkr = {
        .inst = &inst,
        .initialized = 0,
    };

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    for (int i = 0; i < 12; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "message %d", i);

        char sd[HCS_SD_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
        assert(sd_len > 0);

        char line[8192];
        int llen = snprintf(line, sizeof(line), "%s%s", sd, msg);

        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)(i + 1)) == 0);
    }

    verifier_finalize(&vctx);

    if (!verifier_passed(&vctx)) {
        for (int i = 0; i < vctx.error_count; i++) {
            fprintf(stderr, "  error: %s\n",
                    vctx.errors[i].message);
        }
    }
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 12);
    assert(vctx.sig_count == 3);

    verifier_free(&vctx);
    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_mmhashchainsigs_process\n");
}

static void test_mmhashchainsigs_sign_interval(void)
{
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 1,
    };
    mmhashchainsigs_worker_t wrkr = {
        .inst = &inst,
        .initialized = 0,
    };

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    for (int i = 0; i < 5; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "m%d", i);

        char sd[HCS_SD_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
        assert(sd_len > 0);

        char line[8192];
        int llen = snprintf(line, sizeof(line), "%s%s", sd, msg);

        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)(i + 1)) == 0);
    }

    verifier_finalize(&vctx);
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 5);
    assert(vctx.sig_count == 4);

    verifier_free(&vctx);
    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_mmhashchainsigs_sign_interval\n");
}

typedef struct {
    unsigned int pri;
    const char *ts;
    const char *host;
    const char *app;
    const char *procid;
    const char *msgid;
} sim_hdr_t;

/*
 * Simulate the rsyslog doAction pipeline for a message that has been
 * parsed into header fields, an existing client SD section, and a MSG
 * body. Mirrors the real doAction:
 *   1. Format a hdr SD from the six header values.
 *   2. Strip any client-supplied [mmhashchainsigs@32473 ...] and
 *      [mmhashchainsigs-hdr@32473 ...] elements (collision policy).
 *   3. cleaned_sd = hdr_sd || stripped_client_sd
 *   4. Hash cleaned_sd || MSG.
 *   5. Prepend the freshly produced mmhashchainsigs SD element.
 * The output line is then mmhashchainsigs_sd + cleaned_sd + MSG, which is what
 * `omfile` writes with the sd-preserve template.
 */
static int doaction_simulate(
    mmhashchainsigs_worker_t *wrkr,
    const sim_hdr_t *hdr,
    const char *client_sd, size_t client_sd_len,
    const char *msg, size_t msg_len,
    char *line_buf, size_t line_buf_len)
{
    char hdr_sd[HCS_SD_HDR_MAX_LEN];
    int hdr_len = hcs_format_sd_hdr(
        hdr->pri, hdr->ts, hdr->host, hdr->app,
        hdr->procid, hdr->msgid,
        hdr_sd, sizeof(hdr_sd));
    if (hdr_len < 0) return -1;

    char stripped[HCS_SD_MAX_LEN * 4];
    int stripped_len = 0;
    if (client_sd_len > 0) {
        int n = hcs_strip_all_sd(
            client_sd, client_sd_len, HCS_SD_ID,
            stripped, sizeof(stripped), NULL);
        if (n < 0) return -1;
        n = hcs_strip_all_sd(
            stripped, (size_t)n, HCS_SD_HDR_ID,
            stripped, sizeof(stripped), NULL);
        if (n < 0) return -1;
        stripped_len = n;
    }

    char cleaned[HCS_SD_HDR_MAX_LEN + HCS_SD_MAX_LEN * 4];
    if ((size_t)hdr_len + stripped_len > sizeof(cleaned)) return -1;
    memcpy(cleaned, hdr_sd, (size_t)hdr_len);
    memcpy(cleaned + hdr_len, stripped, (size_t)stripped_len);
    int cleaned_len = hdr_len + stripped_len;

    char payload[sizeof(cleaned) + 4096];
    if ((size_t)cleaned_len + msg_len > sizeof(payload)) return -1;
    memcpy(payload, cleaned, (size_t)cleaned_len);
    memcpy(payload + cleaned_len, msg, msg_len);

    char sd[HCS_SD_MAX_LEN];
    int sd_len = mmhashchainsigs_process_msg(
        wrkr, payload, (size_t)cleaned_len + msg_len,
        sd, sizeof(sd));
    if (sd_len < 0) return -1;

    int n = snprintf(line_buf, line_buf_len, "%.*s%.*s%.*s",
        sd_len, sd,
        cleaned_len, cleaned,
        (int)msg_len, msg);
    if (n < 0 || (size_t)n >= line_buf_len) return -1;
    return n;
}

/* Default headers for the tests that don't care about header values. */
static const sim_hdr_t DEFAULT_HDR = {
    .pri = 13, .ts = "2026-05-25T12:00:00Z",
    .host = "h", .app = "a", .procid = "1", .msgid = "-",
};

static void test_rfc5424_with_client_sd(void)
{
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 3,
    };
    mmhashchainsigs_worker_t wrkr = { .inst = &inst, .initialized = 0 };

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    const char *client_sd =
        "[client@9999 trace=\"abc\" span=\"42\"]";

    for (int i = 0; i < 9; i++) {
        char msg[64];
        int mlen = snprintf(msg, sizeof(msg), "msg %d", i);

        char line[4096];
        int llen = doaction_simulate(
            &wrkr, &DEFAULT_HDR,
            client_sd, strlen(client_sd),
            msg, (size_t)mlen,
            line, sizeof(line));
        assert(llen > 0);

        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)(i + 1)) == 0);
    }

    verifier_finalize(&vctx);
    if (!verifier_passed(&vctx)) {
        for (int i = 0; i < vctx.error_count; i++) {
            fprintf(stderr, "  error: %s\n",
                    vctx.errors[i].message);
        }
    }
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 9);
    assert(vctx.sig_count == 3);

    verifier_free(&vctx);
    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_rfc5424_with_client_sd\n");
}

static void test_rfc5424_with_collision(void)
{
    /*
     * Client supplies its own [mmhashchainsigs@32473 ...] element trying to
     * impersonate the signer. mmhashchainsigs must strip it; chain stays
     * consistent, file is well-formed.
     */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 3,
    };
    mmhashchainsigs_worker_t wrkr = { .inst = &inst, .initialized = 0 };

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    const char *poisoned_sd =
        "[mmhashchainsigs@32473 t=\"I\" q=\"99\" h=\"deadbeef\" f=\"cafe\"]"
        "[client@9999 trace=\"abc\"]";

    for (int i = 0; i < 6; i++) {
        char msg[64];
        int mlen = snprintf(msg, sizeof(msg), "msg %d", i);

        char line[4096];
        int llen = doaction_simulate(
            &wrkr, &DEFAULT_HDR,
            poisoned_sd, strlen(poisoned_sd),
            msg, (size_t)mlen,
            line, sizeof(line));
        assert(llen > 0);

        /* The output line must contain exactly one mmhashchainsigs SD element
         * (mmhashchainsigs's). The client's poisoned element must be gone. */
        const char *first = strstr(line, "[mmhashchainsigs@32473 ");
        assert(first != NULL);
        assert(strstr(first + 1, "[mmhashchainsigs@32473 ") == NULL);

        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)(i + 1)) == 0);
    }

    verifier_finalize(&vctx);
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 6);
    assert(vctx.sig_count == 2);

    verifier_free(&vctx);
    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_rfc5424_with_collision\n");
}

static void test_hdr_chain_verify(void)
{
    /* Use non-default per-message headers and confirm the chain holds
     * end to end. Each message carries distinct host/app/procid/msgid
     * so the hdr SD bytes (and therefore the hash payload) differ. */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 3,
    };
    mmhashchainsigs_worker_t wrkr = { .inst = &inst, .initialized = 0 };

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    for (int i = 0; i < 9; i++) {
        char ts[32], host[32], app[32], procid[16], msgid[16];
        snprintf(ts, sizeof(ts),
            "2026-05-25T12:00:%02dZ", i);
        snprintf(host, sizeof(host), "host%d", i);
        snprintf(app,  sizeof(app),  "app%d",  i);
        snprintf(procid, sizeof(procid), "%d", 1000 + i);
        snprintf(msgid, sizeof(msgid), "MID%d", i);
        sim_hdr_t hdr = {
            .pri = 13, .ts = ts, .host = host, .app = app,
            .procid = procid, .msgid = msgid,
        };

        char msg[64];
        int mlen = snprintf(msg, sizeof(msg), "msg %d", i);

        char line[4096];
        int llen = doaction_simulate(
            &wrkr, &hdr, NULL, 0,
            msg, (size_t)mlen,
            line, sizeof(line));
        assert(llen > 0);

        /* Sanity: the line must carry the hdr SD with this message's
         * host value embedded as a parameter. */
        char marker[64];
        snprintf(marker, sizeof(marker), "host=\"%s\"", host);
        assert(strstr(line, marker) != NULL);

        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)(i + 1)) == 0);
    }

    verifier_finalize(&vctx);
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 9);
    assert(vctx.sig_count == 3);

    verifier_free(&vctx);
    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_hdr_chain_verify\n");
}

static void test_hdr_tamper_detect(void)
{
    /* Tamper with a header value in the stored line. Because the hdr
     * SD is part of the hashed payload (the verifier strips only the
     * leading mmhashchainsigs SD), the chain hash for that message must fail. */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 3,
    };
    mmhashchainsigs_worker_t wrkr = { .inst = &inst, .initialized = 0 };

    sim_hdr_t hdr = {
        .pri = 13, .ts = "2026-05-25T12:00:00Z",
        .host = "originhost", .app = "myapp",
        .procid = "1234", .msgid = "ID1",
    };

    char lines[3][4096];
    size_t line_lens[3];
    for (int i = 0; i < 3; i++) {
        char msg[64];
        int mlen = snprintf(msg, sizeof(msg), "msg %d", i);
        int llen = doaction_simulate(
            &wrkr, &hdr, NULL, 0,
            msg, (size_t)mlen,
            lines[i], sizeof(lines[i]));
        assert(llen > 0);
        line_lens[i] = (size_t)llen;
    }
    mmhashchainsigs_free(&wrkr);

    /* Tamper with line 1's host value: "originhost" -> "ATTACKER!!" */
    char *h = strstr(lines[1], "host=\"originhost\"");
    assert(h != NULL);
    memcpy(h + 6, "ATTACKER!!", 10);

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=0}) == 0);
    for (int i = 0; i < 3; i++) {
        verifier_process_line(&vctx, lines[i], line_lens[i],
                              (uint64_t)(i + 1));
    }
    verifier_finalize(&vctx);
    assert(!verifier_passed(&vctx));

    verifier_free(&vctx);
    printf("  PASS: test_hdr_tamper_detect\n");
}

static void test_hdr_collision(void)
{
    /* Client supplies its own [mmhashchainsigs-hdr@32473 ...] element
     * trying to plant fake header values. mmhashchainsigs must strip
     * it; the line ends up with exactly one hdr SD (ours), chain
     * verifies. */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 3,
    };
    mmhashchainsigs_worker_t wrkr = { .inst = &inst, .initialized = 0 };

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    sim_hdr_t real_hdr = {
        .pri = 13, .ts = "2026-05-25T12:00:00Z",
        .host = "realhost", .app = "realapp",
        .procid = "9", .msgid = "-",
    };

    const char *poisoned_client_sd =
        "[mmhashchainsigs-hdr@32473 pri=\"13\" ts=\"FAKE\""
        " host=\"poisoned\" app=\"\" procid=\"\" msgid=\"-\"]"
        "[client@9999 trace=\"abc\"]";

    for (int i = 0; i < 6; i++) {
        char msg[64];
        int mlen = snprintf(msg, sizeof(msg), "msg %d", i);

        char line[4096];
        int llen = doaction_simulate(
            &wrkr, &real_hdr,
            poisoned_client_sd, strlen(poisoned_client_sd),
            msg, (size_t)mlen,
            line, sizeof(line));
        assert(llen > 0);

        /* Exactly one hdr SD in the line; and its host is the real
         * one, not the poisoned one. */
        const char *first_hdr =
            strstr(line, "[mmhashchainsigs-hdr@32473 ");
        assert(first_hdr != NULL);
        assert(strstr(first_hdr + 1,
                      "[mmhashchainsigs-hdr@32473 ") == NULL);
        assert(strstr(line, "host=\"realhost\"") != NULL);
        assert(strstr(line, "host=\"poisoned\"") == NULL);

        assert(verifier_process_line(
            &vctx, line, (size_t)llen,
            (uint64_t)(i + 1)) == 0);
    }

    verifier_finalize(&vctx);
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 6);
    assert(vctx.sig_count == 2);

    verifier_free(&vctx);
    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_hdr_collision\n");
}

static void test_final_sign_covers_tail(void)
{
    /*
     * Process 6 messages with sign_interval=4. After msg 4, a periodic
     * signature covers seq 1-4. Messages 5-6 remain unsigned.
     * mmhashchainsigs_final_sign must produce a signature covering
     * seq 5-6. The verifier in strict mode must pass.
     */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 4,
    };
    mmhashchainsigs_worker_t wrkr = {
        .inst = &inst,
        .initialized = 0,
    };

    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    char lines[7][8192];
    size_t line_lens[7];
    int line_count = 0;

    for (int i = 0; i < 6; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "message %d", i);

        char sd[HCS_SD_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
        assert(sd_len > 0);

        int llen = snprintf(lines[line_count], sizeof(lines[0]),
                            "%s%s", sd, msg);
        assert(llen > 0);
        line_lens[line_count] = (size_t)llen;
        line_count++;
    }

    /* Emit the final signature — should cover the unsigned tail */
    char final_sd[HCS_SD_MAX_LEN];
    int final_len = mmhashchainsigs_final_sign(
        &wrkr, final_sd, sizeof(final_sd));
    assert(final_len > 0);

    /* The final signature is a standalone SD line (no message body).
     * Feed it to the verifier as a line consisting of just the SD. */
    memcpy(lines[line_count], final_sd, (size_t)final_len);
    line_lens[line_count] = (size_t)final_len;
    line_count++;

    for (int i = 0; i < line_count; i++) {
        assert(verifier_process_line(
            &vctx, lines[i], line_lens[i],
            (uint64_t)(i + 1)) == 0);
    }

    verifier_finalize(&vctx);

    if (!verifier_passed(&vctx)) {
        for (int i = 0; i < vctx.error_count; i++) {
            fprintf(stderr, "  error: %s\n",
                    vctx.errors[i].message);
        }
    }
    assert(verifier_passed(&vctx));
    /* 6 real messages + 1 empty-payload final sign entry */
    assert(vctx.msg_count == 7);
    assert(vctx.sig_count == 2);

    verifier_free(&vctx);
    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_final_sign_covers_tail\n");
}

static void test_final_sign_no_unsigned(void)
{
    /*
     * Process exactly sign_interval messages so the periodic signature
     * covers all of them. mmhashchainsigs_final_sign must return 0
     * (nothing to sign).
     */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 4,
    };
    mmhashchainsigs_worker_t wrkr = {
        .inst = &inst,
        .initialized = 0,
    };

    for (int i = 0; i < 4; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "message %d", i);
        char sd[HCS_SD_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
        assert(sd_len > 0);
    }

    /* INIT(1) + MSG(2) + MSG(3) + SIG(4) → msg_count reset to 0 */
    char final_sd[HCS_SD_MAX_LEN];
    int final_len = mmhashchainsigs_final_sign(
        &wrkr, final_sd, sizeof(final_sd));
    assert(final_len == 0);

    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_final_sign_no_unsigned\n");
}

static void test_state_save_load_roundtrip(void)
{
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 4,
    };
    mmhashchainsigs_worker_t wrkr = {
        .inst = &inst,
        .initialized = 0,
        .pending_state = NULL,
    };

    for (int i = 0; i < 6; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "message %d", i);
        char sd[HCS_SD_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
        assert(sd_len > 0);
    }

    char tmpdir[] = "/tmp/hcs_state_XXXXXX";
    assert(mkdtemp(tmpdir) != NULL);

    int saved = mmhashchainsigs_save_state(&wrkr, tmpdir);
    assert(saved == 1);

    mmhashchainsigs_saved_state_t *st =
        mmhashchainsigs_load_state(tmpdir);
    assert(st != NULL);

    assert(memcmp(st->chain_hash, wrkr.chain.current,
                  HCS_HASH_LEN) == 0);
    assert(st->seq == wrkr.chain.seq);
    assert(st->sig_seq_from == wrkr.sig_seq_from);
    assert(memcmp(st->pubkey_fp,
                  signer_pubkey_fp(&wrkr.signer),
                  HCS_HASH_LEN) == 0);

    free(st);
    mmhashchainsigs_delete_state(tmpdir);
    rmdir(tmpdir);
    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_state_save_load_roundtrip\n");
}

static void test_state_inject_and_verify(void)
{
    /*
     * Simulate graceful shutdown + restart:
     * 1. Process 6 msgs (sign_interval=4 → SIG at msg 4, 2 unsigned)
     * 2. Save state
     * 3. New worker loads state
     * 4. First msg gets final SIG from old chain
     * 5. Next msgs start a new chain (INIT + MSG + MSG + SIG)
     * 6. Verify the entire log in strict mode
     */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 4,
        .statefiledir = NULL,
    };

    char tmpdir[] = "/tmp/hcs_state_XXXXXX";
    assert(mkdtemp(tmpdir) != NULL);
    inst.statefiledir = tmpdir;

    mmhashchainsigs_worker_t wrkr1 = {
        .inst = &inst,
        .initialized = 0,
        .pending_state = NULL,
    };

    char lines[20][8192];
    size_t line_lens[20];
    int lc = 0;

    /* Phase 1: original chain — 6 messages */
    for (int i = 0; i < 6; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg),
                            "original %d", i);
        char sd[HCS_SD_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr1, msg, (size_t)mlen,
            sd, sizeof(sd));
        assert(sd_len > 0);
        int n = snprintf(lines[lc], sizeof(lines[0]),
                         "%s%s", sd, msg);
        assert(n > 0);
        line_lens[lc] = (size_t)n;
        lc++;
    }

    assert(mmhashchainsigs_save_state(&wrkr1, tmpdir) == 1);
    mmhashchainsigs_free(&wrkr1);

    /* Phase 2: new worker with loaded state — 5 messages
     * (final SIG + INIT + MSG + MSG + periodic SIG) */
    mmhashchainsigs_worker_t wrkr2 = {
        .inst = &inst,
        .initialized = 0,
        .pending_state = mmhashchainsigs_load_state(tmpdir),
    };
    assert(wrkr2.pending_state != NULL);

    for (int i = 0; i < 5; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg),
                            "restart %d", i);
        char sd[HCS_SD_MAX_LEN];
        int sd_len = mmhashchainsigs_process_msg(
            &wrkr2, msg, (size_t)mlen,
            sd, sizeof(sd));
        assert(sd_len > 0);
        int n = snprintf(lines[lc], sizeof(lines[0]),
                         "%s%s", sd, msg);
        assert(n > 0);
        line_lens[lc] = (size_t)n;
        lc++;
    }

    /* State file should be deleted after consumption */
    assert(mmhashchainsigs_load_state(tmpdir) == NULL);
    rmdir(tmpdir);
    inst.statefiledir = NULL;

    /* Verify the full 11-line log in strict mode */
    verifier_ctx_t vctx;
    assert(verifier_init(&vctx, &(verifier_opts_t){.pubkey_path=pubkey_path, .strict=1}) == 0);

    for (int i = 0; i < lc; i++) {
        int r = verifier_process_line(
            &vctx, lines[i], line_lens[i],
            (uint64_t)(i + 1));
        assert(r == 0);
    }

    verifier_finalize(&vctx);
    if (!verifier_passed(&vctx)) {
        for (int i = 0; i < vctx.error_count; i++) {
            fprintf(stderr, "  error line %lu: %s\n",
                    (unsigned long)vctx.errors[i].line_num,
                    vctx.errors[i].message);
        }
    }
    assert(verifier_passed(&vctx));
    assert(vctx.msg_count == 11);
    assert(vctx.sig_count == 3);
    assert(vctx.segment_count == 2);

    verifier_free(&vctx);
    mmhashchainsigs_free(&wrkr2);
    printf("  PASS: test_state_inject_and_verify\n");
}

static void test_state_no_unsigned(void)
{
    /* When all messages are signed (msg_count=0), save_state
     * should return 0 and not create a state file. */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 4,
    };
    mmhashchainsigs_worker_t wrkr = {
        .inst = &inst,
        .initialized = 0,
        .pending_state = NULL,
    };

    for (int i = 0; i < 4; i++) {
        char msg[128];
        int mlen = snprintf(msg, sizeof(msg), "msg %d", i);
        char sd[HCS_SD_MAX_LEN];
        mmhashchainsigs_process_msg(
            &wrkr, msg, (size_t)mlen, sd, sizeof(sd));
    }

    char tmpdir[] = "/tmp/hcs_state_XXXXXX";
    assert(mkdtemp(tmpdir) != NULL);
    assert(mmhashchainsigs_save_state(&wrkr, tmpdir) == 0);
    assert(mmhashchainsigs_load_state(tmpdir) == NULL);
    rmdir(tmpdir);

    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_state_no_unsigned\n");
}

static void test_final_sign_uninitialized(void)
{
    /*
     * A worker that never processed a message should return 0.
     */
    mmhashchainsigs_instance_t inst = {
        .privkey_path = privkey_path,
        .sign_interval = 4,
    };
    mmhashchainsigs_worker_t wrkr = {
        .inst = &inst,
        .initialized = 0,
    };

    char final_sd[HCS_SD_MAX_LEN];
    int final_len = mmhashchainsigs_final_sign(
        &wrkr, final_sd, sizeof(final_sd));
    assert(final_len == 0);

    mmhashchainsigs_free(&wrkr);
    printf("  PASS: test_final_sign_uninitialized\n");
}

int main(void)
{
    printf("test_mmhashchainsigs:\n");

    create_test_keys();

    test_sd_chain_verify();
    test_sd_tamper_detect();
    test_sd_multi_segment();
    test_sd_single_message();
    test_mmhashchainsigs_process();
    test_mmhashchainsigs_sign_interval();
    test_rfc5424_with_client_sd();
    test_rfc5424_with_collision();
    test_hdr_chain_verify();
    test_hdr_tamper_detect();
    test_hdr_collision();
    test_final_sign_covers_tail();
    test_final_sign_no_unsigned();
    test_final_sign_uninitialized();
    test_state_save_load_roundtrip();
    test_state_inject_and_verify();
    test_state_no_unsigned();

    cleanup_test_keys();

    printf("All mmhashchainsigs tests passed.\n");
    return 0;
}
