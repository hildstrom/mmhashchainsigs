/*
 * verifier.c - Log verification engine for mmhashchainsigs SD-mode logs
 */
#include "verifier.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define SD_MSG_BUF_LEN 8192

static void add_error(
    verifier_ctx_t *ctx,
    uint64_t line_num,
    const char *fmt, ...)
{
    if (ctx->error_count >= VERIFIER_MAX_ERRORS) {
        return;
    }

    verifier_error_t *e = &ctx->errors[ctx->error_count];
    e->line_num = line_num;

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->message, sizeof(e->message), fmt, ap);
    va_end(ap);

    ctx->error_count++;
}

int verifier_init(
    verifier_ctx_t *ctx,
    const char *pubkey_path,
    bool strict)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = VSTATE_EXPECT_INIT;
    ctx->strict = strict;
    ctx->next_seq = 1;

    if (hcs_load_public_key(pubkey_path, &ctx->pubkey) != 0) {
        return -1;
    }

    if (hcs_pubkey_fingerprint(ctx->pubkey, ctx->pubkey_fp) != 0) {
        EVP_PKEY_free(ctx->pubkey);
        ctx->pubkey = NULL;
        return -1;
    }

    return 0;
}

static int verify_sd_msg_hash(
    verifier_ctx_t *ctx,
    const hcs_sd_record_t *sd,
    const char *msg, size_t msg_len,
    uint64_t line_num)
{
    if (sd->seq != ctx->next_seq) {
        add_error(ctx, line_num,
                  "SD seq=%lu, expected %lu",
                  (unsigned long)sd->seq,
                  (unsigned long)ctx->next_seq);
    }

    unsigned char next[HCS_HASH_LEN];
    if (hcs_sha256_chain(ctx->chain_hash, ctx->next_seq,
                            msg, msg_len, next) != 0) {
        ctx->state = VSTATE_ERROR;
        return -1;
    }
    memcpy(ctx->chain_hash, next, HCS_HASH_LEN);

    if (memcmp(ctx->chain_hash, sd->chain_hash,
               HCS_HASH_LEN) != 0) {
        add_error(ctx, line_num,
                  "chain hash mismatch at seq %lu",
                  (unsigned long)sd->seq);
    }

    ctx->next_seq++;
    ctx->msg_count++;
    return 0;
}

static int handle_sd_init(
    verifier_ctx_t *ctx,
    const hcs_sd_record_t *sd,
    const char *msg, size_t msg_len,
    uint64_t line_num)
{
    if (!sd->has_pubkey_fp) {
        add_error(ctx, line_num, "INIT SD missing fingerprint");
        ctx->state = VSTATE_ERROR;
        return -1;
    }
    if (memcmp(sd->pubkey_fp, ctx->pubkey_fp,
               HCS_HASH_LEN) != 0) {
        add_error(ctx, line_num, "INIT fingerprint mismatch");
        ctx->state = VSTATE_ERROR;
        return -1;
    }

    if (ctx->state == VSTATE_PROCESSING) {
        uint64_t unsigned_tail =
            (ctx->next_seq - 1) - ctx->last_signed_seq;
        if (unsigned_tail > 0 && ctx->strict) {
            add_error(ctx, line_num,
                      "%lu messages unsigned before new segment",
                      (unsigned long)unsigned_tail);
        }
        ctx->last_signed_seq = 0;
    }

    unsigned char iv[HCS_HASH_LEN];
    if (hcs_chain_init_hash(iv) != 0) {
        ctx->state = VSTATE_ERROR;
        return -1;
    }
    memcpy(ctx->chain_hash, iv, HCS_HASH_LEN);
    ctx->next_seq = 1;
    ctx->segment_count++;
    ctx->state = VSTATE_PROCESSING;

    return verify_sd_msg_hash(ctx, sd, msg, msg_len, line_num);
}

static int handle_sd_msg(
    verifier_ctx_t *ctx,
    const hcs_sd_record_t *sd,
    const char *msg, size_t msg_len,
    uint64_t line_num)
{
    if (ctx->state != VSTATE_PROCESSING) {
        add_error(ctx, line_num, "message before INIT");
        ctx->state = VSTATE_ERROR;
        return -1;
    }
    return verify_sd_msg_hash(ctx, sd, msg, msg_len, line_num);
}

static int handle_sd_sig(
    verifier_ctx_t *ctx,
    const hcs_sd_record_t *sd,
    const char *msg, size_t msg_len,
    uint64_t line_num)
{
    if (ctx->state != VSTATE_PROCESSING) {
        add_error(ctx, line_num, "SIG before INIT");
        return 0;
    }

    if (verify_sd_msg_hash(ctx, sd, msg, msg_len, line_num) != 0) {
        return -1;
    }

    if (!sd->has_signature) {
        add_error(ctx, line_num, "SIG SD missing signature");
        return 0;
    }

    uint64_t exp_from = ctx->last_signed_seq + 1;
    uint64_t exp_to = ctx->next_seq - 1;
    if (sd->seq_from != exp_from) {
        add_error(ctx, line_num, "SIG qf=%lu, expected %lu",
                  (unsigned long)sd->seq_from,
                  (unsigned long)exp_from);
    }
    if (sd->seq_to != exp_to) {
        add_error(ctx, line_num, "SIG qt=%lu, expected %lu",
                  (unsigned long)sd->seq_to,
                  (unsigned long)exp_to);
    }

    int vr = hcs_ed25519_verify(
        ctx->pubkey, ctx->chain_hash, HCS_HASH_LEN,
        sd->signature, sd->sig_len);
    if (vr == 1) {
        add_error(ctx, line_num,
                  "invalid signature at seq %lu-%lu",
                  (unsigned long)sd->seq_from,
                  (unsigned long)sd->seq_to);
    } else if (vr < 0) {
        add_error(ctx, line_num,
                  "signature verification error at seq %lu-%lu",
                  (unsigned long)sd->seq_from,
                  (unsigned long)sd->seq_to);
    }
    if (vr == 0) {
        ctx->last_signed_seq = sd->seq_to;
        ctx->sig_count++;
    }
    return 0;
}

static int handle_sd_continue(
    verifier_ctx_t *ctx,
    const hcs_sd_record_t *sd,
    const char *msg, size_t msg_len,
    uint64_t line_num)
{
    if (ctx->state != VSTATE_PROCESSING) {
        add_error(ctx, line_num, "CONTINUE before INIT");
        return 0;
    }

    if (sd->has_pubkey_fp &&
        memcmp(sd->pubkey_fp, ctx->pubkey_fp,
               HCS_HASH_LEN) != 0) {
        add_error(ctx, line_num, "CONTINUE fingerprint mismatch");
        return 0;
    }

    ctx->segment_count++;
    return verify_sd_msg_hash(ctx, sd, msg, msg_len, line_num);
}

int verifier_process_line(
    verifier_ctx_t *ctx,
    const char *line, size_t len,
    uint64_t line_num)
{
    if (ctx->state == VSTATE_ERROR || ctx->state == VSTATE_DONE) {
        return -1;
    }

    char msg[SD_MSG_BUF_LEN];
    hcs_sd_record_t sd;
    int msg_len = hcs_strip_sd_from_line(
        line, len, msg, sizeof(msg), &sd);

    if (msg_len < 0) {
        add_error(ctx, line_num, "missing mmhashchainsigs SD element");
        if (ctx->state == VSTATE_EXPECT_INIT) {
            ctx->state = VSTATE_ERROR;
            return -1;
        }
        return 0;
    }

    if (ctx->state == VSTATE_EXPECT_INIT &&
        sd.type != HCS_SD_INIT) {
        add_error(ctx, line_num, "expected INIT SD record");
        ctx->state = VSTATE_ERROR;
        return -1;
    }

    switch (sd.type) {
    case HCS_SD_INIT:
        return handle_sd_init(ctx, &sd, msg, (size_t)msg_len,
                              line_num);
    case HCS_SD_SIG:
        return handle_sd_sig(ctx, &sd, msg, (size_t)msg_len,
                             line_num);
    case HCS_SD_CONTINUE:
        return handle_sd_continue(ctx, &sd, msg, (size_t)msg_len,
                                  line_num);
    case HCS_SD_MSG:
        return handle_sd_msg(ctx, &sd, msg, (size_t)msg_len,
                             line_num);
    default:
        add_error(ctx, line_num, "unknown SD type");
        return 0;
    }
}

int verifier_finalize(verifier_ctx_t *ctx)
{
    if (ctx->state == VSTATE_EXPECT_INIT) {
        add_error(ctx, 0, "empty file: no INIT record found");
    }

    uint64_t unsigned_count = (ctx->next_seq - 1) - ctx->last_signed_seq;
    if (ctx->strict && unsigned_count > 0) {
        add_error(ctx, 0,
                  "%lu messages at tail are unsigned",
                  (unsigned long)unsigned_count);
    }

    ctx->state = VSTATE_DONE;
    return 0;
}

bool verifier_passed(const verifier_ctx_t *ctx)
{
    return ctx->error_count == 0;
}

void verifier_free(verifier_ctx_t *ctx)
{
    if (ctx->pubkey) {
        EVP_PKEY_free(ctx->pubkey);
        ctx->pubkey = NULL;
    }
}
