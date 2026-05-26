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
    const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/*
 * In CA-bundle mode, validate `cert_der` against the trust store and
 * install its public key on the verifier. Returns 0 on success, -1 on
 * any failure (chain invalid, unsupported pubkey, etc.). On failure,
 * records a descriptive error.
 */
static int install_pubkey_from_cert(
    verifier_ctx_t *ctx,
    const unsigned char *cert_der, size_t cert_der_len,
    uint64_t line_num)
{
    X509 *cert = NULL;
    if (hcs_x509_from_der(cert_der, cert_der_len, &cert) != 0) {
        add_error(ctx, line_num,
                  "failed to parse embedded certificate");
        return -1;
    }

    X509_STORE_CTX *sctx = X509_STORE_CTX_new();
    if (!sctx) {
        X509_free(cert);
        return -1;
    }
    int rc = -1;
    if (X509_STORE_CTX_init(sctx, ctx->trust_store, cert, NULL) != 1) {
        add_error(ctx, line_num,
                  "X509_STORE_CTX_init failed");
        goto done;
    }
    if (X509_verify_cert(sctx) != 1) {
        int err = X509_STORE_CTX_get_error(sctx);
        add_error(ctx, line_num,
                  "certificate chain validation failed: %s",
                  X509_verify_cert_error_string(err));
        goto done;
    }

    EVP_PKEY *pub = NULL;
    if (hcs_x509_get_pubkey(cert, &pub) != 0) {
        add_error(ctx, line_num,
                  "unsupported public key algorithm in certificate");
        goto done;
    }
    if (ctx->pubkey) {
        EVP_PKEY_free(ctx->pubkey);
    }
    ctx->pubkey = pub;
    if (hcs_pubkey_fingerprint(ctx->pubkey, ctx->pubkey_fp) != 0) {
        EVP_PKEY_free(ctx->pubkey);
        ctx->pubkey = NULL;
        add_error(ctx, line_num,
                  "failed to compute pubkey fingerprint from cert");
        goto done;
    }
    ctx->have_pubkey = true;
    rc = 0;

done:
    X509_STORE_CTX_free(sctx);
    X509_free(cert);
    return rc;
}

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

static int load_pubkey_from_cert_file(
    const char *cert_path, EVP_PKEY **out)
{
    X509 *cert = NULL;
    if (hcs_load_x509_cert(cert_path, &cert) != 0) {
        return -1;
    }
    int rc = hcs_x509_get_pubkey(cert, out);
    X509_free(cert);
    return rc;
}

int verifier_init(verifier_ctx_t *ctx, const verifier_opts_t *opts)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = VSTATE_EXPECT_INIT;
    ctx->strict = opts->strict;
    ctx->next_seq = 1;

    int n_set = (opts->pubkey_path != NULL)
              + (opts->cert_path != NULL)
              + (opts->ca_bundle_path != NULL);
    if (n_set != 1) {
        return -1;
    }

    if (opts->pubkey_path) {
        if (hcs_load_public_key(
                opts->pubkey_path, &ctx->pubkey) != 0) {
            return -1;
        }
    } else if (opts->cert_path) {
        if (load_pubkey_from_cert_file(
                opts->cert_path, &ctx->pubkey) != 0) {
            return -1;
        }
    } else {
        /* ca_bundle_path: defer pubkey extraction until we see an
         * embedded cert on the wire (Phase 3). */
        ctx->trust_store = X509_STORE_new();
        if (!ctx->trust_store) {
            return -1;
        }
        if (X509_STORE_load_file(
                ctx->trust_store, opts->ca_bundle_path) != 1) {
            X509_STORE_free(ctx->trust_store);
            ctx->trust_store = NULL;
            return -1;
        }
        if (opts->crl_file) {
            if (X509_STORE_load_file(
                    ctx->trust_store, opts->crl_file) != 1) {
                X509_STORE_free(ctx->trust_store);
                ctx->trust_store = NULL;
                return -1;
            }
            X509_STORE_set_flags(
                ctx->trust_store,
                X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        }
        return 0;
    }

    if (hcs_pubkey_fingerprint(ctx->pubkey, ctx->pubkey_fp) != 0) {
        EVP_PKEY_free(ctx->pubkey);
        ctx->pubkey = NULL;
        return -1;
    }
    ctx->have_pubkey = true;
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

    /* Every line after INIT must agree on the hash algorithm. */
    if (sd->chain_hash_len != ctx->hash_len) {
        add_error(ctx, line_num,
                  "chain hash length changed mid-chain"
                  " (got %zu, expected %zu)",
                  sd->chain_hash_len, ctx->hash_len);
        ctx->state = VSTATE_ERROR;
        return -1;
    }

    unsigned char next[HCS_HASH_MAX_LEN];
    if (hcs_hash_chain(ctx->hash_alg, ctx->chain_hash, ctx->next_seq,
                       msg, msg_len, next) != 0) {
        ctx->state = VSTATE_ERROR;
        return -1;
    }
    memcpy(ctx->chain_hash, next, ctx->hash_len);

    if (memcmp(ctx->chain_hash, sd->chain_hash,
               ctx->hash_len) != 0) {
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
    const unsigned char *cert_der, size_t cert_der_len,
    uint64_t line_num)
{
    if (!sd->has_pubkey_fp) {
        add_error(ctx, line_num, "INIT SD missing fingerprint");
        ctx->state = VSTATE_ERROR;
        return -1;
    }

    /* CA-bundle mode: the INIT line must carry an embedded cert,
     * chain-validate it, then install its pubkey. */
    if (ctx->trust_store && !ctx->have_pubkey) {
        if (cert_der_len == 0) {
            add_error(ctx, line_num,
                "CA-bundle mode requires an embedded certificate"
                " on INIT (configure embedcert=on at the signer)");
            ctx->state = VSTATE_ERROR;
            return -1;
        }
        if (install_pubkey_from_cert(
                ctx, cert_der, cert_der_len, line_num) != 0) {
            ctx->state = VSTATE_ERROR;
            return -1;
        }
    }

    if (!ctx->have_pubkey) {
        add_error(ctx, line_num,
                  "no public key available to verify INIT");
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

    /* Auto-detect / lock-in the chain hash algorithm from the INIT
     * line. Once set, every subsequent line must use the same algo. */
    hcs_hash_alg_t alg;
    if (hcs_hash_alg_from_hex_len(sd->chain_hash_len * 2, &alg) != 0) {
        add_error(ctx, line_num,
                  "INIT chain hash has unsupported length %zu",
                  sd->chain_hash_len);
        ctx->state = VSTATE_ERROR;
        return -1;
    }
    if (ctx->have_hash_alg && ctx->hash_alg != alg) {
        add_error(ctx, line_num,
            "hash algorithm changed mid-file (was %s, INIT now %s)",
            hcs_hash_name(ctx->hash_alg), hcs_hash_name(alg));
        ctx->state = VSTATE_ERROR;
        return -1;
    }
    ctx->hash_alg = alg;
    ctx->hash_len = hcs_hash_len(alg);
    ctx->have_hash_alg = true;

    unsigned char iv[HCS_HASH_MAX_LEN];
    if (hcs_chain_init_hash(ctx->hash_alg, iv) != 0) {
        ctx->state = VSTATE_ERROR;
        return -1;
    }
    memcpy(ctx->chain_hash, iv, ctx->hash_len);
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

    int vr = hcs_verify(
        ctx->pubkey, ctx->chain_hash, ctx->hash_len,
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

    /* Also strip a cert SD if present. The cert SD is signer metadata
     * (parallel to the main chain SD) and is not part of the hashed
     * payload. Extracted DER is used by INIT handling in CA-bundle mode. */
    unsigned char cert_der[HCS_CERT_DER_MAX];
    size_t cert_der_len = sizeof(cert_der);
    int new_msg_len = 0;
    int cert_rc = hcs_extract_and_strip_cert_sd(
        msg, (size_t)msg_len, msg, sizeof(msg),
        &new_msg_len, cert_der, &cert_der_len);
    if (cert_rc < 0) {
        add_error(ctx, line_num, "malformed embedded cert SD element");
        cert_der_len = 0;
        new_msg_len = msg_len;
    }
    if (cert_rc == 0) {
        cert_der_len = 0;
    }
    msg_len = new_msg_len;

    if (ctx->state == VSTATE_EXPECT_INIT &&
        sd.type != HCS_SD_INIT) {
        add_error(ctx, line_num, "expected INIT SD record");
        ctx->state = VSTATE_ERROR;
        return -1;
    }

    switch (sd.type) {
    case HCS_SD_INIT:
        return handle_sd_init(ctx, &sd, msg, (size_t)msg_len,
                              cert_der, cert_der_len, line_num);
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
    if (ctx->trust_store) {
        X509_STORE_free(ctx->trust_store);
        ctx->trust_store = NULL;
    }
}
