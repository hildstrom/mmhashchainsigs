/*
 * mmhashchainsigs.h - Rsyslog message modification module for signed logging
 *
 * Enriches syslog messages with RFC 5424 structured data containing
 * hash chain and Ed25519 signature metadata for RELP transmission.
 */
#ifndef MMHASHCHAINSIGS_H
#define MMHASHCHAINSIGS_H

#include "hashchain.h"
#include "hcs_format.h"
#include "signer.h"

#include <stdint.h>

#define MMHASHCHAINSIGS_DEFAULT_SIGN_INTERVAL 1024

typedef struct mmhashchainsigs_instance {
    char *privkey_path;
    char *tpl_name;
    unsigned int sign_interval;
} mmhashchainsigs_instance_t;

typedef struct mmhashchainsigs_worker {
    mmhashchainsigs_instance_t *inst;
    hashchain_ctx_t chain;
    signer_ctx_t signer;
    uint64_t sig_seq_from;
    int initialized;
    int is_first;
} mmhashchainsigs_worker_t;

/*
 * Initialize the worker (load key, init hash chain).
 * Called lazily on first message if not already initialized.
 * Returns 0 on success, -1 on error.
 */
int mmhashchainsigs_init(mmhashchainsigs_worker_t *wrkr);

/*
 * Process one message: feed `payload` into the chain and produce a
 * fresh RFC 5424 structured data element.
 *
 * `payload` is the exact byte sequence the verifier will hash, which
 * for a rsyslog action with non-mmhashchainsigs client SD is the concatenation
 * of (cleaned client SD) || (MSG). The standalone API treats it as
 * opaque bytes; assembling the right payload is the caller's job.
 *
 * The SD element is written to sd_buf (NUL-terminated).
 * Returns the SD element length (excluding NUL), or -1 on error.
 */
int mmhashchainsigs_process_msg(
    mmhashchainsigs_worker_t *wrkr,
    const char *payload, size_t payload_len,
    char *sd_buf, size_t sd_buf_len);

/* Free worker resources. */
void mmhashchainsigs_free(mmhashchainsigs_worker_t *wrkr);

#endif /* MMHASHCHAINSIGS_H */
