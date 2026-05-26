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
#define MMHASHCHAINSIGS_STATE_FILE "mmhashchainsigs.state"

typedef struct mmhashchainsigs_saved_state {
    hcs_hash_alg_t hash_alg;
    size_t hash_len;
    unsigned char chain_hash[HCS_HASH_MAX_LEN];
    uint64_t seq;
    uint64_t sig_seq_from;
    unsigned char pubkey_fp[HCS_HASH_LEN];
} mmhashchainsigs_saved_state_t;

typedef struct mmhashchainsigs_instance {
    char *privkey_path;
    char *cert_path;       /* optional X.509 cert PEM; raw-key mode if NULL */
    char *tpl_name;
    char *statefiledir;
    unsigned int sign_interval;
    int embedcert;         /* emit cert in INIT/CONTINUE SD (Phase 3) */
    hcs_hash_alg_t hash_alg; /* hash for the chain (SHA-256 default) */
} mmhashchainsigs_instance_t;

typedef struct mmhashchainsigs_worker {
    mmhashchainsigs_instance_t *inst;
    hashchain_ctx_t chain;
    signer_ctx_t signer;
    mmhashchainsigs_saved_state_t *pending_state;
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

/*
 * Emit a final signature covering any unsigned tail messages.
 * Extends the chain with an empty payload, signs, and writes
 * a SIG SD element to sd_buf.
 * Returns SD length on success, 0 if no unsigned messages, -1 on error.
 */
int mmhashchainsigs_final_sign(
    mmhashchainsigs_worker_t *wrkr,
    char *sd_buf, size_t sd_buf_len);

/*
 * Save chain state to a file for recovery on next startup.
 * Returns 1 if state was saved, 0 if nothing to save, -1 on error.
 */
int mmhashchainsigs_save_state(
    const mmhashchainsigs_worker_t *wrkr,
    const char *dir);

/*
 * Load saved chain state from a file. Caller must free() the result.
 * Returns the loaded state, or NULL if no state file or parse error.
 */
mmhashchainsigs_saved_state_t *mmhashchainsigs_load_state(
    const char *dir);

/* Remove the state file from the directory. */
void mmhashchainsigs_delete_state(const char *dir);

/*
 * Process one message through a restored chain from a previous
 * shutdown. Signs the message as the final entry of the old chain,
 * then reinitializes the worker for a fresh chain.
 * Returns SD length on success, -2 on key mismatch, -1 on error.
 */
int mmhashchainsigs_process_final(
    mmhashchainsigs_worker_t *wrkr,
    const mmhashchainsigs_saved_state_t *state,
    const char *payload, size_t payload_len,
    char *sd_buf, size_t sd_buf_len);

/* Free worker resources. */
void mmhashchainsigs_free(mmhashchainsigs_worker_t *wrkr);

#endif /* MMHASHCHAINSIGS_H */
