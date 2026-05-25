/*
 * hcs_format.h - SD record format for mmhashchainsigs
 *
 * Defines the RFC 5424 structured data element format that
 * mmhashchainsigs embeds in each log message.
 */
#ifndef HCS_FORMAT_H
#define HCS_FORMAT_H

#include "hcs_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define HCS_CHAIN_IV "MMHASHCHAINSIGS_CHAIN_INIT_V1"

/* Hex-encoded SHA-256 hash: 64 chars + NUL */
#define HCS_HEX_HASH_LEN (HCS_HASH_LEN * 2)

/* Base64-encoded Ed25519 signature (64 bytes -> 88 chars + NUL) */
#define HCS_B64_SIG_LEN 88

/*
 * Compute the well-known chain initialization hash:
 * SHA-256("MMHASHCHAINSIGS_CHAIN_INIT_V1")
 */
int hcs_chain_init_hash(unsigned char out[HCS_HASH_LEN]);

/* Utility: encode bytes to hex string (NUL-terminated) */
void hcs_hex_encode(
    const unsigned char *in, size_t in_len,
    char *out);

/* Utility: decode hex string to bytes. Returns 0 on success, -1 on error. */
int hcs_hex_decode(
    const char *in, size_t in_len,
    unsigned char *out, size_t out_len);

/*
 * Utility: base64 encode (standard alphabet, with padding).
 * out must be large enough. Returns length written, or -1 on error.
 */
int hcs_b64_encode(
    const unsigned char *in, size_t in_len,
    char *out, size_t out_len);

/*
 * Utility: base64 decode.
 * *out_len is set to decoded length. Returns 0 on success, -1 on error.
 */
int hcs_b64_decode(
    const char *in, size_t in_len,
    unsigned char *out, size_t *out_len);

/* ---- RFC 5424 structured data (SD) format ---- */

#define HCS_SD_ID      "mmhashchainsigs@32473"
#define HCS_SD_HDR_ID  "mmhashchainsigs-hdr@32473"
#define HCS_SD_MAX_LEN 384
/* Larger because escaped host/app/procid/msgid values can be long. */
#define HCS_SD_HDR_MAX_LEN 1024

typedef enum {
    HCS_SD_MSG      = 0,
    HCS_SD_INIT     = 'I',
    HCS_SD_SIG      = 'S',
    HCS_SD_CONTINUE = 'C'
} hcs_sd_type_t;

typedef struct {
    hcs_sd_type_t type;
    uint64_t seq;
    unsigned char chain_hash[HCS_HASH_LEN];
    unsigned char pubkey_fp[HCS_HASH_LEN];
    bool has_pubkey_fp;
    uint64_t seq_from;
    uint64_t seq_to;
    unsigned char signature[HCS_SIG_MAX_LEN];
    size_t sig_len;
    bool has_signature;
} hcs_sd_record_t;

/*
 * Format SD elements. buf must be HCS_SD_MAX_LEN bytes.
 * Returns bytes written (excluding NUL), or -1 on error.
 */
int hcs_format_sd_init(
    uint64_t seq,
    const unsigned char chain_hash[HCS_HASH_LEN],
    const unsigned char pubkey_fp[HCS_HASH_LEN],
    char *buf, size_t buf_len);

int hcs_format_sd_msg(
    uint64_t seq,
    const unsigned char chain_hash[HCS_HASH_LEN],
    char *buf, size_t buf_len);

int hcs_format_sd_sig(
    uint64_t seq,
    const unsigned char chain_hash[HCS_HASH_LEN],
    uint64_t seq_from, uint64_t seq_to,
    const unsigned char *signature, size_t sig_len,
    char *buf, size_t buf_len);

int hcs_format_sd_continue(
    uint64_t seq,
    const unsigned char chain_hash[HCS_HASH_LEN],
    const unsigned char pubkey_fp[HCS_HASH_LEN],
    char *buf, size_t buf_len);

/*
 * Format the header-capture SD element. Emits exactly six parameters,
 * always in this fixed order so the byte sequence is deterministic and
 * field presence cannot be toggled to forge hash collisions:
 *
 *   [mmhashchainsigs-hdr@32473 pri="N" ts="..." host="..." app="..."
 *                              procid="..." msgid="..."]
 *
 * String fields may be NULL or empty; the parameter is still emitted
 * with an empty quoted value. String values are RFC 5424 PARAM-VALUE
 * escaped (\, ", ] -> \\, \", \]).
 *
 * Returns bytes written (excluding NUL), or -1 on error (e.g. buffer
 * too small).
 */
int hcs_format_sd_hdr(
    unsigned int pri,
    const char *ts,
    const char *host,
    const char *app,
    const char *procid,
    const char *msgid,
    char *buf, size_t buf_len);

/*
 * Parse a [mmhashchainsigs@32473 ...] SD element into fields.
 * sd must point to the opening '[' and sd_len includes the closing ']'.
 * Returns 0 on success, -1 on error.
 */
int hcs_parse_sd(
    const char *sd, size_t sd_len,
    hcs_sd_record_t *out);

/*
 * Find and strip the [mmhashchainsigs@32473 ...] element from a log line.
 * Writes the line with the SD element removed to msg_buf.
 * Populates out with the parsed SD fields (out may be NULL).
 * Returns bytes written to msg_buf (excluding NUL), or -1 on error.
 */
int hcs_strip_sd_from_line(
    const char *line, size_t line_len,
    char *msg_buf, size_t msg_buf_len,
    hcs_sd_record_t *out);

/*
 * Remove every [<sd_id> ...] element from an SD-section string.
 * Used by mmhashchainsigs to discard any client-supplied element with
 * the same SD-ID as one mmhashchainsigs is about to add (collision
 * policy applies to both HCS_SD_ID and HCS_SD_HDR_ID).
 *
 * It is safe to pass the same buffer as src and out (in-place strip).
 * Writes the cleaned SD bytes to out (NUL-terminated).
 * If removed is non-NULL, *removed is set true when at least one
 * matching element was stripped.
 * Returns bytes written to out (excluding NUL), or -1 if out_cap is
 * too small.
 */
int hcs_strip_all_sd(
    const char *src, size_t src_len,
    const char *sd_id,
    char *out, size_t out_cap,
    bool *removed);

#endif /* HCS_FORMAT_H */
