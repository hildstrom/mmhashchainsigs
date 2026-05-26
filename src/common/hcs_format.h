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

/* Hex-encoded SHA-256 (fingerprint) length: 64 chars. */
#define HCS_HEX_HASH_LEN (HCS_HASH_LEN * 2)
/* Hex-encoded chain hash, sized for the larger of SHA-256/SHA-512. */
#define HCS_HEX_HASH_MAX_LEN (HCS_HASH_MAX_LEN * 2)

/* Base64-encoded signature, sized to cover HCS_SIG_MAX_LEN (144 bytes):
 *   Ed25519 (64B)      -> 88  chars
 *   ECDSA P-256 (72B)  -> 96  chars
 *   ECDSA P-384 (104B) -> 140 chars
 *   ECDSA P-521 (139B) -> 188 chars
 *   ceil(144 / 3) * 4  = 192 chars
 * Round up for safety. */
#define HCS_B64_SIG_LEN 200

/*
 * Compute the well-known chain initialization hash for the given
 * algorithm: H_alg("MMHASHCHAINSIGS_CHAIN_INIT_V1").
 * `out` must be at least hcs_hash_len(alg) bytes.
 * Returns 0 on success, -1 on error.
 */
int hcs_chain_init_hash(hcs_hash_alg_t alg, unsigned char *out);

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
#define HCS_SD_CERT_ID "mmhashchainsigs-cert@32473"
/* Worst case is the SIG element with a SHA-512 chain hash (128 hex)
 * and an ECDSA P-521 base64 signature (~192 chars). */
#define HCS_SD_MAX_LEN 512
/* Larger because escaped host/app/procid/msgid values can be long. */
#define HCS_SD_HDR_MAX_LEN 1024
/* Sized to hold base64 of a CA-issued cert (~1500 bytes DER -> ~2000 b64). */
#define HCS_SD_CERT_MAX_LEN 3072
/* Total output SD buffer for the chain-metadata + optional cert SD. */
#define HCS_SD_WITH_CERT_MAX_LEN (HCS_SD_MAX_LEN + HCS_SD_CERT_MAX_LEN)
/* Max DER cert size we will accept. */
#define HCS_CERT_DER_MAX 4096

typedef enum {
    HCS_SD_MSG      = 0,
    HCS_SD_INIT     = 'I',
    HCS_SD_SIG      = 'S',
    HCS_SD_CONTINUE = 'C'
} hcs_sd_type_t;

typedef struct {
    hcs_sd_type_t type;
    uint64_t seq;
    unsigned char chain_hash[HCS_HASH_MAX_LEN];
    size_t chain_hash_len;   /* set by hcs_parse_sd from h= hex width */
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
 * `chain_hash` is `chain_hash_len` bytes (32 for SHA-256, 64 for SHA-512).
 * `pubkey_fp` is always HCS_HASH_LEN (32) bytes.
 * Returns bytes written (excluding NUL), or -1 on error.
 */
int hcs_format_sd_init(
    uint64_t seq,
    const unsigned char *chain_hash, size_t chain_hash_len,
    const unsigned char pubkey_fp[HCS_HASH_LEN],
    char *buf, size_t buf_len);

int hcs_format_sd_msg(
    uint64_t seq,
    const unsigned char *chain_hash, size_t chain_hash_len,
    char *buf, size_t buf_len);

int hcs_format_sd_sig(
    uint64_t seq,
    const unsigned char *chain_hash, size_t chain_hash_len,
    uint64_t seq_from, uint64_t seq_to,
    const unsigned char *signature, size_t sig_len,
    char *buf, size_t buf_len);

int hcs_format_sd_continue(
    uint64_t seq,
    const unsigned char *chain_hash, size_t chain_hash_len,
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
/*
 * Format the certificate-carrying SD element:
 *   [mmhashchainsigs-cert@32473 cert="<base64 DER>"]
 * Emitted by the signer on INIT (and CONTINUE) messages when embedcert
 * is enabled, so verifiers in CA-bundle mode can chain-validate the
 * signer's certificate without out-of-band distribution.
 * Returns bytes written (excluding NUL), or -1 on error.
 */
int hcs_format_sd_cert(
    const unsigned char *der, size_t der_len,
    char *buf, size_t buf_len);

/*
 * Locate and strip the [mmhashchainsigs-cert@32473 cert="..."] element
 * from a string in-place, decoding its DER payload to der_out.
 * On entry, *der_len is the capacity of der_out.
 * On success, *der_len is set to the decoded DER length.
 *
 * Returns:
 *    1 if a cert SD was found and stripped (der_out populated)
 *    0 if no cert SD was present (msg_buf unchanged, *der_len = 0)
 *   -1 on parse/decode error or insufficient buffer
 *
 * It is safe to pass the same buffer as src and msg_buf (in-place strip).
 */
int hcs_extract_and_strip_cert_sd(
    const char *src, size_t src_len,
    char *msg_buf, size_t msg_buf_cap,
    int *msg_len_out,
    unsigned char *der_out, size_t *der_len);

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
