/*
 * hcs_format.c - SD record format for mmhashchainsigs
 */
#include "hcs_format.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hcs_chain_init_hash(unsigned char out[HCS_HASH_LEN])
{
    return hcs_sha256(
        HCS_CHAIN_IV, strlen(HCS_CHAIN_IV), out);
}

void hcs_hex_encode(
    const unsigned char *in, size_t in_len,
    char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[in_len * 2] = '\0';
}

int hcs_hex_decode(
    const char *in, size_t in_len,
    unsigned char *out, size_t out_len)
{
    if (in_len % 2 != 0 || in_len / 2 > out_len) {
        return -1;
    }

    for (size_t i = 0; i < in_len / 2; i++) {
        unsigned int byte;
        if (sscanf(&in[i * 2], "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (unsigned char)byte;
    }
    return 0;
}

int hcs_b64_encode(
    const unsigned char *in, size_t in_len,
    char *out, size_t out_len)
{
    int encoded_len = EVP_EncodeBlock(
        (unsigned char *)out, in, (int)in_len);
    if (encoded_len < 0 || (size_t)encoded_len >= out_len) {
        return -1;
    }
    out[encoded_len] = '\0';
    return encoded_len;
}

int hcs_b64_decode(
    const char *in, size_t in_len,
    unsigned char *out, size_t *out_len)
{
    /* Strip trailing '=' padding for length calculation */
    int pad = 0;
    if (in_len > 0 && in[in_len - 1] == '=') { pad++; }
    if (in_len > 1 && in[in_len - 2] == '=') { pad++; }

    int decoded_len = EVP_DecodeBlock(
        out, (const unsigned char *)in, (int)in_len);
    if (decoded_len < 0) {
        return -1;
    }
    /* EVP_DecodeBlock doesn't account for padding */
    decoded_len -= pad;
    *out_len = (size_t)decoded_len;
    return 0;
}

/* ---- RFC 5424 structured data (SD) format ---- */

int hcs_format_sd_init(
    uint64_t seq,
    const unsigned char chain_hash[HCS_HASH_LEN],
    const unsigned char pubkey_fp[HCS_HASH_LEN],
    char *buf, size_t buf_len)
{
    char h[HCS_HEX_HASH_LEN + 1];
    char f[HCS_HEX_HASH_LEN + 1];
    hcs_hex_encode(chain_hash, HCS_HASH_LEN, h);
    hcs_hex_encode(pubkey_fp, HCS_HASH_LEN, f);
    int n = snprintf(buf, buf_len,
        "[%s t=\"I\" q=\"%lu\" h=\"%s\" f=\"%s\"]",
        HCS_SD_ID, (unsigned long)seq, h, f);
    if (n < 0 || (size_t)n >= buf_len) return -1;
    return n;
}

int hcs_format_sd_msg(
    uint64_t seq,
    const unsigned char chain_hash[HCS_HASH_LEN],
    char *buf, size_t buf_len)
{
    char h[HCS_HEX_HASH_LEN + 1];
    hcs_hex_encode(chain_hash, HCS_HASH_LEN, h);
    int n = snprintf(buf, buf_len,
        "[%s q=\"%lu\" h=\"%s\"]",
        HCS_SD_ID, (unsigned long)seq, h);
    if (n < 0 || (size_t)n >= buf_len) return -1;
    return n;
}

int hcs_format_sd_sig(
    uint64_t seq,
    const unsigned char chain_hash[HCS_HASH_LEN],
    uint64_t seq_from, uint64_t seq_to,
    const unsigned char *signature, size_t sig_len,
    char *buf, size_t buf_len)
{
    char h[HCS_HEX_HASH_LEN + 1];
    char s[HCS_B64_SIG_LEN + 4];
    hcs_hex_encode(chain_hash, HCS_HASH_LEN, h);
    if (hcs_b64_encode(signature, sig_len, s, sizeof(s)) < 0) {
        return -1;
    }
    int n = snprintf(buf, buf_len,
        "[%s t=\"S\" q=\"%lu\" h=\"%s\""
        " qf=\"%lu\" qt=\"%lu\" s=\"%s\"]",
        HCS_SD_ID, (unsigned long)seq, h,
        (unsigned long)seq_from, (unsigned long)seq_to, s);
    if (n < 0 || (size_t)n >= buf_len) return -1;
    return n;
}

int hcs_format_sd_cert(
    const unsigned char *der, size_t der_len,
    char *buf, size_t buf_len)
{
    if (der_len > HCS_CERT_DER_MAX) return -1;

    /* Worst-case b64 size for HCS_CERT_DER_MAX: ceil(4096/3)*4 = 5464.
     * We allocate dynamically rather than on the stack so the size is
     * proportional to der_len. */
    size_t b64_cap = ((der_len + 2) / 3) * 4 + 4;
    char *b64 = malloc(b64_cap);
    if (!b64) return -1;
    if (hcs_b64_encode(der, der_len, b64, b64_cap) < 0) {
        free(b64);
        return -1;
    }
    int n = snprintf(buf, buf_len,
        "[%s cert=\"%s\"]", HCS_SD_CERT_ID, b64);
    free(b64);
    if (n < 0 || (size_t)n >= buf_len) return -1;
    return n;
}

int hcs_extract_and_strip_cert_sd(
    const char *src, size_t src_len,
    char *msg_buf, size_t msg_buf_cap,
    int *msg_len_out,
    unsigned char *der_out, size_t *der_len)
{
    char prefix[64];
    int plen_signed = snprintf(
        prefix, sizeof(prefix), "[%s ", HCS_SD_CERT_ID);
    if (plen_signed < 0 || (size_t)plen_signed >= sizeof(prefix)) {
        return -1;
    }
    size_t plen = (size_t)plen_signed;

    const char *sd_start = NULL;
    for (size_t i = 0; i + plen <= src_len; i++) {
        if (memcmp(src + i, prefix, plen) == 0) {
            sd_start = src + i;
            break;
        }
    }
    if (!sd_start) {
        /* No cert SD: copy through. */
        if (src_len >= msg_buf_cap) return -1;
        if (src != msg_buf) {
            memmove(msg_buf, src, src_len);
        }
        msg_buf[src_len] = '\0';
        *msg_len_out = (int)src_len;
        *der_len = 0;
        return 0;
    }

    /* Find the cert="..." value. */
    const char *p = sd_start + plen;
    const char *end = src + src_len;

    static const char key[] = "cert=\"";
    size_t klen = sizeof(key) - 1;
    if (p + klen >= end || memcmp(p, key, klen) != 0) {
        return -1;
    }
    const char *vstart = p + klen;
    const char *vend = vstart;
    while (vend < end && *vend != '"') {
        if (*vend == '\\' && vend + 1 < end) vend++;
        vend++;
    }
    if (vend >= end || vend[0] != '"' || vend + 1 >= end || vend[1] != ']') {
        return -1;
    }

    size_t b64_len = (size_t)(vend - vstart);
    size_t cert_sd_len = (size_t)((vend + 2) - sd_start);

    /* Decode DER. */
    size_t der_cap = *der_len;
    *der_len = der_cap;
    if (hcs_b64_decode(vstart, b64_len, der_out, der_len) != 0) {
        return -1;
    }

    /* Strip the cert SD from src into msg_buf (handle in-place). */
    size_t before = (size_t)(sd_start - src);
    size_t after = src_len - before - cert_sd_len;
    size_t total = before + after;
    if (total >= msg_buf_cap) return -1;

    if (msg_buf != src) {
        memcpy(msg_buf, src, before);
        memcpy(msg_buf + before, sd_start + cert_sd_len, after);
    } else {
        /* In-place: shift the tail down. */
        memmove(msg_buf + before, sd_start + cert_sd_len, after);
    }
    msg_buf[total] = '\0';
    *msg_len_out = (int)total;
    return 1;
}

int hcs_format_sd_continue(
    uint64_t seq,
    const unsigned char chain_hash[HCS_HASH_LEN],
    const unsigned char pubkey_fp[HCS_HASH_LEN],
    char *buf, size_t buf_len)
{
    char h[HCS_HEX_HASH_LEN + 1];
    char f[HCS_HEX_HASH_LEN + 1];
    hcs_hex_encode(chain_hash, HCS_HASH_LEN, h);
    hcs_hex_encode(pubkey_fp, HCS_HASH_LEN, f);
    int n = snprintf(buf, buf_len,
        "[%s t=\"C\" q=\"%lu\" h=\"%s\" f=\"%s\"]",
        HCS_SD_ID, (unsigned long)seq, h, f);
    if (n < 0 || (size_t)n >= buf_len) return -1;
    return n;
}

/*
 * RFC 5424 §6.3.3 PARAM-VALUE escaping: `"`, `\`, `]` MUST be escaped
 * with a leading `\`. Writes the escaped value (NUL-terminated) to
 * `out`. Returns escaped length, or -1 if out_cap is too small.
 */
static int sd_escape_param(
    const char *in, size_t in_len,
    char *out, size_t out_cap)
{
    size_t j = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\\' || c == '"' || c == ']') {
            if (j + 2 >= out_cap) return -1;
            out[j++] = '\\';
            out[j++] = (char)c;
        } else {
            if (j + 1 >= out_cap) return -1;
            out[j++] = (char)c;
        }
    }
    if (j >= out_cap) return -1;
    out[j] = '\0';
    return (int)j;
}

int hcs_format_sd_hdr(
    unsigned int pri,
    const char *ts,
    const char *host,
    const char *app,
    const char *procid,
    const char *msgid,
    char *buf, size_t buf_len)
{
    /* Worst-case escaped buffer per field: 2 * raw length + NUL.
     * These sizes accommodate typical syslog field maxima. */
    char ts_e[80];
    char host_e[520];
    char app_e[136];
    char procid_e[136];
    char msgid_e[136];

    const char *ts_in     = ts     ? ts     : "";
    const char *host_in   = host   ? host   : "";
    const char *app_in    = app    ? app    : "";
    const char *procid_in = procid ? procid : "";
    const char *msgid_in  = msgid  ? msgid  : "";

    if (sd_escape_param(ts_in, strlen(ts_in),
                        ts_e, sizeof(ts_e)) < 0) return -1;
    if (sd_escape_param(host_in, strlen(host_in),
                        host_e, sizeof(host_e)) < 0) return -1;
    if (sd_escape_param(app_in, strlen(app_in),
                        app_e, sizeof(app_e)) < 0) return -1;
    if (sd_escape_param(procid_in, strlen(procid_in),
                        procid_e, sizeof(procid_e)) < 0) return -1;
    if (sd_escape_param(msgid_in, strlen(msgid_in),
                        msgid_e, sizeof(msgid_e)) < 0) return -1;

    int n = snprintf(buf, buf_len,
        "[%s pri=\"%u\" ts=\"%s\" host=\"%s\" app=\"%s\""
        " procid=\"%s\" msgid=\"%s\"]",
        HCS_SD_HDR_ID, pri, ts_e, host_e, app_e, procid_e, msgid_e);
    if (n < 0 || (size_t)n >= buf_len) return -1;
    return n;
}

static const char *sd_get_param(
    const char *body, const char *end,
    const char *key, size_t *vlen)
{
    size_t klen = strlen(key);
    const char *p = body;

    while (p + klen + 2 <= end) {
        bool at_start = (p == body);
        bool after_space = (p > body && p[-1] == ' ');

        if ((at_start || after_space) &&
            memcmp(p, key, klen) == 0 &&
            p[klen] == '=' && p[klen + 1] == '"') {
            const char *vstart = p + klen + 2;
            const char *vend = vstart;
            while (vend < end && *vend != '"') {
                if (*vend == '\\' && vend + 1 < end) vend++;
                vend++;
            }
            if (vend >= end) return NULL;
            *vlen = (size_t)(vend - vstart);
            return vstart;
        }
        p++;
    }
    return NULL;
}

static int sd_extract_hex(
    const char *body, const char *end, const char *key,
    unsigned char *out, size_t out_len)
{
    size_t vlen;
    const char *v = sd_get_param(body, end, key, &vlen);
    if (!v || vlen != out_len * 2) return -1;
    char hex[HCS_HEX_HASH_LEN + 1];
    if (vlen >= sizeof(hex)) return -1;
    memcpy(hex, v, vlen);
    hex[vlen] = '\0';
    return hcs_hex_decode(hex, vlen, out, out_len);
}

static int sd_extract_uint64(
    const char *body, const char *end, const char *key,
    uint64_t *out)
{
    size_t vlen;
    const char *v = sd_get_param(body, end, key, &vlen);
    if (!v || vlen == 0 || vlen > 20) return -1;
    char tmp[24];
    memcpy(tmp, v, vlen);
    tmp[vlen] = '\0';
    char *endptr;
    *out = strtoull(tmp, &endptr, 10);
    if (*endptr != '\0') return -1;
    return 0;
}

int hcs_parse_sd(
    const char *sd, size_t sd_len,
    hcs_sd_record_t *out)
{
    memset(out, 0, sizeof(*out));

    const char *prefix = "[" HCS_SD_ID " ";
    size_t plen = strlen(prefix);
    if (sd_len < plen + 1 ||
        memcmp(sd, prefix, plen) != 0 ||
        sd[sd_len - 1] != ']') {
        return -1;
    }

    const char *body = sd + plen;
    const char *end = sd + sd_len - 1;

    size_t vlen;
    const char *v = sd_get_param(body, end, "t", &vlen);
    if (v && vlen == 1) {
        out->type = (hcs_sd_type_t)v[0];
    }

    if (sd_extract_uint64(body, end, "q", &out->seq) != 0) {
        return -1;
    }
    if (sd_extract_hex(body, end, "h",
                       out->chain_hash, HCS_HASH_LEN) != 0) {
        return -1;
    }

    if (sd_extract_hex(body, end, "f",
                       out->pubkey_fp, HCS_HASH_LEN) == 0) {
        out->has_pubkey_fp = true;
    }

    sd_extract_uint64(body, end, "qf", &out->seq_from);
    sd_extract_uint64(body, end, "qt", &out->seq_to);

    v = sd_get_param(body, end, "s", &vlen);
    if (v) {
        char b64[HCS_B64_SIG_LEN + 4];
        if (vlen >= sizeof(b64)) return -1;
        memcpy(b64, v, vlen);
        b64[vlen] = '\0';
        out->sig_len = sizeof(out->signature);
        if (hcs_b64_decode(b64, vlen,
                              out->signature, &out->sig_len) != 0) {
            return -1;
        }
        out->has_signature = true;
    }

    return 0;
}

/*
 * Advance p past one SD element starting with `[`, handling quoted
 * PARAM-VALUE strings (\" escapes). Returns a pointer to the byte
 * right after the closing `]`, or end if the element is unterminated.
 */
static const char *sd_scan_element(const char *p, const char *end)
{
    /* caller has already consumed the opening `[` and prefix */
    while (p < end) {
        if (*p == '"') {
            p++;
            while (p < end && *p != '"') {
                if (*p == '\\' && p + 1 < end) p++;
                p++;
            }
        }
        if (p < end && *p == ']') {
            return p + 1;
        }
        if (p < end) p++;
    }
    return end;
}

int hcs_strip_all_sd(
    const char *src, size_t src_len,
    const char *sd_id,
    char *out, size_t out_cap,
    bool *removed)
{
    /* Build the element prefix "[<sd_id> " on the stack. We allow up
     * to ~64 chars of SD-ID, which fits any SD-ID we issue. */
    char prefix[80];
    int plen_signed = snprintf(prefix, sizeof(prefix), "[%s ", sd_id);
    if (plen_signed < 0 || (size_t)plen_signed >= sizeof(prefix)) {
        return -1;
    }
    size_t plen = (size_t)plen_signed;

    size_t i = 0;
    size_t j = 0;
    bool any = false;

    while (i < src_len) {
        if (i + plen <= src_len
            && memcmp(src + i, prefix, plen) == 0) {
            const char *p = src + i + plen;
            const char *end = src + src_len;
            const char *after = sd_scan_element(p, end);
            i = (size_t)(after - src);
            any = true;
            continue;
        }
        if (j + 1 >= out_cap) return -1;
        out[j++] = src[i++];
    }
    if (j >= out_cap) return -1;
    out[j] = '\0';
    if (removed) *removed = any;
    return (int)j;
}

int hcs_strip_sd_from_line(
    const char *line, size_t line_len,
    char *msg_buf, size_t msg_buf_len,
    hcs_sd_record_t *out)
{
    const char *prefix = "[" HCS_SD_ID " ";
    size_t plen = strlen(prefix);

    const char *sd_start = NULL;
    for (size_t i = 0; i + plen <= line_len; i++) {
        if (memcmp(line + i, prefix, plen) == 0) {
            sd_start = line + i;
            break;
        }
    }
    if (!sd_start) return -1;

    const char *p = sd_start + plen;
    const char *line_end = line + line_len;
    while (p < line_end) {
        if (*p == '"') {
            p++;
            while (p < line_end && *p != '"') {
                if (*p == '\\' && p + 1 < line_end) p++;
                p++;
            }
        }
        if (p < line_end && *p == ']') {
            p++;
            break;
        }
        p++;
    }

    size_t sd_len = (size_t)(p - sd_start);
    if (out && hcs_parse_sd(sd_start, sd_len, out) != 0) {
        return -1;
    }

    size_t before = (size_t)(sd_start - line);
    size_t after = line_len - before - sd_len;
    size_t total = before + after;
    if (total >= msg_buf_len) return -1;

    memcpy(msg_buf, line, before);
    memcpy(msg_buf + before, p, after);
    msg_buf[total] = '\0';
    return (int)total;
}
