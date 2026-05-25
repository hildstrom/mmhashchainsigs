/*
 * test_format.c - Unit tests for record format
 */
#include "hcs_crypto.h"
#include "hcs_format.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_hex_roundtrip(void)
{
    unsigned char data[] = {0x00, 0x01, 0xab, 0xcd, 0xff};
    char hex[11];
    unsigned char decoded[5];

    hcs_hex_encode(data, sizeof(data), hex);
    assert(strcmp(hex, "0001abcdff") == 0);

    assert(hcs_hex_decode(hex, strlen(hex),
                             decoded, sizeof(decoded)) == 0);
    assert(memcmp(data, decoded, sizeof(data)) == 0);

    printf("  PASS: test_hex_roundtrip\n");
}

static void test_b64_roundtrip(void)
{
    unsigned char data[64];
    for (int i = 0; i < 64; i++) {
        data[i] = (unsigned char)i;
    }

    char encoded[128];
    int enc_len = hcs_b64_encode(data, sizeof(data),
                                    encoded, sizeof(encoded));
    assert(enc_len > 0);

    unsigned char decoded[64];
    size_t dec_len;
    assert(hcs_b64_decode(encoded, (size_t)enc_len,
                             decoded, &dec_len) == 0);
    assert(dec_len == sizeof(data));
    assert(memcmp(data, decoded, sizeof(data)) == 0);

    printf("  PASS: test_b64_roundtrip\n");
}

static void test_sd_init_roundtrip(void)
{
    unsigned char hash[HCS_HASH_LEN];
    unsigned char fp[HCS_HASH_LEN];
    memset(hash, 0xaa, HCS_HASH_LEN);
    memset(fp, 0xbb, HCS_HASH_LEN);

    char buf[HCS_SD_MAX_LEN];
    int n = hcs_format_sd_init(1, hash, fp, buf, sizeof(buf));
    assert(n > 0);

    hcs_sd_record_t rec;
    assert(hcs_parse_sd(buf, (size_t)n, &rec) == 0);
    assert(rec.type == HCS_SD_INIT);
    assert(rec.seq == 1);
    assert(memcmp(rec.chain_hash, hash, HCS_HASH_LEN) == 0);
    assert(rec.has_pubkey_fp);
    assert(memcmp(rec.pubkey_fp, fp, HCS_HASH_LEN) == 0);
    assert(!rec.has_signature);

    printf("  PASS: test_sd_init_roundtrip\n");
}

static void test_sd_msg_roundtrip(void)
{
    unsigned char hash[HCS_HASH_LEN];
    memset(hash, 0xcc, HCS_HASH_LEN);

    char buf[HCS_SD_MAX_LEN];
    int n = hcs_format_sd_msg(42, hash, buf, sizeof(buf));
    assert(n > 0);

    hcs_sd_record_t rec;
    assert(hcs_parse_sd(buf, (size_t)n, &rec) == 0);
    assert(rec.type == HCS_SD_MSG);
    assert(rec.seq == 42);
    assert(memcmp(rec.chain_hash, hash, HCS_HASH_LEN) == 0);
    assert(!rec.has_pubkey_fp);
    assert(!rec.has_signature);

    printf("  PASS: test_sd_msg_roundtrip\n");
}

static void test_sd_sig_roundtrip(void)
{
    unsigned char hash[HCS_HASH_LEN];
    unsigned char sig[64];
    memset(hash, 0xdd, HCS_HASH_LEN);
    memset(sig, 0xee, sizeof(sig));

    char buf[HCS_SD_MAX_LEN];
    int n = hcs_format_sd_sig(
        1024, hash, 1, 1024, sig, sizeof(sig),
        buf, sizeof(buf));
    assert(n > 0);

    hcs_sd_record_t rec;
    assert(hcs_parse_sd(buf, (size_t)n, &rec) == 0);
    assert(rec.type == HCS_SD_SIG);
    assert(rec.seq == 1024);
    assert(memcmp(rec.chain_hash, hash, HCS_HASH_LEN) == 0);
    assert(rec.seq_from == 1);
    assert(rec.seq_to == 1024);
    assert(rec.has_signature);
    assert(rec.sig_len == sizeof(sig));
    assert(memcmp(rec.signature, sig, sizeof(sig)) == 0);

    printf("  PASS: test_sd_sig_roundtrip\n");
}

static void test_sd_continue_roundtrip(void)
{
    unsigned char hash[HCS_HASH_LEN];
    unsigned char fp[HCS_HASH_LEN];
    memset(hash, 0x33, HCS_HASH_LEN);
    memset(fp, 0x44, HCS_HASH_LEN);

    char buf[HCS_SD_MAX_LEN];
    int n = hcs_format_sd_continue(
        501, hash, fp, buf, sizeof(buf));
    assert(n > 0);

    hcs_sd_record_t rec;
    assert(hcs_parse_sd(buf, (size_t)n, &rec) == 0);
    assert(rec.type == HCS_SD_CONTINUE);
    assert(rec.seq == 501);
    assert(memcmp(rec.chain_hash, hash, HCS_HASH_LEN) == 0);
    assert(rec.has_pubkey_fp);
    assert(memcmp(rec.pubkey_fp, fp, HCS_HASH_LEN) == 0);

    printf("  PASS: test_sd_continue_roundtrip\n");
}

static void test_sd_strip(void)
{
    unsigned char hash[HCS_HASH_LEN];
    memset(hash, 0x55, HCS_HASH_LEN);

    char sd[HCS_SD_MAX_LEN];
    int sd_len = hcs_format_sd_msg(
        7, hash, sd, sizeof(sd));
    assert(sd_len > 0);

    /* Build a line: "prefix[sd element]suffix" */
    char line[1024];
    const char *before = "2024-01-15T10:30:00Z host1 app:";
    const char *after = "the log message";
    int line_len = snprintf(line, sizeof(line),
        "%s%s%s", before, sd, after);
    assert(line_len > 0);

    char msg[1024];
    hcs_sd_record_t rec;
    int msg_len = hcs_strip_sd_from_line(
        line, (size_t)line_len, msg, sizeof(msg), &rec);
    assert(msg_len > 0);

    /* Verify stripped message */
    char expected[1024];
    int exp_len = snprintf(expected, sizeof(expected),
        "%s%s", before, after);
    assert(msg_len == exp_len);
    assert(memcmp(msg, expected, (size_t)msg_len) == 0);

    /* Verify parsed fields */
    assert(rec.type == HCS_SD_MSG);
    assert(rec.seq == 7);
    assert(memcmp(rec.chain_hash, hash, HCS_HASH_LEN) == 0);

    printf("  PASS: test_sd_strip\n");
}

static void test_sd_parse_rejects_bad_input(void)
{
    hcs_sd_record_t rec;

    assert(hcs_parse_sd("", 0, &rec) != 0);
    assert(hcs_parse_sd("[other@123 q=\"1\"]",
                                  17, &rec) != 0);
    assert(hcs_parse_sd("[mmhashchainsigs@32473 ]",
                                  15, &rec) != 0);

    printf("  PASS: test_sd_parse_rejects_bad_input\n");
}

static void test_strip_all_empty(void)
{
    char out[64];
    bool removed = true;
    int n = hcs_strip_all_sd("", 0, HCS_SD_ID,
                             out, sizeof(out), &removed);
    assert(n == 0);
    assert(!removed);
    assert(out[0] == '\0');

    printf("  PASS: test_strip_all_empty\n");
}

static void test_strip_all_no_self(void)
{
    const char *src = "[client@9999 trace=\"abc\"][other@123 k=\"v\"]";
    char out[128];
    bool removed = true;
    int n = hcs_strip_all_sd(
        src, strlen(src), HCS_SD_ID, out, sizeof(out), &removed);
    assert(n == (int)strlen(src));
    assert(memcmp(out, src, (size_t)n) == 0);
    assert(!removed);

    printf("  PASS: test_strip_all_no_self\n");
}

static void test_strip_all_single_self(void)
{
    const char *src =
        "[mmhashchainsigs@32473 t=\"I\" q=\"1\" h=\"00\" f=\"00\"]"
        "[client@9999 trace=\"abc\"]";
    char out[128];
    bool removed = false;
    int n = hcs_strip_all_sd(
        src, strlen(src), HCS_SD_ID, out, sizeof(out), &removed);
    assert(n > 0);
    assert(removed);
    assert(strcmp(out, "[client@9999 trace=\"abc\"]") == 0);

    printf("  PASS: test_strip_all_single_self\n");
}

static void test_strip_all_multiple_self(void)
{
    /* Pathological but legal-shape input: two mmhashchainsigs elements
     * surrounding a client element. All mmhashchainsigs elements should go. */
    const char *src =
        "[mmhashchainsigs@32473 q=\"1\" h=\"00\"]"
        "[client@9999 k=\"v\"]"
        "[mmhashchainsigs@32473 q=\"2\" h=\"11\"]";
    char out[256];
    bool removed = false;
    int n = hcs_strip_all_sd(
        src, strlen(src), HCS_SD_ID, out, sizeof(out), &removed);
    assert(n > 0);
    assert(removed);
    assert(strcmp(out, "[client@9999 k=\"v\"]") == 0);

    printf("  PASS: test_strip_all_multiple_self\n");
}

static void test_strip_all_handles_quoted_brackets(void)
{
    /* A quoted value containing `]` must not end the element early. */
    const char *src =
        "[mmhashchainsigs@32473 q=\"1\" h=\"a]b\" f=\"00\"]"
        "[client@9999 k=\"v\"]";
    char out[128];
    bool removed = false;
    int n = hcs_strip_all_sd(
        src, strlen(src), HCS_SD_ID, out, sizeof(out), &removed);
    assert(n > 0);
    assert(removed);
    assert(strcmp(out, "[client@9999 k=\"v\"]") == 0);

    printf("  PASS: test_strip_all_handles_quoted_brackets\n");
}

static void test_strip_all_out_too_small(void)
{
    const char *src = "[client@9999 trace=\"abc\"]";
    char out[8];
    int n = hcs_strip_all_sd(
        src, strlen(src), HCS_SD_ID, out, sizeof(out), NULL);
    assert(n < 0);

    printf("  PASS: test_strip_all_out_too_small\n");
}

static void test_strip_all_hdr_id(void)
{
    /* The same helper used with HCS_SD_HDR_ID strips the hdr element
     * but leaves the (also-present) siglog element untouched. */
    const char *src =
        "[mmhashchainsigs@32473 q=\"1\" h=\"00\"]"
        "[mmhashchainsigs-hdr@32473 pri=\"13\" ts=\"-\" host=\"\""
        " app=\"\" procid=\"\" msgid=\"-\"]"
        "[client@9999 k=\"v\"]";
    char out[512];
    bool removed = false;
    int n = hcs_strip_all_sd(
        src, strlen(src), HCS_SD_HDR_ID,
        out, sizeof(out), &removed);
    assert(n > 0);
    assert(removed);
    assert(strcmp(out,
        "[mmhashchainsigs@32473 q=\"1\" h=\"00\"]"
        "[client@9999 k=\"v\"]") == 0);

    printf("  PASS: test_strip_all_hdr_id\n");
}

static void test_strip_all_in_place(void)
{
    /* Documented: same buffer for src and out must work. */
    char buf[256] =
        "[mmhashchainsigs@32473 q=\"1\" h=\"00\"]"
        "[client@9999 k=\"v\"]";
    size_t orig_len = strlen(buf);
    int n = hcs_strip_all_sd(
        buf, orig_len, HCS_SD_ID, buf, sizeof(buf), NULL);
    assert(n > 0);
    assert(strcmp(buf, "[client@9999 k=\"v\"]") == 0);

    printf("  PASS: test_strip_all_in_place\n");
}

static void test_format_sd_hdr_basic(void)
{
    char buf[HCS_SD_HDR_MAX_LEN];
    int n = hcs_format_sd_hdr(
        13, "2026-05-25T12:00:00Z", "myhost",
        "myapp", "1234", "MSGID42",
        buf, sizeof(buf));
    assert(n > 0);
    assert(strcmp(buf,
        "[mmhashchainsigs-hdr@32473 pri=\"13\""
        " ts=\"2026-05-25T12:00:00Z\""
        " host=\"myhost\" app=\"myapp\""
        " procid=\"1234\" msgid=\"MSGID42\"]") == 0);

    printf("  PASS: test_format_sd_hdr_basic\n");
}

static void test_format_sd_hdr_empty_fields(void)
{
    /* NULL and empty must both produce an empty quoted value so field
     * presence cannot be toggled to forge hash collisions. */
    char buf_nulls[HCS_SD_HDR_MAX_LEN];
    char buf_empties[HCS_SD_HDR_MAX_LEN];

    int n1 = hcs_format_sd_hdr(
        0, NULL, NULL, NULL, NULL, NULL,
        buf_nulls, sizeof(buf_nulls));
    int n2 = hcs_format_sd_hdr(
        0, "", "", "", "", "",
        buf_empties, sizeof(buf_empties));
    assert(n1 > 0);
    assert(n1 == n2);
    assert(memcmp(buf_nulls, buf_empties, (size_t)n1) == 0);

    printf("  PASS: test_format_sd_hdr_empty_fields\n");
}

static void test_format_sd_hdr_escaping(void)
{
    /* RFC 5424 §6.3.3: ", \, ] must be escaped with \ inside
     * PARAM-VALUE. Host string deliberately contains all three. */
    char buf[HCS_SD_HDR_MAX_LEN];
    int n = hcs_format_sd_hdr(
        13, "2026-05-25T12:00:00Z",
        "ho\"st]back\\slash",
        "ap\"p", "1234", "ms]gid",
        buf, sizeof(buf));
    assert(n > 0);
    /* Expected literal output (single backslash before each special) */
    const char *expected =
        "[mmhashchainsigs-hdr@32473 pri=\"13\""
        " ts=\"2026-05-25T12:00:00Z\""
        " host=\"ho\\\"st\\]back\\\\slash\""
        " app=\"ap\\\"p\""
        " procid=\"1234\""
        " msgid=\"ms\\]gid\"]";
    assert(strcmp(buf, expected) == 0);

    printf("  PASS: test_format_sd_hdr_escaping\n");
}

static void test_format_sd_hdr_buf_too_small(void)
{
    char tiny[16];
    int n = hcs_format_sd_hdr(
        13, "2026-05-25T12:00:00Z", "h", "a", "p", "m",
        tiny, sizeof(tiny));
    assert(n < 0);

    printf("  PASS: test_format_sd_hdr_buf_too_small\n");
}

int main(void)
{
    printf("test_format:\n");
    test_hex_roundtrip();
    test_b64_roundtrip();
    test_sd_init_roundtrip();
    test_sd_msg_roundtrip();
    test_sd_sig_roundtrip();
    test_sd_continue_roundtrip();
    test_sd_strip();
    test_sd_parse_rejects_bad_input();
    test_strip_all_empty();
    test_strip_all_no_self();
    test_strip_all_single_self();
    test_strip_all_multiple_self();
    test_strip_all_handles_quoted_brackets();
    test_strip_all_out_too_small();
    test_strip_all_hdr_id();
    test_strip_all_in_place();
    test_format_sd_hdr_basic();
    test_format_sd_hdr_empty_fields();
    test_format_sd_hdr_escaping();
    test_format_sd_hdr_buf_too_small();
    printf("All format tests passed.\n");
    return 0;
}
