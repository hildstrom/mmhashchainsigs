/*
 * test_hashchain.c - Unit tests for hash chain
 *
 * Each test runs against both SHA-256 (default) and SHA-512 to make
 * sure algorithm dispatch through hashchain_ctx_t works end to end.
 */
#include "hashchain.h"
#include "hcs_crypto.h"
#include "hcs_format.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_init_for(hcs_hash_alg_t alg)
{
    hashchain_ctx_t ctx;
    assert(hashchain_init(&ctx, alg) == 0);
    size_t hlen = hcs_hash_len(alg);
    assert(ctx.hash_len == hlen);

    unsigned char expected_iv[HCS_HASH_MAX_LEN];
    assert(hcs_chain_init_hash(alg, expected_iv) == 0);

    assert(memcmp(hashchain_get_current(&ctx), expected_iv, hlen) == 0);
    assert(ctx.seq == 1);
    assert(ctx.msg_count == 0);

    printf("  PASS: test_init[%s]\n", hcs_hash_name(alg));
}

static void test_update_for(hcs_hash_alg_t alg)
{
    hashchain_ctx_t ctx;
    assert(hashchain_init(&ctx, alg) == 0);
    size_t hlen = ctx.hash_len;

    const char *msg = "test message";
    unsigned char before[HCS_HASH_MAX_LEN];
    memcpy(before, hashchain_get_current(&ctx), hlen);

    assert(hashchain_update(&ctx, msg, strlen(msg)) == 0);

    assert(memcmp(hashchain_get_current(&ctx), before, hlen) != 0);
    assert(ctx.seq == 2);
    assert(ctx.msg_count == 1);

    unsigned char manual[HCS_HASH_MAX_LEN];
    assert(hcs_hash_chain(alg, before, 1, msg, strlen(msg), manual) == 0);
    assert(memcmp(hashchain_get_current(&ctx), manual, hlen) == 0);

    printf("  PASS: test_update[%s]\n", hcs_hash_name(alg));
}

static void test_chain_determinism_for(hcs_hash_alg_t alg)
{
    hashchain_ctx_t a, b;
    assert(hashchain_init(&a, alg) == 0);
    assert(hashchain_init(&b, alg) == 0);
    size_t hlen = a.hash_len;

    const char *msgs[] = {"hello", "world", "foo"};
    for (int i = 0; i < 3; i++) {
        assert(hashchain_update(&a, msgs[i], strlen(msgs[i])) == 0);
        assert(hashchain_update(&b, msgs[i], strlen(msgs[i])) == 0);
    }

    assert(memcmp(hashchain_get_current(&a),
                  hashchain_get_current(&b), hlen) == 0);

    printf("  PASS: test_chain_determinism[%s]\n", hcs_hash_name(alg));
}

static void test_chain_ordering_matters_for(hcs_hash_alg_t alg)
{
    hashchain_ctx_t a, b;
    assert(hashchain_init(&a, alg) == 0);
    assert(hashchain_init(&b, alg) == 0);
    size_t hlen = a.hash_len;

    assert(hashchain_update(&a, "hello", 5) == 0);
    assert(hashchain_update(&a, "world", 5) == 0);
    assert(hashchain_update(&b, "world", 5) == 0);
    assert(hashchain_update(&b, "hello", 5) == 0);

    assert(memcmp(hashchain_get_current(&a),
                  hashchain_get_current(&b), hlen) != 0);

    printf("  PASS: test_chain_ordering_matters[%s]\n", hcs_hash_name(alg));
}

static void test_reset_count_for(hcs_hash_alg_t alg)
{
    hashchain_ctx_t ctx;
    assert(hashchain_init(&ctx, alg) == 0);
    size_t hlen = ctx.hash_len;
    assert(hashchain_update(&ctx, "msg", 3) == 0);
    assert(ctx.msg_count == 1);

    unsigned char hash_before[HCS_HASH_MAX_LEN];
    memcpy(hash_before, hashchain_get_current(&ctx), hlen);
    uint64_t seq_before = ctx.seq;

    hashchain_reset_count(&ctx);
    assert(ctx.msg_count == 0);

    assert(memcmp(hashchain_get_current(&ctx), hash_before, hlen) == 0);
    assert(ctx.seq == seq_before);

    printf("  PASS: test_reset_count[%s]\n", hcs_hash_name(alg));
}

static void test_full_reset_for(hcs_hash_alg_t alg)
{
    hashchain_ctx_t ctx;
    assert(hashchain_init(&ctx, alg) == 0);
    size_t hlen = ctx.hash_len;
    assert(hashchain_update(&ctx, "msg", 3) == 0);
    assert(hashchain_update(&ctx, "msg2", 4) == 0);

    assert(hashchain_reset(&ctx) == 0);
    assert(ctx.seq == 1);
    assert(ctx.msg_count == 0);

    unsigned char expected_iv[HCS_HASH_MAX_LEN];
    assert(hcs_chain_init_hash(alg, expected_iv) == 0);
    assert(memcmp(hashchain_get_current(&ctx), expected_iv, hlen) == 0);

    printf("  PASS: test_full_reset[%s]\n", hcs_hash_name(alg));
}

/* SHA-256 and SHA-512 over the same message must produce hashes of
 * different lengths and content. */
static void test_alg_distinguishes_chains(void)
{
    hashchain_ctx_t a, b;
    assert(hashchain_init(&a, HCS_HASH_SHA256) == 0);
    assert(hashchain_init(&b, HCS_HASH_SHA512) == 0);
    assert(a.hash_len == 32);
    assert(b.hash_len == 64);
    assert(hashchain_update(&a, "x", 1) == 0);
    assert(hashchain_update(&b, "x", 1) == 0);
    /* Different lengths obviously differ; also verify the 32-byte
     * prefix isn't accidentally aliased. */
    assert(memcmp(hashchain_get_current(&a),
                  hashchain_get_current(&b), 32) != 0);
    printf("  PASS: test_alg_distinguishes_chains\n");
}

int main(void)
{
    printf("test_hashchain:\n");
    hcs_hash_alg_t algs[] = {
        HCS_HASH_SHA256, HCS_HASH_SHA384, HCS_HASH_SHA512};
    for (size_t i = 0; i < sizeof(algs) / sizeof(*algs); i++) {
        test_init_for(algs[i]);
        test_update_for(algs[i]);
        test_chain_determinism_for(algs[i]);
        test_chain_ordering_matters_for(algs[i]);
        test_reset_count_for(algs[i]);
        test_full_reset_for(algs[i]);
    }
    test_alg_distinguishes_chains();
    printf("All hash chain tests passed.\n");
    return 0;
}
