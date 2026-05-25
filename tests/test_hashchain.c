/*
 * test_hashchain.c - Unit tests for hash chain
 */
#include "hashchain.h"
#include "hcs_crypto.h"
#include "hcs_format.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_init(void)
{
    hashchain_ctx_t ctx;
    assert(hashchain_init(&ctx) == 0);

    unsigned char expected_iv[HCS_HASH_LEN];
    assert(hcs_chain_init_hash(expected_iv) == 0);

    assert(memcmp(hashchain_get_current(&ctx),
                  expected_iv, HCS_HASH_LEN) == 0);
    assert(ctx.seq == 1);
    assert(ctx.msg_count == 0);

    printf("  PASS: test_init\n");
}

static void test_update(void)
{
    hashchain_ctx_t ctx;
    assert(hashchain_init(&ctx) == 0);

    const char *msg = "test message";
    unsigned char before[HCS_HASH_LEN];
    memcpy(before, hashchain_get_current(&ctx), HCS_HASH_LEN);

    assert(hashchain_update(&ctx, msg, strlen(msg)) == 0);

    /* Hash should have changed */
    assert(memcmp(hashchain_get_current(&ctx),
                  before, HCS_HASH_LEN) != 0);
    assert(ctx.seq == 2);
    assert(ctx.msg_count == 1);

    /* Verify manually: H = SHA-256(IV || seq_be64(1) || msg) */
    unsigned char manual[HCS_HASH_LEN];
    assert(hcs_sha256_chain(before, 1, msg, strlen(msg),
                               manual) == 0);
    assert(memcmp(hashchain_get_current(&ctx),
                  manual, HCS_HASH_LEN) == 0);

    printf("  PASS: test_update\n");
}

static void test_chain_determinism(void)
{
    hashchain_ctx_t a, b;
    assert(hashchain_init(&a) == 0);
    assert(hashchain_init(&b) == 0);

    const char *msgs[] = {"hello", "world", "foo"};
    for (int i = 0; i < 3; i++) {
        assert(hashchain_update(&a, msgs[i], strlen(msgs[i])) == 0);
        assert(hashchain_update(&b, msgs[i], strlen(msgs[i])) == 0);
    }

    assert(memcmp(hashchain_get_current(&a),
                  hashchain_get_current(&b),
                  HCS_HASH_LEN) == 0);

    printf("  PASS: test_chain_determinism\n");
}

static void test_chain_ordering_matters(void)
{
    hashchain_ctx_t a, b;
    assert(hashchain_init(&a) == 0);
    assert(hashchain_init(&b) == 0);

    assert(hashchain_update(&a, "hello", 5) == 0);
    assert(hashchain_update(&a, "world", 5) == 0);

    assert(hashchain_update(&b, "world", 5) == 0);
    assert(hashchain_update(&b, "hello", 5) == 0);

    assert(memcmp(hashchain_get_current(&a),
                  hashchain_get_current(&b),
                  HCS_HASH_LEN) != 0);

    printf("  PASS: test_chain_ordering_matters\n");
}

static void test_reset_count(void)
{
    hashchain_ctx_t ctx;
    assert(hashchain_init(&ctx) == 0);
    assert(hashchain_update(&ctx, "msg", 3) == 0);
    assert(ctx.msg_count == 1);

    unsigned char hash_before[HCS_HASH_LEN];
    memcpy(hash_before, hashchain_get_current(&ctx), HCS_HASH_LEN);
    uint64_t seq_before = ctx.seq;

    hashchain_reset_count(&ctx);
    assert(ctx.msg_count == 0);

    /* Chain hash and seq should be unchanged */
    assert(memcmp(hashchain_get_current(&ctx),
                  hash_before, HCS_HASH_LEN) == 0);
    assert(ctx.seq == seq_before);

    printf("  PASS: test_reset_count\n");
}

static void test_full_reset(void)
{
    hashchain_ctx_t ctx;
    assert(hashchain_init(&ctx) == 0);
    assert(hashchain_update(&ctx, "msg", 3) == 0);
    assert(hashchain_update(&ctx, "msg2", 4) == 0);

    assert(hashchain_reset(&ctx) == 0);
    assert(ctx.seq == 1);
    assert(ctx.msg_count == 0);

    unsigned char expected_iv[HCS_HASH_LEN];
    assert(hcs_chain_init_hash(expected_iv) == 0);
    assert(memcmp(hashchain_get_current(&ctx),
                  expected_iv, HCS_HASH_LEN) == 0);

    printf("  PASS: test_full_reset\n");
}

int main(void)
{
    printf("test_hashchain:\n");
    test_init();
    test_update();
    test_chain_determinism();
    test_chain_ordering_matters();
    test_reset_count();
    test_full_reset();
    printf("All hash chain tests passed.\n");
    return 0;
}
