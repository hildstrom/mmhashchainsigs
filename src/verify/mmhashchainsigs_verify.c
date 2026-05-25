/*
 * mmhashchainsigs_verify.c - CLI tool for verifying mmhashchainsigs-protected log files
 *
 * Usage: mmhashchainsigs-verify -k <pubkey.pem> [OPTIONS] <logfile>
 */
#include "verifier.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -k <pubkey.pem> [OPTIONS] <logfile>\n"
        "\n"
        "Options:\n"
        "  -k, --publickey <path>  "
            "Path to Ed25519 public key PEM (required)\n"
        "  -v, --verbose           "
            "Print per-block verification details\n"
        "  -q, --quiet             "
            "Only output final pass/fail\n"
        "  -s, --strict            "
            "Fail if file does not end with a signature\n"
        "  -h, --help              "
            "Show this help\n",
        prog);
}

static const struct option long_opts[] = {
    {"publickey", required_argument, NULL, 'k'},
    {"verbose",   no_argument,       NULL, 'v'},
    {"quiet",     no_argument,       NULL, 'q'},
    {"strict",    no_argument,       NULL, 's'},
    {"help",      no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
    const char *pubkey_path = NULL;
    const char *logfile_path = NULL;
    int verbose = 0;
    int quiet = 0;
    int strict = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "k:vqsh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'k': pubkey_path = optarg; break;
        case 'v': verbose = 1; break;
        case 'q': quiet = 1; break;
        case 's': strict = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }

    if (!pubkey_path) {
        fprintf(stderr, "Error: --publickey is required\n");
        usage(argv[0]);
        return 2;
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: log file path required\n");
        usage(argv[0]);
        return 2;
    }
    logfile_path = argv[optind];

    verifier_ctx_t ctx;
    if (verifier_init(&ctx, pubkey_path, strict) != 0) {
        fprintf(stderr,
                "Error: failed to load public key: %s\n",
                pubkey_path);
        return 2;
    }

    FILE *fp = fopen(logfile_path, "r");
    if (!fp) {
        fprintf(stderr, "Error: cannot open %s: %s\n",
                logfile_path, strerror(errno));
        verifier_free(&ctx);
        return 2;
    }

    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;
    uint64_t line_num = 0;

    while ((line_len = getline(&line, &line_cap, fp)) != -1) {
        line_num++;

        /* Strip trailing newline */
        while (line_len > 0
               && (line[line_len - 1] == '\n'
                   || line[line_len - 1] == '\r')) {
            line_len--;
        }

        if (verifier_process_line(&ctx, line, (size_t)line_len,
                                  line_num) != 0) {
            break;
        }
    }

    free(line);
    fclose(fp);

    verifier_finalize(&ctx);

    int exit_code;
    if (verifier_passed(&ctx)) {
        if (!quiet) {
            printf("PASS: %lu messages verified, "
                   "%lu signature blocks\n",
                   (unsigned long)ctx.msg_count,
                   (unsigned long)ctx.sig_count);
        }
        exit_code = 0;
    } else {
        if (!quiet) {
            printf("FAIL: %d error(s) detected\n",
                   ctx.error_count);
            for (int i = 0; i < ctx.error_count; i++) {
                verifier_error_t *e = &ctx.errors[i];
                if (e->line_num > 0) {
                    printf("  line %lu: %s\n",
                           (unsigned long)e->line_num,
                           e->message);
                } else {
                    printf("  %s\n", e->message);
                }
            }
        }
        /* Distinguish key mismatch from integrity failure */
        exit_code = 1;
        for (int i = 0; i < ctx.error_count; i++) {
            if (strstr(ctx.errors[i].message,
                       "fingerprint mismatch")) {
                exit_code = 3;
                break;
            }
        }
    }

    if (verbose && !quiet) {
        printf("\nDetails:\n");
        printf("  Messages:         %lu\n",
               (unsigned long)ctx.msg_count);
        printf("  Signature blocks: %lu\n",
               (unsigned long)ctx.sig_count);
        printf("  Last signed seq:  %lu\n",
               (unsigned long)ctx.last_signed_seq);
        uint64_t total = ctx.next_seq > 0 ? ctx.next_seq - 1 : 0;
        uint64_t unsigned_tail = total - ctx.last_signed_seq;
        if (unsigned_tail > 0) {
            printf("  Unsigned tail:    %lu messages\n",
                   (unsigned long)unsigned_tail);
        }
    }

    verifier_free(&ctx);
    return exit_code;
}
