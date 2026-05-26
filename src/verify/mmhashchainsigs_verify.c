/*
 * mmhashchainsigs_verify.c - CLI tool for verifying mmhashchainsigs-protected log files
 *
 * Usage: mmhashchainsigs-verify (-k <pubkey.pem> | -c <cert.pem> | -C <ca.pem>) [OPTIONS] <logfile>
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
        "Usage: %s (-k <pubkey.pem> | -c <cert.pem> |"
        " -C <ca.pem>) [OPTIONS] <logfile>\n"
        "\n"
        "Trust anchor (exactly one is required):\n"
        "  -k, --publickey <path>  "
            "Raw PEM public key (Ed25519 or ECDSA P-256)\n"
        "  -c, --cert <path>       "
            "Pinned X.509 leaf certificate PEM\n"
        "  -C, --ca-bundle <path>  "
            "PEM bundle of CA certificates; the signer's cert\n"
        "                          must be embedded in the log and chain to a CA\n"
        "      --crl-file <path>   "
            "Optional CRL file (only with --ca-bundle)\n"
        "\n"
        "Options:\n"
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

enum { OPT_CRL_FILE = 1000 };

static const struct option long_opts[] = {
    {"publickey", required_argument, NULL, 'k'},
    {"cert",      required_argument, NULL, 'c'},
    {"ca-bundle", required_argument, NULL, 'C'},
    {"crl-file",  required_argument, NULL, OPT_CRL_FILE},
    {"verbose",   no_argument,       NULL, 'v'},
    {"quiet",     no_argument,       NULL, 'q'},
    {"strict",    no_argument,       NULL, 's'},
    {"help",      no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
    verifier_opts_t opts = {0};
    const char *logfile_path = NULL;
    int verbose = 0;
    int quiet = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "k:c:C:vqsh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'k': opts.pubkey_path = optarg; break;
        case 'c': opts.cert_path = optarg; break;
        case 'C': opts.ca_bundle_path = optarg; break;
        case OPT_CRL_FILE: opts.crl_file = optarg; break;
        case 'v': verbose = 1; break;
        case 'q': quiet = 1; break;
        case 's': opts.strict = true; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }

    int n_trust = (opts.pubkey_path != NULL)
                + (opts.cert_path != NULL)
                + (opts.ca_bundle_path != NULL);
    if (n_trust != 1) {
        fprintf(stderr,
                "Error: exactly one of --publickey, --cert,"
                " or --ca-bundle is required\n");
        usage(argv[0]);
        return 2;
    }
    if (opts.crl_file && !opts.ca_bundle_path) {
        fprintf(stderr,
                "Error: --crl-file requires --ca-bundle\n");
        return 2;
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: log file path required\n");
        usage(argv[0]);
        return 2;
    }
    logfile_path = argv[optind];

    verifier_ctx_t ctx;
    if (verifier_init(&ctx, &opts) != 0) {
        fprintf(stderr,
                "Error: failed to initialize verifier"
                " (check key/cert paths and formats)\n");
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
        /* Map error categories to distinct exit codes:
         *   1 = integrity failure
         *   3 = key/fingerprint mismatch
         *   4 = certificate chain validation failure */
        exit_code = 1;
        for (int i = 0; i < ctx.error_count; i++) {
            const char *m = ctx.errors[i].message;
            if (strstr(m, "fingerprint mismatch")) {
                exit_code = 3;
                break;
            }
            if (strstr(m, "certificate") || strstr(m, "chain validation")) {
                exit_code = 4;
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
