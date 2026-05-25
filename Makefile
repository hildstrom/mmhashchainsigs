CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Werror -pedantic -std=c11 -O2 -fPIC -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=

# OpenSSL
CRYPTO_CFLAGS := $(shell pkg-config --cflags libcrypto 2>/dev/null)
CRYPTO_LIBS   := $(shell pkg-config --libs   libcrypto 2>/dev/null)
ifeq ($(CRYPTO_LIBS),)
  CRYPTO_LIBS := -lcrypto
endif

# Rsyslog (optional — module only builds when headers are present)
# Set RSYSLOG_SRC to a rsyslog source tree to build without rsyslog-dev.
RSYSLOG_CFLAGS := $(shell pkg-config --cflags rsyslog 2>/dev/null)
HAVE_RSYSLOG   := $(shell pkg-config --exists rsyslog 2>/dev/null && echo yes)
ifneq ($(RSYSLOG_SRC),)
  _FASTJSON_CFLAGS := $(shell pkg-config --cflags libfastjson 2>/dev/null)
  ifeq ($(_FASTJSON_CFLAGS),)
    _FASTJSON_CFLAGS := -I/usr/include/libfastjson
  endif
  # Use -isystem so rsyslog source headers are treated as system headers
  # and their internal macros do not trip our -Werror -pedantic policy.
  RSYSLOG_CFLAGS := -isystem $(RSYSLOG_SRC)/runtime \
                     -isystem $(RSYSLOG_SRC)/grammar \
                     -isystem $(RSYSLOG_SRC) $(_FASTJSON_CFLAGS)
  HAVE_RSYSLOG := yes
endif

# Directories
SRC_COMMON   := src/common
SRC_MMHASHCHAINSIGS := src/mmhashchainsigs
SRC_VERIFY   := src/verify
BUILDDIR     := build

# Include paths
INCLUDES := -I$(SRC_COMMON) -I$(SRC_MMHASHCHAINSIGS)

# Common library objects
COMMON_SRCS := $(SRC_COMMON)/hcs_crypto.c $(SRC_COMMON)/hcs_format.c
COMMON_OBJS := $(patsubst $(SRC_COMMON)/%.c,$(BUILDDIR)/common/%.o,$(COMMON_SRCS))

# Hash chain objects
HASHCHAIN_SRCS := $(SRC_MMHASHCHAINSIGS)/hashchain.c
HASHCHAIN_OBJS := $(patsubst $(SRC_MMHASHCHAINSIGS)/%.c,$(BUILDDIR)/mmhashchainsigs/%.o,$(HASHCHAIN_SRCS))

# Signer objects
SIGNER_SRCS := $(SRC_MMHASHCHAINSIGS)/signer.c
SIGNER_OBJS := $(patsubst $(SRC_MMHASHCHAINSIGS)/%.c,$(BUILDDIR)/mmhashchainsigs/%.o,$(SIGNER_SRCS))

# mmhashchainsigs core objects
MMHASHCHAINSIGS_SRCS := $(SRC_MMHASHCHAINSIGS)/mmhashchainsigs.c
MMHASHCHAINSIGS_OBJS := $(patsubst $(SRC_MMHASHCHAINSIGS)/%.c,$(BUILDDIR)/mmhashchainsigs/%.o,$(MMHASHCHAINSIGS_SRCS))

# Verifier objects
VERIFIER_SRCS := $(SRC_VERIFY)/verifier.c
VERIFIER_OBJS := $(patsubst $(SRC_VERIFY)/%.c,$(BUILDDIR)/verify/%.o,$(VERIFIER_SRCS))

# Targets
HCS_VERIFY := $(BUILDDIR)/mmhashchainsigs-verify
MMHASHCHAINSIGS_SO   := $(BUILDDIR)/mmhashchainsigs.so
SEND_SYSLOG   := $(BUILDDIR)/integration/send_syslog

# Test targets
TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(patsubst tests/%.c,$(BUILDDIR)/tests/%,$(TEST_SRCS))

.PHONY: all clean test verify-tool module

all: verify-tool
ifeq ($(HAVE_RSYSLOG),yes)
all: module
endif

module: $(MMHASHCHAINSIGS_SO)

verify-tool: $(HCS_VERIFY)

$(HCS_VERIFY): $(BUILDDIR)/verify/mmhashchainsigs_verify.o $(VERIFIER_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(CRYPTO_LIBS)

# Rsyslog module shared objects (require rsyslog headers)
# Drop -pedantic: rsyslog headers use GCC extensions (forward enum refs, etc.)
# Add -D_DEFAULT_SOURCE so rsyslog headers can use BSD types like `uint`.
# Define NDEBUG so rsyslog's cstr_t (and similar) struct layouts match the
# installed rsyslogd binary's release build; otherwise field offsets
# diverge and reads silently return garbage.
MODULE_CFLAGS := $(filter-out -pedantic,$(CFLAGS)) -Wno-pedantic \
	-D_DEFAULT_SOURCE -DNDEBUG \
	-Wno-unused-function -Wno-unused-parameter -Wno-unused-variable

$(MMHASHCHAINSIGS_SO): $(SRC_MMHASHCHAINSIGS)/mmhashchainsigs.c $(SIGNER_OBJS) $(HASHCHAIN_OBJS) $(COMMON_OBJS)
	$(CC) $(MODULE_CFLAGS) $(CRYPTO_CFLAGS) $(RSYSLOG_CFLAGS) $(INCLUDES) \
		-shared -fPIC -o $@ $^ $(CRYPTO_LIBS)

# Build directories
$(BUILDDIR)/common $(BUILDDIR)/mmhashchainsigs $(BUILDDIR)/verify $(BUILDDIR)/tests $(BUILDDIR)/integration:
	mkdir -p $@

# Integration test helper: fast bulk sender for unix-domain syslog
$(SEND_SYSLOG): tests/integration/send_syslog.c | $(BUILDDIR)/integration
	$(CC) $(CFLAGS) -o $@ $<

# Common objects
$(BUILDDIR)/common/%.o: $(SRC_COMMON)/%.c | $(BUILDDIR)/common
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) $(INCLUDES) -c -o $@ $<

# mmhashchainsigs objects (standalone mode for testing)
$(BUILDDIR)/mmhashchainsigs/%.o: $(SRC_MMHASHCHAINSIGS)/%.c | $(BUILDDIR)/mmhashchainsigs
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) $(INCLUDES) -DMMHASHCHAINSIGS_STANDALONE -c -o $@ $<

# Verify objects
$(BUILDDIR)/verify/%.o: $(SRC_VERIFY)/%.c | $(BUILDDIR)/verify
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) $(INCLUDES) -I$(SRC_VERIFY) -c -o $@ $<

# Test binaries
$(BUILDDIR)/tests/test_hashchain: tests/test_hashchain.c $(HASHCHAIN_OBJS) $(COMMON_OBJS) | $(BUILDDIR)/tests
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) $(INCLUDES) -o $@ $^ $(CRYPTO_LIBS)

$(BUILDDIR)/tests/test_signer: tests/test_signer.c $(COMMON_OBJS) | $(BUILDDIR)/tests
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) $(INCLUDES) -o $@ $^ $(CRYPTO_LIBS)

$(BUILDDIR)/tests/test_format: tests/test_format.c $(COMMON_OBJS) | $(BUILDDIR)/tests
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) $(INCLUDES) -o $@ $^ $(CRYPTO_LIBS)

$(BUILDDIR)/tests/test_mmhashchainsigs: tests/test_mmhashchainsigs.c $(MMHASHCHAINSIGS_OBJS) $(SIGNER_OBJS) $(HASHCHAIN_OBJS) $(VERIFIER_OBJS) $(COMMON_OBJS) | $(BUILDDIR)/tests
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) $(INCLUDES) -I$(SRC_VERIFY) -DMMHASHCHAINSIGS_STANDALONE -o $@ $^ $(CRYPTO_LIBS)

test: $(TEST_BINS)
	@echo "=== Running tests ==="
	@fail=0; \
	for t in $(TEST_BINS); do \
		echo "--- $$t ---"; \
		$$t || fail=1; \
	done; \
	if [ $$fail -eq 0 ]; then \
		echo "=== All tests passed ==="; \
	else \
		echo "=== SOME TESTS FAILED ==="; \
		exit 1; \
	fi

clean:
	rm -rf $(BUILDDIR)

# Install targets
PREFIX   ?= /usr/local
BINDIR   := $(PREFIX)/bin
RSYSLOG_MODDIR := $(shell pkg-config --variable=pkglibdir rsyslog 2>/dev/null)
ifeq ($(RSYSLOG_MODDIR),)
  RSYSLOG_MODDIR := /usr/lib/rsyslog
endif

.PHONY: install install-verify install-module test-integration bench

install: install-verify
ifeq ($(HAVE_RSYSLOG),yes)
install: install-module
endif

install-verify: $(HCS_VERIFY)
	install -D -m 755 $(HCS_VERIFY) $(DESTDIR)$(BINDIR)/mmhashchainsigs-verify

install-module: $(MMHASHCHAINSIGS_SO)
	install -D -m 755 $(MMHASHCHAINSIGS_SO) $(DESTDIR)$(RSYSLOG_MODDIR)/mmhashchainsigs.so

test-integration: all $(SEND_SYSLOG)
	tests/integration/run.sh

bench: all $(SEND_SYSLOG)
	tests/integration/bench.sh
