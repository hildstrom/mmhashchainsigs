# Development Environment

## Reference Platform

The project is developed and tested on:

- **OS:** Ubuntu 24.04 LTS (Noble Numbat)
- **Architecture:** aarch64 (also targets x86_64)
- **Compiler:** GCC 13.3.0
- **OpenSSL:** 3.0.13
- **C Standard:** C11 with POSIX.1-2008 extensions

## Required Packages

### Ubuntu 24.04

```sh
sudo apt-get install build-essential libssl-dev pkg-config
```

To build the rsyslog module (`mmhashchainsigs.so`), also install:

```sh
sudo apt-get install rsyslog libestr-dev libfastjson-dev
```

The modules are built against rsyslog source headers (not `rsyslog-dev`).
Download and extract the rsyslog source tree, then pass its path:

```sh
# Download rsyslog source (match your installed version)
RSYSLOG_VER=$(rsyslogd -v | head -1 | grep -oP '\d+\.\d+\.\d+')
wget "https://www.rsyslog.com/files/download/rsyslog/rsyslog-${RSYSLOG_VER}.tar.gz" -O /tmp/rsyslog.tar.gz
mkdir -p /tmp/rsyslog-src && tar xzf /tmp/rsyslog.tar.gz -C /tmp/rsyslog-src --strip-components=1
cd /tmp/rsyslog-src && ./configure --enable-imtcp >/dev/null 2>&1

# Build modules
make module RSYSLOG_SRC=/tmp/rsyslog-src
```

To run integration tests and benchmarks, `rsyslog` must be installed.
The scripts use the in-tree `build/integration/send_syslog` helper (built
by `make test-integration` / `make bench`) and do not require `logger`.

### RHEL 10

```sh
sudo dnf install gcc make openssl-devel pkgconf-pkg-config
```

For the rsyslog modules (build against source tree, see Ubuntu instructions above):

```sh
sudo dnf install rsyslog libestr-devel libfastjson-devel
```

## Package Versions

| Package | Ubuntu 24.04 | RHEL 10 | Purpose |
|---------|-------------|---------|---------|
| gcc | 13.x | 14.x | C compiler |
| make | 4.3 | 4.4 | Build system |
| libssl-dev / openssl-devel | 3.0.x | 3.2.x | SHA-256, Ed25519 |
| pkg-config / pkgconf | 1.8.x | 2.x | Dependency detection |
| rsyslog | 8.x | 8.x | Daemon (integration tests) |
| libestr-dev / libestr-devel | 0.1.x | 0.1.x | rsyslog string library |
| libfastjson-dev / libfastjson-devel | 1.x | 1.x | rsyslog JSON library |

## Build Commands

```sh
# Build the verification tool (default target)
make

# Build everything (module requires rsyslog source tree)
make all RSYSLOG_SRC=/tmp/rsyslog-src

# Run the test suite
make test

# Build with debug symbols
make CFLAGS="-Wall -Wextra -Werror -pedantic -std=c11 -g -O0 -D_POSIX_C_SOURCE=200809L"

# Build with AddressSanitizer
make CFLAGS="-Wall -Wextra -Werror -pedantic -std=c11 -g -fsanitize=address -D_POSIX_C_SOURCE=200809L" \
     LDFLAGS="-fsanitize=address"

# Clean build artifacts
make clean
```

## Compiler Flags

The default `CFLAGS` are:

```
-Wall -Wextra -Werror -pedantic -std=c11 -O2 -D_POSIX_C_SOURCE=200809L
```

- `-Wall -Wextra -Werror` -- All warnings are errors (zero-warnings policy)
- `-pedantic` -- Strict ISO C conformance
- `-std=c11` -- C11 standard
- `-O2` -- Optimization level 2 for release builds
- `-D_POSIX_C_SOURCE=200809L` -- POSIX.1-2008 for `getline()`, `gmtime_r()`, `mkstemp()`, etc.

## Standalone vs Module Builds

mmhashchainsigs has two compilation modes controlled by a preprocessor define:

- **`-DMMHASHCHAINSIGS_STANDALONE`** -- Compiles only the core logic (no rsyslog
  dependency). Used for unit tests and the Makefile's `.o` targets.
- **Without the define** -- Compiles the full rsyslog module with
  `BEGINmodInit`, `doAction`, etc. Requires rsyslog headers.

The `make test` target always uses standalone mode. The `make module` target
builds the full shared library (`mmhashchainsigs.so`).

To build modules against a rsyslog source tree:

```sh
make module RSYSLOG_SRC=/path/to/rsyslog-source
```

This requires `libestr-dev` and `libfastjson-dev` to be installed for the
rsyslog header dependencies.

## Testing

```sh
make test
```

Runs 4 test suites with 24 total tests. All tests are self-contained: they
generate temporary Ed25519 key pairs at runtime and clean up after themselves.

To run a single test:

```sh
make build/tests/test_signer
./build/tests/test_signer
```

To run tests under Valgrind:

```sh
make test
valgrind --leak-check=full ./build/tests/test_mmhashchainsigs
```

## Key Generation for Development

```sh
# Generate a test key pair in the current directory
tools/mmhashchainsigs-keygen.sh .

# Or use OpenSSL directly
openssl genpkey -algorithm Ed25519 -out test-private.pem
openssl pkey -in test-private.pem -pubout -out test-public.pem
chmod 600 test-private.pem
```

The private key must not be world-readable (mode 0600). The signer will refuse
to load a world-readable key.

## Manual End-to-End Testing

After building:

```sh
# Generate keys
tools/mmhashchainsigs-keygen.sh /tmp

# Run integration tests against a real rsyslog
make test-integration

# Or verify any log produced by mmhashchainsigs + omfile
./build/mmhashchainsigs-verify -k /tmp/mmhashchainsigs-public.pem -v /path/to/signed.log
```

## Project Conventions

- **Language:** C11 with POSIX extensions
- **Error handling:** Functions return 0 on success, -1 on error. No exceptions, no longjmp.
- **Memory:** Caller-owns-output pattern. Crypto key material is cleansed with `OPENSSL_cleanse()`.
- **Naming:** `hcs_` prefix for shared library, `hashchain_` / `signer_` / `mmhashchainsigs_` for module internals, `verifier_` for verification engine.
- **Testing:** Assert-based tests with descriptive failure context. No external test framework dependency.
