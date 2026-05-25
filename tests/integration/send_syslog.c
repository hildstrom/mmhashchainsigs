/*
 * send_syslog.c - Fast bulk sender for unix-domain syslog sockets.
 *
 * Opens a unix datagram socket once and sends <count> RFC 3164 messages.
 * Replaces a bash loop over `logger -u SOCK ...` in the integration
 * test and benchmark scripts.
 *
 * Usage: send_syslog <socket> <tag> <count> [message-prefix]
 *
 * Each datagram looks like:
 *   <13>Mmm DD HH:MM:SS <host> <tag>[<pid>]: <prefix> <i> of <count>
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PREFIX "integration test message"
#define MSG_BUF_LEN    2048

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 5) {
        fprintf(stderr,
            "Usage: %s <socket> <tag> <count> [message-prefix]\n",
            argv[0]);
        return 2;
    }

    const char *sock_path = argv[1];
    const char *tag       = argv[2];
    char *endp;
    long count = strtol(argv[3], &endp, 10);
    if (*endp != '\0' || count < 1) {
        fprintf(stderr, "invalid count: %s\n", argv[3]);
        return 2;
    }
    const char *prefix = (argc == 5) ? argv[4] : DEFAULT_PREFIX;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "socket path too long: %s\n", sock_path);
        return 2;
    }
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    char host[256];
    if (gethostname(host, sizeof(host)) != 0) {
        strncpy(host, "localhost", sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
    }

    int pid = (int)getpid();
    char buf[MSG_BUF_LEN];

    for (long i = 1; i <= count; i++) {
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        char ts[32];
        strftime(ts, sizeof(ts), "%b %e %T", &tm);

        int n = snprintf(buf, sizeof(buf),
            "<13>%s %s %s[%d]: %s %ld of %ld",
            ts, host, tag, pid, prefix, i, count);
        if (n < 0 || (size_t)n >= sizeof(buf)) {
            fprintf(stderr, "message %ld too large\n", i);
            close(fd);
            return 1;
        }

        for (;;) {
            ssize_t s = sendto(fd, buf, (size_t)n, 0,
                               (struct sockaddr *)&addr,
                               sizeof(addr));
            if (s == (ssize_t)n) {
                break;
            }
            if (s < 0 && (errno == ENOBUFS || errno == EAGAIN
                          || errno == EWOULDBLOCK
                          || errno == EINTR)) {
                /* Receive buffer full -- back off briefly */
                struct timespec t = {0, 1000000L}; /* 1 ms */
                nanosleep(&t, NULL);
                continue;
            }
            perror("sendto");
            close(fd);
            return 1;
        }
    }

    close(fd);
    return 0;
}
