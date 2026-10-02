#include "util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void ag_warn_errno(const char *msg)
{
    fprintf(stderr, "agentguard-run: %s: %s\n", msg, strerror(errno));
}

void ag_warnf(const char *fmt, ...)
{
    va_list ap;
    fputs("agentguard-run: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

int ag_write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

long ag_read_all(int fd, void *buf, size_t len)
{
    char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        off += (size_t)n;
    }
    return (long)off;
}
