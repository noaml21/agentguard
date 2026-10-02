/* Small shared helpers for agentguard-run. */
#ifndef AGENTGUARD_UTIL_H
#define AGENTGUARD_UTIL_H

#include <stddef.h>

/* Distinct exit codes so the caller can tell apart runner failures from the
 * target's own exit status. Chosen to match timeout(1) where sensible. */
#define AG_EXIT_SETUP_FAILURE 125 /* refused to run (e.g. EUID 0, bad args, setup) */
#define AG_EXIT_EXEC_FAILURE 127  /* target could not be executed */
#define AG_EXIT_TIMEOUT 124       /* deadline reached; tree terminated */

/* Print "agentguard-run: <msg>: <strerror(errno)>" to stderr. */
void ag_warn_errno(const char *msg);

/* Print "agentguard-run: <fmt...>" to stderr. */
void ag_warnf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* write() the whole buffer, retrying on short writes and EINTR. Returns 0 on
 * success, -1 on error (errno set). */
int ag_write_all(int fd, const void *buf, size_t len);

/* read() exactly len bytes unless EOF; returns bytes read (< len means EOF),
 * or -1 on error. */
long ag_read_all(int fd, void *buf, size_t len);

#endif
