/* seccomp-BPF: a small, default-allow syscall filter with a targeted deny-list.
 *
 * Landlock is the filesystem boundary; this filter closes same-UID and escape
 * vectors Landlock does not cover (ptrace/process memory, namespace and mount
 * manipulation, kernel/module/reboot, BPF/perf, handle-based open). It is
 * installed last (after Landlock) so it need not permit setup syscalls, and it
 * is inherited by every descendant.
 */
#ifndef AGENTGUARD_SECCOMP_H
#define AGENTGUARD_SECCOMP_H

/* True if seccomp filter mode is usable on this kernel and the compiled arch is
 * one we build a filter for. Read-only. */
int sc_available(void);

/* Child side: install the filter. Requires no_new_privs to have been set.
 * If deny_inet is nonzero, socket() is allowed only for AF_UNIX and AF_NETLINK;
 * every other family (AF_INET/AF_INET6 TCP+UDP+raw, AF_PACKET, AF_VSOCK, ...)
 * fails with EACCES.
 * Returns 0 on success, -1 on failure (errno set). */
int sc_apply(int deny_inet);

#endif
