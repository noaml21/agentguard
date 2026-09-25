#define _GNU_SOURCE
#include "seccomp.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Expected audit arch for the compiled target. Adding an arch is a one-line
 * change plus verifying the SYS_* table below resolves for it. */
#if defined(__x86_64__)
#define AG_AUDIT_ARCH AUDIT_ARCH_X86_64
#define AG_HAVE_X32_GUARD 1
#elif defined(__aarch64__)
#define AG_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define AG_HAVE_X32_GUARD 0
#else
#define AG_AUDIT_ARCH 0
#define AG_HAVE_X32_GUARD 0
#endif

/* Denied syscalls. Each: threat it addresses / why ordinary agent work does not
 * need it / expected compatibility impact. All return EPERM (a clean error the
 * program can handle) rather than killing the process. */
static const int kDenied[] = {
#ifdef SYS_ptrace
    SYS_ptrace,            /* attach/inspect other same-UID processes; agents don't debug live procs; low impact */
#endif
#ifdef SYS_process_vm_readv
    SYS_process_vm_readv,  /* read another process's memory; not needed; low impact */
#endif
#ifdef SYS_process_vm_writev
    SYS_process_vm_writev, /* write another process's memory; not needed; low impact */
#endif
#ifdef SYS_unshare
    SYS_unshare,           /* create namespaces (userns gains caps that weaken assumptions); not needed; low impact */
#endif
#ifdef SYS_setns
    SYS_setns,             /* join another process's namespace; not needed; low impact */
#endif
#ifdef SYS_mount
    SYS_mount,             /* change filesystem topology to confuse path rules; needs caps anyway; none */
#endif
#ifdef SYS_umount2
    SYS_umount2,           /* unmount; needs caps; none */
#endif
#ifdef SYS_pivot_root
    SYS_pivot_root,        /* swap root; needs caps; none */
#endif
#ifdef SYS_chroot
    SYS_chroot,            /* change root to escape path assumptions; not needed; none */
#endif
#ifdef SYS_move_mount
    SYS_move_mount,        /* new mount API topology change; needs caps; none */
#endif
#ifdef SYS_open_tree
    SYS_open_tree,         /* new mount API; not needed; none */
#endif
#ifdef SYS_mount_setattr
    SYS_mount_setattr,     /* new mount API; needs caps; none */
#endif
#ifdef SYS_init_module
    SYS_init_module,       /* load kernel module; needs CAP_SYS_MODULE; belt-and-suspenders */
#endif
#ifdef SYS_finit_module
    SYS_finit_module,      /* load kernel module; needs caps; belt-and-suspenders */
#endif
#ifdef SYS_delete_module
    SYS_delete_module,     /* unload kernel module; needs caps; belt-and-suspenders */
#endif
#ifdef SYS_kexec_load
    SYS_kexec_load,        /* stage a replacement kernel; needs caps; belt-and-suspenders */
#endif
#ifdef SYS_kexec_file_load
    SYS_kexec_file_load,   /* stage a replacement kernel; needs caps; belt-and-suspenders */
#endif
#ifdef SYS_reboot
    SYS_reboot,            /* halt/reboot host; needs caps; belt-and-suspenders */
#endif
#ifdef SYS_bpf
    SYS_bpf,               /* load BPF programs / maps; not needed; low impact */
#endif
#ifdef SYS_perf_event_open
    SYS_perf_event_open,   /* perf counters / side channels / info leak; rarely needed; low impact */
#endif
#ifdef SYS_open_by_handle_at
    SYS_open_by_handle_at, /* open by file handle, bypassing path resolution; needs caps; belt-and-suspenders */
#endif
#ifdef SYS_fsopen
    SYS_fsopen,            /* new mount API: create a superblock without mount(); needs caps; none */
#endif
#ifdef SYS_fsconfig
    SYS_fsconfig,          /* new mount API: configure a superblock; needs caps; none */
#endif
#ifdef SYS_fsmount
    SYS_fsmount,           /* new mount API: attach a superblock without mount(); needs caps; none */
#endif
#ifdef SYS_pidfd_getfd
    SYS_pidfd_getfd,       /* steal an fd from another same-UID process (authority leak); not needed; low impact */
#endif
#ifdef SYS_syslog
    SYS_syslog,            /* read/clear the kernel ring buffer (info leak); not needed; low impact */
#endif
#ifdef SYS_io_uring_setup
    SYS_io_uring_setup,    /* io_uring ops (e.g. IORING_OP_SOCKET) bypass per-syscall seccomp rules; libuv etc. fall back; low impact */
#endif
#ifdef SYS_io_uring_enter
    SYS_io_uring_enter,    /* io_uring (see io_uring_setup); low impact */
#endif
#ifdef SYS_io_uring_register
    SYS_io_uring_register, /* io_uring (see io_uring_setup); low impact */
#endif
#ifdef SYS_swapon
    SYS_swapon,            /* enable swap; needs caps; none */
#endif
#ifdef SYS_swapoff
    SYS_swapoff,           /* disable swap; needs caps; none */
#endif
};

/* Namespace-creation flags for clone(2). We cannot deny clone() outright because
 * glibc fork()/pthread_create route through clone/clone3, so we filter the flags
 * argument instead: clone() with any new-namespace bit is denied. This closes the
 * "create a user namespace via clone instead of unshare" escape.
 * clone3(2) takes a struct pointer that seccomp cannot dereference, so its flags
 * cannot be filtered. Instead clone3 returns ENOSYS: glibc (pthread_create,
 * posix_spawn) and other runtimes treat that as "old kernel" and fall back to
 * clone(), which the flag filter covers. CLONE_NEWTIME is only expressible via
 * clone3/unshare, both of which are denied. */
#define AG_CLONE_NEW_MASK 0x7E020000u
/* = CLONE_NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET */

int sc_available(void)
{
    if (AG_AUDIT_ARCH == 0)
        return 0;
    /* SECCOMP_GET_ACTION_AVAIL confirms filter mode + RET_ERRNO without changing
     * anything. Fall back to assuming availability if the query is unsupported
     * but the arch is known (older kernels lacking the query still support
     * filters). */
    uint32_t action = SECCOMP_RET_ERRNO;
    long rc = syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action);
    if (rc == 0)
        return 1;
    return errno == EINVAL ? 1 : 0;
}

int sc_apply(int deny_inet)
{
    if (AG_AUDIT_ARCH == 0) {
        errno = ENOSYS;
        return -1;
    }

    size_t ndeny = sizeof(kDenied) / sizeof(kDenied[0]);
    /* header(3)+x32(2)+load nr(1)+2*deny+clone3(2)+clone block(5)+socket block(6)+allow(1) */
    struct sock_filter prog[3 + 2 + 1 + 2 * (sizeof(kDenied) / sizeof(kDenied[0])) + 2 + 5 +
                            6 + 1];
    size_t n = 0;

    /* Load arch; kill if it isn't what we built for (blocks int-0x80 / wrong ABI). */
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                             offsetof(struct seccomp_data, arch));
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AG_AUDIT_ARCH, 1, 0);
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* Load syscall number. */
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                             offsetof(struct seccomp_data, nr));

#if AG_HAVE_X32_GUARD
    /* On x86_64 the x32 ABI sets bit 30; treat those as out-of-policy and kill. */
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1);
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif

    /* Deny-list: if nr == denied, return EPERM; else fall through. A holds nr. */
    for (size_t i = 0; i < ndeny; i++) {
        prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 (uint32_t)kDenied[i], 0, 1);
        prog[n++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }

#ifdef SYS_clone3
    /* clone3 -> ENOSYS so callers fall back to the flag-filtered clone(). */
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             (uint32_t)SYS_clone3, 0, 1);
    prog[n++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA));
#endif

#ifdef SYS_clone
    /* clone() with any new-namespace flag is denied (fork/threads use clone with
     * no NEW bits, so they pass). A still holds nr here. This 5-instruction block
     * clobbers A, so the socket block below reloads nr. */
    /* [0] if nr==clone fall through, else skip the block (4 instrs). */
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             (uint32_t)SYS_clone, 0, 4);
    /* [1] load clone flags = args[0] low 32 bits. */
    prog[n++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    /* [2] mask to the new-namespace bits. */
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, AG_CLONE_NEW_MASK);
    /* [3] if no NEW bit set, skip the deny (allow via later default). */
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
    /* [4] a new-namespace clone: deny. */
    prog[n++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif

#ifdef SYS_socket
    /* Network mode none: socket() is allowed only for AF_UNIX (local IPC) and
     * AF_NETLINK (local kernel queries such as interface lists; cannot carry
     * traffic off-host). Every other family -- AF_INET/AF_INET6 (TCP, UDP, raw
     * IP), AF_PACKET, AF_VSOCK, AF_BLUETOOTH, ... -- fails with EACCES. An
     * allowlist rather than a deny-list so a family we did not think of is
     * denied by default. 6-instruction block, relative jumps computed by hand. */
    if (deny_inet) {
        /* [0] reload nr (the clone block above may have left flags in A). */
        prog[n++] = (struct sock_filter)BPF_STMT(
            BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
        /* [1] if nr==socket fall through, else skip [2..5] to the ALLOW. */
        prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 (uint32_t)SYS_socket, 0, 4);
        /* [2] load args[0] low 32 bits = address family (kernel takes an int). */
        prog[n++] = (struct sock_filter)BPF_STMT(
            BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
        /* [3],[4] allowed local families jump over the deny to the ALLOW. */
        prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 2, 0);
        prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_NETLINK, 1, 0);
        /* [5] any other family: deny. */
        prog[n++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA));
    }
#endif

    /* Default: allow (execve and all ordinary syscalls). */
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog fprog = {.len = (unsigned short)n, .filter = prog};
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog) != 0) {
        /* Older kernels: fall back to prctl. */
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0) != 0)
            return -1;
    }
    return 0;
}
