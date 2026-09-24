#define _GNU_SOURCE
#include "seccomp.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
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
#ifdef SYS_swapon
    SYS_swapon,            /* enable swap; needs caps; none */
#endif
#ifdef SYS_swapoff
    SYS_swapoff,           /* disable swap; needs caps; none */
#endif
};

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

int sc_apply(void)
{
    if (AG_AUDIT_ARCH == 0) {
        errno = ENOSYS;
        return -1;
    }

    size_t ndeny = sizeof(kDenied) / sizeof(kDenied[0]);
    /* header (arch guard 3) + x32 guard (2) + load nr (1) + 2 per deny + allow (1) */
    struct sock_filter prog[3 + 2 + 1 + 2 * (sizeof(kDenied) / sizeof(kDenied[0])) + 1];
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

    /* Deny-list: if nr == denied, return EPERM; else fall through. */
    for (size_t i = 0; i < ndeny; i++) {
        prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                 (uint32_t)kDenied[i], 0, 1);
        prog[n++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }

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
