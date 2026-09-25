#!/usr/bin/env bash
# Phase 5: seccomp-BPF deny-list tests. Kernel-feature dependent.
set -u

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"
RUN="$(cd -- "$(dirname -- "$RUN")" && pwd -P)/$(basename -- "$RUN")"

PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }

status_json="$("$RUN" --status --json 2>/dev/null)"
if [[ "$status_json" != *'"name":"seccomp","available":true'* ]]; then
    printf 'SKIP all seccomp tests -- seccomp unavailable on this kernel/arch\n'
    printf '\n0 passed, 0 failed, 1 skipped\n'
    exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-sc.XXXXXX")" || exit 1
cleanup() { [[ "$TMP" == */agentguard-sc.* ]] && rm -rf -- "$TMP"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
run() { ( cd "$TMP" && "$RUN" --workspace "$TMP" -- "$@" ); }

# --- The filter is actually installed (Seccomp: 2 = filter mode) ---
out="$(run grep -E '^Seccomp:' /proc/self/status 2>/dev/null)"
[[ "$out" == *"2"* ]] && pass "seccomp filter mode active in target" || fail "seccomp active" "$out"

# --- Denied syscalls return EPERM (clean error, program not killed) ---
# ptrace via a small C helper so we read errno directly.
cat >"$TMP/ptrace.c" <<'EOF'
#include <sys/ptrace.h>
#include <stdio.h>
#include <errno.h>
int main(void){ long r=ptrace(PTRACE_TRACEME,0,0,0); printf("%ld %d\n", r, errno); return 0; }
EOF
gcc -o "$TMP/ptrace" "$TMP/ptrace.c" 2>/dev/null
out="$(run ./ptrace 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "ptrace denied with EPERM" || fail "ptrace EPERM" "$out"

# unshare(CLONE_NEWUSER) denied
cat >"$TMP/uns.c" <<'EOF'
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
int main(void){ int r=unshare(CLONE_NEWUSER); printf("%d %d\n", r, errno); return 0; }
EOF
gcc -o "$TMP/uns" "$TMP/uns.c" 2>/dev/null
out="$(run ./uns 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "unshare denied with EPERM" || fail "unshare EPERM" "$out"

# mount denied
cat >"$TMP/mnt.c" <<'EOF'
#include <sys/mount.h>
#include <stdio.h>
#include <errno.h>
int main(void){ int r=mount("none","/mnt","tmpfs",0,0); printf("%d %d\n", r, errno); return 0; }
EOF
gcc -o "$TMP/mnt" "$TMP/mnt.c" 2>/dev/null
out="$(run ./mnt 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "mount denied with EPERM" || fail "mount EPERM" "$out"

# --- Ordinary work is unaffected ---
out="$(run sh -c 'printf "int main(){return 0;}" > w.c && gcc w.c -o w && ./w && echo OK' 2>/dev/null)"
[[ "$out" == "OK" ]] && pass "compile+run ordinary program" || fail "ordinary work" "$out"
out="$(run python3 -c 'print("PYOK")' 2>/dev/null)"
[[ "$out" == "PYOK" ]] && pass "python runs" || fail "python runs" "$out"

# --- Descendants inherit the filter ---
out="$(run sh -c "cd '$TMP' && ./ptrace" 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "descendant inherits seccomp (ptrace denied)" || fail "descendant inherit" "$out"

# --- x32/wrong-ABI guard: normal 64-bit work already proved allowed; ensure a
# denied syscall via a different path (python ctypes) is also EPERM. ---
out="$(run python3 -c "import ctypes; l=ctypes.CDLL('libc.so.6',use_errno=True); l.ptrace(0,0,0,0); print('e',ctypes.get_errno())" 2>/dev/null)"
[[ "$out" == "e 1" ]] && pass "ptrace via libc also denied (EPERM)" || fail "libc ptrace" "$out"

# --- Phase 6 hardening: namespace clone flags, clone3, new mount API, fd theft,
# io_uring. One helper, action chosen by argv[1]; prints "rc errno". ---
cat >"$TMP/hard.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static void *thr(void *a) { return a; }
int main(int argc, char **argv) {
    const char *a = argc > 1 ? argv[1] : "";
    long r = 0;
    errno = 0;
    if (!strcmp(a, "clone_newuser") || !strcmp(a, "clone_newnet")) {
        unsigned long f = (!strcmp(a, "clone_newuser") ? CLONE_NEWUSER : CLONE_NEWNET) | SIGCHLD;
        r = syscall(SYS_clone, f, 0, 0, 0, 0);
        if (r == 0) _exit(0);
        if (r > 0) waitpid((pid_t)r, 0, 0);
    } else if (!strcmp(a, "clone3")) {
        struct clone_args ca; memset(&ca, 0, sizeof ca);
        ca.flags = CLONE_NEWUSER; ca.exit_signal = SIGCHLD;
        r = syscall(SYS_clone3, &ca, sizeof ca);
        if (r == 0) _exit(0);
        if (r > 0) waitpid((pid_t)r, 0, 0);
    } else if (!strcmp(a, "fsopen")) {
        r = syscall(SYS_fsopen, "tmpfs", 0);
    } else if (!strcmp(a, "pidfd_getfd")) {
        r = syscall(SYS_pidfd_getfd, -1, 0, 0); /* unfiltered: EBADF */
    } else if (!strcmp(a, "io_uring")) {
        r = syscall(SYS_io_uring_setup, 1, NULL); /* unfiltered: EFAULT */
    } else if (!strcmp(a, "fork_thread")) {
        pid_t p = fork();
        if (p == 0) _exit(7);
        int st = 0; waitpid(p, &st, 0);
        pthread_t t; void *ret = NULL;
        if (pthread_create(&t, NULL, thr, (void *)1) != 0 || pthread_join(t, &ret) != 0) return 2;
        printf("%s\n", (WEXITSTATUS(st) == 7 && ret == (void *)1) ? "FORK_THREAD_OK" : "BAD");
        return 0;
    }
    printf("%ld %d\n", r, errno);
    return 0;
}
EOF
gcc -pthread -o "$TMP/hard" "$TMP/hard.c" 2>/dev/null
out="$(run ./hard clone_newuser 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "clone(CLONE_NEWUSER) denied with EPERM" || fail "clone NEWUSER" "$out"
out="$(run ./hard clone_newnet 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "clone(CLONE_NEWNET) denied with EPERM" || fail "clone NEWNET" "$out"
out="$(run ./hard clone3 2>/dev/null)"
[[ "$out" == "-1 38" ]] && pass "clone3 returns ENOSYS (forces flag-filtered clone)" || fail "clone3 ENOSYS" "$out"
out="$(run ./hard fsopen 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "fsopen denied with EPERM" || fail "fsopen EPERM" "$out"
out="$(run ./hard pidfd_getfd 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "pidfd_getfd denied with EPERM" || fail "pidfd_getfd EPERM" "$out"
out="$(run ./hard io_uring 2>/dev/null)"
[[ "$out" == "-1 1" ]] && pass "io_uring_setup denied with EPERM" || fail "io_uring EPERM" "$out"
out="$(run ./hard fork_thread 2>/dev/null)"
[[ "$out" == "FORK_THREAD_OK" ]] && pass "fork + pthread_create still work" || fail "fork/thread" "$out"
out="$(run python3 -c 'import threading,subprocess
r=[]; t=threading.Thread(target=lambda: r.append(1)); t.start(); t.join()
print("PYT" if r==[1] and subprocess.run(["true"]).returncode==0 else "BAD")' 2>/dev/null)"
[[ "$out" == "PYT" ]] && pass "python threads + subprocess work" || fail "python threads" "$out"
out="$(run env HOME="$TMP" sh -c 'git init -q repo && cd repo && echo x > f && git add f &&
    git -c user.name=t -c user.email=t@t commit -qm m && git log --oneline | wc -l' 2>/dev/null)"
[[ "$out" == "1" ]] && pass "git init/add/commit works" || fail "git workflow" "$out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
