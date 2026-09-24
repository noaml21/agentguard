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

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
