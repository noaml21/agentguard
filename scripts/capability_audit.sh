#!/usr/bin/env bash
# AgentGuard V2 Phase 0: unprivileged, read-only host capability audit.
# Never writes outside the repository build directory and never needs sudo.
set -u

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BUILD="$ROOT/build"
mkdir -p -- "$BUILD"

section() { printf '\n## %s\n' "$1"; }
kv() { printf '%s=%s\n' "$1" "$2"; }
readf() { if [[ -r "$1" ]]; then tr '\n' ' ' <"$1" | sed 's/ *$//'; else printf 'unreadable'; fi; }

section host
kv distro "$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-unknown}")"
kv kernel "$(uname -r)"
kv arch "$(uname -m)"
kv gcc "$(gcc --version 2>/dev/null | head -n1 || echo missing)"
kv clang "$(clang --version 2>/dev/null | head -n1 || echo missing)"
kv libseccomp_header "$( [[ -f /usr/include/seccomp.h ]] && echo present || echo absent)"
kv linux_landlock_header "$( [[ -f /usr/include/linux/landlock.h ]] && echo present || echo absent)"

section lsm
kv active_lsms "$(readf /sys/kernel/security/lsm)"
kv apparmor_restrict_unprivileged_userns "$(readf /proc/sys/kernel/apparmor_restrict_unprivileged_userns)"
kv unprivileged_userns_clone "$(readf /proc/sys/kernel/unprivileged_userns_clone)"
kv max_user_namespaces "$(readf /proc/sys/user/max_user_namespaces)"
kv yama_ptrace_scope "$(readf /proc/sys/kernel/yama/ptrace_scope)"
kv seccomp_actions_avail "$(readf /proc/sys/kernel/seccomp/actions_avail)"

section cgroup
kv cgroup_fs "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)"
self_cg="$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)"
kv self_cgroup "$self_cg"
cg_dir="/sys/fs/cgroup$self_cg"
kv self_cgroup_dir_writable "$( [[ -w "$cg_dir" ]] && echo yes || echo no)"
kv self_cgroup_procs_writable "$( [[ -w "$cg_dir/cgroup.procs" ]] && echo yes || echo no)"
kv self_cgroup_kill_present "$( [[ -e "$cg_dir/cgroup.kill" ]] && echo yes || echo no)"
kv self_cgroup_controllers "$(readf "$cg_dir/cgroup.controllers")"
kv self_cgroup_subtree_control "$(readf "$cg_dir/cgroup.subtree_control")"
# Find the nearest ancestor this user owns (systemd user-delegated subtree).
d="$cg_dir"
owned=""
while [[ "$d" != "/sys/fs/cgroup" && -n "$d" ]]; do
    if [[ -O "$d" ]]; then owned="$d"; fi
    d="$(dirname -- "$d")"
done
kv highest_user_owned_cgroup "${owned:-none}"
if [[ -n "$owned" ]]; then
    kv owned_cgroup_controllers "$(readf "$owned/cgroup.controllers")"
    kv owned_cgroup_subtree_control "$(readf "$owned/cgroup.subtree_control")"
fi

section rlimits
ulimit -a 2>/dev/null | sed 's/^/rlimit: /'

section kernel_probe
gcc -std=c11 -O2 -Wall -Wextra -o "$BUILD/capprobe" "$ROOT/sandbox/probe/capprobe.c" \
    && "$BUILD/capprobe"
