# AgentGuard V2 Build Log

Append-only evidence. Newest entries at the bottom.

## 2026-09-24 — Session 1: reconciliation and Phase 0

### Git reconciliation
- `main` = `origin/main` = `904aa3f` (ci: run AgentGuard test suite); tree clean; no V2 branch existed.
- Created and pushed `v2/kernel-sandbox` from `904aa3f`.

### V1 inspection
- Live hooks in `.claude/settings.json` guard this development session: PreToolUse
  (Bash|Read|Edit|Write) → `scripts/run_hook_chain.sh`; PostToolUse (Edit|Write) → syntax
  checker; SessionEnd summary.
- Consequences for development (not changed, recorded as constraints):
  - Rate limiter: `MAX_COMMANDS=50` Bash requests per Claude session (warning after 40).
    Bash work is batched into few calls; work continues in new sessions when exhausted.
    Hooks are not modified to raise the limit.
  - File policy: Read/Edit/Write limited to the workspace; control-plane paths
    (`agentguard/{hooks,lib,config}`, `.claude/settings*.json`, `scripts/run_hook_chain.sh`,
    `.agentguard/`) are not editable with file tools. V2 code lives in new paths.
  - Commit validator: headers must be `type(scope): subject`, 10–72 chars, no trailing period.
- V1 regression suite: `./tests/run_tests.sh` → `40 passed, 0 failed`.

### Phase 0 capability audit
Command: `bash scripts/capability_audit.sh` (unprivileged).
- Ubuntu 24.04.5 LTS, kernel 7.0.0-31-generic, x86_64, GCC 13.3.0, no clang.
- LSMs: lockdown,capability,landlock,yama,apparmor,ima,evm.
- Landlock ABI **8** via `landlock_create_ruleset(NULL,0,VERSION)`. Pathname unix (ABI 9)
  and UDP (ABI 10) not available.
- seccomp filter actions available; no_new_privs settable.
- `apparmor_restrict_unprivileged_userns=1`: `unshare(CLONE_NEWUSER)` ok, but uid_map
  write, NEWNET, NEWPID, NEWNS all EPERM → namespace tier unavailable.
- Yama ptrace_scope=1.
- cgroup v2; own scope writable, `cgroup.kill` present, controllers memory+pids listed;
  user-owned `user@1000.service` with cpu memory pids delegated.
- close_range, pidfd_open, PR_SET_CHILD_SUBREAPER available.
- libseccomp headers absent; tools present: make, strace, socat, nc, python3 3.12, jq.

Decision: design guarantees around ABI 8 with runtime feature degradation; no namespace
tier on this host; hand-written cBPF seccomp (no new host packages).

## 2026-09-24 — Session 1: Phase 1 (V1 adversarial baseline)

Built `redteam/` effect-based corpus (`cases/corpus.json`, 20 cases) and `run_v1.py`.
Each case builds a disposable `mkdtemp` fixture, sends a synthetic hook payload through
`scripts/run_hook_chain.sh` as Claude would, records V1's decision, and — only if V1
allowed it — performs the effect and checks a real-effect oracle.

Result (`redteam/results/v1_results.json`): **bypass=11, prevented=7, allowed-safe=2**.

- Prevented (V1 works): rm -rf, rm -r''f, curl|bash, git reset --hard, Read .env,
  Write ../outside, Read symlink-escape.
- Bypassed (motivates V2): `\rm -rf`, `R=-rf; rm $R`, `find -delete`, python rmtree,
  `bash -c 'rm -rf'`, `cat payload.sh | sh`, `git -C . reset --hard`, `cat .env`,
  `printf > .env`, `printf > ../outside/loot`, `cat symlink-to-outside`.
- Key structural gap confirmed: any Bash command bypasses the Read/Edit/Write file
  policy entirely (env-read-bash, env-write-bash, outside-write-bash, symlink-read-bash),
  and the firewall regex is defeated by interpreters, expansion, and equivalent tools.

Corpus is mechanism-neutral so Phase 11 replays the identical semantic cases under V2.

## 2026-09-24 — Session 1: note on live V1 hook friction during V2 dev

The live PostToolUse syntax checker runs `gcc -fsyntax-only <file>` with no include
path, so every multi-file V2 `.c` Write reports exit 2 ("util.h: No such file or
directory"). This is **cosmetic only**: PostToolUse runs after the write, cannot undo it,
and the file is written correctly (verified on disk). No hook is modified; V2 code is
compiled via `make -C sandbox` which sets `-Iinclude`. Recorded per the self-hosting rule;
not a blocker.

## 2026-09-24 — Session 1: Phase 2 (C runner, lifecycle, FD, TTY)

Built `sandbox/` C project (readable modules): `options` (CLI, `--` separator, no shell),
`fdsan` (close_range + /proc fallback), `lifecycle` (fork/exec/signalfd supervisor,
subreaper, pgrp signal forwarding, wall-clock deadline, TTY foreground handoff, tree
teardown), `util`, `main` (root refusal, version/help). `Makefile` with
`-Wall -Wextra -Werror -Wshadow -Wconversion ...` and an ASan/UBSan `check-asan` target.

Verified:
- `make check`: 18 integration tests pass (exit codes incl. 128+signo, argv verbatim/no
  shell, exec/usage codes 127/125, FD sanitation closes inherited 3/4, `--keep-fd`,
  timeout=124 fires promptly, grandchild terminated, unrelated process survives, no leak
  over 10 runs).
- `python3 tests/tty_test.py`: 5 pty tests pass (target sees TTY; is foreground group;
  Ctrl-C reaches it; SIGWINCH on resize reaches it; exit status through pty).
- `make check-asan`: all 23 pass under ASan+UBSan with leak detection.

Privilege model implemented: refuses EUID 0 (exit 125); never setuid; no root override.
Note: shell-target WINCH traps are deferred by the shell, so the WINCH test uses a Python
target (kernel delivers WINCH to the foreground group regardless).

## 2026-09-24 — Session 1: Phase 3 (fail-closed setup contract)

Added `sandbox` module (`sandbox.h/.c`): enforcement-layer negotiation tracking
AVAILABLE (parent probe) / REQUESTED / REQUIRED / APPLIED (child, reported back), a
structured report protocol over the existing pipe (SETUP_OK+applied_mask / SETUP_FAIL /
EXEC_FAIL), strict (default) vs `--degraded` modes, and `--status`/`--json`/`--verbose`.
First real layer registered: `no_new_privs` (prctl PR_SET_NO_NEW_PRIVS). Phase 4+ append
Landlock/seccomp to the same table; enforcement plugs into `ag_apply_layers` in the child.

Test seams (documented, test-only): `AGENTGUARD_TEST_UNAVAIL=<layer,...>` forces a probe
to report unavailable; `AGENTGUARD_TEST_FAIL=<layer,...>` forces apply() to fail. These
let the contract be tested deterministically on any kernel (real availability is
kernel-dependent).

Verified (`tests/contract_test.sh`, 12 tests; also under ASan/UBSan):
- available+applied: target shows `NoNewPrivs: 1`.
- strict + unavailable required layer: exit 125, **target never ran**.
- strict + apply failure: exit 125, **target never ran**.
- degraded + unavailable: exit 0, runs with `NoNewPrivs: 0` (layer reported not applied).
- no silent downgrade: strict refuses exactly where degraded runs.
- `--status` (exit 0, lists layers), `--status --json` (valid via jq), degraded status.

Full suite green: `make check` = 18 runner + 12 contract + 5 pty = 35 tests;
`make check-asan` all 35 clean under ASan+UBSan.

## 2026-09-24 — Session 1: Phase 4 (Landlock filesystem enforcement)

Added `landlock.{h,c}` (runtime ABI detection via landlock_create_ruleset(NULL,0,VERSION);
ruleset built from handled rights for the running ABI; path_beneath rules bound to O_PATH
inodes; restrict_self) and `policy.{h,c}` (workspace + read/write paths + default system
read set). Registered `AG_LAYER_LANDLOCK_FS` (required, applied after no_new_privs). New
options: `--workspace`, `--allow-read`, `--allow-write`, `--no-default-reads`.

Design decisions recorded: IOCTL_DEV (ABI5) intentionally NOT handled (keeps interactive
TTY working; documented). Landlock depends on no_new_privs → enum order enforces it. In
degraded mode, unavailable required layers are relaxed but apply-failures still fail closed.

Bug fixed during Phase 4: the Makefile lacked header-dependency tracking, so an incremental
build linked stale objects compiled against an older struct layout → segfault (only in the
non-sanitized -O2 build; a full/ASan rebuild was fine). Root cause, not symptom: added
`-MMD -MP` + `-include $(DEP)`. Verified clean rebuild works.

Verified (`tests/landlock_test.sh`, 14 tests, kernel-feature tagged, also under ASan/UBSan):
permitted (workspace read/write, /etc read, create/rename/remove); denied (write outside
via absolute/relative/python/grandchild; read outside via absolute/python; symlink escape
read; symlinked-dir write; path replaced by symlink; listing $HOME). These are the same
semantic effects V1 bypassed in Phase 1, now denied by the kernel regardless of spelling.

Full suite: `make check` = 18+12+14+5 = 49 tests green; `make check-asan` all 49 clean.

## 2026-09-24 — Session 1: Phase 5 (seccomp-BPF + no_new_privs)

Design comparison recorded in ARCHITECTURE (libseccomp vs hand-written cBPF -> cBPF chosen:
no dependency, small filter). Added `seccomp.{h,c}`: runtime-built classic BPF, arch guard
(kill on wrong arch / x32), flat EPERM deny-list from a documented SYS_* table (ptrace,
process_vm_readv/writev, unshare, setns, mount/umount2/pivot_root/chroot/move_mount/
open_tree/mount_setattr, init/finit/delete_module, kexec_load/file_load, reboot, bpf,
perf_event_open, open_by_handle_at, swapon/off), default allow. Each entry commented with
threat / why-not-needed / compat impact. Registered AG_LAYER_SECCOMP (index 2, applied last).

Landlock usability fixes surfaced by running real tools under seccomp tests:
- gcc needs /tmp for temp files -> added `ag_policy_add_default_writes` granting /tmp rw by
  default (documented same-UID broadening; opt out with --no-default-reads). gcc now works.
- `--allow-read <file>` failed with EINVAL because directory-only Landlock rights are
  rejected on a regular file -> add_path now fstat()s and masks the grant to file rights for
  non-dirs. git works with `--allow-read ~/.gitconfig`, and home stays denied otherwise.

Verified (`tests/seccomp_test.sh`, 8 tests, kernel-feature tagged, also under ASan/UBSan):
Seccomp filter mode active (Seccomp: 2); ptrace/unshare/mount return EPERM; ordinary
compile+run and python work; descendants inherit; ptrace via libc also EPERM. Landlock test
updated to use an explicit minimal policy so its /tmp-based "outside" is truly outside the
writable set.

Full suite: `make check` = 18+12+14+8+5 = 57 tests green; `make check-asan` all 57 clean.

## 2026-09-24/25 — Sessions 1–2: Phase 6 (network policy modes + seccomp hardening)

Session 1 wrote the network core (`--net none|all`, `enum ag_net_mode`, `sc_apply(deny_inet)`,
`tests/network_test.sh`) and smoke-tested it green, then added seccomp hardening from a
security-review finding (`allowlist-semantic-escape`: fsopen/fsconfig/fsmount, pidfd_getfd,
syslog, clone() CLONE_NEW* flag filter). It stopped at the live V1 Bash limit (51/50) with
the hardening unbuilt; the session cwd was `sandbox/`, so the file-policy hook blocked writes
to `docs/process/*` and a temporary `sandbox/RESUME.md` held the checkpoint. Session 2
(cwd = repo root) folded that file into these docs and removed it.

Session 2 verified the preserved BPF (clone block: jf=4 / jt=1; socket block reload of `nr`
because the clone block clobbers A) and then changed:
- socket rule: deny-list (INET/INET6/PACKET) → **allowlist** (AF_UNIX, AF_NETLINK), so
  AF_VSOCK and other families are denied too. Block is 6 instructions.
- `clone3` → ENOSYS so libc falls back to the flag-filtered `clone()` (closes the clone3
  namespace path instead of only documenting it).
- `io_uring_setup/enter/register` denied (IORING_OP_SOCKET/CONNECT would bypass seccomp).
- network mode is part of `ag_negotiation`; `--status`/`--json` report
  `"network":{"mode":…,"enforced":…}`; degraded runs with seccomp missing warn that
  `--net none` is not enforced (no silent downgrade).
- tests: network_test.sh rewritten around out-of-sandbox loopback listeners that log arrivals
  (21 cases incl. IPv6, raw/AF_PACKET/AF_VSOCK, bash /dev/tcp, descendants, contract);
  seccomp_test.sh +9 cases (clone flags, clone3, fsopen, pidfd_getfd, io_uring, fork+pthread,
  python threads/subprocess, git).

Baseline (same helper unsandboxed): clone(NEWUSER) and clone3 succeed, pidfd_getfd EBADF,
io_uring_setup EFAULT → those tests discriminate. fsopen and clone(NEWNET) are EPERM even
unsandboxed (no caps); syslog not tested (dmesg_restrict=1 makes it EPERM regardless).

**Finding (VERIFIED escape, all modes):** inside `--net none`, `systemd-run --user --wait`
over `/run/user/1000/bus` launched a process with `Seccomp: 0`, `NoNewPrivs: 0` and a working
AF_INET socket. AF_UNIX connects to same-UID services are unmediated at Landlock ABI 8.
Recorded in THREAT_MODEL §4.1 and ARCHITECTURE; to be addressed in Phase 9. Landlock TCP port
rules (PLAN 6.2) deliberately not used — port-only TCP without UDP cannot back a truthful
intermediate mode on this kernel.

Verified: `make -C sandbox check` = 18+12+14+17+21+5 = **87** green; `make -C sandbox
check-asan` = **87** green, no sanitizer reports.
