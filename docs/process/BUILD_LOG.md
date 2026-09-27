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

## 2026-09-25 — Session 2: Phase 7 (resource limits)

Measured first: the runner's cgroup is the terminal's `vte-spawn-….scope` (user-owned,
controllers `memory pids` available, `subtree_control` empty, 11 unrelated processes). So a
kill tier is safely available (owned child cgroup, no controllers needed) but aggregate
pids/memory limits are not (would require writing a parent cgroup we do not own; blocked by
the no-internal-process rule anyway). Implemented accordingly:

- 7.1 rlimits (`lifecycle.c` `apply_rlimits`, soft = hard): `RLIMIT_CORE`=0 always;
  `--max-file-size` (`RLIMIT_FSIZE`), `--max-open-files` (`RLIMIT_NOFILE`, ≥16) on request.
  `RLIMIT_NPROC` deliberately not used (per-UID system-wide).
- 7.2 no new timer: `--timeout` stays the Phase 2 supervisor deadline; its teardown now
  also writes `cgroup.kill`.
- 7.3 `cgroup.{h,c}` + layer `cgroup_kill` (index 1). New *opportunistic* layer kind in the
  negotiation: requested when available, never required, an apply failure is reported
  `not-applied` rather than refusing. The child joins as its first action.
- status: `resources` block (timeout, rlimits, `aggregate_limits: "unavailable"`).

Bugs found and fixed while building it: (1) `ag_write_all` returns 0 on success, not a byte
count — join/kill checks were inverted; (2) FD sanitation closed the inherited
`cgroup.procs` fd before the layer ran (strace: `write(6,"0") = EBADF`) → join moved to the
first line of `child_exec`, the layer reports the recorded outcome; (3) test race: the
escapee fixture exited before `setsid` completed, so group teardown killed it in both arms
and the discrimination case failed — fixture now waits for the new session.

Verified: `tests/resource_test.sh` 14/14 (6 host-only cgroup cases ran on the dev host,
not skipped); `make -C sandbox check` = 18+12+14+17+21+14+5 = **101**; `check-asan` =
**101**, no sanitizer reports.

## 2026-09-25 — Session 2 (continued): Phase 8 (policy format + integrity)

CI for Phases 6 and 7 green (runs 36180346531, 36181400237). Added `policyfile.{h,c}`
(strict line-based `key = value` parser, fd-based open, inode location walk),
`--policy`, `ag_policy_from_options` in `policy.c` (the one options→policy builder, now
used by `lifecycle.c` too), public shared value parsers in `options.c`, a runner-binary
location check in `main.c`, and a `control` block in status/JSON. No CLI merge: covered
flags alongside `--policy` exit 125. Design and grammar: ARCHITECTURE "Policy file".

Defect fixed in a completed phase, with a regression test: `--timeout nan` passed the
`sec < 0 || sec > 1e7` range check (NaN compares false) and reached an undefined
double→long conversion; the check is now `!(sec >= 0 && sec <= 1e7)`, test in
policy_test.sh.

Test-writing bugs caught before trusting results: a single 8 KiB write under a 4 KiB
`RLIMIT_FSIZE` is a short write, not EFBIG (now chunked); `printf … | bad` ran the checker
in a pipeline subshell so its counts were lost (29 counted of 66 run) — `shopt -s lastpipe`.

Dev-environment notes: the V1 file-policy hook also blocks Write to the session scratchpad
(outside the workspace); throwaway scripts went to the git-ignored `sandbox/build/`.

Verified: `tests/policy_test.sh` 66/66; `make -C sandbox check` =
18+12+14+17+21+14+66+5 = **167**; `check-asan` = **167**, no sanitizer reports. Phase 8
guarantees remain subject to the verified host-IPC escape (THREAT_MODEL §4.1).
CI for Phase 8: run 36188382679 green.

## 2026-09-26 — Session 2 (continued): Phase 9 baseline probe (no code change)

Only 4 Bash commands remained in this Claude session, so Phase 9 was not started; one
disposable probe measured the baseline. Fixtures: an outside `sleep 600` sentinel and an
outside python listener on abstract socket `\0agp9probe`, both killed afterwards.

1. Standalone C program: `landlock_create_ruleset` with a locally defined attr
   `{handled_access_fs = 0, handled_access_net = 0, scoped = 1|2}` (ABSTRACT_UNIX_SOCKET |
   SIGNAL) returned an fd on ABI 8; after `no_new_privs` + `restrict_self`:
   `kill(sentinel, 0)` = -1 EPERM, abstract connect to the outside listener = -1 EPERM,
   `socketpair(AF_UNIX)` = 0.
2. `agentguard-run --workspace <scratch> -- sh -c …` (net none, current layers): `kill -0
   sentinel` permitted; `prlimit --pid sentinel --nofile=77:77` rc 0 and the sentinel's
   `/proc/<pid>/limits` read 77/77 from outside; abstract connect succeeded and the
   listener logged 1 hit; `pidfd_open` + `pidfd_send_signal(fd, 0)` permitted;
   `connect("/run/user/1000/bus")` succeeded.

Classification recorded in THREAT_MODEL (VERIFIED GAPs). Next steps in BUILD_STATE.

## 2026-09-26 — Session 3: Phase 9 slice 1 (Landlock scope + prlimit64)

Scope for this session was deliberately narrow (defensive only): no reproduction of the
session-D-Bus escape and no interaction with real user services; every outside party is a
fixture the suite creates (a `sleep 300` sentinel, a python listener on a random abstract
name). The D-Bus escape stays OPEN.

Measured first (strace, dev host): glibc `ulimit`/`setrlimit`/`getrlimit` and python
`resource.setrlimit` call `prlimit64(0, …)`; node `child_process` and gcc/git/python asyncio
create AF_UNIX sockets only via `socketpair(AF_UNIX, SOCK_STREAM)`; `claude --version`
creates no sockets; `/proc/sys/dev/tty/legacy_tiocsti` = 0; the installed
`linux/landlock.h` has no `scoped` member.

Changes: new required layer `landlock_scope` (index after `landlock_fs`, probe ABI >= 6)
applying a second, scope-only Landlock domain (`ABSTRACT_UNIX_SOCKET | SIGNAL`, attr struct
defined locally); seccomp block allowing `prlimit64` only with pid 0; new suite
`sandbox/tests/hostipc_test.sh` wired into `check` and `check-asan`.

TDD evidence: first run with only the scope layer = 24 pass / 3 fail — the three outside
prlimit cases changed the sentinel's `RLIMIT_NOFILE` to 77, 66 and 55 (read outside from
`/proc/<pid>/limits`). After the seccomp rule: 27/27, sentinel unchanged; util-linux
`prlimit --nofile=200:200 sh -c 'ulimit -n'` inside prints 200 (uses pid 0).

Verified: `tests/hostipc_test.sh` 27/27 (0 skipped); `make -C sandbox check` =
18+12+14+17+21+14+66+27+5 = **194**; `check-asan` = **194**, no ASan/UBSan/LSan reports.
V1 `tests/run_tests.sh` 40/40. CI only runs the V1 suite, so it says nothing
about these changes. TEST_PLAN's CI column corrected accordingly.

## 2026-09-27 — Phase 9 slice 2: disposable IPC evidence, SysV denial, FD capacity

Reconciled first: local branch `v2/kernel-sandbox`, clean worktree, HEAD and remote HEAD
both `244e472b3c8e47d9e7f86351b78d1a030cd95230`. No history rewrite or merge. Tool sandbox
startup failed before execution (`bwrap` loopback permission); repository commands ran
through reviewed escalation as the ordinary user. No hooks or host settings changed.
Capability audit reconfirms kernel 7.0.0-31, Landlock ABI 8, Yama 1, available owned-cgroup
kill tier, unavailable usable namespace tier.

Reproduced before fixing: extended suite had four failures — 64 kept fds refused setup
(EBADF), and the sandbox changed each owned SysV shm/sem/msg fixture. Added seccomp
SysV creation/access/control denials; fixed the keep-array capacity to include the report
pipe in addition to stdio and all 64 user keeps. Afterward the fixture states remain
unchanged; disabling seccomp reproduces their effects. No real SysV ID is inspected.

Outside sentinel explicitly opts into tracing; baseline memory operations succeed,
seccomp independently blocks ptrace/process_vm, and Landlock independently blocks those
plus proc-mem/proc-fd access. This discriminates AgentGuard from host Yama enforcement.
Non-kept Unix/pidfd authority is closed; explicit kept socket traffic succeeds, while
Landlock still denies signalling through a kept pidfd.

Evaluated a test-only AF_UNIX socket + datagram socketpair deny filter. It blocks owned
pathname STREAM/DGRAM/SEQPACKET/socketpair-DGRAM traffic in both net modes, but breaks
multiprocessing.Manager. Preserve compatibility using the canonical explicit-reporting
fallback: runtime does not install the candidate, and status/help explicitly disclaim
host IPC isolation even in strict mode. Pre-run status no longer credits unavailable
requested seccomp as network/SysV enforcement. Candidate compatibility: gcc/git/Node,
claude version, asyncio/socketpair/pipe multiprocessing, localhost NSS and syslog fallback
pass with fresh HOME/minimal environment; no real service contacted.

Additional fixture limits recorded: default `/dev/shm` object readable (not writable),
new `/dev/pts` slave writable, NETLINK_USERSOCK reaches outside fixture. TIOCSTI is EIO
both outside/inside (host policy). The first TTY test incorrectly called setsid from a
process-group leader; corrected it to fork first, then measured the ioctl. No real tty
is touched. Threat-model inventory, architecture, walkthrough, test plan and build state
updated. **Real session-D-Bus finding stays OPEN; no reproduction attempted. Phase 9
closure not claimed; Phase 10 not started.** Scheduling/POSIX queue inventory still pending.

Validation (dev host, no skips):
- `make -C sandbox all`: warning-clean production build.
- `python3 sandbox/tests/hostipc_extended_test.py`: 13/13 test methods, with mode/operation
  subtests (not inflated into the top-level count).
- `bash sandbox/tests/hostipc_test.sh`: 27/27.
- `make -C sandbox check`: **207/207**, including all six host-only cgroup cases.
- `make -C sandbox check-asan`: **207/207**, no ASan/UBSan/LSan reports. Make target now
  builds in `build/asan` and invokes the same suite list, without deleting normal output.
- `bash tests/run_tests.sh`: **40/40**.
- `bash scripts/capability_audit.sh`; `git diff --check`: passed.
Local full output: ignored `build/phase9-{check,asan,v1,capabilities}.log`.

## 2026-09-27 — Phase 9 slice 3: outside scheduling and POSIX queue inventory

Continued after committing/pushing slice 2 (`b305ee5`). Disposable scheduling probes
reproduced six failing cases: setpriority, sched_setaffinity, sched_setscheduler,
sched_setparam, sched_setattr, ioprio_set all succeeded against an outside sentinel.
Externally observed effects: nice 0→19, affinity 12 CPUs→1, policy OTHER→BATCH, I/O
priority 0→IDLE. sched_setparam priority 0 is a no-op (return-code evidence only).
Each sentinel owns a fresh session/process group; group-selector tests never select the
real user's process group or UID. No real user processes or persistent objects touched.

Root-cause fix: shared seccomp pid-zero blocks for prlimit64 and the four scheduler
setters; selector+who-zero blocks for setpriority/ioprio_set. Nonzero PIDs/TIDs and
group/UID selectors rejected, including inside peers. This compatibility limitation is
explicit; nice/taskset/chrt/ionice launches and self APIs pass. Disabled-seccomp controls
still mutate fixture state; protected controls leave all outside values unchanged.

POSIX named queue: exclusive fresh name, baseline send/receive succeed, current Landlock
configuration denies opens for both with EACCES and preserves outside queue contents.
Seccomp omission retains denial; omitting both Landlock domains permits effects. No new
queue rule was needed. Do not generalize the observed open protection to all operations,
policies or ABIs. Queue closed/unlinked by fixture owner.

Review also made UBSan diagnostics fatal (`halt_on_error=1:print_stacktrace=1`), including
the extended suite's isolated environment. Otherwise a captured recoverable diagnostic
could exit zero. Corrected old threat-table degraded-mode wording: nnp and filesystem
integrity depend on the respective applied layers; deadline teardown does not guarantee
killing setsid escapees without the cgroup tier.

Validation, dev host (all passed, zero skips):
- `make -C sandbox all` (warning-clean).
- `python3 sandbox/tests/hostipc_extended_test.py`: **16/16**, including grouped
  baseline, degraded, protected and self-directed scheduling/IPC operations.
- `bash sandbox/tests/seccomp_test.sh`: **17/17**.
- `bash sandbox/tests/hostipc_test.sh`: **27/27**.
- `make -C sandbox check`: **210/210**, all six host-only cgroup cases ran.
- `make -C sandbox check-asan`: **210/210**; repeated with fatal UBSan, **210/210**,
  no ASan/UBSan/LSan reports.
- `bash tests/run_tests.sh`: **40/40**; `git diff --check`: passed.
Full local logs: ignored `build/phase9-final-{check,asan,asan-fatal,v1}.log`.

Updated BUILD_STATE, this log, THREAT_MODEL, ARCHITECTURE, TEST_PLAN and WALKTHROUGH.
Phase 9 remains **IN PROGRESS**: the recorded real session-bus authority regression is
not authorized and has not run. Its finding remains OPEN; pathname sockets, netlink,
shared default grants and explicit inherited authority remain classified limitations.
No scope removed, no Phase 10 work, no strict host-isolation guarantee. Exact next action:
resume from BUILD_STATE and the inventory; separately authorize the real authority-path
verification before attempting it, and satisfy the unchanged gate before advancing.
