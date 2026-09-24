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
