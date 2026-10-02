#!/usr/bin/env bash
# Phase 10: common developer workflows inside the sandbox, and the agent wrapper.
# Everything runs in a disposable root with a fake HOME. The root lives under
# sandbox/build/ (not /tmp) so that "outside" fixtures are outside every root the
# default policy grants (/tmp is default-writable). Oracles are effects observed
# outside the sandbox: files present/absent, bytes unchanged, program output.
set -u

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
REPO_DIR="$(cd -- "$SANDBOX_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"
RUN="$(cd -- "$(dirname -- "$RUN")" && pwd -P)/$(basename -- "$RUN")"
AGENT="$SANDBOX_DIR/scripts/agentguard-agent"

PASS=0; FAIL=0; SKIP=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }
skip() { SKIP=$((SKIP + 1)); printf 'SKIP %s -- %s\n' "$1" "$2"; }

status_json="$("$RUN" --status --json 2>/dev/null)"
if [[ "$status_json" != *'"name":"landlock_fs","available":true'* ||
      "$status_json" != *'"name":"seccomp","available":true'* ]]; then
    skip "dev workflow suite" "Landlock FS or seccomp unavailable on this kernel (see --status)"
    printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
fi

mkdir -p "$SANDBOX_DIR/build"
ROOT="$(mktemp -d "$SANDBOX_DIR/build/agentguard-devwf.XXXXXX")" || exit 1
cleanup() { [[ "$ROOT" == */agentguard-devwf.* ]] && rm -rf -- "$ROOT"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

WS="$ROOT/ws"; OUT="$ROOT/outside"; FHOME="$ROOT/home"
mkdir -p "$WS" "$OUT" "$FHOME/.ssh" "$FHOME/.claude"
printf 'OUTSIDE_SECRET_P10\n' > "$OUT/secret"
printf 'FAKE_KEY_P10\n' > "$FHOME/.ssh/id_fixture"
printf '{}\n' > "$FHOME/.claude.json"
# Fixture builds must not inherit the outer `make check` (flags, -w, sanitizer CFLAGS).
unset MAKEFLAGS MFLAGS MAKELEVEL
export HOME="$FHOME" GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t \
       GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
outside_clean() { [[ ! -e "$OUT/loot" && "$(cat "$OUT/secret")" == "OUTSIDE_SECRET_P10" ]]; }
run() { ( cd "$WS" && "$RUN" --workspace "$WS" -- "$@" ); }

# ---------------------------------------------------------------------------
# Shell and build output inside the workspace
# ---------------------------------------------------------------------------
out="$(run bash -c 'set -e; mkdir -p out; for i in 1 2 3; do echo $i; done | sort -r > out/list
                    tr "\n" , < out/list; cd out && ln -s list alias && cat alias | wc -l' 2>&1)"
[[ "$out" == "3,2,1,3" && -f "$WS/out/list" ]] && pass "shell: pipes, redirects, symlink, files in workspace" ||
    fail "shell workflow" "$out"

# ---------------------------------------------------------------------------
# git in a disposable repository
# ---------------------------------------------------------------------------
out="$(run bash -c 'set -e; git init -q repo; cd repo; printf "a\n" > f; git add f
                    git commit -qm init; git rev-list --count HEAD' 2>&1)"
[[ "$out" == "1" ]] && pass "git: init/add/commit" || fail "git commit" "$out"
out="$(run bash -c 'cd repo && printf "b\n" >> f && printf n > new && git status --porcelain' 2>&1)"
[[ "$out" == *" M f"* && "$out" == *"?? new"* ]] && pass "git: status --porcelain sees edit + untracked" ||
    fail "git status" "$out"
out="$(run bash -c 'cd repo && git diff --stat && git diff | grep "^+b"' 2>&1)"
[[ "$out" == *"1 insertion"* && "$out" == *"+b"* ]] && pass "git: diff shows the change" || fail "git diff" "$out"
out="$(run bash -c 'set -e; cd repo; git switch -qc feat; git commit -qam two; git log --oneline | wc -l
                    git switch -q -; git merge -q --ff-only feat; git rev-list --count HEAD' 2>&1)"
[[ "$out" == $'2\n2' ]] && pass "git: branch, commit -a, switch, fast-forward merge" || fail "git branch" "$out"

# ---------------------------------------------------------------------------
# make + gcc multi-file build with build output in the workspace
# ---------------------------------------------------------------------------
mkdir -p "$WS/proj"
printf 'int add(int a, int b) { return a + b; }\n' > "$WS/proj/add.c"
printf '#include <stdio.h>\nint add(int, int);\nint main(void) { printf("sum=%%d\\n", add(2, 3)); return 0; }\n' > "$WS/proj/main.c"
printf 'build/app: build/main.o build/add.o\n\t$(CC) -o $@ $^\nbuild/%%.o: %%.c | build\n\t$(CC) -Wall -Werror -c -o $@ $<\nbuild:\n\tmkdir -p build\nescape:\n\tprintf x > %s/loot\n' "$OUT" > "$WS/proj/Makefile"
out="$(run bash -c 'make -s -C proj && ./proj/build/app' 2>&1)"
[[ "$out" == "sum=5" && -f "$WS/proj/build/add.o" ]] && pass "build: make + gcc multi-file, objects in workspace" ||
    fail "make build" "$out"
out="$(run make -s -C proj escape 2>&1)"; rc=$?
[[ $rc -ne 0 ]] && outside_clean && pass "descendant: make recipe cannot write outside the workspace" ||
    fail "make escape" "rc=$rc $out"

# ---------------------------------------------------------------------------
# Python and Node process trees
# ---------------------------------------------------------------------------
out="$(run python3 -c '
import asyncio, subprocess, sys
open("py.txt", "w").write("py")
r = subprocess.run([sys.executable, "-c", "print(open(\"py.txt\").read())"], capture_output=True, text=True)
async def main():
    p = await asyncio.create_subprocess_exec("sh", "-c", "echo async", stdout=asyncio.subprocess.PIPE)
    return (await p.communicate())[0].decode().strip()
print(r.stdout.strip(), asyncio.run(main()))' 2>&1)"
[[ "$out" == "py async" ]] && pass "python: file write, subprocess, asyncio subprocess" || fail "python" "$out"
out="$(run python3 -c "
import subprocess
r = subprocess.run(['sh', '-c', 'cat $OUT/secret; printf x > $OUT/loot'], capture_output=True, text=True)
print('LEAK' if 'OUTSIDE_SECRET' in r.stdout else 'DENIED')" 2>&1)"
[[ "$out" == "DENIED" ]] && outside_clean && pass "descendant: python -> sh grandchild cannot read/write outside" ||
    fail "python grandchild" "$out"
if command -v node >/dev/null 2>&1; then
    node_dir="$(dirname -- "$(readlink -f -- "$(command -v node)")")"
    out="$( cd "$WS" && "$RUN" --workspace "$WS" --allow-read "$node_dir" -- node -e '
const cp = require("child_process"); const fs = require("fs");
fs.writeFileSync("node.txt", cp.execSync("echo exec").toString().trim());
const r = cp.spawnSync("sh", ["-c", "cat " + process.argv[1] + "/secret"], {encoding: "utf8"});
console.log(fs.readFileSync("node.txt", "utf8"), r.status !== 0 && !r.stdout.includes("SECRET") ? "denied" : "LEAK");' "$OUT" 2>&1)"
    [[ "$out" == "exec denied" ]] && pass "node: child_process works, child cannot read outside" ||
        fail "node" "$out"
else
    skip "node child_process" "node not installed"
fi

# ---------------------------------------------------------------------------
# git hook (a descendant git spawns) and HOME confidentiality
# ---------------------------------------------------------------------------
printf '#!/bin/sh\n(printf x > %s/loot) 2>/dev/null\ncat %s/secret > leaked 2>/dev/null\nexit 0\n' "$OUT" "$OUT" \
    > "$WS/repo/.git/hooks/pre-commit"
chmod +x "$WS/repo/.git/hooks/pre-commit"
out="$(run bash -c 'cd repo && printf c >> f && git commit -qam hook && git rev-list --count HEAD && wc -c < leaked' 2>&1)"
[[ "$out" == $'3\n0' ]] && outside_clean && pass "descendant: git pre-commit hook cannot touch outside; commit proceeds" ||
    fail "git hook" "$out"
out="$(run sh -c 'cat "$HOME/.ssh/id_fixture" 2>/dev/null || echo DENIED; ls "$HOME" 2>/dev/null || echo NOLIST')"
[[ "$out" == $'DENIED\nNOLIST' ]] && pass "home: \$HOME files are neither readable nor listable by default" ||
    fail "home confidentiality" "$out"

# ---------------------------------------------------------------------------
# agentguard-agent wrapper with a fixture agent (no real agent, no network)
# ---------------------------------------------------------------------------
mkdir -p "$ROOT/agentbin"
cat > "$ROOT/agentbin/fake-agent" <<EOF
#!/bin/sh
printf edited > agent-out.txt || exit 3
printf state > "\$HOME/.claude/state" || exit 4
printf '{"n":1}' > "\$HOME/.claude.json" || exit 5
git status --porcelain >/dev/null || exit 6
cat "\$HOME/.ssh/id_fixture" 2>/dev/null && exit 7
(printf x > "$OUT/loot") 2>/dev/null && exit 8
echo AGENT_OK
EOF
chmod +x "$ROOT/agentbin/fake-agent"
out="$( cd "$WS/repo" && PATH="$ROOT/agentbin:$PATH" AGENTGUARD_RUN="$RUN" AGENTGUARD_NET=none \
        "$AGENT" -- fake-agent 2>&1)"; rc=$?
[[ "$rc" == 0 && "$out" == "AGENT_OK" && "$(cat "$WS/repo/agent-out.txt")" == "edited" &&
   "$(cat "$FHOME/.claude/state")" == "state" ]] && outside_clean &&
    pass "agent wrapper: repo + agent state writable; ~/.ssh and outside denied; agent from \$HOME-like dir runs" ||
    fail "agent wrapper" "rc=$rc $out"
out="$( cd "$WS" && AGENTGUARD_RUN="$RUN" "$AGENT" -- definitely-not-an-agent-p10 2>&1)"; rc=$?
[[ $rc -eq 127 && "$out" == *"command not found"* ]] && pass "agent wrapper: missing agent exits 127" ||
    fail "agent wrapper missing" "rc=$rc $out"
out="$( cd "$WS/repo" && PATH="$ROOT/agentbin:$PATH" AGENTGUARD_RUN="$RUN" \
        "$AGENT" --status --json -- fake-agent 2>/dev/null)"
[[ "$out" == *'"network":{"mode":"all"'* && "$out" == *'"isolation_enforced":false'* ]] &&
    pass "agent wrapper: default --net all and host-IPC limit visible in status" || fail "agent status" "$out"

# ---------------------------------------------------------------------------
# V1 workflow guardrails keep working when the whole session runs under V2
# ---------------------------------------------------------------------------
out="$( cd "$WS" && "$RUN" --workspace "$WS" --allow-read "$REPO_DIR" -- bash "$REPO_DIR/tests/run_tests.sh" 2>&1 | tail -1)"
[[ "$out" =~ ^([0-9]+)\ passed,\ 0\ failed$ && "${BASH_REMATCH[1]}" -ge 40 ]] &&
    pass "V1 hook suite runs unchanged inside the sandbox ($out)" || fail "V1 inside V2" "$out"

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
