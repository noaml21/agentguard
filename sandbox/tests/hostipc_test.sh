#!/usr/bin/env bash
# Phase 9: host IPC / same-UID surface tests. Kernel-feature dependent.
# Every outside party is a disposable fixture created here (a sleep sentinel and
# a python abstract-unix listener); no real user process or service is touched.
# Oracles are effects observed OUTSIDE the sandbox: the sentinel is still alive,
# its /proc limits are unchanged, the listener recorded no connection.
set -u

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"
RUN="$(cd -- "$(dirname -- "$RUN")" && pwd -P)/$(basename -- "$RUN")"

PASS=0; FAIL=0; SKIP=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }
skip() { SKIP=$((SKIP + 1)); printf 'SKIP %s -- %s\n' "$1" "$2"; }

status_json="$("$RUN" --status --json 2>/dev/null)"
have_scope=0; have_sc=0
[[ "$status_json" == *'"name":"landlock_scope","available":true'* ]] && have_scope=1
[[ "$status_json" == *'"name":"seccomp","available":true'* ]] && have_sc=1

TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-ipc.XXXXXX")" || exit 1
FIXTURE_PIDS=()
cleanup() {
    for p in "${FIXTURE_PIDS[@]}"; do kill "$p" 2>/dev/null; done
    [[ "$TMP" == */agentguard-ipc.* ]] && rm -rf -- "$TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
run() { ( cd "$TMP" && "$RUN" --workspace "$TMP" "${EXTRA[@]}" -- "$@" ); }
EXTRA=()

# Disposable outside sentinel (same UID, not a descendant of the runner).
sleep 300 & SENT=$!; FIXTURE_PIDS+=("$SENT")
alive() { kill -0 "$SENT" 2>/dev/null; }
nofile_soft() { awk '/^Max open files/ {print $4}' "/proc/$SENT/limits"; }

# ---------------------------------------------------------------------------
# Landlock scope: signals and abstract AF_UNIX
# ---------------------------------------------------------------------------
if [[ "$have_scope" -eq 1 ]]; then
    out="$(run sh -c "kill -0 $SENT 2>/dev/null; echo \$?")"
    [[ "$out" == "1" ]] && alive && pass "signal: kill -0 outside sentinel denied" ||
        fail "kill -0 outside" "rc=$out"
    out="$(run sh -c "kill -TERM $SENT 2>&1; echo rc=\$?")"
    sleep 0.2
    [[ "$out" == *"rc=1"* ]] && alive && pass "signal: SIGTERM to outside sentinel denied, sentinel alive" ||
        fail "SIGTERM outside" "$out alive=$(alive && echo y || echo n)"
    out="$(run python3 -c "
import os, signal
fd = os.pidfd_open($SENT)
try:
    signal.pidfd_send_signal(fd, signal.SIGTERM); print('SENT')
except PermissionError: print('EPERM')" 2>&1)"
    sleep 0.2
    [[ "$out" == "EPERM" ]] && alive && pass "signal: pidfd_open ok but pidfd_send_signal denied (EPERM)" ||
        fail "pidfd_send_signal" "$out"
    out="$(run sh -c "sh -c 'sh -c \"kill -TERM $SENT\" 2>/dev/null; echo \$?'")"
    sleep 0.2
    [[ "$out" == "1" ]] && alive && pass "signal: grandchild also denied (descendants inherit scope)" ||
        fail "descendant signal" "$out"
    out="$(run sh -c 'kill -0 $PPID 2>/dev/null; echo $?')"
    [[ "$out" == "1" ]] && pass "signal: target cannot signal the (outside) supervisor" ||
        fail "signal supervisor" "$out"
    out="$(run sh -c 'sleep 30 & p=$!; kill -TERM $p; wait $p; echo $?' 2>/dev/null)"
    [[ "$out" == "143" ]] && pass "signal: signalling own child inside the sandbox works" ||
        fail "inside signal" "$out"

    # Outside abstract listener; each accepted connection appends to $TMP/hits.
    ABS="agentguard-p9-$$-$RANDOM"
    python3 - "$ABS" "$TMP/hits" "$TMP/ready" <<'PY' &
import socket, sys
name, hits, ready = sys.argv[1:4]
s = socket.socket(socket.AF_UNIX); s.bind("\0" + name); s.listen(8)
open(ready, "w").close()
while True:
    c, _ = s.accept(); open(hits, "a").write("hit\n"); c.close()
PY
    FIXTURE_PIDS+=("$!")
    for _ in $(seq 50); do [[ -e "$TMP/ready" ]] && break; sleep 0.1; done
    : > "$TMP/hits"
    # Positive control: the listener works for an outside client.
    python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.connect('\0$ABS')"
    sleep 0.2
    [[ "$(wc -l < "$TMP/hits")" == "1" ]] && pass "abstract: outside control connection recorded" ||
        fail "abstract control" "hits=$(wc -l < "$TMP/hits")"
    : > "$TMP/hits"
    out="$(run python3 -c "
import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect('\0$ABS'); print('CONNECTED')
except PermissionError: print('EPERM')" 2>&1)"
    sleep 0.2
    hits="$(wc -l < "$TMP/hits")"
    [[ "$out" == "EPERM" && "$hits" == "0" ]] && pass "abstract: connect to outside listener denied, 0 hits" ||
        fail "abstract outside" "$out hits=$hits"
    out="$(run sh -c "python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.connect('\\\\0$ABS'); print('CONNECTED')\" 2>/dev/null || echo DENIED")"
    sleep 0.2
    hits="$(wc -l < "$TMP/hits")"
    [[ "$out" == "DENIED" && "$hits" == "0" ]] && pass "abstract: descendant also denied, 0 hits" ||
        fail "abstract descendant" "$out hits=$hits"
    out="$(run python3 -c "
import socket, subprocess, sys
srv = socket.socket(socket.AF_UNIX); srv.bind('\0agentguard-inside-$$'); srv.listen(1)
subprocess.Popen([sys.executable, '-c', \"import socket; c=socket.socket(socket.AF_UNIX); c.connect('\\\\0agentguard-inside-$$'); c.sendall(b'hi')\"])
c, _ = srv.accept(); print('INSIDE_OK' if c.recv(2) == b'hi' else 'BAD')" 2>&1)"
    [[ "$out" == "INSIDE_OK" ]] && pass "abstract: listener and client inside the same sandbox work" ||
        fail "abstract inside" "$out"
else
    skip "landlock_scope cases (12)" "Landlock ABI < 6 on this kernel (status: landlock_scope unavailable)"
fi

# ---------------------------------------------------------------------------
# Compatibility of ordinary local IPC and dev workflows under the new layers
# ---------------------------------------------------------------------------
out="$(run python3 -c "
import socket
a, b = socket.socketpair(); a.sendall(b'ok'); print('SP_OK' if b.recv(2) == b'ok' else 'BAD')" 2>&1)"
[[ "$out" == "SP_OK" ]] && pass "compat: socketpair(AF_UNIX, SOCK_STREAM) round trip" || fail "socketpair" "$out"
out="$(run python3 -c "
import asyncio
async def main():
    p = await asyncio.create_subprocess_exec('echo', 'x', stdout=asyncio.subprocess.PIPE)
    o, _ = await p.communicate(); await asyncio.sleep(0)
    return o.strip() == b'x' and p.returncode == 0
print('ASYNC_OK' if asyncio.run(main()) else 'BAD')" 2>&1)"
[[ "$out" == "ASYNC_OK" ]] && pass "compat: python asyncio + subprocess" || fail "asyncio" "$out"
out="$(run python3 -c 'import threading,subprocess
r=[]; t=threading.Thread(target=lambda: r.append(1)); t.start(); t.join()
print("PYT" if r==[1] and subprocess.run(["true"]).returncode==0 else "BAD")' 2>&1)"
[[ "$out" == "PYT" ]] && pass "compat: python threads + subprocess" || fail "python threads" "$out"
out="$(run sh -c 'printf "int main(){return 0;}" > w.c && gcc w.c -o w && ./w && echo OK' 2>&1)"
[[ "$out" == "OK" ]] && pass "compat: gcc compile + run" || fail "gcc" "$out"
out="$(run env HOME="$TMP" sh -c 'git init -q repo && cd repo && echo x > f && git add f &&
    git -c user.name=t -c user.email=t@t commit -qm m && git log --oneline | wc -l' 2>&1)"
[[ "$out" == "1" ]] && pass "compat: git init/add/commit" || fail "git" "$out"
NODE="$(command -v node 2>/dev/null)"
if [[ -n "$NODE" ]]; then
    NODE="$(readlink -f "$NODE")"
    EXTRA=(--allow-read "$(dirname -- "$(dirname -- "$NODE")")")
    out="$(run "$NODE" -e '
const cp = require("child_process");
const a = cp.execSync("echo x").toString().trim();
const b = cp.spawnSync("sh", ["-c", "echo y"], {stdio: "pipe"}).stdout.toString().trim();
console.log(a === "x" && b === "y" ? "NODE_OK" : "BAD")' 2>&1)"
    EXTRA=()
    [[ "$out" == "NODE_OK" ]] && pass "compat: node child_process execSync + spawnSync" || fail "node" "$out"
else
    skip "compat: node child_process" "node not installed"
fi

# ---------------------------------------------------------------------------
# prlimit64: self-only (pid 0); an outside sentinel's limits must not change
# ---------------------------------------------------------------------------
if [[ "$have_sc" -eq 1 ]]; then
    before="$(nofile_soft)"
    out="$(run prlimit --pid "$SENT" --nofile=77:77 2>&1; echo "rc=$?")"
    after="$(nofile_soft)"
    [[ "$out" == *"rc=1"* && "$after" == "$before" && "$after" != "77" ]] &&
        pass "prlimit: outside sentinel limits unchanged ($after)" ||
        fail "prlimit outside" "$out before=$before after=$after"
    out="$(run python3 -c "
import resource
try:
    resource.prlimit($SENT, resource.RLIMIT_NOFILE, (66, 66)); print('CHANGED')
except PermissionError: print('EPERM')" 2>&1)"
    after="$(nofile_soft)"
    [[ "$out" == "EPERM" && "$after" == "$before" ]] && pass "prlimit: python resource.prlimit(outside) denied" ||
        fail "python prlimit outside" "$out after=$after"
    out="$(run sh -c "sh -c 'prlimit --pid $SENT --nofile=55:55' 2>/dev/null; echo \$?")"
    after="$(nofile_soft)"
    [[ "$out" == "1" && "$after" == "$before" ]] && pass "prlimit: descendant also denied" ||
        fail "prlimit descendant" "$out after=$after"
    out="$(run sh -c 'ulimit -n 512 && ulimit -n' 2>&1)"
    [[ "$out" == "512" ]] && pass "prlimit: shell ulimit (self, pid 0) works" || fail "ulimit self" "$out"
    out="$(run python3 -c "
import resource
resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
print(resource.getrlimit(resource.RLIMIT_NOFILE)[0])" 2>&1)"
    [[ "$out" == "256" ]] && pass "prlimit: python setrlimit/getrlimit (self) works" || fail "python self" "$out"
    out="$(run python3 -c "
import resource
print(resource.prlimit(0, resource.RLIMIT_NOFILE)[0])" 2>&1)"
    [[ "$out" =~ ^[0-9]+$ ]] && pass "prlimit: explicit prlimit(0, ...) query works" || fail "prlimit 0" "$out"
else
    skip "prlimit cases (6)" "seccomp unavailable"
fi

# ---------------------------------------------------------------------------
# Fail-closed contract for the new layer (test seam, any kernel)
# ---------------------------------------------------------------------------
out="$(AGENTGUARD_TEST_UNAVAIL=landlock_scope "$RUN" --workspace "$TMP" -- sh -c 'echo RAN' 2>/dev/null)"
rc=$?
[[ "$rc" == "125" && -z "$out" ]] && pass "contract: strict refuses when landlock_scope unavailable" ||
    fail "strict scope unavailable" "rc=$rc out=$out"
out="$(AGENTGUARD_TEST_FAIL=landlock_scope "$RUN" --workspace "$TMP" -- sh -c 'echo RAN' 2>/dev/null)"
rc=$?
[[ "$rc" == "125" && -z "$out" ]] && pass "contract: strict refuses when landlock_scope fails to apply" ||
    fail "strict scope apply-fail" "rc=$rc out=$out"
st="$(AGENTGUARD_TEST_UNAVAIL=landlock_scope "$RUN" --degraded --status 2>/dev/null)"
[[ "$st" == *"landlock_scope   missing"* ]] && pass "contract: degraded status reports landlock_scope missing" ||
    fail "degraded status" "$st"
if [[ "$have_scope" -eq 1 ]]; then
    # Degraded really loses the guarantee (kill -0 only: probes, delivers nothing).
    out="$(cd "$TMP" && AGENTGUARD_TEST_UNAVAIL=landlock_scope "$RUN" --degraded --workspace "$TMP" -- \
        sh -c "kill -0 $SENT; echo \$?" 2>/dev/null)"
    [[ "$out" == "0" ]] && pass "contract: degraded run without scope can reach the sentinel (reported, not hidden)" ||
        fail "degraded reach" "$out"
fi

alive && pass "sentinel survived the whole suite" || fail "sentinel survival" "sentinel $SENT gone"

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
