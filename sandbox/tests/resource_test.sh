#!/usr/bin/env bash
# Phase 7: resource limits. rlimit cases run everywhere (plain setrlimit); the
# cgroup kill tier is HOST-ONLY: it needs a writable (delegated) cgroup v2 and is
# skipped with an explicit reason otherwise. A skip is not verification.
set -u

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"
RUN="$(cd -- "$(dirname -- "$RUN")" && pwd -P)/$(basename -- "$RUN")"

PASS=0; FAIL=0; SKIP=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }
skip() { SKIP=$((SKIP + 1)); printf 'SKIP %s -- %s\n' "$1" "$2"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-res.XXXXXX")" || exit 1
PIDS_TO_KILL=()
cleanup() {
    for p in "${PIDS_TO_KILL[@]}"; do kill "$p" 2>/dev/null; done
    [[ "$TMP" == */agentguard-res.* ]] && rm -rf -- "$TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
run() { ( cd "$TMP" && exec "$RUN" --workspace "$TMP" "$@" ); }

# ---------------- 7.1 rlimits (per process) ----------------
out="$(run -- sh -c 'python3 -c "import resource as r
c = r.getrlimit(r.RLIMIT_CORE)
try:
    r.setrlimit(r.RLIMIT_CORE, (1 << 20, 1 << 20)); raised = \"RAISED\"
except (ValueError, OSError): raised = \"RAISE_DENIED\"
print(c[0], c[1], raised)"' 2>/dev/null)"
[[ "$out" == "0 0 RAISE_DENIED" ]] && pass "core dumps off (soft+hard 0) in descendant; cannot be raised" \
    || fail "rlimit core" "$out"

write_py='import errno, os, sys
n = 0
try:
    with open(sys.argv[1], "wb", buffering=0) as f:
        for _ in range(50): n += f.write(b"x" * 4096)
    print("WROTE", os.path.getsize(sys.argv[1]))
except OSError as e:
    print(errno.errorcode.get(e.errno, e.errno), os.path.getsize(sys.argv[1]))'
out="$(run --max-file-size 65536 -- sh -c "python3 -c '$write_py' big1" 2>/dev/null)"
[[ "$out" == "EFBIG 65536" ]] && pass "max-file-size: write past bound fails EFBIG, file capped at bound (descendant)" \
    || fail "rlimit fsize" "$out"
run --max-file-size 65536 -- sh -c 'head -c 200000 /dev/zero > big2' >/dev/null 2>&1; rc=$?
sz="$(stat -c %s "$TMP/big2" 2>/dev/null)"
[[ "$rc" -ne 0 && "$sz" == 65536 ]] && pass "max-file-size: shell writer stopped at bound (rc=$rc)" \
    || fail "rlimit fsize shell" "rc=$rc size=$sz"
out="$(run -- python3 -c "$write_py" big3 2>/dev/null)"
[[ "$out" == "WROTE 204800" ]] && pass "no --max-file-size: ordinary large write works" || fail "fsize default" "$out"

out="$(run --max-open-files 32 -- python3 -c 'import errno
fs = []
try:
    for i in range(100): fs.append(open("/dev/null"))
    print("OPENED", len(fs))
except OSError as e: print(errno.errorcode[e.errno], len(fs) < 32)' 2>/dev/null)"
[[ "$out" == "EMFILE True" ]] && pass "max-open-files: EMFILE below the bound" || fail "rlimit nofile" "$out"
out="$(run --max-open-files 64 -- sh -c 'printf "int main(void){return 0;}" > w.c && gcc w.c -o w && ./w && echo OK' 2>/dev/null)"
[[ "$out" == "OK" ]] && pass "max-open-files 64: compile workflow still works" || fail "nofile compile" "$out"

bad=0
for args in "--max-file-size 0" "--max-file-size abc" "--max-file-size -5" "--max-open-files 3" "--max-open-files"; do
    # shellcheck disable=SC2086
    "$RUN" $args -- true >/dev/null 2>&1; [[ $? == 125 ]] || bad=1
done
[[ "$bad" == 0 ]] && pass "invalid rlimit values rejected (125)" || fail "rlimit parse" "accepted a bad value"

out="$("$RUN" --max-file-size 4096 --max-open-files 128 --timeout 2.5 --status --json)"
[[ "$out" == *'"resources":{"timeout_ms":2500,"rlimit_core":0,"rlimit_fsize":4096,"rlimit_nofile":128,"aggregate_limits":"unavailable"}'* ]] \
    && pass "status json reports resources (aggregate limits unavailable)" || fail "status resources" "$out"

# ---------------- 7.3 cgroup kill tier (host-only) ----------------
status_json="$("$RUN" --status --json 2>/dev/null)"
if [[ "$status_json" != *'"name":"cgroup_kill","available":true'* ]]; then
    skip "cgroup kill tier (6 cases)" "no writable delegated cgroup v2 here (status: cgroup_kill unavailable)"
    printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
    [[ "$FAIL" -eq 0 ]]; exit
fi
BASE="/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)"
snap() { ls -d "$BASE"/*/ 2>/dev/null; cat "$BASE/cgroup.subtree_control"; }
before="$(snap)"
sleep 300 & UNRELATED=$!; PIDS_TO_KILL+=("$UNRELATED")

out="$(run -- sh -c 'cat /proc/self/cgroup; sh -c "cat /proc/self/cgroup"' 2>/dev/null)"
if [[ "$(printf '%s\n' "$out" | grep -c '/agentguard-run\.[0-9]*$')" == 2 ]]; then
    pass "target and descendant run inside the owned cgroup"
else
    fail "cgroup placement" "$out"
fi

# The target cannot move itself back out (Landlock: cgroupfs is not writable).
out="$(run -- sh -c "echo 0 > '$BASE/cgroup.procs' 2>/dev/null && echo MOVED; grep -o 'agentguard-run\.[0-9]*\$' /proc/self/cgroup" 2>/dev/null)"
[[ "$out" == agentguard-run.* ]] && pass "target cannot migrate out of its cgroup" || fail "cgroup escape" "$out"

# setsid escapee: survives process-group teardown, is killed by cgroup.kill.
alive() { kill -0 "$1" 2>/dev/null && [[ "$(ps -o stat= -p "$1" 2>/dev/null)" != Z* ]]; }
esc_run() {
    ( cd "$TMP" && exec env AGENTGUARD_TEST_UNAVAIL="${UNAVAIL:-}" "$RUN" --workspace "$TMP" "$@" -- \
        sh -c 'setsid sleep 300 </dev/null >/dev/null 2>&1 & p=$!; i=0
            # Wait until the escapee really is in its own session (else the
            # ordinary group teardown would kill it and the case proves nothing).
            while [ "$(ps -o sid= -p $p | tr -d " ")" != "$p" ] && [ $i -lt 100 ]; do
                sleep 0.05; i=$((i + 1)); done
            echo $p > esc.pid; '"${ESC_TAIL:-exit 0}" ) \
        >/dev/null 2>&1
}
UNAVAIL=cgroup_kill; esc_run; UNAVAIL=; e0="$(cat "$TMP/esc.pid")"; PIDS_TO_KILL+=("$e0")
esc_run; e1="$(cat "$TMP/esc.pid")"; PIDS_TO_KILL+=("$e1")
if alive "$e0" && ! alive "$e1"; then
    pass "setsid escapee: survives pgid-only teardown, killed by cgroup.kill"
else
    fail "setsid escapee" "without-cgroup alive=$(alive "$e0" && echo y || echo n) with-cgroup alive=$(alive "$e1" && echo y || echo n)"
fi
kill "$e0" 2>/dev/null

# Timeout path uses the same teardown: exit 124 and the escapee is gone.
ESC_TAIL='sleep 300' esc_run --timeout 1; rc=$?; e2="$(cat "$TMP/esc.pid")"; PIDS_TO_KILL+=("$e2")
[[ "$rc" == 124 ]] && ! alive "$e2" && pass "timeout: exit 124 and setsid escapee killed" \
    || fail "timeout escapee" "rc=$rc alive=$(alive "$e2" && echo y || echo n)"

alive "$UNRELATED" && pass "unrelated process outside the sandbox survives" || fail "unrelated" "killed"
after="$(snap)"
[[ "$before" == "$after" ]] && pass "owned cgroups removed; parent cgroup (children, subtree_control) unchanged" \
    || fail "cgroup cleanup" "before=[$before] after=[$after]"

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
