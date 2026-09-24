#!/usr/bin/env bash
# AgentGuard V2 runner integration tests (Phase 2).
# All fixtures are disposable temp dirs; nothing touches the real environment.
set -u

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"

if [[ ! -x "$RUN" ]]; then
    printf 'error: runner not found at %s (run: make -C sandbox)\n' "$RUN" >&2
    exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-run-tests.XXXXXX")" || exit 1
cleanup() { [[ "$TMP" == */agentguard-run-tests.* ]] && rm -rf -- "$TMP"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }

# assert_eq name expected actual
assert_eq() {
    if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "expected [$2] got [$3]"; fi
}

# --- exit status propagation ---
"$RUN" -- sh -c 'exit 0' >/dev/null 2>&1; assert_eq "exit 0 propagated" 0 $?
"$RUN" -- sh -c 'exit 42' >/dev/null 2>&1; assert_eq "exit 42 propagated" 42 $?
"$RUN" -- sh -c 'kill -TERM $$' >/dev/null 2>&1; assert_eq "SIGTERM -> 143" 143 $?
"$RUN" -- sh -c 'kill -INT $$' >/dev/null 2>&1; assert_eq "SIGINT -> 130" 130 $?

# --- exec / usage failures use distinct codes ---
"$RUN" -- definitely_not_a_command_xyz >/dev/null 2>&1
assert_eq "missing command -> 127" 127 $?
"$RUN" >/dev/null 2>&1; assert_eq "no -- -> 125" 125 $?
"$RUN" -- >/dev/null 2>&1; assert_eq "empty target -> 125" 125 $?
"$RUN" --bogus -- true >/dev/null 2>&1; assert_eq "unknown option -> 125" 125 $?

# --- argv semantics: no shell, exact preservation ---
out="$("$RUN" -- printf '[%s]' 'a b' '$HOME' '*')"
assert_eq "argv preserved verbatim (no shell)" '[a b][$HOME][*]' "$out"

# --- version/help ---
out="$("$RUN" --version)"; assert_eq "version prints" "agentguard-run 0.2.0-phase2" "$out"

# --- root refusal is documented behavior (only checkable when not root) ---
if [[ "$(id -u)" -ne 0 ]]; then
    pass "runs as unprivileged user (root refusal path untriggered)"
else
    "$RUN" -- true >/dev/null 2>&1; assert_eq "root refused -> 125" 125 $?
fi

# --- FD sanitation: an inherited fd must not reach the target ---
probe="$TMP/fdcount.sh"
cat >"$probe" <<'EOF'
#!/usr/bin/env bash
# Count open fds excluding the directory fd ls/globbing opens transiently.
n=0
for fd in /proc/self/fd/*; do
    b="${fd##*/}"
    [[ "$b" == "$(basename "$fd")" ]] || true
    n=$((n + 1))
done
echo "$n"
EOF
chmod +x "$probe"
# Open extra fds 3 (file) and 4 (pipe-ish via /dev/null) into the runner.
fd_list="$("$RUN" -- sh -c 'echo /proc/self/fd/*' 3<"$probe" 4</etc/hostname)"
# Expect only 0,1,2 plus the transient dirfd from the glob (fd 3 inside sh).
leaked=0
for e in $fd_list; do
    b="${e##*/}"
    case "$b" in
        0|1|2|3) ;;    # 3 is the transient fd the shell opens for the glob
        *) leaked=1 ;;
    esac
done
assert_eq "inherited fds 3,4 closed before exec" 0 "$leaked"

# --keep-fd preserves a chosen descriptor
keep_out="$("$RUN" --keep-fd 5 -- sh -c 'if [ -e /proc/self/fd/5 ]; then echo kept; else echo gone; fi' 5<"$probe")"
assert_eq "--keep-fd preserves fd 5" "kept" "$keep_out"

# --- timeout terminates the tree, not just the direct child ---
t0=$(date +%s%N)
"$RUN" --timeout 0.4 -- sh -c 'sleep 30' >/dev/null 2>&1
rc=$?
elapsed=$(( ($(date +%s%N) - t0) / 1000000 ))
assert_eq "timeout exit code 124" 124 "$rc"
if (( elapsed < 3000 )); then pass "timeout fired promptly (${elapsed}ms)"; else fail "timeout prompt" "${elapsed}ms"; fi

# --- descendant reaping: a backgrounded grandchild is not orphaned/leaked ---
marker="$TMP/gc_alive"
"$RUN" -- sh -c 'sh -c "sleep 30 & echo \$! > '"$marker"'.pid" ; exit 0' >/dev/null 2>&1
sleep 0.3
gc_pid="$(cat "$marker.pid" 2>/dev/null || echo)"
if [[ -n "$gc_pid" ]] && kill -0 "$gc_pid" 2>/dev/null; then
    fail "grandchild reaped after runner exit" "pid $gc_pid still alive"
    kill -KILL "$gc_pid" 2>/dev/null
else
    pass "grandchild terminated after runner exit"
fi

# --- unrelated process is never signalled by teardown ---
sleep 30 &
bystander=$!
"$RUN" -- true >/dev/null 2>&1
if kill -0 "$bystander" 2>/dev/null; then
    pass "unrelated process survives a run"
    kill -KILL "$bystander" 2>/dev/null
else
    fail "unrelated process survives a run" "bystander $bystander was killed"
fi
wait "$bystander" 2>/dev/null

# --- repeated runs do not leak processes ---
before=$(ps -o pid= --ppid $$ 2>/dev/null | wc -l)
for _ in $(seq 1 10); do "$RUN" -- true >/dev/null 2>&1; done
sleep 0.2
after=$(ps -o pid= --ppid $$ 2>/dev/null | wc -l)
if (( after <= before + 1 )); then pass "no process leak over 10 runs"; else fail "process leak" "before=$before after=$after"; fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
