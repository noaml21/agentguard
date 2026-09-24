#!/usr/bin/env bash
# Phase 4: Landlock filesystem enforcement tests.
# Kernel-feature dependent: skips with a reason if Landlock FS is unavailable.
# All fixtures are disposable; the "outside" dir models the protected host area.
set -u

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"
# Resolve to an absolute path: tests cd into the workspace before invoking it.
RUN="$(cd -- "$(dirname -- "$RUN")" && pwd -P)/$(basename -- "$RUN")"

PASS=0; FAIL=0; SKIP=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }

# Determine Landlock availability from the runner itself.
status_json="$("$RUN" --status --json 2>/dev/null)"
if [[ "$status_json" != *'"name":"landlock_fs","available":true'* ]]; then
    printf 'SKIP all Landlock FS tests -- landlock_fs unavailable on this kernel\n'
    printf '\n0 passed, 0 failed, 1 skipped\n'
    exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-ll.XXXXXX")" || exit 1
cleanup() { [[ "$TMP" == */agentguard-ll.* ]] && chmod -R u+rwx "$TMP" 2>/dev/null; [[ "$TMP" == */agentguard-ll.* ]] && rm -rf -- "$TMP"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

WS="$TMP/workspace"
OUT="$TMP/outside"
mkdir -p "$WS" "$OUT"
echo "workspace-input" > "$WS/infile"
echo "TOP_SECRET" > "$OUT/secret"

# run <marker-test...> : run a target with cwd=workspace and workspace policy.
run() { ( cd "$WS" && "$RUN" --workspace "$WS" -- "$@" ); }

# --- Permitted operations ---
out="$(run sh -c 'cat infile')"
[[ "$out" == "workspace-input" ]] && pass "read workspace file" || fail "read workspace file" "$out"

run sh -c 'echo data > created' >/dev/null 2>&1
[[ -f "$WS/created" && "$(cat "$WS/created")" == "data" ]] && pass "write workspace file" || fail "write workspace file" "missing"

out="$(run sh -c 'head -c4 /etc/hostname >/dev/null && echo OK' 2>/dev/null)"
[[ "$out" == "OK" ]] && pass "read system path (/etc)" || fail "read system path" "$out"

out="$(run sh -c 'mkdir sub && mv infile sub/f && rm sub/f && rmdir sub && echo OK' 2>/dev/null)"
[[ "$out" == "OK" ]] && pass "create/rename/remove within workspace" || fail "manage workspace" "$out"
echo "workspace-input" > "$WS/infile"  # restore

# --- Denied: writes outside the workspace ---
run sh -c "echo pwn > '$OUT/direct'" >/dev/null 2>&1
[[ ! -f "$OUT/direct" ]] && pass "deny write outside (absolute path)" || fail "deny write outside abs" "created"

run sh -c 'echo pwn > ../outside/relwrite' >/dev/null 2>&1
[[ ! -f "$OUT/relwrite" ]] && pass "deny write outside (relative ..)" || fail "deny write outside rel" "created"

run python3 -c "open('$OUT/pywrite','w').write('x')" >/dev/null 2>&1
[[ ! -f "$OUT/pywrite" ]] && pass "deny write outside (python interpreter)" || fail "deny py write" "created"

run sh -c "sh -c \"echo pwn > '$OUT/gcwrite'\"" >/dev/null 2>&1
[[ ! -f "$OUT/gcwrite" ]] && pass "deny write outside (grandchild inherits)" || fail "deny gc write" "created"

# --- Denied: reads outside the workspace ---
out="$(run sh -c "cat '$OUT/secret' 2>/dev/null" 2>/dev/null)"
[[ "$out" != *"TOP_SECRET"* ]] && pass "deny read outside (absolute)" || fail "deny read outside" "leaked"

out="$(run python3 -c "print(open('$OUT/secret').read())" 2>/dev/null)"
[[ "$out" != *"TOP_SECRET"* ]] && pass "deny read outside (python)" || fail "deny py read" "leaked"

# --- Path integrity: a symlink inside the workspace pointing outside is denied.
# Enforcement binds to the resolved inode, so the symlink cannot grant access.
ln -s "$OUT/secret" "$WS/link_to_secret"
out="$(run sh -c 'cat link_to_secret 2>/dev/null' 2>/dev/null)"
[[ "$out" != *"TOP_SECRET"* ]] && pass "deny read via symlink escape" || fail "deny symlink read" "leaked"

ln -s "$OUT" "$WS/link_dir"
run sh -c 'echo pwn > link_dir/via_symlink' >/dev/null 2>&1
[[ ! -f "$OUT/via_symlink" ]] && pass "deny write via symlinked dir" || fail "deny symlink write" "created"

# --- Path replacement (TOCTOU-style): swap a workspace file for a symlink to
# outside between runs; the next run must still be denied because Landlock
# resolves the real inode at access time, not a cached decision.
rm -f "$WS/swap"
ln -s "$OUT/secret" "$WS/swap"
out="$(run sh -c 'cat swap 2>/dev/null' 2>/dev/null)"
[[ "$out" != *"TOP_SECRET"* ]] && pass "deny read after path replaced by symlink" || fail "deny replaced path" "leaked"

# --- Denied: reaching another repository / home area directly ---
out="$(run sh -c 'ls /home/noam >/dev/null 2>&1 && echo LISTED || echo DENIED' 2>/dev/null)"
[[ "$out" == "DENIED" ]] && pass "deny listing home directory" || fail "deny list home" "$out"

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
