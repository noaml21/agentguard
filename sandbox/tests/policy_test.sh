#!/usr/bin/env bash
# Phase 8: policy file parser + control-plane integrity. Effect-based: rejected
# policies must never run the target; protected files must keep their bytes and
# inode after a sandboxed attack, not merely see an error.
set -u
umask 022
shopt -s lastpipe # "printf ... | bad": run bad in this shell so its counts stick

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"
RUN="$(cd -- "$(dirname -- "$RUN")" && pwd -P)/$(basename -- "$RUN")"

PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }

# TMP: the target's workspace (writable). CTL: control dir outside every writable
# root (not under /tmp, not under the workspace) holding policies + a runner copy.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-pol.XXXXXX")" || exit 1
TMP2="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-pol.XXXXXX")" || exit 1
CTL="$(mktemp -d "$SANDBOX_DIR/build/ctl.XXXXXX")" || exit 1
cleanup() {
    [[ "$TMP" == */agentguard-pol.* ]] && rm -rf -- "$TMP"
    [[ "$TMP2" == */agentguard-pol.* ]] && rm -rf -- "$TMP2"
    [[ "$CTL" == */build/ctl.* ]] && rm -rf -- "$CTL" && rm -f -- "$CTL.lnk"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

P="$CTL/good.policy"
printf 'version = 1\nworkspace = %s\n' "$TMP" > "$P"

# ---------------- valid policies ----------------
out="$(cd "$TMP" && "$RUN" --policy "$P" -- sh -c 'echo hi > ok && cat ok' 2>/dev/null)"
[[ "$out" == "hi" ]] && pass "minimal policy runs target with workspace from policy" || fail "minimal" "$out"
out="$("$RUN" --policy "$P" --status --json 2>&1)"
[[ "$out" == *'"network":{"mode":"none","enforced":true}'* && \
   "$out" == *'"control":{"policy_file":true,"runner_in_writable_root":false}'* ]] \
    && pass "status json: policy in use, defaults (net none), runner protected" || fail "status minimal" "$out"

mkdir -p "$CTL/dir with space" "$TMP/extra"
echo readable > "$CTL/dir with space/r.txt"
cat > "$CTL/full.policy" <<EOF
# every supported key, comments and blank lines

version = 1
workspace = $TMP
read = $CTL/dir with space
write = $TMP/extra
default-reads = yes
net = all
timeout = 2.5
max-file-size = 4096
max-open-files = 64
EOF
out="$("$RUN" --policy "$CTL/full.policy" --status --json 2>&1)"
[[ "$out" == *'"network":{"mode":"all","enforced":true}'* && \
   "$out" == *'"resources":{"timeout_ms":2500,"rlimit_core":0,"rlimit_fsize":4096,"rlimit_nofile":64,'* ]] \
    && pass "full policy: every key reaches the effective configuration" || fail "full status" "$out"
out="$(cd "$TMP" && "$RUN" --policy "$CTL/full.policy" -- sh -c "cat '$CTL/dir with space/r.txt'; python3 -c '
import errno, os
try:
    f = open(\"big\", \"wb\", buffering=0)
    for _ in range(3): f.write(b\"x\" * 4096)
    print(\"WROTE\")
except OSError as e: print(errno.errorcode[e.errno], os.path.getsize(\"big\"))'" 2>/dev/null)"
[[ "$out" == $'readable\nEFBIG 4096' ]] && pass "full policy enforced: read path with spaces + file-size bound" \
    || fail "full effect" "$out"

# ---------------- precedence: no CLI merge ----------------
for extra in "--net all" "--workspace $TMP" "--max-file-size 5" "--timeout 3" "--no-default-reads" \
             "--allow-write $TMP2" "--policy $P"; do
    rm -f "$TMP/ran"
    # shellcheck disable=SC2086
    (cd "$TMP" && "$RUN" --policy "$P" $extra -- touch "$TMP/ran") >/dev/null 2>&1; rc=$?
    [[ "$rc" == 125 && ! -e "$TMP/ran" ]] && pass "precedence: --policy + ${extra%% *} refused, target not run" \
        || fail "precedence ${extra%% *}" "rc=$rc"
done
(cd "$TMP" && "$RUN" --policy "$P" --verbose --degraded -- true) >/dev/null 2>&1 \
    && pass "precedence: non-policy flags (--verbose, --degraded) combine" || fail "precedence ok flags" "rc=$?"
"$RUN" --timeout nan -- true >/dev/null 2>&1; rc=$?
[[ "$rc" == 125 ]] && pass "CLI --timeout nan rejected (shared parser)" || fail "timeout nan" "rc=$rc"

# ---------------- malformed policies: rejected, target never runs ----------------
bad() {
    local f="$CTL/bad.policy"
    cat > "$f"; chmod 644 "$f"; rm -f "$TMP/ran"
    local err rc
    err="$(cd "$TMP" && "$RUN" --policy "$f" -- touch "$TMP/ran" 2>&1 >/dev/null)"; rc=$?
    if [[ "$rc" == 125 && ! -e "$TMP/ran" && "$err" == *policy* && "$err" != *SECRET* && ${#err} -lt 400 ]]; then
        pass "rejects: $1"
    else
        fail "rejects: $1" "rc=$rc err=${err:0:200}"
    fi
}
V="version = 1"; W="workspace = $TMP"
printf '%s\n%s\nnetwork = none\n' "$V" "$W" | bad "unknown key"
printf '%s\n%s\nnet = none\nnet = all\n' "$V" "$W" | bad "duplicate key"
printf '%s\n' "$W" | bad "missing version"
printf 'version = 2\n%s\n' "$W" | bad "unsupported version"
printf '%s\n%s\n' "$W" "$V" | bad "version not first"
printf '%s\n' "$V" | bad "missing workspace"
: | bad "empty file"
printf '%s\nworkspace %s\n' "$V" "$TMP" | bad "missing '='"
printf '%s\nworkspace=%s\n' "$V" "$TMP" | bad "no spaces around '='"
printf ' %s\n%s\n' "$V" "$W" | bad "leading space"
printf '%s\n%s \n' "$V" "$W" | bad "trailing space in value"
printf '%s\n%s\nnet = \n' "$V" "$W" | bad "empty value"
printf '%s\n%s\nnet = SECRET123\n' "$V" "$W" | bad "invalid enum (value not echoed)"
printf '%s\n%s\ndefault-reads = maybe\n' "$V" "$W" | bad "invalid boolean"
printf '%s\n%s\ntimeout = abc\n' "$V" "$W" | bad "invalid timeout"
printf '%s\n%s\ntimeout = 1e3\n' "$V" "$W" | bad "timeout exponent spelling"
printf '%s\n%s\ntimeout = nan\n' "$V" "$W" | bad "timeout nan"
printf '%s\n%s\ntimeout = 1.2.3\n' "$V" "$W" | bad "timeout two dots"
printf '%s\n%s\nmax-file-size = -5\n' "$V" "$W" | bad "negative limit"
printf '%s\n%s\nmax-file-size = 99999999999999999999999\n' "$V" "$W" | bad "integer overflow"
printf '%s\n%s\nmax-open-files = 3\n' "$V" "$W" | bad "limit below range"
printf '%s\nworkspace = rel/dir\n' "$V" | bad "relative path"
printf '%s\nworkspace = %s/../x\n' "$V" "$TMP" | bad "'..' component"
printf '%s\n%s\nread = /usr//lib\n' "$V" "$W" | bad "empty path component"
printf '%s\nworkspace = %s/\n' "$V" "$TMP" | bad "trailing slash"
printf '%s\n%s\nwrite = /\n' "$V" "$W" | bad "write root '/'"
printf '%s\nworkspace =\t%s\n' "$V" "$TMP" | bad "tab"
printf '%s\r\n%s\r\n' "$V" "$W" | bad "CRLF"
printf '%s\n%s\n#\0\n' "$V" "$W" | bad "NUL byte"
printf '%s\n%s\n# caf\xc3\xa9\n' "$V" "$W" | bad "non-ASCII byte"
{ printf '%s\n%s\n' "$V" "$W"; head -c 70000 /dev/zero | tr '\0' '#'; echo; } | bad "oversize file"
{ printf '%s\n%s\n' "$V" "$W"; for _ in $(seq 1 1100); do echo '#'; done; } | bad "too many lines"
{ printf '%s\n%s\nread = /' "$V" "$W"; head -c 5000 /dev/zero | tr '\0' 'a'; echo; } | bad "line too long"
{ printf '%s\n%s\n' "$V" "$W"; for i in $(seq 1 65); do echo "read = /usr/x$i"; done; } | bad "too many paths"
printf '%s\n%s\nread = /usr\nread = /usr\n' "$V" "$W" | bad "duplicate read path"
printf '%s\n%s\nread = %s/extra\nwrite = %s/extra\n' "$V" "$W" "$TMP" "$TMP" | bad "path both read and write"
printf '%s\n%s\nwrite = %s\n' "$V" "$W" "$TMP" | bad "write equals workspace"

# ---------------- policy location / file checks ----------------
loc() { # name, then runner args before --
    local name="$1"; shift; rm -f "$TMP/ran"
    (cd "$TMP" && "$RUN" "$@" -- touch "$TMP/ran") >/dev/null 2>&1; local rc=$?
    [[ "$rc" == 125 && ! -e "$TMP/ran" ]] && pass "refuses policy: $name" || fail "refuses policy: $name" "rc=$rc"
}
cp "$P" "$TMP/in.policy"; loc "inside the workspace" --policy "$TMP/in.policy"
cp "$P" "$TMP2/p.policy"; loc "under default-writable /tmp" --policy "$TMP2/p.policy"
printf 'version = 1\nworkspace = %s\ndefault-reads = no\n' "$TMP" > "$TMP2/nodef.policy"
"$RUN" --policy "$TMP2/nodef.policy" --status >/dev/null 2>&1 \
    && pass "same /tmp location accepted once /tmp is not writable (inode check follows effective roots)" \
    || fail "nodef accepted" "rc=$?"
mkdir -p "$CTL/wr"; printf 'version = 1\nworkspace = %s\nwrite = %s/wr\n' "$TMP" "$CTL" > "$CTL/wr/p.policy"
loc "inside a write root" --policy "$CTL/wr/p.policy"
ln -s good.policy "$CTL/link.policy"; loc "symlink" --policy "$CTL/link.policy"
ln -s "$CTL" "$CTL.lnk"; loc "symlinked directory" --policy "$CTL.lnk/good.policy"
loc "'.' spelling" --policy "$CTL/./good.policy"
(cd "$CTL" && "$RUN" --policy good.policy -- touch "$TMP/ran") >/dev/null 2>&1; rc=$?
[[ "$rc" == 125 && ! -e "$TMP/ran" ]] && pass "refuses policy: relative path" || fail "relative" "rc=$rc"
cp "$P" "$CTL/gw.policy"; chmod 664 "$CTL/gw.policy"; loc "group-writable" --policy "$CTL/gw.policy"
loc "directory" --policy "$CTL"
loc "missing file" --policy "$CTL/nope.policy"

# ---------------- integrity: target cannot alter next run's policy/runner ----------------
cp "$RUN" "$CTL/agentguard-run"
before="$(cd "$CTL" && sha256sum good.policy agentguard-run && stat -c '%n %i %s' good.policy agentguard-run && ls -A)"
cat > "$TMP/attack.sh" <<'EOF'
for T in "$1" "$2"; do
  echo x > "$T"; : > "$T"; echo x >> "$T"
  mv "$T" "$T.old"; rm -f "$T"; ln -sf /etc/passwd "$T"
  printf evil > evil; mv evil "$T"; cp /bin/true "$T"
  ln "$T" hardlink && echo x >> hardlink
  python3 -c 'import os, sys
t = sys.argv[1]
for f in (lambda: open(t, "w").write("x"), lambda: os.rename(t, t + ".2"),
          lambda: os.truncate(t, 0), lambda: os.unlink(t), lambda: os.symlink("/etc/passwd", t)):
    try: f()
    except OSError: pass' "$T"
  sh -c 'sh -c "echo x > \"\$0\""' "$T"
done
echo x > "$3/./$(basename "$1")"; echo x > "$3/../$(basename "$3")/$(basename "$1")"
touch "$3/new-file"; mkdir "$3/new-dir"
exit 0
EOF
(cd "$TMP" && "$RUN" --policy "$P" -- sh attack.sh "$P" "$CTL/agentguard-run" "$CTL") >/dev/null 2>&1
after="$(cd "$CTL" && sha256sum good.policy agentguard-run && stat -c '%n %i %s' good.policy agentguard-run && ls -A)"
[[ "$before" == "$after" ]] && pass "policy + runner copy: bytes, inode, directory listing unchanged after 17 write/replace attacks" \
    || fail "integrity" "$(diff <(echo "$before") <(echo "$after") | head -5)"
[[ ! -e "$TMP/hardlink" ]] && pass "no hard link to protected file created in workspace" || fail "hardlink" "created"
out="$(cd "$TMP" && "$RUN" --policy "$P" -- sh -c 'echo next' 2>/dev/null)"
[[ "$out" == "next" ]] && "$CTL/agentguard-run" --version >/dev/null 2>&1 \
    && pass "next run uses the intact policy; runner copy still executes" || fail "next run" "$out"

# Runner binary inside a writable root: refused in policy mode, reported otherwise.
cp "$RUN" "$TMP/agentguard-run"
(cd "$TMP" && "$TMP/agentguard-run" --policy "$P" -- touch "$TMP/ran") >/dev/null 2>&1; rc=$?
[[ "$rc" == 125 && ! -e "$TMP/ran" ]] && pass "policy mode refuses a runner binary inside the workspace" \
    || fail "runner in workspace" "rc=$rc"
out="$("$TMP/agentguard-run" --workspace "$TMP" --status --json 2>&1)"
[[ "$out" == *'"runner_in_writable_root":true'* ]] && pass "CLI mode reports runner_in_writable_root=true" \
    || fail "runner report" "$out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
