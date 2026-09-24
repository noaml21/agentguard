#!/usr/bin/env bash
# Phase 3: fail-closed setup contract tests.
# Uses the documented AGENTGUARD_TEST_UNAVAIL / AGENTGUARD_TEST_FAIL seams so the
# contract is testable deterministically on any kernel.
set -u

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"

PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }
assert_eq() { [[ "$2" == "$3" ]] && pass "$1" || fail "$1" "expected [$2] got [$3]"; }

# 1. Available + applied: no_new_privs is actually set in the target.
out="$("$RUN" -- sh -c 'grep -o "NoNewPrivs:.*" /proc/self/status')"
assert_eq "required layer available+applied" "NoNewPrivs:	1" "$out"

# 2. Strict + required layer unavailable -> refuse, target never runs.
out="$(AGENTGUARD_TEST_UNAVAIL=no_new_privs "$RUN" -- sh -c 'echo TARGET_RAN' 2>/dev/null)"
rc=$?
assert_eq "strict unavailable refuses (exit 125)" 125 "$rc"
assert_eq "strict unavailable: target did not run" "" "$out"

# 3. Strict + apply failure -> refuse, target never runs.
out="$(AGENTGUARD_TEST_FAIL=no_new_privs "$RUN" -- sh -c 'echo TARGET_RAN' 2>/dev/null)"
rc=$?
assert_eq "strict apply-failure refuses (exit 125)" 125 "$rc"
assert_eq "strict apply-failure: target did not run" "" "$out"

# 4. Degraded + unavailable -> runs with the remaining layers applied.
#    We force landlock_fs unavailable (it has no dependents; no_new_privs is a
#    prerequisite for Landlock, so forcing *that* unavailable would correctly
#    also break Landlock -- a real dependency, not a test artifact).
out="$(AGENTGUARD_TEST_UNAVAIL=landlock_fs "$RUN" --degraded -- \
       sh -c 'echo TARGET_RAN; grep -o "NoNewPrivs:.*" /proc/self/status' 2>/dev/null)"
rc=$?
assert_eq "degraded unavailable runs (exit 0)" 0 "$rc"
[[ "$out" == *"TARGET_RAN"* && "$out" == *"NoNewPrivs:	1"* ]] \
    && pass "degraded: remaining layers still applied" \
    || fail "degraded remaining layers" "$out"

# 5. No silent downgrade: strict never runs the target with a missing layer.
strict_ran="$(AGENTGUARD_TEST_UNAVAIL=landlock_fs "$RUN" -- true 2>/dev/null; echo $?)"
degraded_ran="$(AGENTGUARD_TEST_UNAVAIL=landlock_fs "$RUN" --degraded -- true 2>/dev/null; echo $?)"
if [[ "$strict_ran" == "125" && "$degraded_ran" == "0" ]]; then
    pass "no silent downgrade (strict refuses where degraded runs)"
else
    fail "no silent downgrade" "strict=$strict_ran degraded=$degraded_ran"
fi

# 6. --status exits 0 without running a target and lists the layer.
out="$("$RUN" --status)"; rc=$?
assert_eq "--status exit 0" 0 "$rc"
[[ "$out" == *"no_new_privs"* ]] && pass "--status lists layers" || fail "--status lists layers" "$out"

# 7. --status --json is valid JSON with the expected fields.
json="$("$RUN" --status --json)"
if command -v jq >/dev/null 2>&1; then
    if jq -e '.mode=="strict" and (.layers[0].name=="no_new_privs") and (.layers[0].available==true)' \
        <<<"$json" >/dev/null 2>&1; then
        pass "--status --json well-formed"
    else
        fail "--status --json well-formed" "$json"
    fi
else
    pass "--status --json (jq absent; skipped structural check)"
fi

# 8. Degraded status reflects mode.
out="$("$RUN" --degraded --status)"
[[ "$out" == *"mode=degraded"* ]] && pass "degraded mode reflected in status" \
    || fail "degraded mode reflected in status" "$out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
