#!/usr/bin/env bash

AG_HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$AG_HOOK_DIR/../lib/common.sh"

emit_no_activity() {
    jq -cn \
        --arg session_id "$session_id" \
        --arg end_reason "$end_reason" \
        '{systemMessage: ("AgentGuard session summary\nSession: \($session_id)\nEnd reason: \($end_reason)\nNo recorded activity for this session.")}'
}

emit_unavailable() {
    jq -cn \
        --arg session_id "$session_id" \
        '{systemMessage: ("AgentGuard session summary\nSession: \($session_id)\nSummary unavailable because the audit log is malformed.")}'
}

if ! ag_read_input; then
    printf 'AgentGuard session-summary diagnostic: invalid hook input; summary skipped.\n' >&2
    exit 0
fi

if ! session_id="$(ag_session_id 2>/dev/null)"; then
    printf 'AgentGuard session-summary diagnostic: unable to read session ID; summary skipped.\n' >&2
    exit 0
fi

if ! hook_event_name="$(ag_json_get '.hook_event_name' 2>/dev/null)"; then
    printf 'AgentGuard session-summary diagnostic: unable to read hook event; summary skipped.\n' >&2
    exit 0
fi

if [[ -n "$hook_event_name" && "$hook_event_name" != "SessionEnd" ]]; then
    exit 0
fi

if ! end_reason="$(ag_json_get '.reason' 2>/dev/null)"; then
    end_reason="unknown"
fi
end_reason="${end_reason:-unknown}"

if [[ ! -s "$AG_AUDIT_LOG" ]]; then
    emit_no_activity || printf 'AgentGuard session-summary diagnostic: unable to emit summary.\n' >&2
    exit 0
fi

if ! jq -Rse '
    split("\n")
    | map(select(length > 0))
    | length > 0 and all(.[]; try (fromjson | type == "object") catch false)
' "$AG_AUDIT_LOG" >/dev/null 2>&1; then
    emit_unavailable || printf 'AgentGuard session-summary diagnostic: unable to emit summary.\n' >&2
    exit 0
fi

if ! statistics="$(jq -Rsc --arg session_id "$session_id" '
    [
        split("\n")[]
        | select(length > 0)
        | fromjson
        | select(.session_id == $session_id)
    ] as $records
    | {
        total_events: ($records | length),
        allowed_events: ($records | map(select(.decision == "allowed")) | length),
        blocked_events: ($records | map(select(.decision == "blocked")) | length),
        command_checks: ($records | map(select(.event == "command_check")) | length),
        file_checks: ($records | map(select(.event == "file_check")) | length),
        rate_limit_checks: ($records | map(select(.event == "rate_limit")) | length),
        snapshot_events: ($records | map(select(.event == "snapshot")) | length),
        successful_snapshots: ($records | map(select(
            .event == "snapshot"
            and .decision == "allowed"
            and (((.reason // "") | if type == "string" then startswith("pre-change snapshot created") else false end))
        )) | length),
        syntax_checks: ($records | map(select(.event == "syntax_check")) | length),
        syntax_failures: ($records | map(select(
            .event == "syntax_check" and .decision == "blocked"
        )) | length),
        commit_checks: ($records | map(select(.event == "commit_check")) | length),
        first_timestamp: ($records[0].timestamp // "unknown"),
        last_timestamp: ($records[-1].timestamp // "unknown")
    }
' "$AG_AUDIT_LOG" 2>/dev/null)"; then
    emit_unavailable || printf 'AgentGuard session-summary diagnostic: unable to emit summary.\n' >&2
    exit 0
fi

if [[ "$(jq -r '.total_events' <<<"$statistics" 2>/dev/null)" == "0" ]]; then
    emit_no_activity || printf 'AgentGuard session-summary diagnostic: unable to emit summary.\n' >&2
    exit 0
fi

jq -cn \
    --arg session_id "$session_id" \
    --arg end_reason "$end_reason" \
    --argjson statistics "$statistics" \
    '{systemMessage: (
        "AgentGuard session summary\n"
        + "Session: \($session_id)\n"
        + "End reason: \($end_reason)\n"
        + "Period: \($statistics.first_timestamp) -> \($statistics.last_timestamp)\n\n"
        + "Events: \($statistics.total_events) total, \($statistics.allowed_events) allowed, \($statistics.blocked_events) blocked\n"
        + "Commands: \($statistics.command_checks)\n"
        + "File checks: \($statistics.file_checks)\n"
        + "Rate-limit checks: \($statistics.rate_limit_checks)\n"
        + "Snapshots: \($statistics.successful_snapshots) created (\($statistics.snapshot_events) events)\n"
        + "Syntax checks: \($statistics.syntax_checks) (\($statistics.syntax_failures) failed)\n"
        + "Commit checks: \($statistics.commit_checks)"
    )}' || printf 'AgentGuard session-summary diagnostic: unable to emit summary.\n' >&2

exit 0
