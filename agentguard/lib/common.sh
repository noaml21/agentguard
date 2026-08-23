#!/usr/bin/env bash

AG_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AG_PROJECT_ROOT="$(cd -- "$AG_LIB_DIR/../.." && pwd -P)"
AG_CONFIG_DIR="$AG_PROJECT_ROOT/agentguard/config"
AG_STATE_DIR="${AGENTGUARD_STATE_DIR:-$AG_PROJECT_ROOT/.agentguard}"
AG_AUDIT_LOG="$AG_STATE_DIR/audit.jsonl"

ag_require_command() {
    local name="${1:-}"

    if [[ -z "$name" ]] || ! command -v -- "$name" >/dev/null 2>&1; then
        printf 'AgentGuard error: required command not found: %s\n' "${name:-<unspecified>}" >&2
        return 1
    fi
}

ag_read_input() {
    local input

    ag_require_command jq || return 1
    if ! input="$(cat)"; then
        printf 'AgentGuard error: failed to read stdin.\n' >&2
        return 1
    fi
    AG_INPUT="$input"

    if ! jq -e -s 'length == 1' <<<"$AG_INPUT" >/dev/null 2>&1; then
        printf 'AgentGuard error: stdin must contain exactly one valid JSON value.\n' >&2
        return 1
    fi
}

ag_json_get() {
    local filter="${1:-}"

    ag_require_command jq || return 1
    jq -r "($filter) | if . == null then \"\" else . end" <<<"${AG_INPUT:-}"
}

ag_session_id() {
    local session_id

    session_id="$(ag_json_get '.session_id')" || return 1
    printf '%s\n' "${session_id:-default}"
}

ag_tool_name() {
    ag_json_get '.tool_name'
}

ag_command() {
    ag_json_get '.tool_input.command'
}

ag_cwd() {
    ag_json_get '.cwd'
}

ag_file_path() {
    ag_json_get '.tool_input.file_path'
}

ag_canonical_path() {
    local path="${1:-}"
    local base="${2:-}"

    ag_require_command realpath || return 1
    if [[ -z "$path" ]]; then
        printf 'AgentGuard error: cannot canonicalize an empty path.\n' >&2
        return 1
    fi

    if [[ "$path" == /* ]]; then
        realpath --canonicalize-missing -- "$path"
    elif [[ -n "$base" ]]; then
        realpath --canonicalize-missing -- "$base/$path"
    else
        printf 'AgentGuard error: relative path requires a base directory.\n' >&2
        return 1
    fi
}

ag_log_event() {
    local event="${1:-}"
    local hook="${2:-}"
    local decision="${3:-info}"
    local reason="${4:-}"
    local timestamp session_id

    ag_require_command jq || return 1
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" || return 1
    session_id="$(ag_session_id)" || return 1
    mkdir -p -- "$AG_STATE_DIR" || return 1

    jq -cn \
        --arg timestamp "$timestamp" \
        --arg session_id "$session_id" \
        --arg event "$event" \
        --arg hook "$hook" \
        --arg decision "$decision" \
        --arg reason "$reason" \
        '{timestamp: $timestamp, session_id: $session_id, event: $event, hook: $hook, decision: $decision, reason: $reason}' \
        >>"$AG_AUDIT_LOG"
}
