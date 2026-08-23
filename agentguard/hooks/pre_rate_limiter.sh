#!/usr/bin/env bash

AG_HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$AG_HOOK_DIR/../lib/common.sh"

ag_rate_limit_log() {
    ag_log_event "rate_limit" "pre_rate_limiter" "$1" "$2" >/dev/null 2>&1 || true
}

ag_rate_limit_error() {
    printf 'AgentGuard rate-limiter error: %s\n' "$1" >&2
    ag_rate_limit_log "blocked" "$1"
    exit 2
}

if ! ag_read_input; then
    printf 'AgentGuard rate-limiter error: invalid hook input; command blocked.\n' >&2
    exit 2
fi

if ! tool_name="$(ag_tool_name 2>/dev/null)"; then
    ag_rate_limit_error "unable to read tool name"
fi

if [[ "$tool_name" != "Bash" ]]; then
    exit 0
fi

if ! command="$(ag_command 2>/dev/null)"; then
    ag_rate_limit_error "unable to read Bash command"
fi

if [[ -z "$command" ]]; then
    exit 0
fi

if ! session_id="$(ag_session_id 2>/dev/null)"; then
    ag_rate_limit_error "unable to read session ID"
fi

config_file="$AG_CONFIG_DIR/agentguard.conf"
if [[ ! -f "$config_file" || ! -r "$config_file" ]] || ! exec 3<"$config_file"; then
    ag_rate_limit_error "configuration file is missing or unreadable: $config_file"
fi

max_commands=""
warning_threshold=""
while IFS= read -r line <&3 || [[ -n "$line" ]]; do
    if [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi

    if [[ ! "$line" =~ ^[[:space:]]*([A-Z][A-Z0-9_]*)[[:space:]]*=[[:space:]]*([^[:space:]]+)[[:space:]]*$ ]]; then
        exec 3<&-
        ag_rate_limit_error "configuration contains an invalid assignment"
    fi

    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    case "$key" in
        MAX_COMMANDS|WARNING_THRESHOLD)
            if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
                exec 3<&-
                ag_rate_limit_error "$key must be a positive decimal integer"
            fi
            ;;
        *)
            continue
            ;;
    esac

    case "$key" in
        MAX_COMMANDS)
            if [[ -n "$max_commands" ]]; then
                exec 3<&-
                ag_rate_limit_error "configuration contains duplicate MAX_COMMANDS"
            fi
            max_commands="$value"
            ;;
        WARNING_THRESHOLD)
            if [[ -n "$warning_threshold" ]]; then
                exec 3<&-
                ag_rate_limit_error "configuration contains duplicate WARNING_THRESHOLD"
            fi
            warning_threshold="$value"
            ;;
    esac
done
exec 3<&-

if [[ -z "$max_commands" || -z "$warning_threshold" ]]; then
    ag_rate_limit_error "configuration must define MAX_COMMANDS and WARNING_THRESHOLD"
fi

if (( warning_threshold >= max_commands )); then
    ag_rate_limit_error "WARNING_THRESHOLD must be less than MAX_COMMANDS"
fi

if ! ag_require_command flock; then
    ag_rate_limit_error "required flock command is unavailable"
fi

state_file="$AG_STATE_DIR/rate_limit_state.json"
lock_file="$AG_STATE_DIR/rate_limit.lock"
if ! mkdir -p -- "$AG_STATE_DIR"; then
    ag_rate_limit_error "unable to create state directory: $AG_STATE_DIR"
fi

if ! exec 9>>"$lock_file"; then
    ag_rate_limit_error "unable to open rate-limit lock: $lock_file"
fi
if ! flock -x 9; then
    ag_rate_limit_error "unable to acquire rate-limit lock: $lock_file"
fi

if [[ -e "$state_file" ]]; then
    if ! state="$(cat -- "$state_file")"; then
        flock -u 9 >/dev/null 2>&1 || true
        ag_rate_limit_error "unable to read rate-limit state"
    fi
else
    state='{}'
fi

if ! jq -e -s 'length == 1 and (.[0] | type == "object")' <<<"$state" >/dev/null 2>&1; then
    flock -u 9 >/dev/null 2>&1 || true
    ag_rate_limit_error "rate-limit state is not one valid JSON object"
fi

if ! state_tmp="$(mktemp "$AG_STATE_DIR/.rate_limit_state.XXXXXX")"; then
    flock -u 9 >/dev/null 2>&1 || true
    ag_rate_limit_error "unable to create temporary rate-limit state"
fi

if ! jq -ce --arg session_id "$session_id" '
    (if has($session_id) then .[$session_id] else 0 end) as $count
    | if ($count | type) != "number" then
        error("session count is not a number")
      elif $count < 0 or $count != ($count | floor) then
        error("session count is not a non-negative integer")
      else
        .[$session_id] = ($count + 1)
      end
' <<<"$state" >"$state_tmp" 2>/dev/null; then
    rm -f -- "$state_tmp"
    flock -u 9 >/dev/null 2>&1 || true
    ag_rate_limit_error "session count is not a non-negative integer"
fi

if ! count="$(jq -er --arg session_id "$session_id" '.[$session_id]' "$state_tmp" 2>/dev/null)"; then
    rm -f -- "$state_tmp"
    flock -u 9 >/dev/null 2>&1 || true
    ag_rate_limit_error "unable to verify updated rate-limit state"
fi

if ! mv -- "$state_tmp" "$state_file"; then
    rm -f -- "$state_tmp"
    flock -u 9 >/dev/null 2>&1 || true
    ag_rate_limit_error "unable to replace rate-limit state"
fi

flock -u 9 >/dev/null 2>&1 || true

if (( count > max_commands )); then
    printf 'AgentGuard rate limiter: BLOCKED session %s at %s/%s commands.\n' \
        "$session_id" "$count" "$max_commands" >&2
    ag_rate_limit_log "blocked" "command count $count exceeds limit $max_commands"
    exit 2
fi

if (( count > warning_threshold )); then
    printf 'AgentGuard rate limiter: WARNING session %s at %s/%s commands.\n' \
        "$session_id" "$count" "$max_commands" >&2
    ag_rate_limit_log "allowed" \
        "command count $count exceeds warning threshold $warning_threshold; limit $max_commands"
    exit 0
fi

ag_rate_limit_log "allowed" "command count $count of limit $max_commands"
exit 0
