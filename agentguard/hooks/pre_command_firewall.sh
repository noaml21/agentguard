#!/usr/bin/env bash

AG_HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$AG_HOOK_DIR/../lib/common.sh"

if ! ag_read_input; then
    printf 'AgentGuard firewall error: invalid hook input; command blocked.\n' >&2
    exit 2
fi

if ! tool_name="$(ag_tool_name 2>/dev/null)"; then
    printf 'AgentGuard firewall error: unable to read tool name; command blocked.\n' >&2
    exit 2
fi

if [[ "$tool_name" != "Bash" ]]; then
    exit 0
fi

if ! command="$(ag_command 2>/dev/null)"; then
    printf 'AgentGuard firewall error: unable to read Bash command; command blocked.\n' >&2
    exit 2
fi

if [[ -z "$command" ]]; then
    exit 0
fi

policy_file="$AG_CONFIG_DIR/dangerous_patterns.txt"
if [[ ! -f "$policy_file" || ! -r "$policy_file" ]] || ! exec 3<"$policy_file"; then
    printf 'AgentGuard firewall error: policy file is missing or unreadable: %s\n' "$policy_file" >&2
    ag_log_event "command_check" "pre_command_firewall" "blocked" \
        "policy file missing or unreadable: $policy_file" >/dev/null 2>&1 || true
    exit 2
fi

while IFS= read -r pattern <&3 || [[ -n "$pattern" ]]; do
    if [[ -z "${pattern//[[:space:]]/}" || "$pattern" =~ ^[[:space:]]*# ]]; then
        continue
    fi

    printf '%s\n' "$command" | grep -qE -- "$pattern" 2>/dev/null
    grep_status=$?

    case "$grep_status" in
        0)
            printf 'AgentGuard firewall: BLOCKED by policy pattern: %s\n' "$pattern" >&2
            ag_log_event "command_check" "pre_command_firewall" "blocked" \
                "matched dangerous pattern: $pattern" >/dev/null 2>&1 || true
            exit 2
            ;;
        1)
            ;;
        2)
            printf 'AgentGuard firewall policy error: invalid pattern: %s\n' "$pattern" >&2
            ag_log_event "command_check" "pre_command_firewall" "blocked" \
                "invalid policy pattern: $pattern" >/dev/null 2>&1 || true
            exit 2
            ;;
        *)
            printf 'AgentGuard firewall policy error: grep failed with status %s.\n' "$grep_status" >&2
            ag_log_event "command_check" "pre_command_firewall" "blocked" \
                "policy evaluation failed with status $grep_status" >/dev/null 2>&1 || true
            exit 2
            ;;
    esac
done
exec 3<&-

ag_log_event "command_check" "pre_command_firewall" "allowed" \
    "no dangerous pattern matched" >/dev/null 2>&1 || true
exit 0
