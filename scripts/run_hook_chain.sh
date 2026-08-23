#!/usr/bin/env bash

AG_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AG_REPOSITORY_ROOT="$(cd -- "$AG_SCRIPT_DIR/.." && pwd -P)"
source "$AG_REPOSITORY_ROOT/agentguard/lib/common.sh"

hook_event="${1:-}"
case "$hook_event" in
    PreToolUse|PostToolUse)
        ;;
    *)
        printf 'AgentGuard dispatcher error: unsupported hook event: %s\n' \
            "${hook_event:-<unspecified>}" >&2
        exit 2
        ;;
esac

if ! ag_read_input; then
    printf 'AgentGuard dispatcher error: invalid hook input.\n' >&2
    exit 2
fi

if ! tool_name="$(ag_tool_name 2>/dev/null)"; then
    printf 'AgentGuard dispatcher error: unable to read tool name.\n' >&2
    exit 2
fi

run_hook() {
    local hook_path="$1"
    local hook_status

    printf '%s' "$AG_INPUT" | "$hook_path"
    hook_status=${PIPESTATUS[1]}

    case "$hook_status" in
        0)
            return 0
            ;;
        2)
            return 2
            ;;
        *)
            printf 'AgentGuard dispatcher error: %s failed with exit %s.\n' \
                "${hook_path##*/}" "$hook_status" >&2
            return 2
            ;;
    esac
}

hooks=()
case "$hook_event:$tool_name" in
    PreToolUse:Bash)
        hooks=(
            "$AG_PROJECT_ROOT/agentguard/hooks/pre_command_firewall.sh"
            "$AG_PROJECT_ROOT/agentguard/hooks/pre_rate_limiter.sh"
            "$AG_PROJECT_ROOT/agentguard/hooks/pre_commit_validator.sh"
        )
        ;;
    PreToolUse:Read)
        hooks=("$AG_PROJECT_ROOT/agentguard/hooks/pre_file_policy.sh")
        ;;
    PreToolUse:Edit|PreToolUse:Write)
        hooks=(
            "$AG_PROJECT_ROOT/agentguard/hooks/pre_file_policy.sh"
            "$AG_PROJECT_ROOT/agentguard/hooks/pre_change_snapshot.sh"
        )
        ;;
    PostToolUse:Edit|PostToolUse:Write)
        hooks=("$AG_PROJECT_ROOT/agentguard/hooks/post_syntax_checker.sh")
        ;;
    *)
        exit 0
        ;;
esac

for hook_path in "${hooks[@]}"; do
    if ! run_hook "$hook_path"; then
        exit 2
    fi
done

exit 0
