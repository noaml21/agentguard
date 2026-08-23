#!/usr/bin/env bash

AG_HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$AG_HOOK_DIR/../lib/common.sh"

ag_file_policy_log() {
    ag_log_event "file_check" "pre_file_policy" "$1" "$2" >/dev/null 2>&1 || true
}

if ! ag_read_input; then
    printf 'AgentGuard file-policy error: invalid hook input; access blocked.\n' >&2
    exit 2
fi

if ! tool_name="$(ag_tool_name 2>/dev/null)"; then
    printf 'AgentGuard file-policy error: unable to read tool name; access blocked.\n' >&2
    exit 2
fi

case "$tool_name" in
    Read|Edit|Write)
        ;;
    *)
        exit 0
        ;;
esac

if ! cwd="$(ag_cwd 2>/dev/null)" || [[ -z "$cwd" ]]; then
    printf 'AgentGuard file-policy error: workspace cwd is missing; access blocked.\n' >&2
    ag_file_policy_log "blocked" "workspace cwd is missing"
    exit 2
fi

if ! file_path="$(ag_file_path 2>/dev/null)" || [[ -z "$file_path" ]]; then
    printf 'AgentGuard file-policy error: file path is missing; access blocked.\n' >&2
    ag_file_policy_log "blocked" "file path is missing"
    exit 2
fi

if ! workspace_root="$(ag_canonical_path "$cwd" "$PWD" 2>/dev/null)" \
    || [[ ! -d "$workspace_root" ]]; then
    printf 'AgentGuard file-policy error: workspace cwd cannot be resolved; access blocked.\n' >&2
    ag_file_policy_log "blocked" "workspace cwd cannot be resolved: $cwd"
    exit 2
fi

if ! target_path="$(ag_canonical_path "$file_path" "$workspace_root" 2>/dev/null)"; then
    printf 'AgentGuard file-policy error: file path cannot be resolved; access blocked.\n' >&2
    ag_file_policy_log "blocked" "file path cannot be resolved: $file_path"
    exit 2
fi

workspace_prefix="${workspace_root%/}/"
if [[ "$target_path" != "$workspace_root" && "$target_path" != "$workspace_prefix"* ]]; then
    printf 'AgentGuard file policy: BLOCKED path outside workspace: %s\n' "$target_path" >&2
    ag_file_policy_log "blocked" "target is outside workspace: $target_path"
    exit 2
fi

if [[ "$target_path" == "$workspace_root" ]]; then
    relative_path="."
else
    relative_path="${target_path#"$workspace_prefix"}"
fi

policy_file="$AG_CONFIG_DIR/protected_paths.txt"
if [[ ! -f "$policy_file" || ! -r "$policy_file" ]] || ! exec 3<"$policy_file"; then
    printf 'AgentGuard file-policy error: policy file is missing or unreadable: %s\n' "$policy_file" >&2
    ag_file_policy_log "blocked" "policy file missing or unreadable: $policy_file"
    exit 2
fi

while IFS= read -r pattern <&3 || [[ -n "$pattern" ]]; do
    if [[ -z "${pattern//[[:space:]]/}" || "$pattern" =~ ^[[:space:]]*# ]]; then
        continue
    fi

    printf '%s\n' "$relative_path" | grep -qE -- "$pattern" 2>/dev/null
    grep_status=$?

    case "$grep_status" in
        0)
            printf 'AgentGuard file policy: BLOCKED protected path: %s\n' "$relative_path" >&2
            ag_file_policy_log "blocked" "protected path matched pattern: $pattern"
            exit 2
            ;;
        1)
            ;;
        2)
            printf 'AgentGuard file-policy error: invalid policy pattern: %s\n' "$pattern" >&2
            ag_file_policy_log "blocked" "invalid protected-path pattern: $pattern"
            exit 2
            ;;
        *)
            printf 'AgentGuard file-policy error: grep failed with status %s.\n' "$grep_status" >&2
            ag_file_policy_log "blocked" "policy evaluation failed with status $grep_status"
            exit 2
            ;;
    esac
done
exec 3<&-

ag_file_policy_log "allowed" "path allowed by workspace policy"
exit 0
