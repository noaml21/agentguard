#!/usr/bin/env bash

AG_HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$AG_HOOK_DIR/../lib/common.sh"

ag_syntax_log() {
    ag_log_event "syntax_check" "post_syntax_checker" "$1" "$2" >/dev/null 2>&1 || true
}

ag_syntax_error() {
    printf 'AgentGuard syntax-checker error: %s\n' "$1" >&2
    ag_syntax_log "blocked" "$1"
    exit 2
}

if ! ag_read_input; then
    printf 'AgentGuard syntax-checker error: invalid hook input.\n' >&2
    exit 2
fi

if ! tool_name="$(ag_tool_name 2>/dev/null)"; then
    ag_syntax_error "unable to read tool name"
fi

case "$tool_name" in
    Edit|Write)
        ;;
    *)
        exit 0
        ;;
esac

if ! cwd="$(ag_cwd 2>/dev/null)" || [[ -z "$cwd" ]]; then
    ag_syntax_error "workspace cwd is missing"
fi

if ! file_path="$(ag_file_path 2>/dev/null)" || [[ -z "$file_path" ]]; then
    ag_syntax_error "file path is missing"
fi

if ! workspace_root="$(ag_canonical_path "$cwd" "$PWD" 2>/dev/null)" \
    || [[ ! -d "$workspace_root" ]]; then
    ag_syntax_error "workspace cwd cannot be resolved: $cwd"
fi

if ! target_path="$(ag_canonical_path "$file_path" "$workspace_root" 2>/dev/null)"; then
    ag_syntax_error "file path cannot be resolved: $file_path"
fi

workspace_prefix="${workspace_root%/}/"
if [[ "$target_path" != "$workspace_root" && "$target_path" != "$workspace_prefix"* ]]; then
    ag_syntax_error "target is outside workspace: $target_path"
fi

if [[ "$target_path" == "$workspace_root" ]]; then
    relative_path="."
else
    relative_path="${target_path#"$workspace_prefix"}"
fi

if [[ ! -e "$target_path" ]]; then
    ag_syntax_log "allowed" "target does not exist after tool use; syntax check skipped"
    exit 0
fi

if [[ ! -f "$target_path" ]]; then
    ag_syntax_error "existing target is not a regular file: $relative_path"
fi

case "$target_path" in
    *.sh)
        language="Bash"
        checker_command="bash"
        checker=(bash -n -- "$target_path")
        ;;
    *.py)
        language="Python"
        checker_command="python3"
        python_validator='import io, pathlib, sys, tokenize
data = pathlib.Path(sys.argv[1]).read_bytes()
encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
compile(data.decode(encoding), sys.argv[1], "exec")'
        checker=(python3 -c "$python_validator" "$target_path")
        ;;
    *.c)
        language="C"
        checker_command="gcc"
        checker=(gcc -fsyntax-only "$target_path")
        ;;
    *)
        ag_syntax_log "allowed" "unsupported file type; syntax check skipped for $relative_path"
        exit 0
        ;;
esac

if ! ag_require_command "$checker_command" 2>/dev/null; then
    ag_syntax_error "required $checker_command checker is unavailable for $relative_path"
fi

if ! checker_diagnostic="$("${checker[@]}" 2>&1)"; then
    printf 'AgentGuard BLOCKED: syntax validation failed for %s\n' "$relative_path" >&2
    if [[ -n "$checker_diagnostic" ]]; then
        printf '%s\n' "$checker_diagnostic" >&2
    fi
    ag_syntax_log "blocked" "$language syntax validation failed for $relative_path"
    # PostToolUse reports the failure; it cannot undo the completed Edit or Write.
    exit 2
fi

ag_syntax_log "allowed" "$language syntax validation succeeded for $relative_path"
exit 0
