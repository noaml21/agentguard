#!/usr/bin/env bash

AG_HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$AG_HOOK_DIR/../lib/common.sh"

ag_snapshot_log() {
    ag_log_event "snapshot" "pre_change_snapshot" "$1" "$2" >/dev/null 2>&1 || true
}

ag_snapshot_error() {
    printf 'AgentGuard snapshot error: %s\n' "$1" >&2
    ag_snapshot_log "blocked" "$1"
    exit 2
}

if ! ag_read_input; then
    printf 'AgentGuard snapshot error: invalid hook input; change blocked.\n' >&2
    exit 2
fi

if ! tool_name="$(ag_tool_name 2>/dev/null)"; then
    ag_snapshot_error "unable to read tool name"
fi

case "$tool_name" in
    Edit|Write)
        ;;
    *)
        exit 0
        ;;
esac

if ! session_id="$(ag_session_id 2>/dev/null)"; then
    ag_snapshot_error "unable to read session ID"
fi

if ! cwd="$(ag_cwd 2>/dev/null)" || [[ -z "$cwd" ]]; then
    ag_snapshot_error "workspace cwd is missing"
fi

if ! file_path="$(ag_file_path 2>/dev/null)" || [[ -z "$file_path" ]]; then
    ag_snapshot_error "file path is missing"
fi

if ! workspace_root="$(ag_canonical_path "$cwd" "$PWD" 2>/dev/null)" \
    || [[ ! -d "$workspace_root" ]]; then
    ag_snapshot_error "workspace cwd cannot be resolved: $cwd"
fi

if ! target_path="$(ag_canonical_path "$file_path" "$workspace_root" 2>/dev/null)"; then
    ag_snapshot_error "file path cannot be resolved: $file_path"
fi

workspace_prefix="${workspace_root%/}/"
if [[ "$target_path" != "$workspace_root" && "$target_path" != "$workspace_prefix"* ]]; then
    ag_snapshot_error "target is outside workspace: $target_path"
fi

if [[ "$target_path" == "$workspace_root" ]]; then
    relative_path="."
else
    relative_path="${target_path#"$workspace_prefix"}"
fi

if [[ ! -e "$target_path" ]]; then
    ag_snapshot_log "allowed" "target does not exist; no snapshot required"
    exit 0
fi

if [[ ! -f "$target_path" ]]; then
    ag_snapshot_error "existing target is not a regular file: $relative_path"
fi

config_file="$AG_CONFIG_DIR/agentguard.conf"
if [[ ! -f "$config_file" || ! -r "$config_file" ]] || ! exec 3<"$config_file"; then
    ag_snapshot_error "configuration file is missing or unreadable: $config_file"
fi

max_snapshots=""
snapshot_key_count=0
while IFS= read -r line <&3 || [[ -n "$line" ]]; do
    if [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi

    if [[ "$line" =~ ^[[:space:]]*MAX_SNAPSHOTS_PER_FILE[[:space:]]*=(.*)$ ]]; then
        snapshot_key_count=$((snapshot_key_count + 1))
        if (( snapshot_key_count > 1 )); then
            exec 3<&-
            ag_snapshot_error "configuration contains duplicate MAX_SNAPSHOTS_PER_FILE"
        fi
        if [[ ! "${BASH_REMATCH[1]}" =~ ^[[:space:]]*([1-9][0-9]*)[[:space:]]*$ ]]; then
            exec 3<&-
            ag_snapshot_error "MAX_SNAPSHOTS_PER_FILE must be a positive decimal integer"
        fi
        max_snapshots="${BASH_REMATCH[1]}"
    elif [[ ! "$line" =~ ^[[:space:]]*[A-Z][A-Z0-9_]*[[:space:]]*=[[:space:]]*[^[:space:]]+[[:space:]]*$ ]]; then
        exec 3<&-
        ag_snapshot_error "configuration contains an invalid assignment"
    fi
done
exec 3<&-

if (( snapshot_key_count != 1 )); then
    ag_snapshot_error "configuration must define MAX_SNAPSHOTS_PER_FILE exactly once"
fi

if ! ag_require_command sha256sum; then
    ag_snapshot_error "required sha256sum command is unavailable"
fi

if ! hash_record="$(printf '%s' "$relative_path" | sha256sum)"; then
    ag_snapshot_error "unable to hash workspace-relative path"
fi
path_hash="${hash_record%% *}"
if [[ ! "$path_hash" =~ ^[[:xdigit:]]{64}$ ]]; then
    ag_snapshot_error "sha256sum returned an invalid path identifier"
fi

snapshot_dir="$AG_STATE_DIR/snapshots/$path_hash"
versions_dir="$snapshot_dir/versions"
if ! mkdir -p -- "$versions_dir"; then
    ag_snapshot_error "unable to create snapshot directory"
fi

if ! metadata_tmp="$(mktemp "$snapshot_dir/.metadata.XXXXXX")"; then
    ag_snapshot_error "unable to create temporary snapshot metadata"
fi
if ! jq -cn \
    --arg canonical_path "$target_path" \
    --arg workspace_relative_path "$relative_path" \
    '{canonical_path: $canonical_path, workspace_relative_path: $workspace_relative_path}' \
    >"$metadata_tmp"; then
    rm -f -- "$metadata_tmp"
    ag_snapshot_error "unable to construct snapshot metadata"
fi
if ! mv -- "$metadata_tmp" "$snapshot_dir/metadata.json"; then
    rm -f -- "$metadata_tmp"
    ag_snapshot_error "unable to replace snapshot metadata"
fi

if ! snapshot_timestamp="$(date -u '+%Y%m%dT%H%M%S.%N')"; then
    ag_snapshot_error "unable to create snapshot timestamp"
fi
if ! snapshot_path="$(mktemp --tmpdir="$versions_dir" --suffix='.snapshot' \
    "${snapshot_timestamp}.XXXXXXXX")"; then
    ag_snapshot_error "unable to create snapshot file"
fi
if ! cp -- "$target_path" "$snapshot_path"; then
    rm -f -- "$snapshot_path"
    ag_snapshot_error "unable to copy existing file into snapshot storage"
fi

shopt -s nullglob
snapshot_files=("$versions_dir"/*.snapshot)
excess_count=$((${#snapshot_files[@]} - max_snapshots))
for ((index = 0; index < excess_count; index++)); do
    if ! rm -f -- "${snapshot_files[index]}"; then
        ag_snapshot_error "unable to rotate old snapshots"
    fi
done

ag_snapshot_log "allowed" "pre-change snapshot created for $relative_path in session $session_id"
exit 0
