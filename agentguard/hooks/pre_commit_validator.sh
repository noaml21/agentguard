#!/usr/bin/env bash

AG_HOOK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$AG_HOOK_DIR/../lib/common.sh"

ag_commit_log() {
    ag_log_event "commit_check" "pre_commit_validator" "$1" "$2" >/dev/null 2>&1 || true
}

ag_commit_block() {
    printf 'AgentGuard BLOCKED: %s\n' "$1" >&2
    ag_commit_log "blocked" "$1"
    exit 2
}

ag_commit_config_error() {
    printf 'AgentGuard commit-policy configuration error: %s\n' "$1" >&2
    ag_commit_log "blocked" "configuration error: $1"
    exit 2
}

if ! ag_read_input; then
    printf 'AgentGuard commit-policy error: invalid hook input; command blocked.\n' >&2
    exit 2
fi

if ! tool_name="$(ag_tool_name 2>/dev/null)"; then
    ag_commit_block "unable to read tool name"
fi

if [[ "$tool_name" != "Bash" ]]; then
    exit 0
fi

if ! command="$(ag_command 2>/dev/null)"; then
    ag_commit_block "unable to read Bash command"
fi

if [[ -z "$command" ]]; then
    exit 0
fi

if [[ ! "$command" =~ ^[[:space:]]*git[[:space:]]+commit([[:space:]]|$) ]]; then
    exit 0
fi

if ! ag_require_command python3 2>/dev/null; then
    ag_commit_block "required python3 tokenizer is unavailable"
fi

shlex_parser='import json, shlex, sys
try:
    tokens = shlex.split(sys.argv[1], posix=True)
except ValueError as error:
    print(error)
    raise SystemExit(2)

message_found = False
message = ""
for index, token in enumerate(tokens[2:], start=2):
    if token in {"-m", "-am", "--message"}:
        message_found = True
        message = tokens[index + 1] if index + 1 < len(tokens) else ""
        break
    if token.startswith("--message="):
        message_found = True
        message = token.split("=", 1)[1]
        break

json.dump({"message_found": message_found, "message": message}, sys.stdout)'

if ! parsed_message="$(python3 -c "$shlex_parser" "$command" 2>&1)"; then
    ag_commit_block "unable to parse direct git commit command: $parsed_message"
fi

if ! jq -e '
    type == "object" and
    (.message_found | type == "boolean") and
    (.message | type == "string")
' <<<"$parsed_message" >/dev/null 2>&1; then
    ag_commit_block "tokenizer returned invalid output"
fi

if [[ "$(jq -r '.message_found' <<<"$parsed_message")" != "true" ]]; then
    ag_commit_log "allowed" "no supported static commit message; validation skipped"
    exit 0
fi

prefix_file="$AG_CONFIG_DIR/commit_prefixes.txt"
if [[ ! -f "$prefix_file" || ! -r "$prefix_file" ]] || ! exec 3<"$prefix_file"; then
    ag_commit_config_error "prefix policy is missing or unreadable: $prefix_file"
fi

declare -A allowed_prefixes=()
prefix_count=0
while IFS= read -r prefix <&3 || [[ -n "$prefix" ]]; do
    prefix="${prefix#"${prefix%%[![:space:]]*}"}"
    prefix="${prefix%"${prefix##*[![:space:]]}"}"

    if [[ -z "$prefix" || "$prefix" == \#* ]]; then
        continue
    fi
    if [[ ! "$prefix" =~ ^[a-z][a-z0-9-]*$ ]]; then
        exec 3<&-
        ag_commit_config_error "invalid commit prefix: $prefix"
    fi
    if [[ -n "${allowed_prefixes[$prefix]+present}" ]]; then
        exec 3<&-
        ag_commit_config_error "duplicate commit prefix: $prefix"
    fi

    allowed_prefixes["$prefix"]=1
    prefix_count=$((prefix_count + 1))
done
exec 3<&-

if (( prefix_count == 0 )); then
    ag_commit_config_error "prefix policy contains no valid prefixes"
fi

if jq -e '.message | test("^\\s|\\s$")' <<<"$parsed_message" >/dev/null; then
    ag_commit_block "commit message must not begin or end with whitespace"
fi

header="$(jq -r '.message | split("\n")[0]' <<<"$parsed_message")"
header_length=${#header}
if (( header_length < 10 || header_length > 72 )); then
    ag_commit_block "commit header length must be between 10 and 72 characters; got $header_length"
fi

if [[ "$header" =~ [[:space:]]$ ]]; then
    ag_commit_block "commit header must not end with whitespace"
fi
if [[ "$header" == *. ]]; then
    ag_commit_block "commit header must not end with a period"
fi

if [[ ! "$header" =~ ^([a-z][a-z0-9-]*)(\(([a-z0-9._-]+)\))?:\ ([^[:space:]].*)$ ]]; then
    ag_commit_block "commit header must match 'type: subject' or 'type(scope): subject'"
fi

commit_type="${BASH_REMATCH[1]}"
if [[ -z "${allowed_prefixes[$commit_type]+present}" ]]; then
    ag_commit_block "commit type is not allowed: $commit_type"
fi

ag_commit_log "allowed" "commit header validated successfully with type $commit_type"
exit 0
