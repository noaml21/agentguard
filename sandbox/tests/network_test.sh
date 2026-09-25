#!/usr/bin/env bash
# Phase 6: network policy mode tests. Kernel-feature dependent (needs seccomp).
# --net none must deny all IP networking (TCP/UDP/raw, v4+v6) while keeping
# AF_UNIX; --net all must allow it. Listeners OUTSIDE the sandbox on loopback
# model external services and record what actually arrives (effect oracle), so
# a pass means "no packet reached the listener", not just "a nonzero exit".
set -u

TESTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SANDBOX_DIR="$(cd -- "$TESTS_DIR/.." && pwd -P)"
RUN="${AGENTGUARD_RUN:-$SANDBOX_DIR/build/agentguard-run}"
RUN="$(cd -- "$(dirname -- "$RUN")" && pwd -P)/$(basename -- "$RUN")"

PASS=0; FAIL=0; SKIP=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }
skip() { SKIP=$((SKIP + 1)); printf 'SKIP %s -- %s\n' "$1" "$2"; }

status_json="$("$RUN" --status --json 2>/dev/null)"
if [[ "$status_json" != *'"name":"seccomp","available":true'* ]]; then
    printf 'SKIP all network tests -- seccomp unavailable (net enforcement needs it)\n'
    printf '\n0 passed, 0 failed, 1 skipped\n'
    exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentguard-net.XXXXXX")" || exit 1
cleanup() {
    [[ -n "${LISTENER_PID:-}" ]] && kill "$LISTENER_PID" 2>/dev/null
    [[ "$TMP" == */agentguard-net.* ]] && rm -rf -- "$TMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Listeners outside the sandbox: TCP+UDP on 127.0.0.1 and (if the host has it)
# ::1. Each received connection/datagram appends its kind to $TMP/events.
python3 - "$TMP/ports" "$TMP/events" <<'PY' &
import selectors, socket, sys, time
ports, events = sys.argv[1], sys.argv[2]
sel = selectors.DefaultSelector()
def mk(fam, typ, host):
    try:
        s = socket.socket(fam, typ); s.bind((host, 0))
    except OSError:
        return 0
    if typ == socket.SOCK_STREAM: s.listen()
    kind = ("tcp" if typ == socket.SOCK_STREAM else "udp") + ("4" if fam == socket.AF_INET else "6")
    sel.register(s, selectors.EVENT_READ, kind)
    return s.getsockname()[1]
p = [mk(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1"), mk(socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1"),
     mk(socket.AF_INET6, socket.SOCK_STREAM, "::1"), mk(socket.AF_INET6, socket.SOCK_DGRAM, "::1")]
open(ports + ".tmp", "w").write(" ".join(map(str, p)) + "\n")
import os; os.rename(ports + ".tmp", ports)
end = time.time() + 60
while time.time() < end:
    for key, _ in sel.select(timeout=0.5):
        s = key.fileobj
        if key.data.startswith("tcp"):
            c, _ = s.accept(); c.close()
        else:
            s.recvfrom(64)
        with open(events, "a") as f: f.write(key.data + "\n")
PY
LISTENER_PID=$!
for _ in $(seq 1 50); do [[ -s "$TMP/ports" ]] && break; sleep 0.1; done
read -r TCP4 UDP4 TCP6 UDP6 < "$TMP/ports" 2>/dev/null || { echo "could not start listeners"; exit 1; }
: > "$TMP/events"

# Client run inside the sandbox: FAMILY(4|6) PROTO(tcp|udp) PORT -> SENT|EACCES|ERR n
client='import socket,sys
fam = socket.AF_INET if sys.argv[1] == "4" else socket.AF_INET6
host = "127.0.0.1" if sys.argv[1] == "4" else "::1"
port = int(sys.argv[3])
try:
    if sys.argv[2] == "tcp":
        s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(3); s.connect((host, port))
    else:
        s = socket.socket(fam, socket.SOCK_DGRAM); s.sendto(b"x", (host, port))
    s.close(); print("SENT")
except PermissionError: print("EACCES")
except OSError as e: print("ERR", e.errno)'
net() { local mode="$1"; shift; ( cd "$TMP" && "$RUN" --net "$mode" --workspace "$TMP" -- "$@" 2>/dev/null ); }
events_has() { grep -qx "$1" "$TMP/events"; }
wait_event() { for _ in $(seq 1 30); do events_has "$1" && return 0; sleep 0.1; done; return 1; }

# ---------------- --net none ----------------
out="$(net none python3 -c "$client" 4 tcp "$TCP4")"
[[ "$out" == "EACCES" ]] && pass "net=none: IPv4 TCP connect denied (EACCES)" || fail "net=none tcp4" "$out"
out="$(net none python3 -c "$client" 4 udp "$UDP4")"
[[ "$out" == "EACCES" ]] && pass "net=none: IPv4 UDP send denied" || fail "net=none udp4" "$out"
if [[ "$TCP6" != 0 && "$UDP6" != 0 ]]; then
    out="$(net none python3 -c "$client" 6 tcp "$TCP6")"
    [[ "$out" == "EACCES" ]] && pass "net=none: IPv6 TCP connect denied" || fail "net=none tcp6" "$out"
    out="$(net none python3 -c "$client" 6 udp "$UDP6")"
    [[ "$out" == "EACCES" ]] && pass "net=none: IPv6 UDP send denied" || fail "net=none udp6" "$out"
else
    skip "net=none IPv6" "host has no ::1 loopback"
fi

# Raw IP and other non-local families (allowlist: only AF_UNIX/AF_NETLINK).
out="$(net none python3 -c 'import socket
r=[]
for fam, typ in ((socket.AF_INET, socket.SOCK_RAW), (socket.AF_PACKET, socket.SOCK_RAW), (40, socket.SOCK_STREAM)):
    try: socket.socket(fam, typ); r.append("OPEN")
    except PermissionError: r.append("EACCES")
    except OSError as e: r.append("ERR%d" % e.errno)
print(" ".join(r))')"
[[ "$out" == "EACCES EACCES EACCES" ]] && pass "net=none: raw IP, AF_PACKET, AF_VSOCK denied" \
    || fail "net=none raw/other families" "$out"

# A different spelling (bash /dev/tcp) and a descendant: kernel-enforced, so both fail.
out="$(net none bash -c "exec 3<>/dev/tcp/127.0.0.1/$TCP4 && echo CONNECTED || echo DENIED")"
[[ "$out" == "DENIED" ]] && pass "net=none: bash /dev/tcp spelling denied" || fail "net=none bash" "$out"
out="$(net none sh -c "python3 -c '$client' 4 tcp $TCP4")"
[[ "$out" == "EACCES" ]] && pass "net=none: descendant inherits restriction" || fail "net=none descendant" "$out"

# Default mode is none (restrictive by default).
out="$( cd "$TMP" && "$RUN" --workspace "$TMP" -- python3 -c "$client" 4 tcp "$TCP4" 2>/dev/null )"
[[ "$out" == "EACCES" ]] && pass "default mode is net=none" || fail "default net" "$out"

# Effect oracle: nothing from the none-mode runs reached any listener.
sleep 0.3
[[ ! -s "$TMP/events" ]] && pass "net=none: listeners received nothing" \
    || fail "net=none effect" "$(tr '\n' ' ' < "$TMP/events")"

# AF_UNIX local IPC works (socketpair round trip + pathname socket in workspace).
out="$(net none python3 -c 'import socket, threading
a, b = socket.socketpair(); a.sendall(b"ping"); ok1 = b.recv(4) == b"ping"
srv = socket.socket(socket.AF_UNIX); srv.bind("u.sock"); srv.listen()
c = socket.socket(socket.AF_UNIX); c.connect("u.sock"); c.sendall(b"pong")
conn, _ = srv.accept(); ok2 = conn.recv(4) == b"pong"
print("UNIX_OK" if ok1 and ok2 else "BAD")')"
[[ "$out" == "UNIX_OK" ]] && pass "net=none: AF_UNIX local IPC works" || fail "net=none AF_UNIX" "$out"

# ---------------- --net all ----------------
out="$(net all python3 -c "$client" 4 tcp "$TCP4")"
[[ "$out" == "SENT" ]] && wait_event tcp4 && pass "net=all: IPv4 TCP connect reaches listener" \
    || fail "net=all tcp4" "$out"
out="$(net all python3 -c "$client" 4 udp "$UDP4")"
[[ "$out" == "SENT" ]] && wait_event udp4 && pass "net=all: IPv4 UDP datagram reaches listener" \
    || fail "net=all udp4" "$out"
if [[ "$TCP6" != 0 ]]; then
    out="$(net all python3 -c "$client" 6 tcp "$TCP6")"
    [[ "$out" == "SENT" ]] && wait_event tcp6 && pass "net=all: IPv6 TCP connect reaches listener" \
        || fail "net=all tcp6" "$out"
else
    skip "net=all IPv6" "host has no ::1 loopback"
fi
: > "$TMP/events"
out="$(net all sh -c "python3 -c '$client' 4 tcp $TCP4")"
[[ "$out" == "SENT" ]] && wait_event tcp4 && pass "net=all: descendant can connect" \
    || fail "net=all descendant" "$out"
out="$(net all python3 -c 'import socket; a,b=socket.socketpair(); a.sendall(b"k"); print("UNIX_OK" if b.recv(1)==b"k" else "BAD")')"
[[ "$out" == "UNIX_OK" ]] && pass "net=all: AF_UNIX works" || fail "net=all AF_UNIX" "$out"

# ---------------- status / contract ----------------
out="$("$RUN" --net none --status --json)"
[[ "$out" == *'"network":{"mode":"none","enforced":true}'* ]] \
    && pass "status json: net none enforced" || fail "status json none" "$out"
out="$("$RUN" --net all --status --json)"
[[ "$out" == *'"network":{"mode":"all","enforced":true}'* ]] \
    && pass "status json: net all" || fail "status json all" "$out"
# seccomp unavailable: strict refuses; degraded runs but loudly reports net none unenforced.
AGENTGUARD_TEST_UNAVAIL=seccomp "$RUN" --net none -- true >/dev/null 2>&1; rc=$?
[[ "$rc" == 125 ]] && pass "strict: net none without seccomp refuses (125)" || fail "strict net" "rc=$rc"
out="$(AGENTGUARD_TEST_UNAVAIL=seccomp "$RUN" --degraded --net none --status --json)"
[[ "$out" == *'"network":{"mode":"none","enforced":false}'* ]] \
    && pass "degraded status: net none reported NOT enforced" || fail "degraded status" "$out"
err="$(cd "$TMP" && AGENTGUARD_TEST_UNAVAIL=seccomp "$RUN" --degraded --net none --workspace "$TMP" -- true 2>&1 >/dev/null)"
[[ "$err" == *"--net none is NOT enforced"* ]] && pass "degraded run warns net none unenforced" \
    || fail "degraded warning" "$err"
"$RUN" --net bogus -- true >/dev/null 2>&1; rc=$?
[[ "$rc" == 125 ]] && pass "invalid --net value rejected (125)" || fail "invalid --net" "rc=$rc"

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[[ "$FAIL" -eq 0 ]]
