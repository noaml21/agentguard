#!/usr/bin/env python3
"""Interactive-TTY tests for agentguard-run, driven through a real pty.

`agentguard-run -- claude` must behave like a normal terminal program: the
target must see a TTY, be the foreground process group, receive Ctrl-C, and see
SIGWINCH on resize. These properties cannot be checked without a controlling
terminal, so we allocate one with the pty module.
"""
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUN = os.environ.get("AGENTGUARD_RUN",
                     os.path.join(REPO, "sandbox", "build", "agentguard-run"))

results = []


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" -- {detail}" if detail else ""))


def read_until(fd, needle, timeout=5.0):
    """Read from fd until needle appears or timeout; return accumulated bytes."""
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline and needle not in buf:
        r, _, _ = select.select([fd], [], [], max(0, deadline - time.time()))
        if fd in r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
    return buf


def read_to_eof(fd, timeout=5.0):
    """Drain fd until the slave side closes (target+runner exited)."""
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], max(0, deadline - time.time()))
        if fd not in r:
            break
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


SH = "bash" if os.path.exists("/bin/bash") else "sh"


def run_in_pty(args):
    """Fork the runner as session leader with a controlling pty. Returns
    (child_pid, master_fd)."""
    pid, master = pty.fork()
    if pid == 0:
        os.execvp(args[0], args)
        os._exit(127)
    return pid, master


def test_target_sees_tty():
    pid, master = run_in_pty([RUN, "--", SH, "-c",
                              "test -t 0 && test -t 1 && echo IS_TTY || echo NOT_TTY"])
    out = read_until(master, b"TTY")
    os.close(master)
    os.waitpid(pid, 0)
    record("target sees a controlling TTY", b"IS_TTY" in out, out[-60:].decode(errors="replace"))


def test_target_is_foreground():
    # tcgetpgrp of the target's stdin should equal the target's own pgrp.
    pid, master = run_in_pty([RUN, "--", SH, "-c",
                              'echo FG:$(ps -o pgid= -p $$)/$(ps -o tpgid= -p $$)'])
    out = read_until(master, b"FG:")
    os.close(master)
    os.waitpid(pid, 0)
    ok = False
    for line in out.decode(errors="replace").splitlines():
        if line.startswith("FG:"):
            try:
                pgid, tpgid = line[3:].split("/")
                ok = pgid.strip() == tpgid.strip()
            except ValueError:
                ok = False
    record("target is the foreground process group", ok, out[-80:].decode(errors="replace"))


def test_ctrl_c_reaches_target():
    # The target traps SIGINT and prints a marker. Sending 0x03 (Ctrl-C) on the
    # pty must be delivered by the kernel to the foreground group (the target).
    pid, master = run_in_pty([RUN, "--", SH, "-c",
                              'trap "echo GOT_INT; exit 0" INT; echo READY; sleep 10'])
    read_until(master, b"READY")
    os.write(master, b"\x03")
    out = read_until(master, b"GOT_INT")
    os.close(master)
    _, status = os.waitpid(pid, 0)
    record("Ctrl-C reaches the target", b"GOT_INT" in out, out[-80:].decode(errors="replace"))


def test_sigwinch_reaches_target():
    # A shell defers a WINCH trap until its foreground command (sleep) returns,
    # so use a Python target whose handler runs immediately during time.sleep.
    prog = ("import signal,sys,time;"
            "signal.signal(signal.SIGWINCH, lambda *a:(print('GOT_WINCH',flush=True),sys.exit(0)));"
            "print('READY',flush=True); time.sleep(10)")
    pid, master = run_in_pty([RUN, "--", "python3", "-c", prog])
    read_until(master, b"READY")
    # Resize the pty; the kernel sends SIGWINCH to the foreground group.
    winsize = struct.pack("HHHH", 40, 100, 0, 0)
    fcntl.ioctl(master, termios.TIOCSWINSZ, winsize)
    out = read_until(master, b"GOT_WINCH")
    os.close(master)
    os.waitpid(pid, 0)
    record("SIGWINCH reaches the target on resize", b"GOT_WINCH" in out,
           out[-80:].decode(errors="replace"))


def test_exit_status_through_pty():
    pid, master = run_in_pty([RUN, "--", SH, "-c", "exit 33"])
    read_to_eof(master, timeout=3.0)
    _, status = os.waitpid(pid, 0)
    os.close(master)
    code = os.waitstatus_to_exitcode(status)
    record("exit status propagates through pty", code == 33, f"got {code}")


def main():
    if not os.access(RUN, os.X_OK):
        print(f"error: runner not executable at {RUN}", file=sys.stderr)
        return 1
    for t in (test_target_sees_tty, test_target_is_foreground,
              test_ctrl_c_reaches_target, test_sigwinch_reaches_target,
              test_exit_status_through_pty):
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            record(t.__name__, False, f"exception: {exc}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
