#!/usr/bin/env python3
"""Phase 9 effect oracles. Every PID, IPC ID, socket and byte is fixture-owned.

No real bus, syslog/nscd service, credentials, or existing SysV objects are used.
The sentinel opts *itself* out of Yama restrictions so baselines discriminate
AgentGuard from host policy; no host setting is changed.
"""
import ctypes as C
import errno
import json
import os
import platform
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve()
RUN = Path(os.environ.get("AGENTGUARD_RUN", HERE.parents[1] / "build/agentguard-run")).resolve()
LIB = C.CDLL(None, use_errno=True)
LIB.shmat.restype = C.c_void_p
LIB.ptrace.restype = C.c_long
ORIGINAL = b"fixture-original"
CHANGED = b"fixture-modified"
SYSCALLS = {
    "x86_64": {"ioprio_set": 251, "ioprio_get": 252, "sched_setattr": 314},
    "aarch64": {"ioprio_set": 30, "ioprio_get": 31, "sched_setattr": 274},
}.get(platform.machine(), {})


class MQAttr(C.Structure):
    _fields_ = [("flags", C.c_long), ("maxmsg", C.c_long), ("msgsize", C.c_long),
                ("curmsgs", C.c_long), ("reserved", C.c_long * 4)]


def checked(value):
    if value == -1 or value == C.c_void_p(-1).value:
        err = C.get_errno()
        raise OSError(err, os.strerror(err))
    return value


class IOVec(C.Structure):
    _fields_ = [("base", C.c_void_p), ("length", C.c_size_t)]


def probe(op, args):
    if op.startswith("schedule-"):
        pid = int(args[0])
        if op == "schedule-nice":
            os.setpriority(os.PRIO_PROCESS, pid, 19)
        elif op == "schedule-affinity":
            os.sched_setaffinity(pid, {min(os.sched_getaffinity(pid))})
        elif op == "schedule-policy":
            os.sched_setscheduler(pid, os.SCHED_BATCH, os.sched_param(0))
        elif op == "schedule-param":
            os.sched_setparam(pid, os.sched_param(0))
        elif op == "schedule-ioprio":
            checked(LIB.syscall(SYSCALLS["ioprio_set"], 1, pid, 3 << 13))
        elif op == "schedule-nice-group":
            os.setpriority(os.PRIO_PGRP, pid, 19)
        elif op == "schedule-ioprio-group":
            checked(LIB.syscall(SYSCALLS["ioprio_set"], 2, pid, 3 << 13))
        elif op == "schedule-attr":
            class SchedAttr(C.Structure):
                _fields_ = [("size", C.c_uint32), ("policy", C.c_uint32),
                            ("flags", C.c_uint64), ("nice", C.c_int32),
                            ("priority", C.c_uint32), ("runtime", C.c_uint64),
                            ("deadline", C.c_uint64), ("period", C.c_uint64)]
            attr = SchedAttr(size=C.sizeof(SchedAttr), policy=os.SCHED_BATCH)
            checked(LIB.syscall(SYSCALLS["sched_setattr"], pid, C.byref(attr), 0))
        return "changed"
    if op in ("mq", "mq-read"):
        flags = os.O_RDONLY if op == "mq-read" else os.O_WRONLY
        fd = checked(LIB.mq_open(args[0].encode(), flags | os.O_NONBLOCK))
        try:
            if op == "mq-read":
                buf = C.create_string_buffer(64)
                checked(LIB.mq_receive(fd, buf, 64, None))
            else:
                checked(LIB.mq_send(fd, CHANGED, len(CHANGED), 0))
        finally:
            checked(LIB.mq_close(fd))
        return "sent"
    if op in ("vm-read", "vm-write", "ptrace", "proc-read", "proc-write", "proc-fd"):
        pid, addr, fd = map(int, args)
        if op.startswith("vm-"):
            buf = C.create_string_buffer(CHANGED, 64)
            local, remote = IOVec(C.addressof(buf), len(ORIGINAL)), IOVec(addr, len(ORIGINAL))
            fn = LIB.process_vm_readv if op == "vm-read" else LIB.process_vm_writev
            checked(fn(pid, C.byref(local), 1, C.byref(remote), 1, 0))
            return buf.raw[:len(ORIGINAL)].decode()
        if op == "ptrace":
            checked(LIB.ptrace(16, pid, None, None))  # ATTACH only this fixture
            try:
                os.waitpid(pid, 0)
                checked(LIB.ptrace(5, pid, C.c_void_p(addr), C.c_void_p(0x41414141)))
            finally:
                checked(LIB.ptrace(17, pid, None, None))
            return "attached-and-wrote"
        if op == "proc-fd":
            return Path(f"/proc/{pid}/fd/{fd}").read_text()
        flags = os.O_RDONLY if op == "proc-read" else os.O_RDWR
        mem = os.open(f"/proc/{pid}/mem", flags)
        try:
            if op == "proc-read":
                return os.pread(mem, len(ORIGINAL), addr).decode()
            return os.pwrite(mem, CHANGED, addr)
        finally:
            os.close(mem)
    if op == "shm":
        addr = checked(LIB.shmat(int(args[0]), None, 0))
        try:
            C.memmove(addr, CHANGED, len(CHANGED))
        finally:
            checked(LIB.shmdt(C.c_void_p(addr)))
        return "wrote"
    if op == "sem":
        # SETVAL=16; only the explicitly passed, owned fixture ID.
        checked(LIB.semctl(int(args[0]), 0, 16, 7))
        return "changed"
    if op == "msg":
        class Message(C.Structure):
            _fields_ = [("kind", C.c_long), ("data", C.c_char * 16)]
        msg = Message(1, CHANGED)
        checked(LIB.msgsnd(int(args[0]), C.byref(msg), 16, 0o4000))
        return "sent"
    if op == "fd":
        fd, kind = int(args[0]), args[1]
        if kind == "socket":
            sock = socket.socket(fileno=fd)
            sock.sendall(b"fixture-hit")
        elif kind == "pidfd":
            signal.pidfd_send_signal(fd, 0)
        else:
            os.fstat(fd)
        return "open"
    if op == "fds":
        for fd in map(int, args):
            os.fstat(fd)
        return len(args)
    if op == "unix":
        path, kind = args
        if kind == "pair-dgram":
            sock, peer = socket.socketpair(type=socket.SOCK_DGRAM)
            sock.sendto(b"fixture-hit", path)
            peer.close()
        else:
            sock = socket.socket(socket.AF_UNIX, int(kind))
            sock.connect(path)
            sock.sendall(b"fixture-hit")
        sock.close()
        return "sent"
    raise ValueError(op)


def sentinel(path):
    checked(LIB.prctl(4, 1, 0, 0, 0))  # PR_SET_DUMPABLE, fixture only
    checked(LIB.prctl(0x59616D61, C.c_ulong(-1), 0, 0, 0))  # PR_SET_PTRACER_ANY
    buf = C.create_string_buffer(ORIGINAL, 64)
    with open(path) as file:
        print(json.dumps([os.getpid(), C.addressof(buf), file.fileno()]), flush=True)
        for line in sys.stdin:
            if line.strip() == "reset":
                buf.value = ORIGINAL
            print(json.dumps(buf.raw[:len(ORIGINAL)].decode()), flush=True)


class HostIPC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="agentguard-ipc-extra-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.env = {"PATH": os.environ["PATH"], "HOME": str(cls.root),
                   "TMPDIR": str(cls.root), "XDG_RUNTIME_DIR": str(cls.root), "LC_ALL": "C"}
        # Keep sanitizer configuration, never forward login/session credentials.
        for key in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):
            if key in os.environ:
                cls.env[key] = os.environ[key]
        cls.script = cls.root / HERE.name
        shutil.copyfile(HERE, cls.script)
        cls.candidate = cls.root / "unix-filter"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o",
                        str(cls.candidate), str(HERE.with_name("unix_filter_probe.c"))], check=True)
        status = subprocess.run([str(RUN), "--status", "--json"], env=cls.env,
                                capture_output=True, text=True, check=True)
        cls.layers = {x["name"]: x["available"] for x in json.loads(status.stdout)["layers"]}
        if not all(cls.layers.get(x) for x in ("no_new_privs", "landlock_fs", "landlock_scope", "seccomp")):
            raise unittest.SkipTest("extended fixtures require Landlock ABI >= 6 and seccomp")

    def command(self, argv, *, disabled="", keep=(), passed=(), candidate=False, baseline=False,
                net="none"):
        env = dict(self.env)
        if disabled:
            env["AGENTGUARD_TEST_UNAVAIL"] = disabled
        prefix = [] if baseline else [str(RUN), "--workspace", str(self.root), "--net", net,
                                      "--timeout", "8"]
        if disabled and not baseline:
            prefix += ["--degraded"]
        for fd in keep:
            prefix += ["--keep-fd", str(fd)]
        if not baseline:
            # Installed developer binaries can live outside /usr; grant only the
            # named executable, never a real home/config/credential directory.
            executable = Path(argv[0]).resolve()
            prefix += ["--allow-read", str(executable)]
            prefix += ["--"]
        if candidate:
            prefix += [str(self.candidate)]
        return subprocess.run(prefix + list(map(str, argv)), env=env, cwd=self.root,
                              pass_fds=passed, capture_output=True, text=True, timeout=15)

    def attack(self, op, args, **kwargs):
        result = self.command([sys.executable, self.script, "--probe", op, *args], **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def outside(self):
        path = self.root / "fixture-data"
        path.write_text("fixture-file-data")
        proc = subprocess.Popen([sys.executable, str(self.script), "--sentinel", str(path)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=self.env, start_new_session=True)
        def cleanup():
            # The fixture is our child and has not been reaped, so PID reuse is impossible.
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            proc.stdin.close(); proc.stdout.close(); proc.stderr.close()
        self.addCleanup(cleanup)
        self.assertTrue(select.select([proc.stdout], [], [], 5)[0], "sentinel not ready")
        args = json.loads(proc.stdout.readline())
        return proc, args

    def value(self, proc, command="read"):
        proc.stdin.write(command + "\n"); proc.stdin.flush()
        self.assertTrue(select.select([proc.stdout], [], [], 5)[0], "sentinel stopped or dead")
        return json.loads(proc.stdout.readline())

    def test_outside_memory_and_proc(self):
        proc, args = self.outside()
        for op in ("ptrace", "vm-read", "vm-write", "proc-read", "proc-write", "proc-fd"):
            with self.subTest(operation=op, mode="unconfined-control"):
                self.value(proc, "reset")
                control = self.attack(op, args, baseline=True)
                self.assertNotIn("errno", control, control)
                if op in ("ptrace", "vm-write", "proc-write"):
                    self.assertNotEqual(self.value(proc), ORIGINAL.decode())
                elif op == "proc-fd":
                    self.assertEqual(control["value"], "fixture-file-data")
                else:
                    self.assertEqual(control["value"], ORIGINAL.decode())
            for disabled in ("", "seccomp", "landlock_fs,landlock_scope"):
                # seccomp does not mediate /proc opens. The deliberate no-Landlock
                # arm must demonstrate that those reads/writes can really succeed.
                allowed = op.startswith("proc-") and disabled == "landlock_fs,landlock_scope"
                with self.subTest(operation=op, disabled=disabled):
                    self.value(proc, "reset")
                    got = self.attack(op, args, disabled=disabled)
                    if allowed:
                        self.assertNotIn("errno", got, got)
                    else:
                        self.assertIn(got.get("errno"), (errno.EPERM, errno.EACCES), got)
                        self.assertEqual(self.value(proc), ORIGINAL.decode())
        result = self.command([sys.executable, "-c",
                               f"print('Name:' in open('/proc/{args[0]}/status').read())"])
        self.assertEqual(result.stdout.strip(), "True")  # metadata is NOT confidential

    def test_inherited_socket_and_pidfd(self):
        proc, args = self.outside()
        a, b = socket.socketpair()
        self.addCleanup(a.close); self.addCleanup(b.close)
        b.settimeout(0.2)
        pidfd = os.pidfd_open(args[0]); self.addCleanup(os.close, pidfd)
        for fd, kind in ((a.fileno(), "socket"), (pidfd, "pidfd")):
            with self.subTest(kind=kind):
                got = self.attack("fd", [fd, kind], passed=(fd,))
                self.assertEqual(got.get("errno"), errno.EBADF, got)
        with self.assertRaises(TimeoutError):
            b.recv(64)
        got = self.attack("fd", [a.fileno(), "socket"], passed=(a.fileno(),), keep=(a.fileno(),))
        self.assertEqual(got, {"value": "open"})
        self.assertEqual(b.recv(64), b"fixture-hit")  # explicit authority delegation
        got = self.attack("fd", [pidfd, "pidfd"], passed=(pidfd,), keep=(pidfd,))
        self.assertEqual(got.get("errno"), errno.EPERM)  # scope still protects the sentinel
        self.assertEqual(self.value(proc), ORIGINAL.decode())

    def test_keep_fd_capacity(self):
        fds = [os.open(self.script, os.O_RDONLY) for _ in range(64)]
        for fd in fds:
            self.addCleanup(os.close, fd)
        got = self.attack("fds", fds, passed=tuple(fds), keep=tuple(fds))
        self.assertEqual(got, {"value": 64})

    def test_pathname_unix_and_candidate(self):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET, "pair-dgram"):
            with self.subTest(kind=kind):
                path = str(self.root / f"socket-{kind}")
                typ = socket.SOCK_DGRAM if kind == "pair-dgram" else kind
                with socket.socket(socket.AF_UNIX, typ) as server:
                    server.bind(path); server.settimeout(0.2)
                    if typ != socket.SOCK_DGRAM:
                        server.listen(8)
                    def receive():
                        if typ == socket.SOCK_DGRAM:
                            return server.recv(64)
                        conn, _ = server.accept()
                        with conn:
                            conn.settimeout(0.2)
                            return conn.recv(64)
                    for net in ("none", "all"):
                        got = self.attack("unix", [path, kind], net=net)
                        self.assertEqual(got, {"value": "sent"})
                        self.assertEqual(receive(), b"fixture-hit")
                        got = self.attack("unix", [path, kind], candidate=True, net=net)
                        self.assertEqual(got.get("errno"), errno.EACCES)
                        with self.assertRaises(TimeoutError):
                            receive()

    def test_sysv_objects(self):
        # IPC_PRIVATE always allocates NEW objects; never enumerate existing IDs.
        shm = checked(LIB.shmget(0, 64, 0o600))
        self.addCleanup(lambda: checked(LIB.shmctl(shm, 0, None)))  # IPC_RMID
        addr = checked(LIB.shmat(shm, None, 0))
        self.addCleanup(lambda: checked(LIB.shmdt(C.c_void_p(addr))))
        sem = checked(LIB.semget(0, 1, 0o600))
        self.addCleanup(lambda: checked(LIB.semctl(sem, 0, 0)))
        msg = checked(LIB.msgget(0, 0o600))
        self.addCleanup(lambda: checked(LIB.msgctl(msg, 0, None)))
        for op, ident in (("shm", shm), ("sem", sem), ("msg", msg)):
            for disabled, allowed in (("seccomp", True), ("", False)):
                with self.subTest(operation=op, disabled=disabled):
                    C.memmove(addr, ORIGINAL, len(ORIGINAL))
                    checked(LIB.semctl(sem, 0, 16, 1))
                    got = self.attack(op, [ident], disabled=disabled)
                    if allowed:
                        self.assertNotIn("errno", got, got)
                    else:
                        self.assertEqual(got.get("errno"), errno.EPERM, got)
                    if op == "shm":
                        self.assertEqual(C.string_at(addr, len(ORIGINAL)), CHANGED if allowed else ORIGINAL)
                    elif op == "sem":
                        self.assertEqual(checked(LIB.semctl(sem, 0, 12)), 7 if allowed else 1)  # GETVAL
                    else:
                        buf = C.create_string_buffer(64)
                        rc = LIB.msgrcv(msg, buf, 16, 0, 0o4000)  # IPC_NOWAIT
                        self.assertEqual(rc, 16 if allowed else -1)
                        if not allowed:
                            self.assertEqual(C.get_errno(), errno.ENOMSG)

    def test_candidate_compatibility(self):
        cases = {
            "asyncio": "import asyncio; asyncio.run(asyncio.sleep(0)); print('ok')",
            "socketpair": "import socket; a,b=socket.socketpair(); a.send(b'x'); assert b.recv(1)==b'x'; print('ok')",
            "multiprocessing-pipe": "import multiprocessing as m; a,b=m.Pipe(); p=m.Process(target=lambda: b.send(7)); p.start(); assert a.recv()==7; p.join(); print('ok')",
            "multiprocessing-manager": "import multiprocessing as m; manager=m.Manager(); d=manager.dict(); d['x']=1; assert d['x']==1; manager.shutdown(); print('ok')",
        }
        for name, code in cases.items():
            for candidate in (False, True):
                with self.subTest(workflow=name, candidate=candidate):
                    result = self.command([sys.executable, "-c", code], candidate=candidate)
                    if name == "multiprocessing-manager" and candidate:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("PermissionError", result.stderr)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), "ok")

    def test_candidate_developer_tools(self):
        (self.root / "hello.c").write_text("int main(void) { return 0; }\n")
        commands = [
            ["/bin/sh", "-c", "cc hello.c -o hello && ./hello"],
            ["/bin/sh", "-c", "git init -q devrepo && cd devrepo && printf x > f && git add f && "
             "git -c user.name=fixture -c user.email=fixture@example.invalid commit -qm fixture"],
        ]
        node = shutil.which("node")
        if node:
            commands.append([str(Path(node).resolve()), "-e",
                             "const c=require('child_process'); "
                             "if(c.execSync('printf fixture').toString()!=='fixture') process.exit(1)"])
        for argv in commands:
            with self.subTest(tool=argv):
                result = self.command(argv, candidate=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_candidate_claude_version(self):
        claude = shutil.which("claude")
        if not claude:
            self.skipTest("claude not installed; no CLI compatibility claim")
        result = self.command([str(Path(claude).resolve()), "--version"], candidate=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Claude Code", result.stdout)

    def test_candidate_nss_and_syslog_fallback(self):
        # Candidate filter is already active before libc can create AF_UNIX:
        # neither the real nscd nor the real /dev/log can be contacted. Only
        # localhost NSS resolution and the best-effort syslog API are exercised.
        code = """
import socket, syslog
assert socket.getaddrinfo('localhost', 80)
syslog.openlog('agentguard-disposable-fixture', 0, syslog.LOG_USER)
syslog.syslog(syslog.LOG_INFO, 'disposable fixture')
syslog.closelog()
print('ok')
"""
        result = self.command([sys.executable, "-c", code], candidate=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")

    def test_host_ipc_status(self):
        for mode in ("--strict", "--degraded"):
            for missing in ("", "seccomp"):
                with self.subTest(mode=mode, missing=missing):
                    env = dict(self.env, AGENTGUARD_TEST_UNAVAIL=missing)
                    result = subprocess.run([str(RUN), mode, "--status", "--json"],
                                            env=env, capture_output=True, text=True, check=True)
                    report = json.loads(result.stdout)["host_ipc"]
                    self.assertFalse(report["isolation_enforced"])
                    self.assertEqual(report["pathname_unix"], "unrestricted")
                    self.assertEqual(report["sysv_denied"], not missing)
                    self.assertEqual(json.loads(result.stdout)["network"]["enforced"], not missing)

    def test_posix_shared_memory_policy(self):
        # A regular tmpfs file is the POSIX shm backing object. Create our own,
        # never enumerate/read existing shared-memory objects.
        if not os.access("/dev/shm", os.W_OK):
            self.skipTest("no writable /dev/shm for disposable POSIX shm fixture")
        with tempfile.NamedTemporaryFile(prefix="agentguard-fixture-", dir="/dev/shm") as file:
            file.write(ORIGINAL); file.flush()
            code = """
import errno, mmap, os, sys
path = sys.argv[1]
with open(path, 'rb') as f:
    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        assert m[:] == b'fixture-original'
try:
    os.open(path, os.O_RDWR)
except OSError as e:
    assert e.errno == errno.EACCES
else:
    raise AssertionError('unexpected write authority')
print('readable-not-writable')
"""
            result = self.command([sys.executable, "-c", code, file.name])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "readable-not-writable")
            file.seek(0); self.assertEqual(file.read(), ORIGINAL)

    def test_disposable_tty_policy(self):
        # Reopen only a newly allocated fixture slave: the default /dev/pts
        # grant intentionally permits this. No real user terminal is touched.
        master, slave = os.openpty()
        self.addCleanup(os.close, master); self.addCleanup(os.close, slave)
        path = os.ttyname(slave)
        result = self.command([sys.executable, "-c",
                               "import os,sys; f=os.open(sys.argv[1],os.O_WRONLY); "
                               "os.write(f,b'fixture-output')", path])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(select.select([master], [], [], 2)[0])
        self.assertEqual(os.read(master, 64), b"fixture-output")
        # TIOCSTI host policy is measured on the same disposable tty in both
        # arms. A matching denial is NOT attributed to AgentGuard.
        code = """
import errno, fcntl, json, os, sys, termios
p = os.fork()
if p:
    _, status = os.waitpid(p, 0)
    sys.exit(os.waitstatus_to_exitcode(status))
os.setsid()
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
try:
    fcntl.ioctl(fd, termios.TIOCSTI, b'x'); print('allowed')
except OSError as e:
    print(e.errno)
"""
        baseline = self.command([sys.executable, "-c", code, path], baseline=True)
        sandboxed = self.command([sys.executable, "-c", code, path])
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertEqual(sandboxed.returncode, 0, sandboxed.stderr)
        self.assertEqual(sandboxed.stdout, baseline.stdout)
        print("TTY TIOCSTI baseline/sandbox result:", baseline.stdout.strip(), flush=True)

    def test_netlink_userspace_fixture(self):
        # NETLINK_USERSOCK goes only to this freshly allocated port, never a
        # kernel control endpoint or another user's daemon.
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 2) as server:
            server.bind((0, 0)); server.settimeout(2)
            port = server.getsockname()[0]
            code = """
import socket, sys
s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 2)
s.sendto(b'fixture-netlink', (int(sys.argv[1]), 0))
"""
            for baseline in (True, False):
                result = self.command([sys.executable, "-c", code, port], baseline=baseline)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(server.recv(64), b"fixture-netlink")

    def test_outside_scheduling(self):
        if not SYSCALLS:
            self.skipTest("scheduling probe syscall numbers unavailable for this architecture")
        for kind in ("nice", "affinity", "policy", "param", "attr", "ioprio",
                     "nice-group", "ioprio-group"):
            for disabled in ("baseline", "seccomp", ""):
                with self.subTest(kind=kind, disabled=disabled):
                    proc, args = self.outside()
                    pid = args[0]
                    def state():
                        return (os.getpriority(os.PRIO_PROCESS, pid), os.sched_getaffinity(pid),
                                os.sched_getscheduler(pid), os.sched_getparam(pid).sched_priority,
                                checked(LIB.syscall(SYSCALLS["ioprio_get"], 1, pid)))
                    before = state()
                    got = self.attack("schedule-" + kind, [pid], baseline=disabled == "baseline",
                                      disabled="seccomp" if disabled == "seccomp" else "")
                    after = state()
                    if disabled:
                        self.assertEqual(got, {"value": "changed"})
                        # sched_setparam with unprivileged priority 0 is a no-op;
                        # a one-CPU cpuset similarly cannot discriminate affinity.
                        if kind != "param" and not (kind == "affinity" and len(before[1]) == 1):
                            self.assertNotEqual(before, after)
                    else:
                        self.assertEqual(got.get("errno"), errno.EPERM, (got, before, after))
                        self.assertEqual(before, after)
                    self.assertEqual(self.value(proc), ORIGINAL.decode())
        # pid zero remains usable for ordinary developer tools.
        for kind in ("nice", "affinity", "policy", "param", "attr", "ioprio"):
            self.assertEqual(self.attack("schedule-" + kind, [0]), {"value": "changed"})

    def test_scheduling_tools(self):
        cpu = str(min(os.sched_getaffinity(0)))
        for argv in (["nice", "-n", "1", "true"], ["taskset", "-c", cpu, "true"],
                     ["chrt", "-b", "0", "true"], ["ionice", "-c", "3", "true"]):
            with self.subTest(tool=argv[0]):
                path = shutil.which(argv[0])
                if path is None:
                    self.skipTest(f"{argv[0]} not installed")
                result = self.command([path, *argv[1:]])
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_posix_message_queue(self):
        name = ("/" + self.root.name + "-mq").encode()
        attrs = MQAttr(maxmsg=2, msgsize=64)
        fd = checked(LIB.mq_open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NONBLOCK,
                                 0o600, C.byref(attrs)))
        self.addCleanup(lambda: checked(LIB.mq_unlink(name)))
        self.addCleanup(lambda: checked(LIB.mq_close(fd)))
        for baseline in (True, False):
            got = self.attack("mq", [name.decode()], baseline=baseline)
            buf = C.create_string_buffer(64)
            count = LIB.mq_receive(fd, buf, 64, None)
            print("POSIX mq", "baseline" if baseline else "sandbox", got,
                  "received", count, flush=True)
            if baseline:
                self.assertEqual(got, {"value": "sent"})
                self.assertEqual(buf.raw[:count], CHANGED)
            else:
                self.assertIn(got.get("errno"), (errno.EPERM, errno.EACCES), got)
                self.assertEqual(count, -1)
                self.assertEqual(C.get_errno(), errno.EAGAIN)
        checked(LIB.mq_send(fd, ORIGINAL, len(ORIGINAL), 0))
        got = self.attack("mq-read", [name.decode()])
        buf = C.create_string_buffer(64)
        count = LIB.mq_receive(fd, buf, 64, None)
        print("POSIX mq sandbox read", got, "remaining", count, flush=True)
        self.assertIn(got.get("errno"), (errno.EPERM, errno.EACCES), got)
        self.assertEqual(buf.raw[:count], ORIGINAL)
        # Attribute the denial by disabling each layer independently.
        for disabled in ("seccomp", "landlock_fs,landlock_scope"):
            allowed = disabled != "seccomp"
            for op in ("mq", "mq-read"):
                if op == "mq-read":
                    checked(LIB.mq_send(fd, ORIGINAL, len(ORIGINAL), 0))
                got = self.attack(op, [name.decode()], disabled=disabled)
                buf = C.create_string_buffer(64)
                count = LIB.mq_receive(fd, buf, 64, None)
                if allowed:
                    self.assertEqual(got, {"value": "sent"})
                    self.assertEqual(count, 16 if op == "mq" else -1)
                else:
                    self.assertEqual(got.get("errno"), errno.EACCES)
                    self.assertEqual(count, -1 if op == "mq" else 16)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--sentinel":
        sentinel(sys.argv[2])
    elif len(sys.argv) > 1 and sys.argv[1] == "--probe":
        try:
            print(json.dumps({"value": probe(sys.argv[2], sys.argv[3:])}))
        except OSError as exc:
            print(json.dumps({"errno": exc.errno}))
    else:
        unittest.main(verbosity=2)
