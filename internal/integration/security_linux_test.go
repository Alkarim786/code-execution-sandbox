//go:build linux

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Alkarim786/code-execution-sandbox/internal/judge"
	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
	"github.com/Alkarim786/code-execution-sandbox/internal/service"
)

// ---- resource abuse -------------------------------------------------------------------------

func TestForkBombIsContainedByPidsCgroup(t *testing.T) {
	// Toolchain profile allows fork, so this exercises the cgroup pids.max limit on its own.
	res := py(t, `
import os, time
n = 0
try:
    while True:
        if os.fork() == 0:
            time.sleep(30); os._exit(0)
        n += 1
except OSError as e:
    print("forks", n, "errno", e.errno)
`, func(s *sandbox.Spec) {
		s.Profile = sandbox.ProfileToolchain
		s.Limits.Pids = 16
		s.Limits.WallTime = 8 * time.Second
	})
	t.Logf("stdout=%q pids_peak=%d wall=%v", res.Stdout, res.PidsPeak, res.WallTime)
	if !strings.Contains(string(res.Stdout), "errno 11") { // EAGAIN: the kernel refused the fork
		t.Fatalf("fork bomb was not stopped by pids.max: %q (signal %s)", res.Stdout, res.Signal)
	}
	if res.PidsPeak > 16 || res.PidsPeak < 10 {
		t.Errorf("pids.peak = %d, want 10..16", res.PidsPeak)
	}
}

func TestForkIsForbiddenInRunProfile(t *testing.T) {
	resp := eval(t, "python", "import os\nos.fork()\nprint('forked')", "", "", service.Limits{})
	r := resp.Tests[0]
	if r.Verdict != judge.RE || !strings.Contains(r.Reason, "seccomp") {
		t.Fatalf("%+v", r)
	}
}

func TestThreadBombIsContainedToo(t *testing.T) {
	res := py(t, `
import threading, time
n = 0
try:
    while True:
        threading.Thread(target=time.sleep, args=(30,), daemon=True).start()
        n += 1
except RuntimeError as e:
    print("threads", n, e)
`, func(s *sandbox.Spec) { s.Limits.Pids = 24 })
	if !strings.Contains(string(res.Stdout), "can't start new thread") || res.PidsPeak > 24 {
		t.Fatalf("stdout=%q pids_peak=%d", res.Stdout, res.PidsPeak)
	}
}

func TestMemoryHogIsMLE(t *testing.T) {
	for name, tc := range map[string]struct{ lang, src string }{
		"python": {"python", "x = []\nwhile True:\n    x.append(bytearray(10_000_000))\n"},
		"c": {"c", `#include <stdlib.h>
#include <string.h>
int main(){ for(;;){ char *p = malloc(10<<20); if(!p) return 1; memset(p, 1, 10<<20);} }`},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			resp := eval(t, tc.lang, tc.src, "", "", service.Limits{MemoryMB: 64})
			r := resp.Tests[0]
			if r.Verdict != judge.MLE {
				t.Fatalf("%+v", r)
			}
			if time.Since(start) > 15*time.Second {
				t.Error("memory hog took too long to be stopped")
			}
			if r.MemoryKB > 200<<10 {
				t.Errorf("peak %d KB exceeded the cgroup limit by far", r.MemoryKB)
			}
		})
	}
}

func TestInfiniteLoopIsTLEByCPUTime(t *testing.T) {
	for lang, src := range map[string]string{"python": "while True:\n    pass\n", "c": "int main(){for(;;);}"} {
		start := time.Now()
		resp := eval(t, lang, src, "", "", service.Limits{CPUMillis: 500})
		r := resp.Tests[0]
		if r.Verdict != judge.TLE || !strings.Contains(r.Reason, "CPU") && !strings.Contains(r.Reason, "wall") {
			t.Fatalf("%s: %+v", lang, r)
		}
		if r.CPUMs < 400 || r.CPUMs > 2000 {
			t.Errorf("%s: cpu_ms=%d, expected about the 500 ms limit", lang, r.CPUMs)
		}
		t.Logf("%s: TLE after cpu=%d ms wall=%d ms (%v incl. compile)", lang, r.CPUMs, r.WallMs, time.Since(start).Round(time.Millisecond))
	}
}

func TestSleepingProgramIsCaughtByWallClock(t *testing.T) {
	resp := eval(t, "python", "import time\ntime.sleep(100)\n", "", "", service.Limits{CPUMillis: 500})
	r := resp.Tests[0]
	if r.Verdict != judge.TLE || !strings.Contains(r.Reason, "wall") {
		t.Fatalf("%+v", r)
	}
	if r.CPUMs > 400 {
		t.Errorf("a sleeping program should use almost no CPU, used %d ms", r.CPUMs)
	}
}

func TestOutputFloodIsOLE(t *testing.T) {
	resp := eval(t, "python", "while True:\n    print('x' * 1000)\n", "", "", service.Limits{})
	if r := resp.Tests[0]; r.Verdict != judge.OLE {
		t.Fatalf("%+v", r)
	}
}

func TestFileSizeAndTmpfsLimits(t *testing.T) {
	res := py(t, `
import os, errno
try:
    with open('/work/big', 'wb') as f:
        for _ in range(100):
            f.write(b'x' * (1 << 20))
        f.flush()
    print("wrote-100MB")
except OSError as e:
    print("blocked", errno.errorcode[e.errno])
`, func(s *sandbox.Spec) { s.Limits.FileSizeBytes = 4 << 20 })
	if !strings.Contains(string(res.Stdout), "blocked EFBIG") && res.Signal != "SIGXFSZ" {
		t.Fatalf("RLIMIT_FSIZE not enforced: %q signal=%s", res.Stdout, res.Signal)
	}
	res = py(t, `
import errno
try:
    with open('/tmp/fill', 'wb') as f:
        for _ in range(64):
            f.write(b'x' * (1 << 20))
        f.flush()
    print("wrote-64MB")
except OSError as e:
    print("blocked", errno.errorcode[e.errno])
`, func(s *sandbox.Spec) { s.Limits.TmpfsBytes = 8 << 20; s.Limits.FileSizeBytes = 1 << 30 })
	if !strings.Contains(string(res.Stdout), "blocked ENOSPC") {
		t.Fatalf("tmpfs size cap not enforced: %q", res.Stdout)
	}
}

func TestStackOverflowIsRE(t *testing.T) {
	resp := eval(t, "c", "int f(int n){ volatile char b[4096]; b[0]=n; return f(n+1)+b[0]; } int main(){ return f(0); }", "", "", service.Limits{StackMB: 8})
	if r := resp.Tests[0]; r.Verdict != judge.RE {
		t.Fatalf("%+v", r)
	}
	resp = eval(t, "python", "def f(): return f()\nf()\n", "", "", service.Limits{})
	if r := resp.Tests[0]; r.Verdict != judge.RE {
		t.Fatalf("%+v", r)
	}
}

// ---- network ----------------------------------------------------------------------------------

func TestNetworkIsBlockedAtTwoLayers(t *testing.T) {
	probe := `
import socket, errno
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as e:
    print("socket-refused", errno.errorcode[e.errno]); raise SystemExit
s.settimeout(2)
try:
    s.connect(("1.1.1.1", 80)); print("CONNECTED")
except OSError as e:
    print("connect-failed", errno.errorcode[e.errno])
print("interfaces", [n for _, n in socket.if_nameindex()])
`
	// Layer 1: seccomp refuses to create an internet socket at all.
	res := py(t, probe, nil)
	if !strings.Contains(string(res.Stdout), "socket-refused EAFNOSUPPORT") {
		t.Fatalf("seccomp layer: %q signal=%s", res.Stdout, res.Signal)
	}
	// Layer 2: even with seccomp disabled (test hook), the empty network namespace has no route.
	res = py(t, probe, func(s *sandbox.Spec) { s.DisableSeccomp = true })
	out := string(res.Stdout)
	if strings.Contains(out, "CONNECTED") || !strings.Contains(out, "connect-failed") {
		t.Fatalf("network namespace layer: %q (stderr %q)", out, res.Stderr)
	}
	if !strings.Contains(out, "['lo']") {
		t.Errorf("only the (down) loopback device should exist: %q", out)
	}
	t.Logf("with seccomp disabled: %s", strings.TrimSpace(out))
}

// ---- filesystem -----------------------------------------------------------------------------------

func TestFilesystemIsolationAndReadOnlyRoot(t *testing.T) {
	res := py(t, fmt.Sprintf(`
import os, errno
print("root", sorted(os.listdir('/')))
for p in ['/etc/shadow', '/root', '/home', '/var', '/sys', '/boot', %q, '/proc/1/root/etc/shadow', '../../../../etc/shadow']:
    print("exists", p, os.path.exists(p))
pw = open('/etc/passwd').read()
print("passwd-has-host-users", 'daemon' in pw or '/bin/bash' in pw)
for p in ['/usr/evil', '/etc/evil', '/bin/evil', '/evil']:
    try:
        open(p, 'w'); print("WRITABLE", p)
    except OSError as e:
        print("write", p, errno.errorcode[e.errno])
for p in ['/tmp/ok', '/work/ok']:
    open(p, 'w').write('x'); print("write", p, "OK")
print("proc-pids", sorted(d for d in os.listdir('/proc') if d.isdigit()))
`, workDir), func(s *sandbox.Spec) { s.Cwd = "/work" })
	out := string(res.Stdout)
	t.Log("\n" + out)
	for _, bad := range []string{"exists /etc/shadow True", "exists /root True", "exists /home True", "exists /var True",
		"exists /sys True", "exists " + workDir + " True", "WRITABLE", "passwd-has-host-users True"} {
		if strings.Contains(out, bad) {
			t.Errorf("isolation failure: %q", bad)
		}
	}
	for _, want := range []string{"write /usr/evil EROFS", "write /etc/evil EROFS", "write /evil EACCES", "write /tmp/ok OK", "write /work/ok OK", "proc-pids ['1']"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestPrivilegesAreDropped(t *testing.T) {
	res := py(t, `
import os, socket
st = dict(l.split(':\t') for l in open('/proc/self/status').read().splitlines() if ':\t' in l)
print("uid", os.getuid(), os.geteuid(), "gid", os.getgid())
print("pid", os.getpid(), "hostname", socket.gethostname())
for k in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp']:
    print(k, st[k].strip())
`, nil)
	out := string(res.Stdout)
	t.Log("\n" + out)
	for _, want := range []string{"uid 1000 1000 gid 1000", "pid 1 hostname sandbox", "CapEff 0000000000000000", "CapBnd 0000000000000000",
		"CapPrm 0000000000000000", "NoNewPrivs 1", "Seccomp 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestEscapeAttemptsViaSyscallsAreKilledBySeccomp(t *testing.T) {
	// name -> x86_64 syscall number
	for name, nr := range map[string]int{
		"ptrace": 101, "mount": 165, "umount2": 166, "chroot": 161, "pivot_root": 155, "unshare": 272, "setns": 308,
		"reboot": 169, "setuid": 105, "keyctl": 250, "bpf": 321, "init_module": 175, "kexec_load": 246,
		"open_by_handle_at": 304, "process_vm_readv": 310, "perf_event_open": 298, "userfaultfd": 323,
	} {
		t.Run(name, func(t *testing.T) {
			res := py(t, fmt.Sprintf("import ctypes\nctypes.CDLL(None, use_errno=True).syscall(%d, 0, 0, 0, 0, 0)\nprint('SURVIVED')", nr), nil)
			if res.Signal != sandbox.SeccompSignal || strings.Contains(string(res.Stdout), "SURVIVED") {
				t.Fatalf("syscall %s (%d): signal=%q stdout=%q", name, nr, res.Signal, res.Stdout)
			}
		})
	}
	// The same through the judge pipeline reports a clear reason.
	resp := eval(t, "python", "import os\nos.chroot('/')\n", "", "", service.Limits{})
	if r := resp.Tests[0]; r.Verdict != judge.RE || !strings.Contains(r.Reason, "seccomp") {
		t.Fatalf("%+v", r)
	}
}

func TestCannotCreateNewNamespacesWithCloneFlags(t *testing.T) {
	// glibc's clone() wrapper with CLONE_NEWUSER|CLONE_NEWNET must be killed even though thread-clones are fine.
	res := py(t, `
import ctypes
libc = ctypes.CDLL(None)
CLONE_NEWUSER, CLONE_NEWNET, CLONE_THREAD = 0x10000000, 0x40000000, 0x10000
libc.syscall(56, CLONE_NEWUSER | CLONE_NEWNET | 17, 0, 0, 0, 0)  # SYS_clone
print("SURVIVED")
`, nil)
	if res.Signal != sandbox.SeccompSignal {
		t.Fatalf("signal=%q stdout=%q", res.Signal, res.Stdout)
	}
}

func TestCompilerCannotBeAbusedToReadHostFilesOrExhaustResources(t *testing.T) {
	start := time.Now()
	for name, src := range map[string]string{
		"read host shadow":      "#include \"/etc/shadow\"\nint main(){}",
		"infinite include":      "#include </dev/zero>\nint main(){}",
		"recursive macro bloat": "#define A B B B B B B B B B B\n#define B C C C C C C C C C C\n#define C D D D D D D D D D D\n#define D E E E E E E E E E E\n#define E F F F F F F F F F F\n#define F G G G G G G G G G G\n#define G H H H H H H H H H H\n#define H x x x x x x x x x x\nint main(){ int x=0; A; }",
	} {
		resp := eval(t, "c", src, "", "", service.Limits{})
		if resp.Verdict != judge.CE && resp.Verdict != judge.RE {
			t.Errorf("%s: %+v", name, resp)
		}
		if strings.Contains(resp.CompileOutput, "root:") {
			t.Errorf("%s leaked host data: %s", name, resp.CompileOutput)
		}
	}
	// A 1 TB static array is only virtual address space: it must not consume real memory.
	resp := eval(t, "c", "char big[1ull<<40]; int main(){return big[0];}", "", "", service.Limits{})
	if resp.Verdict == judge.AC && resp.Tests[0].MemoryKB > 16<<10 {
		t.Errorf("untouched bss was charged %d KB", resp.Tests[0].MemoryKB)
	}
	if d := time.Since(start); d > 90*time.Second {
		t.Errorf("compile-time abuse took %v", d)
	}
	t.Logf("compile-time abuse contained in %v", time.Since(start).Round(time.Millisecond))
}
