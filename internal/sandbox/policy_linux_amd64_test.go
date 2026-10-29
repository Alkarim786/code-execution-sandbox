//go:build linux && amd64

package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The real policies, evaluated without a kernel.
func evalPolicy(t *testing.T, p Profile, nr uintptr, args [6]uint32) uint32 {
	t.Helper()
	prog, err := Compile(PolicyFor(p))
	if err != nil {
		t.Fatal(err)
	}
	return Eval(prog, auditArchX8664, uint32(nr), args)
}

func TestRealPolicyDeniesDangerousSyscalls(t *testing.T) {
	for name, nr := range map[string]uintptr{
		"ptrace": unix.SYS_PTRACE, "mount": unix.SYS_MOUNT, "umount2": unix.SYS_UMOUNT2, "bind": unix.SYS_BIND,
		"listen": unix.SYS_LISTEN, "accept": unix.SYS_ACCEPT, "unshare": unix.SYS_UNSHARE, "setns": unix.SYS_SETNS, "chroot": unix.SYS_CHROOT,
		"pivot_root": unix.SYS_PIVOT_ROOT, "reboot": unix.SYS_REBOOT, "kexec_load": unix.SYS_KEXEC_LOAD,
		"init_module": unix.SYS_INIT_MODULE, "bpf": unix.SYS_BPF, "perf_event_open": unix.SYS_PERF_EVENT_OPEN,
		"setuid": unix.SYS_SETUID, "keyctl": unix.SYS_KEYCTL, "open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT,
		"process_vm_readv": unix.SYS_PROCESS_VM_READV, "userfaultfd": unix.SYS_USERFAULTFD, "personality": unix.SYS_PERSONALITY,
	} {
		for _, p := range []Profile{ProfileRun, ProfileToolchain} {
			if got := evalPolicy(t, p, nr, [6]uint32{}); got != retKillProcess {
				t.Errorf("%s/%s should be killed, got %#x", p, name, got)
			}
		}
	}
}

func TestRunProfileForbidsForkButToolchainAllowsIt(t *testing.T) {
	if got := evalPolicy(t, ProfileRun, unix.SYS_FORK, [6]uint32{}); got != retKillProcess {
		t.Errorf("fork in run profile: %#x", got)
	}
	if got := evalPolicy(t, ProfileRun, unix.SYS_VFORK, [6]uint32{}); got != retKillProcess {
		t.Errorf("vfork in run profile: %#x", got)
	}
	if got := evalPolicy(t, ProfileToolchain, unix.SYS_FORK, [6]uint32{}); got != retAllow {
		t.Errorf("fork in toolchain profile: %#x", got)
	}
	// glibc's pthread_create path: clone with CLONE_THREAD must still work in the run profile.
	if got := evalPolicy(t, ProfileRun, unix.SYS_CLONE, [6]uint32{0x3d0f00}); got != retAllow {
		t.Errorf("thread clone: %#x", got)
	}
}

func TestCommonSyscallsAllowedAndProbesFailGracefully(t *testing.T) {
	for _, nr := range []uintptr{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_MMAP, unix.SYS_FUTEX, unix.SYS_EXIT_GROUP, unix.SYS_EXECVE} {
		if got := evalPolicy(t, ProfileRun, nr, [6]uint32{}); got != retAllow {
			t.Errorf("syscall %d: %#x", nr, got)
		}
	}
	if got := evalPolicy(t, ProfileRun, unix.SYS_CLONE3, [6]uint32{}); got != retErrnoBase|uint32(unix.ENOSYS) {
		t.Errorf("clone3 should fail with ENOSYS so glibc falls back to clone, got %#x", got)
	}
}

func TestPolicySizeFitsAndNoDuplicateNumbers(t *testing.T) {
	for _, p := range []Profile{ProfileRun, ProfileToolchain} {
		prog, err := Compile(PolicyFor(p))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s profile: %d rules, %d BPF instructions", p, len(PolicyFor(p)), len(prog))
		seen := map[uint32]string{}
		for _, r := range PolicyFor(p) {
			if prev, dup := seen[r.Nr]; dup {
				t.Errorf("syscall number %d listed twice (%s, %s)", r.Nr, prev, r.Name)
			}
			seen[r.Nr] = r.Name
		}
	}
}

func TestOnlyUnixSocketsAreAllowed(t *testing.T) {
	const afUnix, afInet, afInet6, afNetlink, afPacket = 1, 2, 10, 16, 17
	for _, p := range []Profile{ProfileRun, ProfileToolchain} {
		for _, call := range []uintptr{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
			if got := evalPolicy(t, p, call, [6]uint32{afUnix}); got != retAllow {
				t.Errorf("%s: AF_UNIX should be allowed, got %#x", p, got)
			}
			for _, fam := range []uint32{afInet, afInet6, afNetlink, afPacket} {
				if got := evalPolicy(t, p, call, [6]uint32{fam}); got != retErrnoBase|uint32(unix.EAFNOSUPPORT) {
					t.Errorf("%s: family %d must fail with EAFNOSUPPORT, got %#x", p, fam, got)
				}
			}
		}
	}
}
