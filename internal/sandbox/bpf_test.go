package sandbox

import "testing"

const (
	nrRead   = 0
	nrWrite  = 1
	nrIoctl  = 16
	nrClone  = 56
	nrFork   = 57
	nrMount  = 165
	nrSock   = 41
	nrClone3 = 435
)

func testRules() []Rule {
	return []Rule{
		{Name: "read", Nr: nrRead, Kind: Allow},
		{Name: "write", Nr: nrWrite, Kind: Allow},
		{Name: "ioctl", Nr: nrIoctl, Kind: AllowArg1, Errno: 25, Values: []uint32{0x5401, 0x5413}},
		{Name: "clone", Nr: nrClone, Kind: CloneThreadOnly},
		{Name: "fork", Nr: nrFork, Kind: Allow},
		{Name: "clone3", Nr: nrClone3, Kind: Errno, Errno: 38},
	}
}

func eval(t *testing.T, rules []Rule, nr uint32, args [6]uint32) uint32 {
	t.Helper()
	prog, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	return Eval(prog, auditArchX8664, nr, args)
}

func TestAllowedAndDeniedSyscalls(t *testing.T) {
	r := testRules()
	var none [6]uint32
	if got := eval(t, r, nrRead, none); got != retAllow {
		t.Errorf("read: %#x", got)
	}
	if got := eval(t, r, nrWrite, none); got != retAllow {
		t.Errorf("write: %#x", got)
	}
	for _, nr := range []uint32{nrMount, nrSock, 101 /* ptrace */, 169 /* reboot */} {
		if got := eval(t, r, nr, none); got != retKillProcess {
			t.Errorf("syscall %d should be killed, got %#x", nr, got)
		}
	}
}

func TestWrongArchitectureAndX32AreKilled(t *testing.T) {
	prog, _ := Compile(testRules())
	var none [6]uint32
	if got := Eval(prog, 0x40000028 /* AUDIT_ARCH_ARM */, nrRead, none); got != retKillProcess {
		t.Errorf("foreign arch must be killed, got %#x", got)
	}
	// x32 ABI syscalls (nr | 0x40000000) could alias allowed numbers: must be rejected.
	if got := Eval(prog, auditArchX8664, nrRead|x32SyscallBit, none); got != retKillProcess {
		t.Errorf("x32 syscall must be killed, got %#x", got)
	}
}

func TestErrnoRuleReturnsErrnoNotKill(t *testing.T) {
	var none [6]uint32
	if got := eval(t, testRules(), nrClone3, none); got != retErrnoBase|38 {
		t.Errorf("clone3 should return ENOSYS, got %#x", got)
	}
}

func TestArgumentFilteredIoctl(t *testing.T) {
	r := testRules()
	if got := eval(t, r, nrIoctl, [6]uint32{0, 0x5401}); got != retAllow { // TCGETS
		t.Errorf("TCGETS: %#x", got)
	}
	if got := eval(t, r, nrIoctl, [6]uint32{0, 0x5412}); got != retErrnoBase|25 { // TIOCSTI is not allowed
		t.Errorf("TIOCSTI should get ENOTTY, got %#x", got)
	}
}

func TestCloneThreadOnlyRejectsProcessesAndNamespaces(t *testing.T) {
	r := testRules()
	const thread, newUser, newNet = 0x10000, 0x10000000, 0x40000000
	if got := eval(t, r, nrClone, [6]uint32{thread | 0x100 /* CLONE_VM-ish */}); got != retAllow {
		t.Errorf("thread clone: %#x", got)
	}
	if got := eval(t, r, nrClone, [6]uint32{17 /* SIGCHLD: plain fork */}); got != retKillProcess {
		t.Errorf("fork-style clone must be killed in the run profile, got %#x", got)
	}
	for _, f := range []uint32{newUser, newNet, thread | newUser, thread | newNet} {
		if got := eval(t, r, nrClone, [6]uint32{f}); got != retKillProcess {
			t.Errorf("clone with namespace flag %#x must be killed, got %#x", f, got)
		}
	}
}

func TestCloneNoNamespacesAllowsFork(t *testing.T) {
	rules := []Rule{{Name: "clone", Nr: nrClone, Kind: CloneNoNamespaces}}
	if got := eval(t, rules, nrClone, [6]uint32{17}); got != retAllow {
		t.Errorf("plain clone: %#x", got)
	}
	if got := eval(t, rules, nrClone, [6]uint32{0x20000000}); got != retKillProcess { // CLONE_NEWPID
		t.Errorf("CLONE_NEWPID: %#x", got)
	}
}

func TestProgramSizeIsBounded(t *testing.T) {
	var rules []Rule
	for i := 0; i < 3000; i++ {
		rules = append(rules, Rule{Name: "x", Nr: uint32(i), Kind: Allow})
	}
	if _, err := Compile(rules); err == nil {
		t.Error("expected an error for a program over the 4096-instruction kernel limit")
	}
}
