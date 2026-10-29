// Package sandbox runs untrusted programs inside Linux namespaces, a cgroup v2 resource
// jail, a read-only pivot_root'ed filesystem, rlimits and a seccomp-bpf syscall allowlist.
//
// Everything except the portable types in this file only builds on Linux (amd64 for the
// seccomp filter). Other platforms get a stub Runner that returns ErrUnsupported.
package sandbox

import (
	"errors"
	"time"
)

// ErrUnsupported is returned on platforms where the sandbox cannot run.
var ErrUnsupported = errors.New("sandbox: requires Linux (amd64) and root; see README")

// Profile selects the seccomp allowlist.
type Profile string

const (
	// ProfileRun is for judged programs: no fork/vfork, clone only for threads.
	ProfileRun Profile = "run"
	// ProfileToolchain additionally allows spawning processes (compilers drive cc1/as/ld).
	ProfileToolchain Profile = "toolchain"
)

// Limits bound what a sandboxed process may consume.
type Limits struct {
	CPUTime       time.Duration // total CPU time across all threads (cgroup cpu.stat)
	WallTime      time.Duration // real time; the whole cgroup is killed when it expires
	MemoryBytes   int64         // cgroup memory.max (RSS + page cache + tmpfs), swap disabled
	Pids          int           // cgroup pids.max (fork-bomb protection)
	FileSizeBytes int64         // RLIMIT_FSIZE
	OpenFiles     int           // RLIMIT_NOFILE
	StackBytes    int64         // RLIMIT_STACK
	OutputBytes   int64         // cap on captured stdout and on stderr (each)
	TmpfsBytes    int64         // size of /tmp and /work
}

// Mount is an extra bind mount from the host into the sandbox root.
type Mount struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	ReadWrite bool   `json:"rw"`
	Exec      bool   `json:"exec"`
}

// Spec describes one sandboxed execution.
type Spec struct {
	ID             string
	Argv           []string // Argv[0] must be an absolute path inside the sandbox
	Env            []string
	Stdin          []byte
	Cwd            string // inside the sandbox; defaults to /work
	Profile        Profile
	Limits         Limits
	Mounts         []Mount
	DisableSeccomp bool // test hook: demonstrates that namespaces alone also block e.g. networking
}

// Result is the outcome of one execution. Verdict mapping lives in the judge package.
type Result struct {
	ExitCode     int
	Signal       string // e.g. "SIGSYS", "SIGKILL"; empty if exited normally
	Stdout       []byte
	Stderr       []byte
	CPUTime      time.Duration
	WallTime     time.Duration
	SetupTime    time.Duration // host-side time to create the cgroup and start the child
	MemoryPeak   int64
	PidsPeak     int64
	OOMKilled    bool
	TimedOut     bool // wall-clock limit hit
	CPULimitHit  bool // CPU-time limit hit (cgroup usage or RLIMIT_CPU)
	OutputCapHit bool // stdout or stderr exceeded Limits.OutputBytes
	SetupError   string
}

// Seccomp violation (a syscall outside the allowlist) kills the process with SIGSYS.
const SeccompSignal = "SIGSYS"

// DefaultLimits are conservative defaults for judged programs.
func DefaultLimits() Limits {
	return Limits{
		CPUTime:       2 * time.Second,
		WallTime:      6 * time.Second,
		MemoryBytes:   256 << 20,
		Pids:          32,
		FileSizeBytes: 16 << 20,
		OpenFiles:     64,
		StackBytes:    64 << 20,
		OutputBytes:   1 << 20,
		TmpfsBytes:    16 << 20,
	}
}
