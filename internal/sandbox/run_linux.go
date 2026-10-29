//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// hostIDBase is the first host uid/gid of the 65536-id range that user-namespace ids map to.
// uid 0 inside the jail is host uid 100000 (unprivileged), never the real root.
const hostIDBase = 100000

// Runner executes Specs. It requires root (to create cgroups and id mappings).
type Runner struct {
	cg      *Cgroups
	workDir string
	seq     uint64
	mu      sync.Mutex
}

// NewRunner prepares cgroups and a scratch directory.
func NewRunner(workDir string) (*Runner, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("sandbox must run as root (cgroups, uid mappings): %w", ErrUnsupported)
	}
	cg, err := NewCgroups()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, err
	}
	// The jail's uids are host uids 100000+; they need search permission down to the job dirs.
	if err := os.Chmod(workDir, 0o755); err != nil {
		return nil, err
	}
	return &Runner{cg: cg, workDir: workDir}, nil
}

// JobDir is host-side storage shared by the steps of one submission: In holds the source
// (mounted read-only, noexec), Out a size-capped tmpfs for compiled artifacts.
type JobDir struct {
	Root, In, Out string
}

// NewJobDir creates the directories; Out is a tmpfs of at most outBytes, owned by the sandbox uid.
func (r *Runner) NewJobDir(outBytes int64) (*JobDir, error) {
	r.mu.Lock()
	r.seq++
	n := r.seq
	r.mu.Unlock()
	root := filepath.Join(r.workDir, fmt.Sprintf("job-%d-%d", os.Getpid(), n))
	jd := &JobDir{Root: root, In: filepath.Join(root, "in"), Out: filepath.Join(root, "out")}
	for _, d := range []string{jd.In, jd.Out} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := unix.Mount("tmpfs", jd.Out, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, fmt.Sprintf("size=%d,mode=0755", outBytes)); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("mount out tmpfs: %w", err)
	}
	if err := os.Chown(jd.Out, hostIDBase+sandboxUID, hostIDBase+sandboxUID); err != nil {
		jd.Cleanup()
		return nil, err
	}
	return jd, nil
}

// WriteSource stores a source file where the sandbox sees it as /in/<name>.
func (jd *JobDir) WriteSource(name string, data []byte) error {
	p := filepath.Join(jd.In, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return err
	}
	return os.Chmod(p, 0o644)
}

// Cleanup unmounts and removes the job directory.
func (jd *JobDir) Cleanup() {
	_ = unix.Unmount(jd.Out, unix.MNT_DETACH)
	_ = os.RemoveAll(jd.Root)
}

// capWriter keeps at most max bytes and flags (once) when more was written.
type capWriter struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	max      int64
	exceeded chan struct{}
	over     bool
}

func newCapWriter(max int64, exceeded chan struct{}) *capWriter {
	return &capWriter{max: max, exceeded: exceeded}
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.max - int64(c.buf.Len())
	if int64(len(p)) > room {
		if room > 0 {
			c.buf.Write(p[:room])
		}
		if !c.over {
			c.over = true
			close(c.exceeded)
		}
		return len(p), nil // keep draining so the child never blocks on a full pipe
	}
	c.buf.Write(p)
	return len(p), nil
}

func (c *capWriter) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// Run executes the spec and returns its resource usage and exit status.
func (r *Runner) Run(ctx context.Context, spec Spec) (*Result, error) {
	start := time.Now()
	res := &Result{}
	l := spec.Limits
	job, err := r.cg.NewJob(l)
	if err != nil {
		return nil, err
	}
	defer job.Close()

	rootDir, err := os.MkdirTemp(r.workDir, "root-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(rootDir)
	if err := os.Chmod(rootDir, 0o755); err != nil { // MkdirTemp creates 0700; the jail's ns-root is not host root
		return nil, err
	}
	if spec.Cwd == "" {
		spec.Cwd = "/work"
	}
	cfg := childConfig{
		Argv: spec.Argv, Env: envFor(spec.Env), Cwd: spec.Cwd, Profile: spec.Profile, RootDir: rootDir,
		Mounts: spec.Mounts, DisableSeccomp: spec.DisableSeccomp,
		Limits: limitsJSON{
			CPUSeconds:    int64((l.CPUTime + time.Second - 1) / time.Second), // RLIMIT_CPU is a coarse backstop
			FileSizeBytes: l.FileSizeBytes, OpenFiles: int64(l.OpenFiles), StackBytes: l.StackBytes, TmpfsBytes: l.TmpfsBytes,
		},
	}
	cfg.Limits.CPUSeconds += 1
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	exceeded := make(chan struct{})
	stdout, stderr := newCapWriter(l.OutputBytes, exceeded), newCapWriter(l.OutputBytes, exceeded)
	errR, errW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer errR.Close()

	cmd := exec.Command("/proc/self/exe", initArg)
	cmd.Env = []string{"SANDBOX_CONFIG=" + string(cfgJSON)}
	cmd.Stdin = bytes.NewReader(spec.Stdin)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.ExtraFiles = []*os.File{errW}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET |
			syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC | syscall.CLONE_NEWCGROUP,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostIDBase, Size: 65536}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostIDBase, Size: 65536}},
		// Become uid/gid 0 *inside* the namespace (host 100000), so the child holds a full
		// capability set there to build the jail; it drops them again before exec'ing user code.
		Credential:  &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true},
		UseCgroupFD: true,
		CgroupFD:    job.FD(), // born inside the cgroup: no window where it runs unconstrained
	}
	if err := cmd.Start(); err != nil {
		errW.Close()
		return nil, fmt.Errorf("start sandbox child: %w", err)
	}
	errW.Close()
	res.SetupTime = time.Since(start)
	began := time.Now()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	wall := l.WallTime
	timer := time.NewTimer(wall)
	defer timer.Stop()
	cpuTick := time.NewTicker(10 * time.Millisecond)
	defer cpuTick.Stop()
	var waitErr error
loop:
	for {
		select {
		case waitErr = <-done:
			break loop
		case <-timer.C:
			res.TimedOut = true
			job.Kill()
		case <-cpuTick.C:
			if l.CPUTime > 0 && job.CPU() > l.CPUTime {
				res.CPULimitHit = true
				job.Kill()
			}
		case <-exceeded:
			res.OutputCapHit = true
			job.Kill()
			exceeded = nil // fire once
		case <-ctx.Done():
			job.Kill()
		}
	}
	res.WallTime = time.Since(began)
	job.Kill() // leftover descendants, if any
	if ee, ok := waitErr.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				res.Signal = unix.SignalName(ws.Signal()) // "SIGSYS", not Go's "bad system call"
				res.ExitCode = -int(ws.Signal())
			} else {
				res.ExitCode = ws.ExitStatus()
			}
		}
	} else if waitErr != nil {
		return nil, waitErr
	}
	if setupMsg, _ := io.ReadAll(errR); len(setupMsg) > 0 {
		res.SetupError = string(setupMsg)
	}
	res.Stdout, res.Stderr = stdout.bytes(), stderr.bytes()
	res.CPUTime, res.MemoryPeak, res.PidsPeak, res.OOMKilled = job.Stats()
	if l.CPUTime > 0 && res.CPUTime > l.CPUTime {
		res.CPULimitHit = true
	}
	if res.Signal == "SIGXCPU" {
		res.CPULimitHit = true
	}
	return res, nil
}
