//go:build linux

package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const cgroupMount = "/sys/fs/cgroup"

// Cgroups manages a delegated cgroup v2 subtree: <self>/runner holds the server process and
// <self>/jobs/<id> holds one jail per execution.
type Cgroups struct {
	jobs string
	seq  atomic.Uint64
}

func ownCgroupPath() (string, error) {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("cgroup v2 not detected (no 0:: line in /proc/self/cgroup)")
}

func write(path, val string) error {
	return os.WriteFile(path, []byte(val), 0o644)
}

// NewCgroups prepares the hierarchy: moves every process of our own cgroup into a "runner"
// leaf (cgroup v2's "no internal processes" rule), then enables the memory, pids and cpu
// controllers for the "jobs" subtree.
func NewCgroups() (*Cgroups, error) {
	rel, err := ownCgroupPath()
	if err != nil {
		return nil, err
	}
	self := filepath.Join(cgroupMount, rel)
	runner := filepath.Join(self, "sandbox-runner")
	jobs := filepath.Join(self, "sandbox-jobs")
	for _, d := range []string{runner, jobs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("create cgroup %s (need root and a writable cgroup v2): %w", d, err)
		}
	}
	// Move all processes (including ourselves) out of the parent into the runner leaf.
	procs, err := os.ReadFile(filepath.Join(self, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	for _, pid := range strings.Fields(string(procs)) {
		_ = write(filepath.Join(runner, "cgroup.procs"), pid) // kernel threads / races are fine
	}
	avail, err := os.ReadFile(filepath.Join(self, "cgroup.controllers"))
	if err != nil {
		return nil, err
	}
	var enable []string
	for _, c := range strings.Fields(string(avail)) {
		if c == "memory" || c == "pids" || c == "cpu" {
			enable = append(enable, "+"+c)
		}
	}
	if len(enable) != 3 {
		return nil, fmt.Errorf("cgroup controllers memory, pids and cpu must all be available, have: %s", avail)
	}
	if err := write(filepath.Join(self, "cgroup.subtree_control"), strings.Join(enable, " ")); err != nil {
		return nil, fmt.Errorf("enable controllers: %w", err)
	}
	if err := write(filepath.Join(jobs, "cgroup.subtree_control"), strings.Join(enable, " ")); err != nil {
		return nil, fmt.Errorf("enable controllers for jobs: %w", err)
	}
	return &Cgroups{jobs: jobs}, nil
}

// Job is one cgroup jail.
type Job struct {
	path string
	fd   *os.File
}

// NewJob creates a cgroup with the limits applied.
func (c *Cgroups) NewJob(l Limits) (*Job, error) {
	path := filepath.Join(c.jobs, fmt.Sprintf("job-%d-%d", os.Getpid(), c.seq.Add(1)))
	if err := os.Mkdir(path, 0o755); err != nil {
		return nil, err
	}
	set := func(file, val string) error {
		if err := write(filepath.Join(path, file), val); err != nil {
			return fmt.Errorf("cgroup %s=%s: %w", file, val, err)
		}
		return nil
	}
	steps := [][2]string{
		{"memory.max", strconv.FormatInt(l.MemoryBytes, 10)},
		{"memory.swap.max", "0"},
		{"memory.oom.group", "1"}, // an OOM kills the whole jail, not a random member
		{"pids.max", strconv.Itoa(l.Pids)},
		{"cpu.max", "100000 100000"}, // at most one CPU worth of time, however many threads
	}
	for _, s := range steps {
		if err := set(s[0], s[1]); err != nil {
			_ = os.Remove(path)
			return nil, err
		}
	}
	fd, err := os.Open(path)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return &Job{path: path, fd: fd}, nil
}

// FD is passed to clone via CLONE_INTO_CGROUP so the child is born inside the jail.
func (j *Job) FD() int { return int(j.fd.Fd()) }

// Kill SIGKILLs every process in the jail atomically (cgroup.kill, Linux 5.14+).
func (j *Job) Kill() { _ = write(filepath.Join(j.path, "cgroup.kill"), "1") }

func (j *Job) readKV(file, key string) int64 {
	b, err := os.ReadFile(filepath.Join(j.path, file))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == key {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

func (j *Job) readInt(file string) int64 {
	b, err := os.ReadFile(filepath.Join(j.path, file))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// Stats are read after the process exits.
func (j *Job) Stats() (cpu time.Duration, memPeak, pidsPeak int64, oom bool) {
	cpu = time.Duration(j.readKV("cpu.stat", "usage_usec")) * time.Microsecond
	return cpu, j.readInt("memory.peak"), j.readInt("pids.peak"), j.readKV("memory.events", "oom_kill") > 0
}

// CPU returns CPU time consumed so far (used by the watchdog).
func (j *Job) CPU() time.Duration {
	return time.Duration(j.readKV("cpu.stat", "usage_usec")) * time.Microsecond
}

// Close kills anything left, waits for the cgroup to empty, and removes it.
func (j *Job) Close() {
	j.Kill()
	_ = j.fd.Close()
	for i := 0; i < 200; i++ {
		if err := unix.Rmdir(j.path); err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
