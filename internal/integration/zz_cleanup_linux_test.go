//go:build linux

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Runs last (file name sorts after the others): after every abusive program above, nothing may
// be left behind on the host.
func TestNothingLeaksAfterAbuse(t *testing.T) {
	setup(t)
	time.Sleep(300 * time.Millisecond)
	cg, _ := os.ReadFile("/proc/self/cgroup")
	rel := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(cg)), "0::"))
	// This process lives in <parent>/sandbox-runner; the jails live in <parent>/sandbox-jobs.
	jobs := filepath.Join("/sys/fs/cgroup", filepath.Dir(rel), "sandbox-jobs")
	entries, err := os.ReadDir(jobs)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		if e.IsDir() {
			left = append(left, e.Name())
		}
	}
	if len(left) > 0 {
		t.Errorf("leftover job cgroups: %v", left)
	}
	if procs, _ := os.ReadFile(filepath.Join(jobs, "cgroup.procs")); len(strings.TrimSpace(string(procs))) > 0 {
		t.Errorf("leftover processes in the jobs cgroup: %q", procs)
	}
	mounts, _ := os.ReadFile("/proc/self/mountinfo")
	if n := strings.Count(string(mounts), filepath.Base(workDir)); n > 0 {
		t.Errorf("%d leftover mounts under the work dir", n)
	}
	if rest, _ := filepath.Glob(filepath.Join(workDir, "*")); len(rest) > 0 {
		t.Errorf("leftover job directories: %v", rest)
	}
}
