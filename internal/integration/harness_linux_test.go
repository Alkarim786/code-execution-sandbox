//go:build linux

// Package integration runs real programs through the real sandbox. It needs root and a
// writable cgroup v2 (e.g. `docker run --privileged`); otherwise the tests skip.
package integration

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
	"github.com/Alkarim786/code-execution-sandbox/internal/service"
)

var (
	once    sync.Once
	svc     *service.Service
	runner  *sandbox.Runner
	workDir string
	runErr  error
)

func setup(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration tests need root (run: docker compose run --rm test)")
	}
	once.Do(func() {
		workDir, runErr = os.MkdirTemp("", "sandbox-it-")
		if runErr != nil {
			return
		}
		runner, runErr = sandbox.NewRunner(workDir)
		if runErr == nil {
			svc = &service.Service{Runner: service.SandboxRunner{R: runner}}
		}
	})
	if runErr != nil {
		t.Skipf("sandbox unavailable in this environment: %v", runErr)
	}
}

// eval submits one program with a single test case through the whole judge pipeline.
func eval(t testing.TB, lang, source, input, expected string, lim service.Limits) *service.Response {
	t.Helper()
	setup(t)
	return svc.Evaluate(context.Background(), &service.Request{
		Language: lang, Source: source, Tests: []service.Test{{Input: input, Expected: expected}}, Limits: lim,
	})
}

// py runs a Python snippet directly in the sandbox (no /in, no compile step) so the test can
// inspect raw stdout and resource usage.
func py(t testing.TB, code string, mutate func(*sandbox.Spec)) *sandbox.Result {
	t.Helper()
	setup(t)
	spec := sandbox.Spec{
		Argv:    []string{"/usr/bin/python3", "-S", "-E", "-c", code},
		Profile: sandbox.ProfileRun,
		Limits:  sandbox.DefaultLimits(),
	}
	if mutate != nil {
		mutate(&spec)
	}
	res, err := runner.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}
