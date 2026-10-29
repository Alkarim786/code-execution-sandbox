package service

import (
	"context"

	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
)

// SandboxRunner adapts *sandbox.Runner to the Runner interface.
type SandboxRunner struct{ R *sandbox.Runner }

type sandboxJob struct{ jd *sandbox.JobDir }

func (s SandboxRunner) NewJob(outBytes int64) (Job, error) {
	jd, err := s.R.NewJobDir(outBytes)
	if err != nil {
		return nil, err
	}
	return &sandboxJob{jd}, nil
}

func (s SandboxRunner) Run(ctx context.Context, spec sandbox.Spec) (*sandbox.Result, error) {
	return s.R.Run(ctx, spec)
}

func (j *sandboxJob) WriteSource(name string, data []byte) error { return j.jd.WriteSource(name, data) }
func (j *sandboxJob) Cleanup()                                   { j.jd.Cleanup() }

// Mounts: the source is always read-only; /out is writable only for the compile step.
func (j *sandboxJob) Mounts(outWritable bool) []sandbox.Mount {
	return []sandbox.Mount{
		{Source: j.jd.In, Target: "/in"},
		{Source: j.jd.Out, Target: "/out", ReadWrite: outWritable, Exec: true},
	}
}
