// Package service evaluates a submission: compile (if needed) and run each test case inside the
// sandbox, then judge the outputs. It depends only on the Runner interface so the logic is
// unit-testable on any OS with a fake runner.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Alkarim786/code-execution-sandbox/internal/judge"
	"github.com/Alkarim786/code-execution-sandbox/internal/languages"
	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
)

// Job is the per-submission scratch space (source in, compiled artifacts out).
type Job interface {
	WriteSource(name string, data []byte) error
	Mounts(outWritable bool) []sandbox.Mount
	Cleanup()
}

// Runner executes sandbox specs.
type Runner interface {
	NewJob(outBytes int64) (Job, error)
	Run(ctx context.Context, spec sandbox.Spec) (*sandbox.Result, error)
}

// Limits a client may request; zero values mean "use the default". All are clamped to Max*.
type Limits struct {
	CPUMillis int `json:"cpu_ms,omitempty"`
	MemoryMB  int `json:"memory_mb,omitempty"`
	StackMB   int `json:"stack_mb,omitempty"`
}

type Test struct {
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

type Request struct {
	Language   string `json:"language"`
	Source     string `json:"source"`
	Tests      []Test `json:"tests"`
	Limits     Limits `json:"limits"`
	StopOnFail *bool  `json:"stop_on_fail,omitempty"` // default true
}

type TestResult struct {
	Index    int           `json:"index"`
	Verdict  judge.Verdict `json:"verdict"`
	Reason   string        `json:"reason,omitempty"`
	CPUMs    int64         `json:"cpu_ms"`
	WallMs   int64         `json:"wall_ms"`
	MemoryKB int64         `json:"memory_kb"`
	Stdout   string        `json:"stdout,omitempty"`
	Stderr   string        `json:"stderr,omitempty"`
}

type Response struct {
	Verdict       judge.Verdict `json:"verdict"`
	CompileOutput string        `json:"compile_output,omitempty"`
	CompileMs     int64         `json:"compile_ms,omitempty"`
	Tests         []TestResult  `json:"tests,omitempty"`
	Error         string        `json:"error,omitempty"`
}

// Server-side ceilings.
const (
	MaxSourceBytes = 256 << 10
	MaxTests       = 100
	MaxIOBytes     = 1 << 20
	MaxCPU         = 10 * time.Second
	MaxMemory      = 1 << 30
	MaxStack       = 256 << 20
	echoBytes      = 2048
)

// Service evaluates submissions.
type Service struct {
	Runner Runner
}

// Validate rejects malformed requests before any sandbox work happens.
func Validate(req *Request) error {
	if _, err := languages.Get(req.Language); err != nil {
		return err
	}
	if len(req.Source) == 0 || len(req.Source) > MaxSourceBytes {
		return fmt.Errorf("source must be 1..%d bytes", MaxSourceBytes)
	}
	if len(req.Tests) == 0 || len(req.Tests) > MaxTests {
		return fmt.Errorf("tests must contain 1..%d cases", MaxTests)
	}
	for i, t := range req.Tests {
		if len(t.Input) > MaxIOBytes || len(t.Expected) > MaxIOBytes {
			return fmt.Errorf("test %d: input/expected exceed %d bytes", i, MaxIOBytes)
		}
	}
	if req.Limits.CPUMillis < 0 || req.Limits.MemoryMB < 0 || req.Limits.StackMB < 0 {
		return fmt.Errorf("limits must not be negative")
	}
	return nil
}

// RunLimits derives sandbox limits for judged runs from the request, clamped to server maxima.
func RunLimits(lang *languages.Language, l Limits) sandbox.Limits {
	lim := sandbox.DefaultLimits()
	if l.CPUMillis > 0 {
		lim.CPUTime = time.Duration(l.CPUMillis) * time.Millisecond
	}
	if lim.CPUTime > MaxCPU {
		lim.CPUTime = MaxCPU
	}
	lim.CPUTime = lang.ScaleCPU(lim.CPUTime)
	if l.MemoryMB > 0 {
		lim.MemoryBytes = int64(l.MemoryMB) << 20
	}
	if lim.MemoryBytes > MaxMemory {
		lim.MemoryBytes = MaxMemory
	}
	if l.StackMB > 0 {
		lim.StackBytes = int64(l.StackMB) << 20
	}
	if lim.StackBytes > MaxStack {
		lim.StackBytes = MaxStack
	}
	lim.MemoryBytes += lang.MemoryOverhead
	lim.WallTime = 3*lim.CPUTime + time.Second
	return lim
}

func compileLimits(lang *languages.Language) sandbox.Limits {
	lim := sandbox.DefaultLimits()
	lim.CPUTime = 15 * time.Second
	lim.WallTime = 30 * time.Second
	lim.MemoryBytes = 768 << 20
	if lang.Name == "java" {
		lim.MemoryBytes = 1 << 30
	}
	lim.Pids = 256 // compilers spawn helpers and, for Java, many threads
	lim.OutputBytes = 64 << 10
	lim.FileSizeBytes = 64 << 20
	lim.TmpfsBytes = 128 << 20
	lim.OpenFiles = 256
	return lim
}

func trunc(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "...[truncated]"
	}
	return string(b)
}

// Evaluate runs a whole submission.
func (s *Service) Evaluate(ctx context.Context, req *Request) *Response {
	if err := Validate(req); err != nil {
		return &Response{Verdict: judge.IE, Error: err.Error()}
	}
	lang, _ := languages.Get(req.Language)
	job, err := s.Runner.NewJob(64 << 20)
	if err != nil {
		return &Response{Verdict: judge.IE, Error: "create job: " + err.Error()}
	}
	defer job.Cleanup()
	if err := job.WriteSource(lang.SourceFile, []byte(req.Source)); err != nil {
		return &Response{Verdict: judge.IE, Error: "write source: " + err.Error()}
	}
	resp := &Response{}

	if lang.Compile != nil {
		t0 := time.Now()
		res, err := s.Runner.Run(ctx, sandbox.Spec{
			Argv: lang.Compile(), Profile: sandbox.ProfileToolchain, Limits: compileLimits(lang),
			Mounts: job.Mounts(true),
		})
		resp.CompileMs = time.Since(t0).Milliseconds()
		if err != nil {
			return &Response{Verdict: judge.IE, Error: "compile sandbox: " + err.Error()}
		}
		v, reason := judge.Classify(res)
		if v == judge.IE {
			return &Response{Verdict: judge.IE, Error: reason}
		}
		if v != judge.AC {
			out := trunc(res.Stderr, 8192)
			if out == "" {
				out = reason
			}
			resp.Verdict, resp.CompileOutput = judge.CE, out
			return resp
		}
	}

	stop := req.StopOnFail == nil || *req.StopOnFail
	limits := RunLimits(lang, req.Limits)
	var verdicts []judge.Verdict
	for i, t := range req.Tests {
		res, err := s.Runner.Run(ctx, sandbox.Spec{
			Argv: lang.Run(limits.MemoryBytes - lang.MemoryOverhead), Stdin: []byte(t.Input), Profile: sandbox.ProfileRun,
			Limits: limits, Mounts: job.Mounts(false),
		})
		if err != nil {
			return &Response{Verdict: judge.IE, Error: "run sandbox: " + err.Error(), Tests: resp.Tests}
		}
		v, reason := judge.Classify(res)
		if v == judge.AC && !judge.Equal(string(res.Stdout), t.Expected) {
			v, reason = judge.WA, "output differs from expected"
		}
		resp.Tests = append(resp.Tests, TestResult{
			Index: i, Verdict: v, Reason: reason, CPUMs: res.CPUTime.Milliseconds(), WallMs: res.WallTime.Milliseconds(),
			MemoryKB: res.MemoryPeak >> 10, Stdout: trunc(res.Stdout, echoBytes), Stderr: trunc(res.Stderr, echoBytes),
		})
		verdicts = append(verdicts, v)
		if v == judge.IE {
			resp.Error = reason
		}
		if v != judge.AC && stop {
			break
		}
	}
	resp.Verdict = judge.Overall(verdicts)
	return resp
}
