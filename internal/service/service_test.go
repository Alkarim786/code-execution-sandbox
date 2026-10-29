package service

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alkarim786/code-execution-sandbox/internal/judge"
	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
)

type fakeJob struct{ wrote map[string][]byte }

func (f *fakeJob) WriteSource(n string, d []byte) error { f.wrote[n] = d; return nil }
func (f *fakeJob) Mounts(rw bool) []sandbox.Mount {
	return []sandbox.Mount{{Target: "/out", ReadWrite: rw}}
}
func (f *fakeJob) Cleanup() {}

// fakeRunner returns scripted results in order and records every spec it was given.
type fakeRunner struct {
	mu      sync.Mutex
	results []*sandbox.Result
	specs   []sandbox.Spec
	job     *fakeJob
}

func (f *fakeRunner) NewJob(int64) (Job, error) {
	f.job = &fakeJob{wrote: map[string][]byte{}}
	return f.job, nil
}
func (f *fakeRunner) Run(_ context.Context, s sandbox.Spec) (*sandbox.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs = append(f.specs, s)
	r := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return r, nil
}

func ok(out string) *sandbox.Result {
	return &sandbox.Result{Stdout: []byte(out), CPUTime: 5 * time.Millisecond}
}

func TestAllAcceptedPython(t *testing.T) {
	fr := &fakeRunner{results: []*sandbox.Result{ok("3\n"), ok("7\n")}}
	s := &Service{Runner: fr}
	resp := s.Evaluate(context.Background(), &Request{Language: "python", Source: "print(1)",
		Tests: []Test{{Input: "1 2", Expected: "3"}, {Input: "3 4", Expected: "7"}}})
	if resp.Verdict != judge.AC || len(resp.Tests) != 2 {
		t.Fatalf("%+v", resp)
	}
	if string(fr.job.wrote["main.py"]) != "print(1)" {
		t.Error("source was not written under the language's file name")
	}
	if len(fr.specs) != 2 || fr.specs[0].Profile != sandbox.ProfileRun || string(fr.specs[0].Stdin) != "1 2" {
		t.Errorf("python has no compile step; unexpected specs: %+v", fr.specs)
	}
}

func TestCompileErrorStopsEverything(t *testing.T) {
	fr := &fakeRunner{results: []*sandbox.Result{{ExitCode: 1, Stderr: []byte("main.c:1: error: expected ';'")}}}
	resp := (&Service{Runner: fr}).Evaluate(context.Background(), &Request{Language: "c", Source: "int main(){",
		Tests: []Test{{Input: "", Expected: ""}}})
	if resp.Verdict != judge.CE || !strings.Contains(resp.CompileOutput, "expected ';'") || len(resp.Tests) != 0 {
		t.Fatalf("%+v", resp)
	}
	if len(fr.specs) != 1 || fr.specs[0].Profile != sandbox.ProfileToolchain || !fr.specs[0].Mounts[0].ReadWrite {
		t.Errorf("compile must use the toolchain profile with a writable /out: %+v", fr.specs)
	}
}

func TestRunStepUsesRunProfileAndReadOnlyOut(t *testing.T) {
	fr := &fakeRunner{results: []*sandbox.Result{ok(""), ok("x")}}
	(&Service{Runner: fr}).Evaluate(context.Background(), &Request{Language: "cpp", Source: "int main(){}", Tests: []Test{{Expected: "x"}}})
	if len(fr.specs) != 2 {
		t.Fatalf("expected compile + 1 run, got %d", len(fr.specs))
	}
	run := fr.specs[1]
	if run.Profile != sandbox.ProfileRun || run.Mounts[0].ReadWrite {
		t.Errorf("run step must not get a writable /out or the toolchain profile: %+v", run)
	}
}

func TestStopOnFirstFailureByDefault(t *testing.T) {
	fr := &fakeRunner{results: []*sandbox.Result{ok("1"), ok("wrong"), ok("3")}}
	resp := (&Service{Runner: fr}).Evaluate(context.Background(), &Request{Language: "python", Source: "x",
		Tests: []Test{{Expected: "1"}, {Expected: "2"}, {Expected: "3"}}})
	if resp.Verdict != judge.WA || len(resp.Tests) != 2 {
		t.Fatalf("should stop after the first failure: %+v", resp)
	}
	no := false
	fr2 := &fakeRunner{results: []*sandbox.Result{ok("1"), ok("wrong"), ok("3")}}
	resp = (&Service{Runner: fr2}).Evaluate(context.Background(), &Request{Language: "python", Source: "x", StopOnFail: &no,
		Tests: []Test{{Expected: "1"}, {Expected: "2"}, {Expected: "3"}}})
	if resp.Verdict != judge.WA || len(resp.Tests) != 3 || resp.Tests[2].Verdict != judge.AC {
		t.Fatalf("stop_on_fail=false should run all tests: %+v", resp)
	}
}

func TestResourceVerdictsPropagate(t *testing.T) {
	for name, tc := range map[string]struct {
		res  *sandbox.Result
		want judge.Verdict
	}{
		"tle": {&sandbox.Result{TimedOut: true}, judge.TLE},
		"mle": {&sandbox.Result{OOMKilled: true}, judge.MLE},
		"re":  {&sandbox.Result{Signal: "SIGSYS"}, judge.RE},
		"ole": {&sandbox.Result{OutputCapHit: true}, judge.OLE},
	} {
		resp := (&Service{Runner: &fakeRunner{results: []*sandbox.Result{tc.res}}}).Evaluate(context.Background(),
			&Request{Language: "python", Source: "x", Tests: []Test{{Expected: ""}}})
		if resp.Verdict != tc.want {
			t.Errorf("%s: got %s want %s", name, resp.Verdict, tc.want)
		}
	}
}

func TestValidation(t *testing.T) {
	bad := []Request{
		{Language: "cobol", Source: "x", Tests: []Test{{}}},
		{Language: "python", Source: "", Tests: []Test{{}}},
		{Language: "python", Source: "x"},
		{Language: "python", Source: strings.Repeat("x", MaxSourceBytes+1), Tests: []Test{{}}},
		{Language: "python", Source: "x", Tests: make([]Test, MaxTests+1)},
		{Language: "python", Source: "x", Tests: []Test{{Input: strings.Repeat("x", MaxIOBytes+1)}}},
		{Language: "python", Source: "x", Tests: []Test{{}}, Limits: Limits{CPUMillis: -1}},
	}
	for i := range bad {
		if Validate(&bad[i]) == nil {
			t.Errorf("request %d should be rejected", i)
		}
	}
	resp := (&Service{Runner: &fakeRunner{results: []*sandbox.Result{ok("")}}}).Evaluate(context.Background(), &bad[0])
	if resp.Verdict != judge.IE {
		t.Errorf("invalid request should be IE, got %s", resp.Verdict)
	}
}

func TestLimitsAreClampedAndScaled(t *testing.T) {
	java := mustLang(t, "java")
	lim := RunLimits(java, Limits{CPUMillis: 3_600_000, MemoryMB: 1 << 20, StackMB: 1 << 20})
	if lim.StackBytes != MaxStack {
		t.Errorf("stack %d", lim.StackBytes)
	}
	if lim.CPUTime != 2*MaxCPU { // clamp to MaxCPU, then Java's 2x factor
		t.Errorf("cpu %v", lim.CPUTime)
	}
	if lim.MemoryBytes != MaxMemory+java.MemoryOverhead {
		t.Errorf("mem %d", lim.MemoryBytes)
	}
	if lim.WallTime <= lim.CPUTime {
		t.Error("wall limit must exceed the cpu limit so sleeping programs are caught separately")
	}
	def := RunLimits(mustLang(t, "c"), Limits{})
	if def.CPUTime != sandbox.DefaultLimits().CPUTime || def.Pids != sandbox.DefaultLimits().Pids {
		t.Errorf("defaults not applied: %+v", def)
	}
}
