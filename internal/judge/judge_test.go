package judge

import (
	"testing"

	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
)

func TestClassifyPriorityAndMapping(t *testing.T) {
	cases := []struct {
		name string
		r    sandbox.Result
		want Verdict
	}{
		{"clean exit", sandbox.Result{}, AC},
		{"non-zero exit", sandbox.Result{ExitCode: 1}, RE},
		{"segfault", sandbox.Result{Signal: "segmentation fault", ExitCode: -11}, RE},
		{"seccomp violation", sandbox.Result{Signal: "SIGSYS"}, RE},
		{"wall timeout", sandbox.Result{TimedOut: true, Signal: "killed"}, TLE},
		{"cpu limit", sandbox.Result{CPULimitHit: true, Signal: "killed"}, TLE},
		{"oom kill", sandbox.Result{OOMKilled: true, Signal: "killed"}, MLE},
		{"output flood", sandbox.Result{OutputCapHit: true, Signal: "killed"}, OLE},
		{"setup failure", sandbox.Result{SetupError: "pivot_root: EPERM", ExitCode: 125}, IE},
		// Limits win over the exit status they themselves cause:
		{"oom and timeout", sandbox.Result{OOMKilled: true, TimedOut: true}, MLE},
		{"timeout beats signal", sandbox.Result{TimedOut: true, Signal: "SIGSYS"}, TLE},
	}
	for _, c := range cases {
		if got, _ := Classify(&c.r); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestSeccompReasonIsExplicit(t *testing.T) {
	_, reason := Classify(&sandbox.Result{Signal: sandbox.SeccompSignal})
	if reason == "" {
		t.Error("a seccomp kill should explain itself")
	}
}

func TestEqualIgnoresTrailingWhitespace(t *testing.T) {
	cases := []struct {
		got, want string
		eq        bool
	}{
		{"1 2 3\n", "1 2 3", true},
		{"1 2 3   \n\n\n", "1 2 3\n", true},
		{"a\r\nb\r\n", "a\nb\n", true},
		{"a \nb\t\n", "a\nb", true},
		{"a b", "a  b", false}, // interior whitespace is significant
		{"a\n\nb", "a\nb", false},
		{"", "", true},
		{"\n\n", "", true},
		{"1", "2", false},
		{" 1", "1", false}, // leading whitespace is significant
	}
	for _, c := range cases {
		if Equal(c.got, c.want) != c.eq {
			t.Errorf("Equal(%q, %q) = %v, want %v", c.got, c.want, !c.eq, c.eq)
		}
	}
}

func TestOverall(t *testing.T) {
	if Overall([]Verdict{AC, AC}) != AC || Overall(nil) != AC {
		t.Error("all accepted should be AC")
	}
	if Overall([]Verdict{AC, WA, TLE}) != WA {
		t.Error("first failure wins")
	}
}
