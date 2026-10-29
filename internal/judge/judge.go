// Package judge turns raw sandbox results into verdicts and compares program output.
package judge

import (
	"strings"

	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
)

// Verdict is the outcome of one test or of a whole submission.
type Verdict string

const (
	AC  Verdict = "AC"  // accepted
	WA  Verdict = "WA"  // wrong answer
	TLE Verdict = "TLE" // time limit exceeded (CPU or wall)
	MLE Verdict = "MLE" // memory limit exceeded
	RE  Verdict = "RE"  // runtime error (non-zero exit, signal, seccomp violation)
	CE  Verdict = "CE"  // compile error
	OLE Verdict = "OLE" // output limit exceeded
	IE  Verdict = "IE"  // internal error (sandbox failure, never the user's fault)
)

// Classify maps a sandbox result (without comparing output) to a verdict and a reason.
// The order matters: resource limits are checked before exit status, because killing a process
// for exceeding a limit also makes it exit "abnormally".
func Classify(r *sandbox.Result) (Verdict, string) {
	switch {
	case r.SetupError != "":
		return IE, "sandbox setup failed: " + r.SetupError
	case r.OOMKilled:
		return MLE, "memory limit exceeded"
	case r.OutputCapHit:
		return OLE, "output limit exceeded"
	case r.TimedOut:
		return TLE, "wall-clock time limit exceeded"
	case r.CPULimitHit:
		return TLE, "CPU time limit exceeded"
	case r.Signal == sandbox.SeccompSignal:
		return RE, "killed by seccomp: forbidden system call"
	case r.Signal != "":
		return RE, "terminated by " + r.Signal
	case r.ExitCode != 0:
		return RE, "non-zero exit code"
	}
	return AC, ""
}

// Equal compares program output with the expected output, ignoring trailing whitespace on each
// line and trailing blank lines (the usual online-judge convention).
func Equal(got, want string) bool {
	return normalize(got) == normalize(want)
}

func normalize(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// Overall picks the submission verdict: the first non-AC test verdict, else AC.
func Overall(vs []Verdict) Verdict {
	for _, v := range vs {
		if v != AC {
			return v
		}
	}
	return AC
}
