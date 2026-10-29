//go:build linux

// bench measures sandbox startup overhead and judge throughput. Run as root on Linux:
//
//	go run ./cmd/bench            (inside the privileged test container; see README)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/Alkarim786/code-execution-sandbox/internal/judge"
	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
	"github.com/Alkarim786/code-execution-sandbox/internal/service"
)

func pct(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f", float64(d.Microseconds())/1000) }

func main() {
	n := flag.Int("n", 100, "repetitions per startup measurement")
	subs := flag.Int("subs", 200, "submissions per throughput measurement")
	flag.Parse()

	dir, _ := os.MkdirTemp("", "sandbox-bench-")
	defer os.RemoveAll(dir)
	runner, err := sandbox.NewRunner(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "need root and cgroup v2:", err)
		os.Exit(1)
	}
	ctx := context.Background()
	fmt.Printf("CPUs visible: %d\n\n", numCPU())

	// ---- startup overhead ----------------------------------------------------------------
	fmt.Println("### Startup overhead (one execution, n =", *n, ")")
	fmt.Println("| Program | Mode | p50 ms | p95 ms | max ms |")
	fmt.Println("|---|---|---|---|---|")
	progs := []struct {
		name string
		argv []string
	}{
		{"/usr/bin/true (pure sandbox cost)", []string{"/usr/bin/true"}},
		{"python3 -c pass", []string{"/usr/bin/python3", "-S", "-E", "-c", "pass"}},
		{"node -e 0", []string{"/usr/bin/node", "-e", "0"}},
		{"java -version", []string{"/usr/bin/java", "-Xshare:auto", "-XX:TieredStopAtLevel=1", "-XX:+UseSerialGC", "-Xmx64m", "-version"}},
	}
	for _, p := range progs {
		var bare, boxed, setup []time.Duration
		boxedRun := func() (*sandbox.Result, time.Duration) {
			lim := sandbox.DefaultLimits()
			lim.MemoryBytes = 512 << 20
			lim.Pids = 128
			lim.CPUTime, lim.WallTime = 10*time.Second, 20*time.Second
			t0 := time.Now()
			res, err := runner.Run(ctx, sandbox.Spec{Argv: p.argv, Profile: sandbox.ProfileRun, Limits: lim})
			if err != nil || res.SetupError != "" {
				fmt.Fprintf(os.Stderr, "%s failed: %v %+v\n", p.name, err, res)
				os.Exit(1)
			}
			return res, time.Since(t0)
		}
		for i := 0; i < 5; i++ { // warm the page cache for both modes before timing anything
			_ = exec.Command(p.argv[0], p.argv[1:]...).Run()
			boxedRun()
		}
		for i := 0; i < *n; i++ { // bare exec, no isolation at all
			t0 := time.Now()
			_ = exec.Command(p.argv[0], p.argv[1:]...).Run()
			bare = append(bare, time.Since(t0))
		}
		for i := 0; i < *n; i++ {
			res, d := boxedRun()
			boxed = append(boxed, d)
			setup = append(setup, res.SetupTime)
		}
		fmt.Printf("| %s | bare exec (no isolation) | %s | %s | %s |\n", p.name, ms(pct(bare, .5)), ms(pct(bare, .95)), ms(pct(bare, 1)))
		fmt.Printf("| %s | sandboxed (total Run) | %s | %s | %s |\n", p.name, ms(pct(boxed, .5)), ms(pct(boxed, .95)), ms(pct(boxed, 1)))
		fmt.Printf("| %s | of which host-side setup (cgroup + clone) | %s | %s | %s |\n", p.name, ms(pct(setup, .5)), ms(pct(setup, .95)), ms(pct(setup, 1)))
	}

	// ---- throughput --------------------------------------------------------------------------
	svc := &service.Service{Runner: service.SandboxRunner{R: runner}}
	cases := []struct {
		name string
		req  service.Request
	}{
		{"python (no compile, 1 test)", service.Request{Language: "python", Source: "a,b=map(int,input().split())\nprint(a+b)\n", Tests: []service.Test{{Input: "1 2", Expected: "3"}}}},
		{"c (gcc compile + 1 test)", service.Request{Language: "c", Source: "#include <stdio.h>\nint main(){int a,b;scanf(\"%d %d\",&a,&b);printf(\"%d\\n\",a+b);}", Tests: []service.Test{{Input: "1 2", Expected: "3"}}}},
	}
	fmt.Println("\n### Judge throughput (", *subs, "submissions per cell; full pipeline: job dir, compile if any, run, judge)")
	fmt.Println("| Workload | Workers | Submissions/s | Mean latency ms | p95 latency ms | All AC |")
	fmt.Println("|---|---|---|---|---|---|")
	for _, c := range cases {
		count := *subs
		if c.req.Language == "c" {
			count = *subs / 4 // compiling dominates; keep the run short
		}
		for w := 0; w < 3; w++ {
			r := c.req
			svc.Evaluate(ctx, &r)
		}
		for _, workers := range []int{1, 2, 4, 8} {
			var mu sync.Mutex
			var lat []time.Duration
			allAC := true
			jobs := make(chan struct{}, count)
			for i := 0; i < count; i++ {
				jobs <- struct{}{}
			}
			close(jobs)
			var wg sync.WaitGroup
			start := time.Now()
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range jobs {
						req := c.req
						t0 := time.Now()
						resp := svc.Evaluate(ctx, &req)
						d := time.Since(t0)
						mu.Lock()
						lat = append(lat, d)
						if resp.Verdict != judge.AC {
							allAC = false
						}
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			total := time.Since(start)
			var sum time.Duration
			for _, d := range lat {
				sum += d
			}
			fmt.Printf("| %s | %d | %.1f | %s | %s | %v |\n", c.name, workers, float64(count)/total.Seconds(), ms(sum/time.Duration(len(lat))), ms(pct(lat, .95)), allAC)
		}
	}
}

func numCPU() int { return runtimeNumCPU() }
