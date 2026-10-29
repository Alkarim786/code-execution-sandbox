CPUs visible: 8

### Startup overhead (one execution, n = 100 )
| Program | Mode | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| /usr/bin/true (pure sandbox cost) | bare exec (no isolation) | 2.6 | 13.4 | 34.8 |
| /usr/bin/true (pure sandbox cost) | sandboxed (total Run) | 82.8 | 314.3 | 696.8 |
| /usr/bin/true (pure sandbox cost) | of which host-side setup (cgroup + clone) | 20.6 | 279.8 | 493.2 |
| python3 -c pass | bare exec (no isolation) | 48.8 | 61.8 | 72.3 |
| python3 -c pass | sandboxed (total Run) | 109.0 | 200.1 | 324.7 |
| python3 -c pass | of which host-side setup (cgroup + clone) | 15.2 | 74.7 | 260.5 |
| node -e 0 | bare exec (no isolation) | 488.5 | 802.4 | 1186.5 |
| node -e 0 | sandboxed (total Run) | 845.4 | 1641.7 | 3316.5 |
| node -e 0 | of which host-side setup (cgroup + clone) | 25.1 | 192.6 | 425.3 |
| java -version | bare exec (no isolation) | 167.6 | 278.1 | 357.5 |
| java -version | sandboxed (total Run) | 180.0 | 373.5 | 666.2 |
| java -version | of which host-side setup (cgroup + clone) | 10.6 | 80.2 | 321.2 |

### Judge throughput ( 200 submissions per cell; full pipeline: job dir, compile if any, run, judge)
| Workload | Workers | Submissions/s | Mean latency ms | p95 latency ms | All AC |
|---|---|---|---|---|---|
| python (no compile, 1 test) | 1 | 15.7 | 63.6 | 137.4 | true |
| python (no compile, 1 test) | 2 | 16.1 | 124.3 | 212.9 | true |
| python (no compile, 1 test) | 4 | 47.7 | 83.5 | 121.2 | true |
| python (no compile, 1 test) | 8 | 50.2 | 158.3 | 242.7 | true |
| c (gcc compile + 1 test) | 1 | 2.7 | 368.3 | 536.0 | true |
| c (gcc compile + 1 test) | 2 | 12.7 | 156.8 | 188.0 | true |
| c (gcc compile + 1 test) | 4 | 20.5 | 190.3 | 267.3 | true |
| c (gcc compile + 1 test) | 8 | 23.9 | 323.2 | 459.1 | true |
