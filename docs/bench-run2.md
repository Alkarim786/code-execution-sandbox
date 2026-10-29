CPUs visible: 8

### Startup overhead (one execution, n = 100 )
| Program | Mode | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| /usr/bin/true (pure sandbox cost) | bare exec (no isolation) | 2.6 | 3.6 | 8.2 |
| /usr/bin/true (pure sandbox cost) | sandboxed (total Run) | 23.5 | 35.2 | 49.9 |
| /usr/bin/true (pure sandbox cost) | of which host-side setup (cgroup + clone) | 7.9 | 12.9 | 14.7 |
| python3 -c pass | bare exec (no isolation) | 18.5 | 32.6 | 52.5 |
| python3 -c pass | sandboxed (total Run) | 37.2 | 59.6 | 74.6 |
| python3 -c pass | of which host-side setup (cgroup + clone) | 7.2 | 11.1 | 14.1 |
| node -e 0 | bare exec (no isolation) | 459.0 | 1050.0 | 1232.0 |
| node -e 0 | sandboxed (total Run) | 518.4 | 1028.2 | 1403.3 |
| node -e 0 | of which host-side setup (cgroup + clone) | 11.2 | 151.6 | 470.9 |
| java -version | bare exec (no isolation) | 167.7 | 281.3 | 364.1 |
| java -version | sandboxed (total Run) | 229.1 | 336.6 | 374.1 |
| java -version | of which host-side setup (cgroup + clone) | 11.6 | 38.8 | 58.9 |

### Judge throughput ( 200 submissions per cell; full pipeline: job dir, compile if any, run, judge)
| Workload | Workers | Submissions/s | Mean latency ms | p95 latency ms | All AC |
|---|---|---|---|---|---|
| python (no compile, 1 test) | 1 | 11.0 | 91.2 | 168.5 | true |
| python (no compile, 1 test) | 2 | 11.6 | 171.4 | 290.7 | true |
| python (no compile, 1 test) | 4 | 14.5 | 273.1 | 470.6 | true |
| python (no compile, 1 test) | 8 | 20.3 | 390.5 | 563.1 | true |
| c (gcc compile + 1 test) | 1 | 3.3 | 307.1 | 445.6 | true |
| c (gcc compile + 1 test) | 2 | 5.1 | 384.8 | 585.8 | true |
| c (gcc compile + 1 test) | 4 | 5.0 | 768.6 | 1092.5 | true |
| c (gcc compile + 1 test) | 8 | 6.9 | 1108.9 | 1774.5 | true |
