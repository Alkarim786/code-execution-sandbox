// Package languages defines how each supported language is compiled and run inside the sandbox.
package languages

import (
	"fmt"
	"sort"
	"strconv"
	"time"
)

// Language describes a toolchain. Paths are absolute paths inside the sandbox root (the host's
// /usr is bind-mounted read-only), the source is mounted read-only at /in and compiled
// artifacts live in /out.
type Language struct {
	Name       string
	SourceFile string
	// Compile is nil for interpreted languages.
	Compile func() []string
	// Run builds the argv for running a test; memBytes lets the JVM size its heap.
	Run func(memBytes int64) []string
	// Extra memory the runtime itself needs on top of the problem's limit (interpreter, JIT).
	MemoryOverhead int64
	// TimeFactor scales CPU limits for slow-starting runtimes.
	TimeFactor float64
}

var all = map[string]*Language{
	"python": {
		Name: "python", SourceFile: "main.py",
		Run:            func(int64) []string { return []string{"/usr/bin/python3", "-S", "-E", "/in/main.py"} },
		MemoryOverhead: 24 << 20, TimeFactor: 1,
	},
	"c": {
		Name: "c", SourceFile: "main.c",
		Compile: func() []string {
			return []string{"/usr/bin/gcc", "-O2", "-std=c17", "-pipe", "-o", "/out/main", "/in/main.c", "-lm"}
		},
		Run:        func(int64) []string { return []string{"/out/main"} },
		TimeFactor: 1,
	},
	"cpp": {
		Name: "cpp", SourceFile: "main.cpp",
		Compile: func() []string {
			return []string{"/usr/bin/g++", "-O2", "-std=c++17", "-pipe", "-o", "/out/main", "/in/main.cpp"}
		},
		Run:        func(int64) []string { return []string{"/out/main"} },
		TimeFactor: 1,
	},
	"javascript": {
		Name: "javascript", SourceFile: "main.js",
		Run: func(int64) []string {
			return []string{"/usr/bin/node", "--max-old-space-size=" + mib(128), "/in/main.js"}
		},
		MemoryOverhead: 64 << 20, TimeFactor: 1,
	},
	"java": {
		Name: "java", SourceFile: "Main.java",
		Compile: func() []string {
			return []string{"/usr/bin/javac", "-J-Xmx256m", "-J-XX:+UseSerialGC", "-d", "/out", "/in/Main.java"}
		},
		Run: func(mem int64) []string {
			heap := mem / 2
			if heap < 32<<20 {
				heap = 32 << 20
			}
			return []string{"/usr/bin/java", "-Xmx" + strconv.FormatInt(heap>>20, 10) + "m", "-Xss8m", "-XX:+UseSerialGC",
				"-XX:TieredStopAtLevel=1", "-XX:-UsePerfData", "-Xshare:auto", "-cp", "/out", "Main"}
		},
		MemoryOverhead: 160 << 20, TimeFactor: 2,
	},
}

func mib(n int) string { return strconv.Itoa(n) }

// Get returns a language by name.
func Get(name string) (*Language, error) {
	l, ok := all[name]
	if !ok {
		return nil, fmt.Errorf("unsupported language %q (supported: %v)", name, Names())
	}
	return l, nil
}

// Names lists supported languages in a stable order.
func Names() []string {
	out := make([]string, 0, len(all))
	for k := range all {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ScaleCPU applies the language's time factor.
func (l *Language) ScaleCPU(d time.Duration) time.Duration {
	return time.Duration(float64(d) * l.TimeFactor)
}
