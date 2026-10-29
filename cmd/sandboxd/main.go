// sandboxd is the judge HTTP daemon. Linux + root only (see README).
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
	"github.com/Alkarim786/code-execution-sandbox/internal/server"
	"github.com/Alkarim786/code-execution-sandbox/internal/service"
)

func main() {
	addr := flag.String("addr", envOr("SANDBOX_ADDR", ":8080"), "listen address")
	workers := flag.Int("workers", runtime.NumCPU(), "concurrent sandboxed executions")
	queue := flag.Int("queue", 256, "max queued submissions before returning 429")
	work := flag.String("workdir", envOr("SANDBOX_WORKDIR", "/var/lib/sandbox"), "scratch directory")
	flag.Parse()

	runner, err := sandbox.NewRunner(*work)
	if err != nil {
		log.Fatalf("sandbox unavailable: %v", err)
	}
	srv := server.New(&service.Service{Runner: service.SandboxRunner{R: runner}}, *workers, *queue)
	hs := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	}()
	log.Printf("sandboxd listening on %s with %d workers", *addr, *workers)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	srv.Close()
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
