package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Alkarim786/code-execution-sandbox/internal/sandbox"
	"github.com/Alkarim786/code-execution-sandbox/internal/service"
)

type nopJob struct{}

func (nopJob) WriteSource(string, []byte) error { return nil }
func (nopJob) Mounts(bool) []sandbox.Mount      { return nil }
func (nopJob) Cleanup()                         {}

// slowRunner blocks every Run until released, to exercise queueing and back-pressure.
type slowRunner struct {
	release chan struct{}
	running atomic.Int32
}

func (s *slowRunner) NewJob(int64) (service.Job, error) { return nopJob{}, nil }
func (s *slowRunner) Run(ctx context.Context, _ sandbox.Spec) (*sandbox.Result, error) {
	s.running.Add(1)
	defer s.running.Add(-1)
	select {
	case <-s.release:
	case <-ctx.Done():
	}
	return &sandbox.Result{Stdout: []byte("ok")}, nil
}

func body(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

var goodReq = service.Request{Language: "python", Source: "print('ok')", Tests: []service.Test{{Expected: "ok"}}}

func TestSubmitWaitAndPoll(t *testing.T) {
	sr := &slowRunner{release: make(chan struct{})}
	close(sr.release)
	srv := New(&service.Service{Runner: sr}, 2, 8)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/submissions?wait=1", "application/json", body(t, goodReq))
	if err != nil {
		t.Fatal(err)
	}
	var sub Submission
	_ = json.NewDecoder(resp.Body).Decode(&sub)
	if resp.StatusCode != 200 || sub.Status != Done || sub.Result == nil || sub.Result.Verdict != "AC" {
		t.Fatalf("%d %+v", resp.StatusCode, sub)
	}
	got, _ := http.Get(ts.URL + "/submissions/" + sub.ID)
	if got.StatusCode != 200 {
		t.Errorf("poll: %d", got.StatusCode)
	}
	missing, _ := http.Get(ts.URL + "/submissions/nope")
	if missing.StatusCode != 404 {
		t.Errorf("unknown id: %d", missing.StatusCode)
	}
}

func TestAsyncSubmitReturns202ThenCompletes(t *testing.T) {
	sr := &slowRunner{release: make(chan struct{})}
	srv := New(&service.Service{Runner: sr}, 1, 4)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, _ := http.Post(ts.URL+"/submissions", "application/json", body(t, goodReq))
	var acc map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&acc)
	if resp.StatusCode != 202 || acc["id"] == "" {
		t.Fatalf("%d %v", resp.StatusCode, acc)
	}
	close(sr.release)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snap, _ := srv.snapshot(acc["id"])
		if snap.Status == Done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("submission never completed")
}

func TestWorkerPoolBoundsConcurrencyAndQueueAppliesBackPressure(t *testing.T) {
	sr := &slowRunner{release: make(chan struct{})}
	srv := New(&service.Service{Runner: sr}, 2, 3) // 2 running + 3 queued = 5 accepted
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var codes []int
	for i := 0; i < 8; i++ {
		resp, _ := http.Post(ts.URL+"/submissions", "application/json", body(t, goodReq))
		codes = append(codes, resp.StatusCode)
		if i == 1 { // let the workers pick the first two up so the queue starts empty
			time.Sleep(100 * time.Millisecond)
		}
	}
	accepted, rejected := 0, 0
	for _, c := range codes {
		switch c {
		case 202:
			accepted++
		case 429:
			rejected++
		}
	}
	if accepted != 5 || rejected != 3 {
		t.Errorf("accepted %d rejected %d (codes %v), want 5 and 3", accepted, rejected, codes)
	}
	if n := sr.running.Load(); n != 2 {
		t.Errorf("%d concurrent executions, worker pool size is 2", n)
	}
	close(sr.release)
}

func TestBadRequests(t *testing.T) {
	srv := New(&service.Service{Runner: &slowRunner{release: make(chan struct{})}}, 1, 1)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	for name, payload := range map[string]string{
		"not json":      `{`,
		"unknown field": `{"language":"python","source":"x","tests":[{}],"evil":1}`,
		"bad language":  `{"language":"brainfuck","source":"x","tests":[{}]}`,
		"no tests":      `{"language":"python","source":"x","tests":[]}`,
	} {
		resp, _ := http.Post(ts.URL+"/submissions", "application/json", bytes.NewBufferString(payload))
		if resp.StatusCode != 400 {
			t.Errorf("%s: got %d", name, resp.StatusCode)
		}
	}
	h, _ := http.Get(ts.URL + "/health")
	l, _ := http.Get(ts.URL + "/languages")
	if h.StatusCode != 200 || l.StatusCode != 200 {
		t.Error("health/languages should be 200")
	}
}
