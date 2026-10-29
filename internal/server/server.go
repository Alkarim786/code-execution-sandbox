// Package server exposes the judge over HTTP with a bounded queue and a fixed worker pool.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alkarim786/code-execution-sandbox/internal/judge"
	"github.com/Alkarim786/code-execution-sandbox/internal/languages"
	"github.com/Alkarim786/code-execution-sandbox/internal/service"
)

type Status string

const (
	Queued  Status = "queued"
	Running Status = "running"
	Done    Status = "done"
)

// Submission is the stored state of one request.
type Submission struct {
	ID        string            `json:"id"`
	Status    Status            `json:"status"`
	Language  string            `json:"language"`
	CreatedAt time.Time         `json:"created_at"`
	QueueMs   int64             `json:"queue_ms,omitempty"`
	TotalMs   int64             `json:"total_ms,omitempty"`
	Result    *service.Response `json:"result,omitempty"`

	req     *service.Request
	done    chan struct{}
	started time.Time
}

// Server owns the queue, the workers and the in-memory submission store.
type Server struct {
	svc     *service.Service
	queue   chan *Submission
	mu      sync.RWMutex
	subs    map[string]*Submission
	order   []string
	maxKeep int
	wg      sync.WaitGroup
	cancel  context.CancelFunc

	completed atomic.Int64
	rejected  atomic.Int64
}

// New starts `workers` goroutines consuming a queue of `queueSize`.
func New(svc *service.Service, workers, queueSize int) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{svc: svc, queue: make(chan *Submission, queueSize), subs: map[string]*Submission{}, maxKeep: 5000, cancel: cancel}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	return s
}

// Close stops accepting work and waits for the workers.
func (s *Server) Close() {
	s.cancel()
	close(s.queue)
	s.wg.Wait()
}

func (s *Server) worker(ctx context.Context) {
	defer s.wg.Done()
	for sub := range s.queue {
		s.mu.Lock()
		sub.Status = Running
		sub.QueueMs = time.Since(sub.CreatedAt).Milliseconds()
		sub.started = time.Now()
		s.mu.Unlock()

		resp := s.svc.Evaluate(ctx, sub.req)

		s.mu.Lock()
		sub.Result, sub.Status = resp, Done
		sub.TotalMs = time.Since(sub.CreatedAt).Milliseconds()
		sub.req = nil // free the source
		s.mu.Unlock()
		s.completed.Add(1)
		close(sub.done)
	}
}

var ErrQueueFull = errors.New("queue full")

// Submit validates and enqueues a request without blocking.
func (s *Server) Submit(req *service.Request) (*Submission, error) {
	if err := service.Validate(req); err != nil {
		return nil, err
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	sub := &Submission{ID: hex.EncodeToString(b), Status: Queued, Language: req.Language, CreatedAt: time.Now(), req: req, done: make(chan struct{})}
	select {
	case s.queue <- sub:
	default:
		s.rejected.Add(1)
		return nil, ErrQueueFull
	}
	s.mu.Lock()
	s.subs[sub.ID] = sub
	s.order = append(s.order, sub.ID)
	for len(s.order) > s.maxKeep { // bounded memory: forget the oldest finished submissions
		delete(s.subs, s.order[0])
		s.order = s.order[1:]
	}
	s.mu.Unlock()
	return sub, nil
}

// Wait blocks until the submission finishes or the context ends.
func (s *Server) Wait(ctx context.Context, sub *Submission) bool {
	select {
	case <-sub.done:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Server) snapshot(id string) (Submission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.subs[id]
	if !ok {
		return Submission{}, false
	}
	return Submission{ID: sub.ID, Status: sub.Status, Language: sub.Language, CreatedAt: sub.CreatedAt,
		QueueMs: sub.QueueMs, TotalMs: sub.TotalMs, Result: sub.Result}, true
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "queued": len(s.queue), "completed": s.completed.Load(), "rejected": s.rejected.Load()})
	})
	mux.HandleFunc("GET /languages", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"languages": languages.Names()})
	})
	mux.HandleFunc("POST /submissions", s.handleSubmit)
	mux.HandleFunc("GET /submissions/{id}", func(w http.ResponseWriter, r *http.Request) {
		snap, ok := s.snapshot(r.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "unknown submission"})
			return
		}
		writeJSON(w, 200, snap)
	})
	return mux
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var req service.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	sub, err := s.Submit(&req)
	switch {
	case errors.Is(err, ErrQueueFull):
		w.Header().Set("Retry-After", "1")
		writeJSON(w, 429, map[string]string{"error": "queue full, retry later"})
		return
	case err != nil:
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if r.URL.Query().Get("wait") == "1" {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		if s.Wait(ctx, sub) {
			snap, _ := s.snapshot(sub.ID)
			writeJSON(w, 200, snap)
			return
		}
	}
	writeJSON(w, 202, map[string]string{"id": sub.ID, "status": string(Queued)})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var _ = judge.AC
