package main

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// LogEntry deliberately has no URL, query, fragment, body, header, IP, secret
// ID, ciphertext, key, token, or error-detail fields. The route is always the
// matched ServeMux pattern, never the request path.
type LogEntry struct {
	Time       string  `json:"time"`
	Level      string  `json:"level"`
	Method     string  `json:"method,omitempty"`
	Route      string  `json:"route"`
	Status     int     `json:"status,omitempty"`
	DurationMS float64 `json:"duration_ms,omitempty"`
	ErrorClass string  `json:"error_class,omitempty"`
}

type Logger interface {
	Log(LogEntry)
}

const (
	logBufferBytes = 32 << 10
	// flushAt keeps the buffer below its capacity: one more line always fits.
	flushAt        = logBufferBytes - 512
	logFlushPeriod = 100 * time.Millisecond
)

// JSONLogger writes newline-delimited JSON through a buffered writer. Each
// request logs one line, and an unbuffered writer cost a write syscall per line
// under a mutex (measured ~39% of server CPU for a full create/open cycle), so
// lines are batched and flushed on a short timer. A crash can lose at most the
// buffered tail; nothing here was fsynced before either.
type JSONLogger struct {
	mu      sync.Mutex
	buf     *bufio.Writer
	encoder *json.Encoder
	started bool
	closed  bool
	stop    chan struct{}
	once    sync.Once
}

func NewJSONLogger(w io.Writer) *JSONLogger {
	buf := bufio.NewWriterSize(w, logBufferBytes)
	return &JSONLogger{
		buf:     buf,
		encoder: json.NewEncoder(buf),
		stop:    make(chan struct{}),
	}
}

func (l *JSONLogger) Log(e LogEntry) {
	if e.Time == "" {
		e.Time = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if e.Level == "" {
		e.Level = "info"
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	if !l.started {
		l.started = true
		go l.flushLoop()
	}
	_ = l.encoder.Encode(e)
	if l.buf.Buffered() >= flushAt {
		_ = l.buf.Flush()
	}
}

func (l *JSONLogger) flushLoop() {
	ticker := time.NewTicker(logFlushPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			_ = l.buf.Flush()
			l.mu.Unlock()
		case <-l.stop:
			return
		}
	}
}

// Close flushes buffered lines and stops the flush timer. It is safe to call
// more than once.
func (l *JSONLogger) Close() error {
	var err error
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		err = l.buf.Flush()
		l.mu.Unlock()
		close(l.stop)
	})
	return err
}

type MemoryLogger struct {
	mu      sync.Mutex
	entries []LogEntry
}

func (l *MemoryLogger) Log(e LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
}

func (l *MemoryLogger) Entries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}
