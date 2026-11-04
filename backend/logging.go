package main

import (
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

type JSONLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONLogger(w io.Writer) *JSONLogger {
	return &JSONLogger{w: w}
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
	_ = json.NewEncoder(l.w).Encode(e)
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
