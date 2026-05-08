package web

import (
	"sync"
	"time"
)

type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

type LogBuffer struct {
	mu     sync.RWMutex
	buffer []LogEntry
	max    int
	idx    int
	filled bool
}

func NewLogBuffer(max int) *LogBuffer {
	return &LogBuffer{
		buffer: make([]LogEntry, max),
		max:    max,
	}
}

func (lb *LogBuffer) Write(p []byte) (n int, err error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	msg := string(p)
	level := "info"
	if len(msg) > 7 && msg[1:7] == "ERRO" {
		level = "error"
	} else if len(msg) > 6 && msg[1:6] == "WARN" {
		level = "warn"
	} else if len(msg) > 6 && msg[1:6] == "DEBU" {
		level = "debug"
	}

	entry := LogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: msg,
	}
	lb.buffer[lb.idx] = entry
	lb.idx = (lb.idx + 1) % lb.max
	if lb.idx == 0 {
		lb.filled = true
	}
	return len(p), nil
}

func (lb *LogBuffer) Entries() []LogEntry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if !lb.filled {
		result := make([]LogEntry, lb.idx)
		copy(result, lb.buffer[:lb.idx])
		return result
	}

	result := make([]LogEntry, lb.max)
	copy(result, lb.buffer[lb.idx:])
	copy(result[lb.max-lb.idx:], lb.buffer[:lb.idx])
	return result
}
