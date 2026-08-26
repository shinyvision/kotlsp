package index

import (
	"sync"
	"time"
)

// CompilerPassStatus describes one language's background validation. It exists
// so latency can be measured against the pass that actually finished rather
// than against a shared counter both languages bump, and so the editor can say
// what the server is doing and how long it took last time.
type CompilerPassStatus struct {
	Language     string
	Passes       uint64
	Running      bool
	LastDuration time.Duration
	LastFinished time.Time
	// Hosted reports whether the last pass reused the warm compiler process or
	// fell back to starting one.
	Hosted bool
}

type compilerStatusTracker struct {
	mu       sync.RWMutex
	byLangue map[string]*CompilerPassStatus
}

func (t *compilerStatusTracker) begin(language string) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.byLangue == nil {
		t.byLangue = make(map[string]*CompilerPassStatus, 2)
	}
	status, ok := t.byLangue[language]
	if !ok {
		status = &CompilerPassStatus{Language: language}
		t.byLangue[language] = status
	}
	status.Running = true
	return time.Now()
}

func (t *compilerStatusTracker) finish(language string, started time.Time, hosted bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	status, ok := t.byLangue[language]
	if !ok {
		return
	}
	status.Running = false
	status.Passes++
	status.LastDuration = time.Since(started)
	status.LastFinished = time.Now()
	status.Hosted = hosted
}

func (t *compilerStatusTracker) snapshot() []CompilerPassStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]CompilerPassStatus, 0, len(t.byLangue))
	for _, status := range t.byLangue {
		out = append(out, *status)
	}
	return out
}

func (t *compilerStatusTracker) passes(language string) uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if status, ok := t.byLangue[language]; ok {
		return status.Passes
	}
	return 0
}

// CompilerStatus reports what background validation has been doing.
func (i *Index) CompilerStatus() []CompilerPassStatus { return i.compilerStatus.snapshot() }

// CompilerPasses counts completed passes for one language.
func (i *Index) CompilerPasses(language string) uint64 { return i.compilerStatus.passes(language) }
