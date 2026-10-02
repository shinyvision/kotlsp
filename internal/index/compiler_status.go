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
	Language            string
	Passes              uint64
	Running             bool
	LastDuration        time.Duration
	LastFinished        time.Time
	LastOutcome         string
	LastError           string
	Compiler            string
	RequestedVersion    string
	CompilerVersion     string
	FallbackReason      string
	DiagnosticTransport string
	EffectiveArguments  []string
	Published           bool
	PublicationOutcome  string
	// Hosted reports whether the last pass reused the warm compiler process or
	// fell back to starting one.
	Hosted bool
	// Run identifies the validation run this pass belongs to, so a pass that
	// was replaced by a newer one can be told apart from one that failed.
	Run uint64
}

type compilerStatusTracker struct {
	mu       sync.RWMutex
	byLangue map[string]*CompilerPassStatus
	// dispatched identifies the newest run the scheduler has started. A pass
	// whose context was cancelled while an older run than this one was in
	// flight was replaced, not abandoned: every keystroke supersedes the pass
	// before it, and calling that a cancellation made status readers -- the
	// editor's status view and the latency gate among them -- report ordinary
	// editing as a broken compiler.
	dispatched uint64
}

// dispatch records the newest run the scheduler has started.
func (t *compilerStatusTracker) dispatch(run uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dispatched = run
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
	status.Published = false
	status.PublicationOutcome = "running; no compiler transaction has been published"
	// The scheduler records the run it dispatched before either language pass
	// starts, so a pass can say which run it belongs to without every scan
	// having to carry the identity through its signature.
	status.Run = t.dispatched
	return time.Now()
}

func (t *compilerStatusTracker) publication(published bool, outcome string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, status := range t.byLangue {
		status.Published = published
		status.PublicationOutcome = outcome
	}
}

func (t *compilerStatusTracker) finish(language string, started time.Time, hosted bool, outcome, failure, compiler, requestedVersion, version, fallbackReason, diagnosticTransport string, arguments []string) {
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
	if outcome == "cancelled" && t.dispatched > status.Run {
		// A newer run replaced this pass while it was in flight.
		outcome, failure = "superseded", "a newer validation run replaced this pass"
	}
	status.LastOutcome = boundedStatusText(outcome, 256)
	status.LastError = boundedStatusText(failure, 4096)
	status.Compiler = boundedStatusText(compiler, 1024)
	status.RequestedVersion = boundedStatusText(requestedVersion, 256)
	status.CompilerVersion = boundedStatusText(version, 1024)
	status.FallbackReason = boundedStatusText(fallbackReason, 4096)
	status.DiagnosticTransport = boundedStatusText(diagnosticTransport, 1024)
	status.EffectiveArguments = status.EffectiveArguments[:0]
	for _, argument := range arguments {
		if len(status.EffectiveArguments) >= 256 {
			status.EffectiveArguments = append(status.EffectiveArguments, "… arguments omitted")
			break
		}
		status.EffectiveArguments = append(status.EffectiveArguments, boundedStatusText(argument, 4096))
	}
}

func (t *compilerStatusTracker) snapshot() []CompilerPassStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]CompilerPassStatus, 0, len(t.byLangue))
	for _, status := range t.byLangue {
		copy := *status
		copy.EffectiveArguments = append([]string(nil), status.EffectiveArguments...)
		out = append(out, copy)
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
