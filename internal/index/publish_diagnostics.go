package index

import (
	"context"
	"sync"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Diagnostics for an edited document are computed and published off the edit's
// path. Computing them walks every reference in the file (a large file is
// well over a hundred milliseconds), and requests are ordered behind earlier
// notifications, so doing it inline made every request after an edit wait for
// it -- including requests about other files. Edits to the same document
// arriving meanwhile are coalesced: one computation covers the burst.
type diagnosticPublisher struct {
	mu      sync.Mutex
	pending map[protocol.URI]time.Time
	order   []protocol.URI
	running bool
	// current is the document being computed and cancel stops it: an edit to
	// that document makes the computation's answer obsolete before it lands.
	current protocol.URI
	cancel  context.CancelFunc
}

// diagnosticSettle is how long a document must go without edits before its
// diagnostics are computed. Typing produces an edit per keystroke; computing
// each one only for the next keystroke to discard it was most of the CPU an
// editing session used.
const diagnosticSettle = 60 * time.Millisecond

// diagnosticDeadline bounds one background computation. It runs without a
// request to bound it, and whatever it has not proved by then is not shown.
const diagnosticDeadline = 5 * time.Second

// SetDiagnosticsPush turns the computation of pushed diagnostics on or off. A
// client that pulls diagnostics ignores whatever is pushed, so computing it
// -- a full pass over the document, per edit, per reload, per compiler run --
// was pure waste that also held the index lock.
func (i *Index) SetDiagnosticsPush(enabled bool) { i.pushDisabled.Store(!enabled) }

// publishNow computes and publishes a document's diagnostics inline.
func (i *Index) publishNow(uri protocol.URI) {
	if i.onParsed == nil || i.pushDisabled.Load() {
		return
	}
	i.onParsed(uri, i.Diagnostics(uri))
}

// preemptDiagnostics stops the diagnostics computation in flight and queues
// it again. It holds the index read lock for as long as it runs, and an edit
// waits for the write lock behind it -- and every request waits behind the
// edit: a completion typed while a neighbouring file's import check was
// resolving took 1.4 s. Edits come first; the computation starts over once
// they settle.
func (i *Index) preemptDiagnostics() {
	i.publisher.mu.Lock()
	defer i.publisher.mu.Unlock()
	if i.publisher.cancel == nil || i.publisher.current == "" {
		return
	}
	uri := i.publisher.current
	i.publisher.cancel()
	if i.publisher.pending == nil {
		i.publisher.pending = make(map[protocol.URI]time.Time)
	}
	if _, queued := i.publisher.pending[uri]; !queued {
		i.publisher.order = append([]protocol.URI{uri}, i.publisher.order...)
		i.publisher.pending[uri] = time.Now()
	}
}

// publishDiagnosticsSoon schedules publication of the document's diagnostics.
func (i *Index) publishDiagnosticsSoon(uri protocol.URI) {
	if i.onParsed == nil || i.pushDisabled.Load() || i.closed.Load() {
		return
	}
	i.publisher.mu.Lock()
	if i.publisher.pending == nil {
		i.publisher.pending = make(map[protocol.URI]time.Time)
	}
	if _, queued := i.publisher.pending[uri]; !queued {
		i.publisher.order = append(i.publisher.order, uri)
	}
	i.publisher.pending[uri] = time.Now()
	if i.publisher.current == uri && i.publisher.cancel != nil {
		i.publisher.cancel()
	}
	start := !i.publisher.running
	i.publisher.running = true
	i.publisher.mu.Unlock()
	if !start {
		return
	}
	i.scanWG.Add(1)
	go func() {
		defer i.scanWG.Done()
		defer i.recoverBackground("diagnostics")
		for {
			i.publisher.mu.Lock()
			if len(i.publisher.order) == 0 || i.closed.Load() {
				i.publisher.running = false
				i.publisher.current, i.publisher.cancel = "", nil
				i.publisher.mu.Unlock()
				return
			}
			next := i.publisher.order[0]
			if wait := time.Until(i.publisher.pending[next].Add(diagnosticSettle)); wait > 0 {
				i.publisher.mu.Unlock()
				time.Sleep(wait)
				continue
			}
			i.publisher.order = i.publisher.order[1:]
			delete(i.publisher.pending, next)
			ctx, cancel := context.WithTimeout(i.lifecycleContext(), diagnosticDeadline)
			i.publisher.current, i.publisher.cancel = next, cancel
			i.publisher.mu.Unlock()
			// The document may have been closed since: Diagnostics of an
			// unknown document is empty and publishing it clears the client's.
			i.mu.RLock()
			before := i.files[next]
			i.mu.RUnlock()
			diagnostics := i.DiagnosticsContext(ctx, next)
			superseded := ctx.Err() != nil
			cancel()
			i.publisher.mu.Lock()
			i.publisher.current, i.publisher.cancel = "", nil
			i.publisher.mu.Unlock()
			i.mu.RLock()
			after := i.files[next]
			i.mu.RUnlock()
			if before != after || superseded {
				// Replaced or cancelled while computing: the edit that replaced it
				// queued its own publication, and this result is incomplete or
				// describes a file that is gone.
				continue
			}
			i.onParsed(next, diagnostics)
		}
	}()
}
