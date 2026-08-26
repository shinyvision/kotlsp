package index

import (
	"context"
	"testing"
	"time"
)

// Compiler validation finishes long after the edit that triggered it. A client
// that pulls diagnostics re-requests only when told to, so the index has to
// announce that the set changed.
func TestCompilerDiagnosticsAnnounceThatTheyChanged(t *testing.T) {
	requireCompilerBackedTest(t)
	idx := New(nil)
	defer idx.Close()
	notified := make(chan struct{}, 4)
	idx.SetDiagnosticsListener(func() {
		select {
		case notified <- struct{}{}:
		default:
		}
	})
	idx.ScheduleCompilerDiagnostics(context.Background())
	select {
	case <-notified:
	case <-time.After(30 * time.Second):
		t.Fatal("a completed compiler pass never announced its diagnostics")
	}
}

// A superseded pass must stay silent: it wrote nothing.
func TestSupersededCompilerPassDoesNotAnnounce(t *testing.T) {
	requireCompilerBackedTest(t)
	idx := New(nil)
	defer idx.Close()
	notified := make(chan struct{}, 4)
	idx.SetDiagnosticsListener(func() {
		select {
		case notified <- struct{}{}:
		default:
		}
	})
	idx.ScheduleCompilerDiagnostics(context.Background())
	idx.cancelCompilerDiagnostics()
	select {
	case <-notified:
		t.Fatal("a cancelled compiler pass announced diagnostics it never wrote")
	case <-time.After(2 * time.Second):
	}
}
