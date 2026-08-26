package lsp

import (
	"context"
	"io"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/index"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

func diagnosticServer(t *testing.T, capabilities map[string]any) (*Server, *recordingConn) {
	t.Helper()
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.index.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	recorder := &recordingConn{}
	s.notify = recorder.record
	s.rootMu.Lock()
	s.clientCaps = capabilities
	s.rootMu.Unlock()
	return s, recorder
}

// A client that pulls diagnostics and is also pushed them records both, in
// separate namespaces, and reports every problem twice.
func TestDiagnosticsAreNotPushedToAPullingClient(t *testing.T) {
	pulling := map[string]any{"textDocument": map[string]any{"diagnostic": map[string]any{}}}
	s, recorder := diagnosticServer(t, pulling)
	s.publishDiagnostics(protocol.URI("file:///workspace/A.kt"), []protocol.Diagnostic{{Message: "x"}})
	if got := len(recorder.snapshot()); got != 0 {
		t.Fatalf("pushed %d notifications to a client that pulls", got)
	}

	pushOnly, pushRecorder := diagnosticServer(t, map[string]any{"textDocument": map[string]any{}})
	pushOnly.publishDiagnostics(protocol.URI("file:///workspace/A.kt"), []protocol.Diagnostic{{Message: "x"}})
	if got := len(pushRecorder.snapshot()); got != 1 {
		t.Fatalf("a client without pull support got %d notifications, want 1", got)
	}
}

// Diagnostics computed while the workspace was cold describe an index without
// the standard library or any dependency. Nothing recomputes them, so the
// client must be told to ask again once indexing finishes.
func TestClientIsAskedToRefreshOnceIndexingCompletes(t *testing.T) {
	s, _ := diagnosticServer(t, map[string]any{
		"textDocument": map[string]any{"diagnostic": map[string]any{}},
		"workspace":    map[string]any{"diagnostics": map[string]any{"refreshSupport": true}},
	})
	refreshed := make(chan struct{}, 1)
	s.clientCall = func(_ context.Context, method string, _, _ any) error {
		if method == "workspace/diagnostic/refresh" {
			select {
			case refreshed <- struct{}{}:
			default:
			}
		}
		return nil
	}
	var ready atomic.Bool
	s.progressSource = func() index.Progress { return index.Progress{Ready: ready.Load()} }

	s.refreshDiagnosticsWhenIndexed()
	select {
	case <-refreshed:
		t.Fatal("refresh was requested before the index was ready")
	case <-time.After(600 * time.Millisecond):
	}
	ready.Store(true)
	select {
	case <-refreshed:
	case <-time.After(10 * time.Second):
		t.Fatal("the client was never asked to re-request diagnostics")
	}
}

// Without refresh support there is nothing to ask, and a pull client must still
// never be pushed to.
func TestRefreshIsSilentWithoutClientSupport(t *testing.T) {
	s, recorder := diagnosticServer(t, map[string]any{"textDocument": map[string]any{"diagnostic": map[string]any{}}})
	calls := 0
	s.clientCall = func(context.Context, string, any, any) error { calls++; return nil }
	s.refreshDiagnostics()
	if calls != 0 || len(recorder.snapshot()) != 0 {
		t.Fatalf("refresh contacted a client that advertised nothing: %d calls, %d notifications", calls, len(recorder.snapshot()))
	}
}

// The whole path: the index finishes a background compiler pass and the client
// is asked to re-request. Without this the recomputed diagnostics sit unread
// until the editor is restarted.
func TestCompilerPassAsksTheClientToRefresh(t *testing.T) {
	s, _ := diagnosticServer(t, map[string]any{
		"textDocument": map[string]any{"diagnostic": map[string]any{}},
		"workspace":    map[string]any{"diagnostics": map[string]any{"refreshSupport": true}},
	})
	refreshed := make(chan struct{}, 4)
	s.clientCall = func(_ context.Context, method string, _, _ any) error {
		if method == "workspace/diagnostic/refresh" {
			select {
			case refreshed <- struct{}{}:
			default:
			}
		}
		return nil
	}
	s.index.ScheduleCompilerDiagnostics(context.Background())
	select {
	case <-refreshed:
	case <-time.After(30 * time.Second):
		t.Fatal("the client was never asked to re-request after a compiler pass")
	}
}
