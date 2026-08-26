package lsp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/index"
)

// A validation pass that takes seconds must be visible, or the server looks
// broken rather than merely busy.
func TestCompilerPassIsReportedAsProgress(t *testing.T) {
	s, recorder := diagnosticServer(t, map[string]any{
		"window": map[string]any{"workDoneProgress": true},
	})
	created := make(chan struct{}, 1)
	s.clientCall = func(_ context.Context, method string, _, _ any) error {
		if method == "window/workDoneProgress/create" {
			select {
			case created <- struct{}{}:
			default:
			}
		}
		return nil
	}
	var running atomic.Bool
	s.compilerStatusSource = func() []index.CompilerPassStatus {
		return []index.CompilerPassStatus{
			{Language: "kotlin", Running: running.Load()},
			{Language: "java", Running: false},
		}
	}

	s.watchCompilerProgress()
	running.Store(true)
	select {
	case <-created:
	case <-time.After(15 * time.Second):
		t.Fatal("a running validation pass was never reported")
	}
	if !waitFor(func() bool {
		kinds := progressKinds(recorder.snapshot(), "")
		return len(kinds) > 0 && kinds[0] == "begin"
	}) {
		t.Fatalf("no begin was sent: %v", progressKinds(recorder.snapshot(), ""))
	}

	running.Store(false)
	if !waitFor(func() bool {
		kinds := progressKinds(recorder.snapshot(), "")
		return len(kinds) > 0 && kinds[len(kinds)-1] == "end"
	}) {
		t.Fatalf("the stream never ended: %v", progressKinds(recorder.snapshot(), ""))
	}
}

// A pass shorter than the floor finishes before a reader could register it, and
// announcing it would only make the status line flicker.
func TestBriefCompilerPassIsNotReported(t *testing.T) {
	s, recorder := diagnosticServer(t, map[string]any{
		"window": map[string]any{"workDoneProgress": true},
	})
	calls := 0
	s.clientCall = func(context.Context, string, any, any) error { calls++; return nil }
	var running atomic.Bool
	s.compilerStatusSource = func() []index.CompilerPassStatus {
		return []index.CompilerPassStatus{{Language: "kotlin", Running: running.Load()}}
	}
	s.watchCompilerProgress()
	running.Store(true)
	time.Sleep(compilerProgressFloor / 2)
	running.Store(false)
	time.Sleep(2 * compilerProgressFloor)
	if calls != 0 || len(recorder.snapshot()) != 0 {
		t.Fatalf("a pass below the floor was reported: %d calls, %d notifications", calls, len(recorder.snapshot()))
	}
}

// A client that did not advertise support must not be sent progress.
func TestCompilerProgressIsSkippedWithoutClientSupport(t *testing.T) {
	s, recorder := diagnosticServer(t, map[string]any{})
	calls := 0
	s.clientCall = func(context.Context, string, any, any) error { calls++; return nil }
	s.compilerStatusSource = func() []index.CompilerPassStatus {
		return []index.CompilerPassStatus{{Language: "kotlin", Running: true}}
	}
	s.watchCompilerProgress()
	time.Sleep(time.Second)
	if calls != 0 || len(recorder.snapshot()) != 0 {
		t.Fatalf("reported progress to a client that advertised none: %d calls, %d notifications", calls, len(recorder.snapshot()))
	}
}
