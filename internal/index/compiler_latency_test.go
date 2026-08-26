package index

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// TestCompilerRoundTripLatency measures the interval an author actually feels:
// from an edit to the compiler's findings being available again. It runs only
// when asked, because it spends seconds per iteration compiling for real.
//
//	KOTLSP_LATENCY=1 go test ./internal/index/ -run CompilerRoundTripLatency -v
func TestCompilerRoundTripLatency(t *testing.T) {
	if os.Getenv("KOTLSP_LATENCY") == "" {
		t.Skip("set KOTLSP_LATENCY=1 to measure")
	}
	idx, root := startedFixtureIndex(t)
	uri := fixtureFile(root, "src/main/kotlin/fixture/Errors.kt")
	path, _ := filepath.Abs(filepath.Join(root, "src/main/kotlin/fixture/Errors.kt"))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: uri, LanguageID: "kotlin", Version: 1, Text: string(original),
	})
	if len(waitForCompilerDiagnostics(t, idx, uri, 1)) == 0 {
		t.Skip("no Kotlin compiler available in this environment")
	}

	durations := make([]time.Duration, 0, 5)
	for run := 0; run < 5; run++ {
		// An edit on a line no diagnostic sits on: retained findings survive it,
		// so this measures the pass, not the retention.
		appended := string(original) + "\n// touch " + time.Duration(run).String() + "\n"
		start := time.Now()
		if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
			TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: 2 + run},
			ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: appended}},
		}); err != nil {
			t.Fatal(err)
		}
		// Wait for the Kotlin pass specifically: javac finishes in a fraction
		// of the time and would otherwise stop the clock early.
		passes := idx.CompilerPasses("kotlin")
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) && idx.CompilerPasses("kotlin") == passes {
			time.Sleep(10 * time.Millisecond)
		}
		durations = append(durations, time.Since(start))
	}
	sort.Slice(durations, func(a, b int) bool { return durations[a] < durations[b] })
	for _, status := range idx.CompilerStatus() {
		t.Logf("  %s: passes=%d lastPass=%v hosted=%v", status.Language, status.Passes,
			status.LastDuration.Round(time.Millisecond), status.Hosted)
	}
	t.Logf("edit -> compiler findings available (%d runs)", len(durations))
	t.Logf("  best   %v", durations[0].Round(time.Millisecond))
	t.Logf("  median %v", durations[len(durations)/2].Round(time.Millisecond))
	t.Logf("  worst  %v", durations[len(durations)-1].Round(time.Millisecond))
}
