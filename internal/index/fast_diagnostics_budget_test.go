package index

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// The fast layer runs on the foreground diagnostic path, so it answers within
// the interaction budget or it is not fast at all. This bounds it well below
// the 100ms the request as a whole is held to.
func TestFastDiagnosticsStayWithinTheInteractionBudget(t *testing.T) {
	// A ready index: an abstaining one would measure nothing.
	idx, root := startedFixtureIndex(t)
	var source strings.Builder
	source.WriteString("package app\n\n")
	for n := 0; n < 400; n++ {
		source.WriteString("class Type")
		source.WriteString(strings.Repeat("X", 1+n%5))
		source.WriteString(itoa(n))
		source.WriteString(" {\n    val value: Int = ")
		source.WriteString(itoa(n))
		source.WriteString("\n    fun read(): Int = value\n}\n\n")
	}
	uri := fixtureFile(root, "src/main/kotlin/fixture/Big.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: uri, LanguageID: "kotlin", Version: 1, Text: source.String(),
	})

	idx.mu.RLock()
	file := idx.files[uri]
	idx.mu.RUnlock()
	if file == nil {
		t.Fatal("the document was not indexed")
	}
	if !idx.fastDiagnosticsEligibleLocked(file) {
		t.Fatal("the rules abstained, so this measures nothing")
	}

	best := time.Hour
	for run := 0; run < 5; run++ {
		start := time.Now()
		idx.mu.RLock()
		_ = idx.fastDiagnosticsLocked(file)
		idx.mu.RUnlock()
		if elapsed := time.Since(start); elapsed < best {
			best = elapsed
		}
	}
	const budget = 25 * time.Millisecond
	t.Logf("fast diagnostics over %d declarations: %v", 400, best.Round(time.Microsecond))
	if best > budget {
		t.Fatalf("the fast layer took %v on one file, budget is %v", best, budget)
	}
}
