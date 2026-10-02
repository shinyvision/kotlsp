package index

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// TestFastDiagnosticsSurviveImportRemoval is the soundness gate with teeth. A
// corpus where every import is already correct proves nothing: the rule never
// fires, and the assertion passes vacuously.
//
// So the fixture is damaged on purpose. Its imports are stripped, which is
// exactly the error the rule predicts, and then every prediction must be
// confirmed by the compiler on the same line. A prediction the compiler does
// not share is a soundness bug.
func TestFastDiagnosticsSurviveImportRemoval(t *testing.T) {
	requireCompilerBackedTest(t)
	root := fixtureProjectFrom(t, filepath.Join("testdata", "project"))

	// Strip imports from a sample, leaving the rest of the project intact so
	// the damage stays comprehensible.
	var damaged []string
	for _, path := range corpusFiles(root) {
		if !strings.HasSuffix(path, ".kt") || len(damaged) >= 4 {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		kept := make([]string, 0, len(lines))
		removed := 0
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "import ") {
				removed++
				kept = append(kept, "")
				continue
			}
			kept = append(kept, line)
		}
		if removed == 0 {
			continue
		}
		if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
			continue
		}
		damaged = append(damaged, path)
	}
	if len(damaged) == 0 {
		t.Fatal("no Kotlin file in the fixture has imports to remove")
	}
	t.Logf("stripped imports from %d files", len(damaged))

	idx := New(nil)
	defer idx.Close()
	idx.Start(context.Background(), []protocol.URI{fileURI(root)})
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && !idx.Progress().Ready {
		time.Sleep(10 * time.Millisecond)
	}
	if !idx.Progress().Ready {
		t.Fatal("the fixture index never became ready")
	}

	predictions := 0
	for _, path := range damaged {
		predictions += len(fastFindings(idx, fileURI(path), "UNRESOLVED_REFERENCE"))
	}
	if predictions == 0 {
		t.Fatal("stripping every import produced no prediction, so this proves nothing")
	}
	t.Logf("predictions before validation: %d", predictions)

	// Now let the compiler speak and check every prediction against it. The
	// merge hides predictions the compiler has confirmed, so soundness is
	// checked against the raw rule output rather than the merged result.
	idx.ScheduleCompilerDiagnostics(context.Background())
	if !waitForCompilerPass(t, idx, 90*time.Second) {
		t.Fatal("the compiler never finished a pass over the damaged fixture, so there is no oracle")
	}

	// The same exact-match assertion the fixture gate uses, so every source
	// of predictions is checked, not only the registered rules.
	checked := 0
	for _, path := range damaged {
		checked += len(assertFastDiagnosticsAreSound(t, idx, fileURI(path)))
	}
	t.Logf("checked %d predictions against the compiler, exact code and message", checked)
	if checked == 0 {
		t.Fatal("no prediction survived to be checked, so this proves nothing")
	}
}
