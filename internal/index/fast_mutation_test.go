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

// copyTree duplicates a project so a test can damage it safely.
func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name := info.Name()
		if info.IsDir() && (name == ".git" || name == "build" || name == "bin" || name == ".gradle") {
			return filepath.SkipDir
		}
		relative, relErr := filepath.Rel(source, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copying the corpus: %v", err)
	}
}

// TestFastDiagnosticsSurviveImportRemoval is the soundness gate with teeth. A
// corpus where every import is already correct proves nothing: the rule never
// fires, and the assertion passes vacuously.
//
// So the corpus is damaged on purpose. Imports are stripped from a sample of
// files, which is exactly the error the rule predicts, and then every
// prediction must be confirmed by the compiler on the same line. A prediction
// the compiler does not share is a soundness bug.
//
//	KOTLSP_CORPUS=~/Projects/some-project go test ./internal/index/ -run ImportRemoval -v
func TestFastDiagnosticsSurviveImportRemoval(t *testing.T) {
	corpus := requireCorpusTest(t)
	root := t.TempDir()
	copyTree(t, corpus, root)

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
		t.Skip("no Kotlin file in the corpus has imports to remove")
	}
	t.Logf("stripped imports from %d files", len(damaged))

	idx := New(nil)
	defer idx.Close()
	idx.Start(context.Background(), []protocol.URI{fileURI(root)})
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) && !idx.Progress().Ready {
		time.Sleep(200 * time.Millisecond)
	}
	if !idx.Progress().Ready {
		t.Fatal("the corpus index never became ready")
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
	if !waitForCompilerPass(t, idx, 3*time.Minute) {
		t.Fatal("the compiler never finished a pass over the damaged corpus, so there is no oracle")
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
