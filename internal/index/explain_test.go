package index

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

// TestExplainUnresolvedNames prints the scope engine's verdict and reason for
// every bare name in one file of a corpus, for investigating an abstention or
// a false positive on real code:
//
//	KOTLSP_CORPUS=~/Projects/x KOTLSP_EXPLAIN=src/main/kotlin/a/B.kt go test ./internal/index -run Explain -v
func TestExplainUnresolvedNames(t *testing.T) {
	root := requireCorpusTest(t)
	relative := os.Getenv("KOTLSP_EXPLAIN")
	if relative == "" {
		t.Skip("KOTLSP_EXPLAIN names the file to explain")
	}
	idx := New(nil)
	defer idx.Close()
	idx.Start(context.Background(), []protocol.URI{fileURI(root)})
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) && !idx.Progress().Ready {
		time.Sleep(200 * time.Millisecond)
	}
	uri := fileURI(root + "/" + relative)
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files[uri]
	if file == nil {
		t.Fatalf("%s is not indexed", uri)
	}
	c := newUnresolvedNameContext(file)
	for _, ref := range file.References {
		if ref.Qualifier != "" || ref.Role == analysis.RoleType || ref.Role == analysis.RoleImport || ref.ArgumentLabel {
			continue
		}
		if len(idx.resolveLocked(file, ref)) > 0 {
			continue
		}
		unresolved, reason := idx.unresolvedVerdictLocked(c, ref)
		fmt.Printf("L%d %-28s unresolved=%-5v %s\n", ref.Range.Start.Line+1, ref.Name, unresolved, strings.TrimSpace(reason))
	}
}
