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
	if os.Getenv("KOTLSP_EXPLAIN_BINARY_ONLY") != "" {
		// The state between the binary phases and source attachment.
		libraryArchiveFilter = func(archive sourceArchive) bool {
			return archive.binary || archive.jdk && !strings.HasSuffix(archive.path, ".zip") || strings.Contains(archive.path, "kotlin-stdlib")
		}
		defer func() { libraryArchiveFilter = nil }()
	}
	if os.Getenv("KOTLSP_EXPLAIN_AT_READY") != "" {
		// Hold the scan immediately after the complete declaration/source
		// barrier flips Ready.
		release := make(chan struct{})
		scanDeclarationsCompleteHook = func() { <-release }
		defer func() { scanDeclarationsCompleteHook = nil }()
		defer close(release)
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
	if fqn := os.Getenv("KOTLSP_EXPLAIN_TYPE"); fqn != "" {
		for _, id := range idx.byFQN[fqn] {
			symbol := idx.symbols[id]
			fmt.Printf("type %s id=%s kind=%v uri=%s supertypes=%v file=%v\n", fqn, id, symbol.Kind, symbol.URI, symbol.Supertypes, idx.files[symbol.URI] != nil)
			for _, member := range idx.typeMembersLocked(*symbol) {
				fmt.Printf("   member %s kind=%v container=%s\n", member.Name, member.Kind, member.ContainerID)
			}
		}
		for _, id := range idx.byName[os.Getenv("KOTLSP_EXPLAIN_NAME")] {
			symbol := idx.symbols[id]
			fmt.Printf("candidate %s container=%s uri=%s synthetic=%v tparams=%v params=%+v\n", symbol.FQN, symbol.ContainerID, symbol.URI, symbol.Synthetic, symbol.TypeParameters, symbol.Parameters)
		}
	}
	c := newUnresolvedNameContext(file)
	if fqn := os.Getenv("KOTLSP_EXPLAIN_TYPE"); fqn != "" {
		c.prepare(idx)
		for _, id := range idx.byFQN[fqn] {
			h := idx.completeHierarchyLocked(c, *idx.symbols[id])
			fmt.Printf("hierarchy of %s: complete=%v reason=%q\n", id, h.complete, h.reason)
			for _, t := range h.types {
				fmt.Printf("   %s %s\n", t.ID, t.FQN)
			}
		}
		for _, ref := range file.References {
			if ref.Name == os.Getenv("KOTLSP_EXPLAIN_NAME") && ref.Qualifier == "" {
				scope := idx.scopeAtLocked(c, ref)
				fmt.Printf("scope at %d: complete=%v types=%d reason=%q\n", ref.StartByte, scope.complete, len(scope.types), scope.reason)
				for id := range scope.types {
					fmt.Printf("   in scope: %s %s\n", id, idx.symbols[id].FQN)
				}
				for _, l := range c.lambdas {
					if l.start < ref.StartByte && ref.StartByte < l.end {
						fmt.Printf("   lambda %d-%d known=%v receivers=%v reason=%q\n", l.start, l.end, l.known, l.receivers, l.reason)
					}
				}
				break
			}
		}
	}
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
