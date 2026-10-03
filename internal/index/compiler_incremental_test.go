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

// An incremental pass recompiles only the edited file when the edit changes
// nothing another file can see. An inferred return type is something another
// file sees: changing the body that infers it must recompile its users.
func TestIncrementalCompilerPassFollowsInferredTypes(t *testing.T) {
	requireCompilerBackedTest(t)
	source := t.TempDir()
	write := func(relative, text string) {
		path := filepath.Join(source, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("src/main/kotlin/demo/B.kt", "package demo\n\nfun value() = 1\n\nfun helper(): Int {\n    return 1\n}\n")
	write("src/main/kotlin/demo/A.kt", "package demo\n\nval s: String = value()\n")
	idx, root := startedFixtureIndexFrom(t, source)
	a, b := fixtureFile(root, "src/main/kotlin/demo/A.kt"), fixtureFile(root, "src/main/kotlin/demo/B.kt")
	read := func(uri protocol.URI) string {
		path, _ := filepath.Abs(filepath.Join(root, strings.TrimPrefix(string(uri), "file://"+root+"/")))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	ctx := context.Background()
	idx.Open(ctx, protocol.TextDocumentItem{URI: a, LanguageID: "kotlin", Version: 1, Text: read(a)})
	idx.Open(ctx, protocol.TextDocumentItem{URI: b, LanguageID: "kotlin", Version: 1, Text: read(b)})
	mismatches := func() int {
		idx.mu.RLock()
		defer idx.mu.RUnlock()
		count := 0
		for _, diagnostic := range idx.compilerDiagnostics[a] {
			if strings.Contains(diagnostic.Message, "mismatch") || strings.Contains(diagnostic.Message, "Initializer type") {
				count++
			}
		}
		return count
	}
	pass := func() {
		t.Helper()
		idx.ScheduleCompilerDiagnostics(ctx)
		if !waitForCompilerPass(t, idx, 90*time.Second) {
			t.Fatal("no compiler pass")
		}
	}
	version := 1
	change := func(text string) {
		t.Helper()
		version++
		if _, err := idx.Change(ctx, protocol.DidChangeTextDocumentParams{
			TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: b, Version: version},
			ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: text}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	pass()
	if mismatches() != 1 {
		t.Fatalf("A's String = Int mismatch was not reported: %v", idx.compilerDiagnostics[a])
	}
	// A body nobody else sees: A's finding stands.
	change("package demo\n\nfun value() = 1\n\nfun helper(): Int {\n    return 2\n}\n")
	pass()
	if mismatches() != 1 {
		t.Fatalf("a body-only edit in B lost A's finding: %v", idx.compilerDiagnostics[a])
	}
	// value()'s inferred type becomes String: A now compiles.
	change("package demo\n\nfun value() = \"x\"\n\nfun helper(): Int {\n    return 2\n}\n")
	pass()
	if mismatches() != 0 {
		t.Fatalf("A kept a finding its fixed inferred type removed: %v", idx.compilerDiagnostics[a])
	}
}
