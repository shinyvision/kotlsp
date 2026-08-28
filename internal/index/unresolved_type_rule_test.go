package index

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func fastFindings(idx *Index, uri protocol.URI, code string) []protocol.Diagnostic {
	out := make([]protocol.Diagnostic, 0, 2)
	for _, diagnostic := range idx.Diagnostics(uri) {
		if value, _ := diagnostic.Code.(string); value == code && diagnostic.Source == "kotlsp" {
			out = append(out, diagnostic)
		}
	}
	return out
}

// A type named where it is not in scope cannot compile. This is the shape of a
// forgotten import, the most common real error, and the index can prove it
// without waiting seconds for a compiler.
func TestUnresolvedTypeIsPredictedBeforeTheCompilerRuns(t *testing.T) {
	if _, err := os.Stat(filepath.Join("testdata", "project")); err != nil {
		t.Skip("fixture missing")
	}
	idx, root := startedFixtureIndex(t)

	missing := fastFindings(idx, fixtureFile(root, "src/main/kotlin/fixture/MissingImport.kt"), "UNRESOLVED_REFERENCE")
	if len(missing) != 1 {
		t.Fatalf("expected one prediction for the unimported type, got %d", len(missing))
	}
	if !strings.Contains(missing[0].Message, "Reachable") {
		t.Fatalf("prediction did not name the type: %q", missing[0].Message)
	}
	data, _ := missing[0].Data.(map[string]any)
	candidates, _ := data["candidates"].([]string)
	found := false
	for _, candidate := range candidates {
		if candidate == "other.Reachable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the prediction carries no importable candidate: %#v", data)
	}

	// The same type, imported: nothing may be reported.
	if imported := fastFindings(idx, fixtureFile(root, "src/main/kotlin/fixture/Imported.kt"), "UNRESOLVED_REFERENCE"); len(imported) != 0 {
		t.Fatalf("a correctly imported type was reported: %#v", imported)
	}
	// And nothing anywhere in the clean sources.
	if clean := fastFindings(idx, fixtureFile(root, "src/main/kotlin/fixture/Clean.kt"), "UNRESOLVED_REFERENCE"); len(clean) != 0 {
		t.Fatalf("clean source was reported: %#v", clean)
	}
}

// A prediction carries the compiler's own code and wording. When the compiler
// confirms it, nothing on screen may change: the prediction stands and the
// compiler's identical copy is dropped. Only if the wording has drifted does
// the compiler's finding replace it.
func TestPredictionStandsWhenTheCompilerConfirmsIt(t *testing.T) {
	if _, err := os.Stat(filepath.Join("testdata", "project")); err != nil {
		t.Skip("fixture missing")
	}
	idx, root := startedFixtureIndex(t)
	uri := fixtureFile(root, "src/main/kotlin/fixture/MissingImport.kt")
	before := fastFindings(idx, uri, "UNRESOLVED_REFERENCE")
	if len(before) != 1 {
		t.Fatalf("expected one prediction to begin with, got %d", len(before))
	}
	line := before[0].Range.Start.Line
	confirming := protocol.Diagnostic{
		Range:    protocol.Range{Start: protocol.Position{Line: line}, End: protocol.Position{Line: line, Character: 9}},
		Severity: 1, Source: "kotlinc", Code: "UNRESOLVED_REFERENCE", Message: before[0].Message,
	}
	idx.mu.Lock()
	idx.compilerDiagnostics[uri] = []protocol.Diagnostic{confirming}
	idx.mu.Unlock()

	onLine := 0
	for _, diagnostic := range idx.Diagnostics(uri) {
		if diagnostic.Range.Start.Line == line {
			onLine++
			if diagnostic.Source != "kotlsp" {
				t.Fatalf("the compiler's identical copy was shown instead of the prediction: %#v", diagnostic)
			}
		}
	}
	if onLine != 1 {
		t.Fatalf("expected exactly one finding on the line, got %d", onLine)
	}

	// Drifted wording: the compiler is authoritative and its finding wins.
	drifted := confirming
	drifted.Message = "Unresolved reference 'Reachable' (some future wording)."
	idx.mu.Lock()
	idx.compilerDiagnostics[uri] = []protocol.Diagnostic{drifted}
	idx.mu.Unlock()
	if after := fastFindings(idx, uri, "UNRESOLVED_REFERENCE"); len(after) != 0 {
		t.Fatalf("the prediction survived beside a compiler finding with different wording: %#v", after)
	}
}

// Every rule abstains while the index is still building: a name that is merely
// not indexed yet is not an unknown name.
func TestPredictionsAbstainUntilIndexingFinishes(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	// A type that exists but is not imported: only the rule could report it,
	// and the rule must wait for the index to be ready.
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: "file:///workspace/other/Known.kt", LanguageID: "kotlin", Version: 1,
		Text: "package other\n\nclass Known\n",
	})
	uri := protocol.URI("file:///workspace/app/A.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: uri, LanguageID: "kotlin", Version: 1,
		Text: "package app\n\nfun use(value: Known): Int = 1\n",
	})
	if found := fastFindings(idx, uri, "UNRESOLVED_REFERENCE"); len(found) != 0 {
		t.Fatalf("a prediction was made before indexing finished: %#v", found)
	}
	idx.markReady()
	if found := fastFindings(idx, uri, "UNRESOLVED_REFERENCE"); len(found) != 1 {
		t.Fatalf("once ready the same file should yield one prediction, got %d", len(found))
	}
}

func TestUnresolvedTypeUncertaintyIsLocalizedToOwningScope(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{
			"unresolved supertype",
			"package app\nclass Broken : Missing() { val local: Known? = null }\nfun outside(value: Known) {}\n",
		},
		{
			"type parameter",
			"package app\nclass Box<Known> { val local: Known? = null }\nfun outside(value: Known) {}\n",
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			idx := New(nil)
			defer idx.Close()
			idx.Open(context.Background(), protocol.TextDocumentItem{
				URI: "file:///workspace/other/Known.kt", LanguageID: "kotlin", Version: 1,
				Text: "package other\nclass Known\n",
			})
			uri := protocol.URI("file:///workspace/app/Probe.kt")
			idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: fixture.source})
			idx.markReady()
			found := fastFindings(idx, uri, "UNRESOLVED_REFERENCE")
			if len(found) != 1 || found[0].Range.Start.Line != 2 {
				t.Fatalf("localized unresolved-type findings = %#v", found)
			}
		})
	}
}
