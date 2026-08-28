package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

func symbolIDNamed(file *analysis.ParsedFile, name string, kind analysis.SymbolKind) string {
	for _, symbol := range file.Symbols {
		if symbol.Name == name && symbol.Kind == kind {
			return symbol.ID
		}
	}
	return ""
}

func TestBodyEditPreservesStableSymbolIDsAndReferenceBuckets(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Stable.kt")
	source := "package gap\nclass Stable { fun value(input: Int): Int = input }\nfun use(s: Stable) = s.value(1)\n"
	before := idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	classID := symbolIDNamed(before, "Stable", analysis.KindClass)
	methodID := symbolIDNamed(before, "value", analysis.KindMethod)
	if classID == "" || methodID == "" {
		t.Fatalf("missing initial declarations: %#v", before.Symbols)
	}
	changed := "// body-only offset shift\n" + source
	after, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
		TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: 2},
		ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: changed}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := symbolIDNamed(after, "Stable", analysis.KindClass); got != classID {
		t.Fatalf("class ID changed across offset-only edit: %q -> %q", classID, got)
	}
	if got := symbolIDNamed(after, "value", analysis.KindMethod); got != methodID {
		t.Fatalf("method ID changed across offset-only edit: %q -> %q", methodID, got)
	}
	count := 0
	for _, id := range idx.byName["value"] {
		if id == methodID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("value bucket contains stable ID %d times: %#v", count, idx.byName["value"])
	}
	wantStart := strings.LastIndex(changed, "value(1)")
	found := false
	for _, reference := range idx.refsByName["value"] {
		if reference.URI == uri && reference.StartByte == wantStart {
			found = true
		}
	}
	if !found {
		t.Fatalf("reference bucket did not update shifted range: %#v", idx.refsByName["value"])
	}
}

func TestDeclarationShapeChangeInvalidatesExternalResolvedReferences(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	declarationURI := protocol.URI("file:///workspace/Api.kt")
	useURI := protocol.URI("file:///workspace/Use.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: declarationURI, LanguageID: "kotlin", Version: 1, Text: "package gap\nfun consume(value: Int): Int = value\n"})
	idx.markReady()
	use := idx.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: "package gap\nfun use() = consume(1)\n"})
	resolved := ""
	for _, reference := range use.References {
		if reference.Name == "consume" {
			resolved = reference.ResolvedID
		}
	}
	if resolved == "" {
		t.Fatal("fixture call did not resolve before declaration edit")
	}
	_, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
		TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: declarationURI, Version: 2},
		ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: "package gap\nfun consume(value: String): String = value\n"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range idx.files[useURI].References {
		if reference.Name == "consume" && reference.ResolvedID != "" {
			t.Fatalf("stale target survived signature change: %#v", reference)
		}
	}
	if len(idx.unresolvedRefsByName["consume"]) == 0 {
		t.Fatal("invalidated call was not moved to the unresolved bucket")
	}
}
