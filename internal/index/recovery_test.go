package index

import (
	"context"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
)

func TestBrokenIncrementalEditDoesNotCopyOldDeclarations(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///Recovery.kt")
	old := idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: uri, LanguageID: "kotlin", Version: 1, Text: "class Before {}",
	})
	if old == nil || len(old.Symbols) == 0 {
		t.Fatal("valid fixture declaration was not indexed")
	}
	oldID := analysis.SymbolID(uri, 0, analysis.KindClass, "Before")
	if _, ok := idx.Symbol(oldID); !ok {
		t.Fatal("valid fixture declaration was not published")
	}
	if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
		TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: 2},
		ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: "class "}},
	}); err != nil {
		t.Fatal(err)
	}
	if symbol, ok := idx.Symbol(oldID); ok {
		t.Fatalf("old declaration was copied into the broken snapshot: %#v", symbol)
	}
}
