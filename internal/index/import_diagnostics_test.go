package index

import (
	"context"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func TestUnusedImportDiagnosticUsesDestructiveEditConfidencePolicy(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: "file:///workspace/library/Foo.kt", LanguageID: "kotlin", Version: 1,
		Text: "package library\n\nclass Foo\n",
	})
	uri := protocol.URI("file:///workspace/app/Use.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: uri, LanguageID: "kotlin", Version: 1,
		Text: "package app\n\nimport library.Foo\n\nfun use() = unresolvedReceiver.value\n",
	})
	idx.markReady()
	for _, diagnostic := range idx.Diagnostics(uri) {
		if diagnostic.Code == "unused-import" {
			t.Fatalf("uncertain semantic binding produced a removal hint: %#v", diagnostic)
		}
	}
}

func TestUnusedImportDiagnosticStillReportsWhenBindingIsComplete(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: "file:///workspace/library/Foo.kt", LanguageID: "kotlin", Version: 1,
		Text: "package library\n\nclass Foo\n",
	})
	uri := protocol.URI("file:///workspace/app/Use.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: uri, LanguageID: "kotlin", Version: 1,
		Text: "package app\n\nimport library.Foo\n\nfun use(): Int = 1\n",
	})
	idx.markReady()
	found := false
	for _, diagnostic := range idx.Diagnostics(uri) {
		found = found || diagnostic.Code == "unused-import"
	}
	if !found {
		t.Fatal("complete unused class import was not reported")
	}
}
