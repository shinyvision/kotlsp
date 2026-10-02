package index

import (
	"context"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A member name declared nowhere in a complete index is reported at once,
// without waiting for the compiler; one declared anywhere is left to it.
func TestUnknownMemberNameIsReportedImmediately(t *testing.T) {
	source := "package app\nclass Repo { fun find(id: Int) = id }\nfun f(repo: Repo) {\n    repo.doesNotExist()\n    repo.find(1)\n    val n = 1 + 2\n}\n"
	idx, uri := ruleIndex(t, source)
	stdlib := protocol.URI("file:///workspace/stdlib/Collections.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: stdlib, LanguageID: "kotlin", Version: 1, Text: "package kotlin.collections\nfun <T, R> Iterable<T>.map(transform: (T) -> R): List<R> = TODO()\n"})
	var unresolved []string
	for _, diagnostic := range idx.DiagnosticsContext(context.Background(), uri) {
		if diagnostic.Code == "UNRESOLVED_REFERENCE" {
			unresolved = append(unresolved, diagnostic.Message)
		}
	}
	if len(unresolved) != 1 || unresolved[0] != "Unresolved reference 'doesNotExist'." {
		t.Fatalf("got %q, want only doesNotExist", unresolved)
	}
}
