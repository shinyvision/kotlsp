package lsp

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func extractedSource(t *testing.T, source, selected, kind string) (string, bool) {
	t.Helper()
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(s.Close)
	uri := protocol.URI("file:///workspace/Extract.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	start := strings.Index(source, selected)
	if start < 0 {
		t.Fatalf("no %q", selected)
	}
	for _, action := range s.extractActions(uri, doc.Range(start, start+len(selected)), doc, selected) {
		if string(action.Kind) != kind {
			continue
		}
		edited := applyTextEdits(t, doc, action.Edit.Changes[uri])
		if parsed := analysis.Parse(context.Background(), textdoc.NewDocument(uri, "kotlin", 2, edited)); len(parsed.Diagnostics) != 0 {
			t.Fatalf("%s produced invalid source:\n%s\n%#v", kind, edited, parsed.Diagnostics)
		}
		return edited, true
	}
	return "", false
}

// The declaration goes before the statement the selection belongs to, in the
// innermost block around it: never into the previous lambda, never between
// the links of a chain, never among the branches of a `when`.
func TestExtractVariablePlacesTheDeclarationBeforeItsStatement(t *testing.T) {
	for _, c := range []struct{ label, source, selected, want string }{
		{"continued chain",
			"fun f(xs: List<Int>): List<Int> {\n    return xs\n        .filter { it > 0 }\n        .map { it * limit(3) }\n}\nfun limit(x: Int) = x\n",
			"limit(3)",
			"fun f(xs: List<Int>): List<Int> {\n    return xs\n        .filter { it > 0 }\n        .map {\n            val extractedValue = limit(3)\n            it * extractedValue }\n}\nfun limit(x: Int) = x\n"},
		{"after a lambda block",
			"fun f(xs: List<Int>): Int {\n    xs.forEach {\n        println(it)\n    }\n    return xs.size + 1\n}\n",
			"xs.size + 1",
			"fun f(xs: List<Int>): Int {\n    xs.forEach {\n        println(it)\n    }\n    val extractedValue = xs.size + 1\n    return extractedValue\n}\n"},
		{"inside a when branch",
			"fun f(x: Int): String {\n    val s = when (x) {\n        1 -> \"one\".uppercase()\n        else -> \"many\"\n    }\n    return s\n}\n",
			"\"one\".uppercase()",
			"fun f(x: Int): String {\n    val extractedValue = \"one\".uppercase()\n    val s = when (x) {\n        1 -> extractedValue\n        else -> \"many\"\n    }\n    return s\n}\n"},
	} {
		got, ok := extractedSource(t, c.source, c.selected, "refactor.extract.variable")
		if !ok {
			t.Errorf("%s: extract variable not offered", c.label)
			continue
		}
		if got != c.want {
			t.Errorf("%s:\n%s\nwant:\n%s", c.label, got, c.want)
		}
	}
}

func TestExtractConstantUsesTheExistingCompanion(t *testing.T) {
	source := "class Limits {\n    companion object {\n        const val MAX = 10\n    }\n\n    fun f(): Int {\n        return 42\n    }\n}\n"
	got, ok := extractedSource(t, source, "42", "refactor.extract.constant")
	if !ok {
		t.Fatal("extract constant not offered")
	}
	if strings.Count(got, "companion object") != 1 || !strings.Contains(got, "private const val EXTRACTED_CONSTANT: Int = 42") {
		t.Fatalf("constant not placed in the existing companion:\n%s", got)
	}
}
