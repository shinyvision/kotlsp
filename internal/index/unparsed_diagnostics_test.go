package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// Where the parser could not read the source, a recovered identifier is not
// evidence that anything is unresolved. Reporting it turns one syntax error
// into a cascade of false claims about correct code.
func TestUnresolvedReferencesAreNotReportedInsideSyntaxErrors(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Broken.kt")
	// A genuine syntax error, not a grammar gap.
	source := "package demo\n\nclass Broken {\n    fun run() {\n        val value = ????\n        println(value)\n    }\n}\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})

	found := idx.Diagnostics(uri)
	syntax := 0
	for _, diagnostic := range found {
		if diagnostic.Code == "syntax" {
			syntax++
		}
	}
	if syntax == 0 {
		t.Fatalf("the real syntax error was not reported: %#v", found)
	}
	for _, diagnostic := range found {
		if diagnostic.Code != "UNRESOLVED_REFERENCE" {
			continue
		}
		for _, other := range found {
			if other.Code == "syntax" && rangesOverlap(other.Range, diagnostic.Range) {
				t.Fatalf("unresolved reference %q reported inside a syntax error", diagnostic.Message)
			}
		}
	}
}

// The reported regression, end to end through the index.
func TestAnnotationWithEmptyArrayDefaultsHasNoDiagnostics(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/PasswordsMatch.kt")
	source := "package demo\n\nimport kotlin.reflect.KClass\n\n@Target(AnnotationTarget.CLASS)\n@Retention(AnnotationRetention.RUNTIME)\nannotation class PasswordsMatch(\n    val message: String = \"Passwords do not match\",\n    val groups: Array<KClass<*>> = [],\n    val payload: Array<KClass<*>> = [],\n)\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})

	for _, diagnostic := range idx.Diagnostics(uri) {
		if strings.Contains(diagnostic.Message, "PasswordsMatch") ||
			strings.Contains(diagnostic.Message, "groups") ||
			strings.Contains(diagnostic.Message, "payload") {
			t.Fatalf("a declaration in valid Kotlin was reported: %s (%v)", diagnostic.Message, diagnostic.Code)
		}
		if diagnostic.Code == "syntax" {
			t.Fatalf("valid Kotlin reported a syntax error at %v", diagnostic.Range)
		}
	}
	if symbol, _, ok := idx.SymbolAt(uri, protocol.Position{Line: 6, Character: 18}); !ok || symbol.Name != "PasswordsMatch" {
		t.Fatal("the annotation class declaration is not in the index")
	}
}
