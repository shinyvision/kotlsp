package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// Navigation must obey the language's scoping rules. Jumping to a declaration
// the file cannot name hides a genuine compile error behind a working jump.
func TestSimpleNamesResolveOnlyWhenInScope(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	defer idx.Close()
	idx.Open(ctx, protocol.TextDocumentItem{
		URI: "file:///workspace/lib/Marker.kt", LanguageID: "kotlin", Version: 1,
		Text: "package lib\n\ninterface Marker\n",
	})
	idx.Open(ctx, protocol.TextDocumentItem{
		URI: "file:///workspace/app/Neighbour.kt", LanguageID: "kotlin", Version: 1,
		Text: "package app\n\ninterface Neighbour\n",
	})
	// A bare index has no standard library, so the default-import case needs one.
	idx.Open(ctx, protocol.TextDocumentItem{
		URI: "file:///workspace/stdlib/Text.kt", LanguageID: "kotlin", Version: 1,
		Text: "package kotlin\n\nclass DefaultImported\n",
	})

	for _, fixture := range []struct {
		label   string
		source  string
		name    string
		resolve bool
	}{
		{"not imported", "package app\n\nclass A : Marker\n", "Marker", false},
		{"explicitly imported", "package app\n\nimport lib.Marker\n\nclass A : Marker\n", "Marker", true},
		{"wildcard imported", "package app\n\nimport lib.*\n\nclass A : Marker\n", "Marker", true},
		{"same package", "package app\n\nclass A : Neighbour\n", "Neighbour", true},
		{"default imported", "package app\n\nclass A { val v: DefaultImported? = null }\n", "DefaultImported", true},
	} {
		uri := protocol.URI("file:///workspace/app/Probe.kt")
		idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 2, Text: fixture.source})
		document := textdoc.NewDocument(uri, "kotlin", 2, fixture.source)
		at := strings.LastIndex(fixture.source, fixture.name)
		found := idx.Definitions(uri, document.Position(at+1))
		if fixture.resolve && len(found) == 0 {
			t.Fatalf("%s: %q is in scope but did not resolve", fixture.label, fixture.name)
		}
		if !fixture.resolve && len(found) != 0 {
			t.Fatalf("%s: %q is not in scope but resolved to %s", fixture.label, fixture.name, found[0].URI)
		}
	}
}

// The owner of an annotation argument is the annotation whose parentheses are
// still open. A class's own parameter list kept the running depth positive, so
// every position inside the declaration looked like an annotation argument and
// completion offered only that annotation's attributes.
func TestAnnotationAttributeOwnerStopsAtTheClosingParen(t *testing.T) {
	source := "@Constraint(validatedBy = [V::class])\nannotation class A(\n    val payload: Array<String> = [],\n)\n"
	inside := strings.Index(source, "validatedBy") + 3
	if owner := AnnotationAttributeOwner(source, inside); owner != "Constraint" {
		t.Fatalf("inside the annotation the owner is Constraint, got %q", owner)
	}
	after := strings.Index(source, "Array<String>") + 3
	if owner := AnnotationAttributeOwner(source, after); owner != "" {
		t.Fatalf("past the annotation's closing paren there is no owner, got %q", owner)
	}
}

// A use-site target names where an annotation applies, not what it is.
func TestAnnotationAttributeOwnerIgnoresUseSiteTargets(t *testing.T) {
	source := "class A(\n    @field:Column(nullable = true)\n    var token: String? = null,\n)\n"
	at := strings.Index(source, "nullable") + 3
	if owner := AnnotationAttributeOwner(source, at); owner != "Column" {
		t.Fatalf("owner of @field:Column is Column, got %q", owner)
	}
}
