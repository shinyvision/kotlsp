package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// `name` in `@Ann(name = value)` is an attribute of the annotation, not a free
// identifier. The annotation is recorded as a type rather than a call, so
// resolving it through the call path finds nothing and it was reported as an
// unresolved reference.
func TestAnnotationAttributeLabelResolves(t *testing.T) {
	for _, fixture := range []struct{ label, declaration, declURI, usage string }{
		{
			label:       "kotlin annotation",
			declaration: "package demo\n\nannotation class Restrict(val validatedBy: Array<String> = [], val message: String = \"\")\n",
			declURI:     "file:///workspace/Restrict.kt",
			usage:       "package demo\n\n@Restrict(validatedBy = [\"checker\"], message = \"nope\")\nclass Guarded\n",
		},
		{
			label:       "java annotation",
			declaration: "package demo;\n\npublic @interface Restrict {\n    String[] validatedBy();\n    String message();\n}\n",
			declURI:     "file:///workspace/Restrict.java",
			usage:       "package demo\n\n@Restrict(validatedBy = [\"checker\"], message = \"nope\")\nclass Guarded\n",
		},
	} {
		idx := New(nil)
		language := "kotlin"
		if strings.HasSuffix(fixture.declURI, ".java") {
			language = "java"
		}
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: protocol.URI(fixture.declURI), LanguageID: language, Version: 1, Text: fixture.declaration})
		usageURI := protocol.URI("file:///workspace/Guarded.kt")
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: usageURI, LanguageID: "kotlin", Version: 1, Text: fixture.usage})

		for _, diagnostic := range idx.Diagnostics(usageURI) {
			if diagnostic.Code == "unresolved-reference" {
				t.Fatalf("%s: %s", fixture.label, diagnostic.Message)
			}
		}
		// The attribute should also be navigable, not merely unreported.
		at := strings.Index(fixture.usage, "validatedBy") + 2
		document := idx.docs[usageURI]
		if document == nil {
			t.Fatalf("%s: usage document missing", fixture.label)
		}
		if found := idx.Definitions(usageURI, document.Position(at)); len(found) == 0 {
			t.Fatalf("%s: the annotation attribute does not resolve to its declaration", fixture.label)
		}
		idx.Close()
	}
}
