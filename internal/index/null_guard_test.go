package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// Guarding a nullable and then using it is the ordinary shape of Kotlin code.
// Only a condition that was nothing but a null check was recognised, so the
// short-circuit forms resolved none of their members.
func TestNullGuardedMembersResolve(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	defer idx.Close()
	idx.Open(ctx, protocol.TextDocumentItem{
		URI: "file:///workspace/form/Form.kt", LanguageID: "kotlin", Version: 1,
		Text: "package form\n\ninterface Form {\n    val password: String\n    val passwordRepeat: String\n}\n",
	})

	body := func(statements string) string {
		return "package app\n\nimport form.Form\n\nclass Use {\n    fun run(form: Form?, other: Form?): Boolean {\n" + statements + "\n    }\n}\n"
	}
	for _, fixture := range []struct {
		label   string
		source  string
		resolve bool
	}{
		{"disjunctive null guard", body("        if (form == null || form.password == \"\") return true\n        return false"), true},
		{"conjunctive non-null guard", body("        if (form != null && form.password == \"\") return true\n        return false"), true},
		{"guard in a returned expression", body("        return form != null && form.password == \"\""), true},
		{"two guards in one chain", body("        if (form == null || other == null || form.password == \"\") return true\n        return false"), true},
		{"then branch of a conjunctive guard", body("        if (form != null && other != null) { return form.password == \"\" }\n        return false"), true},
		{"else branch of a disjunctive guard", body("        if (form == null || other == null) { return false } else { return form.password == \"\" }"), true},
		{"parenthesised guard", body("        if ((form == null) || form.password == \"\") return true\n        return false"), true},

		// A later `||` restores reachability when the guard was false, so the
		// fact does not carry past it.
		{"fact does not survive a later or", body("        return form != null && other == null || form.password == \"\""), false},
		// Not guarded at all: Kotlin rejects this, and so must navigation.
		{"unguarded nullable", body("        return form.password == \"\""), false},
	} {
		uri := protocol.URI("file:///workspace/app/Use.kt")
		idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 2, Text: fixture.source})
		document := textdoc.NewDocument(uri, "kotlin", 2, fixture.source)
		at := strings.LastIndex(fixture.source, "form.password") + len("form.")
		found := idx.Definitions(uri, document.Position(at+1))
		if fixture.resolve && len(found) == 0 {
			t.Fatalf("%s: form.password did not resolve", fixture.label)
		}
		if !fixture.resolve && len(found) != 0 {
			t.Fatalf("%s: form.password resolved although the guard does not reach it", fixture.label)
		}
		if fixture.resolve && found[0].Name != "password" {
			t.Fatalf("%s: resolved to %q", fixture.label, found[0].Name)
		}
	}
}
