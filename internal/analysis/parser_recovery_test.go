package analysis

import (
	"context"
	"strings"
	"testing"

	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// `every { repo.find(1) } returns 5` calls the infix function `returns` on the
// stub scope. Read as a bare name it was reported unresolved on every mockk
// stubbing line.
func TestInfixCallIsACallOnItsLeftOperand(t *testing.T) {
	source := "package p\nfun t() {\n    every { repo.find(1) } returns 5\n    val pair = 1 to 2\n}\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///p/P.kt", "kotlin", 1, source))
	want := map[string]string{"returns": "every { repo.find(1) }", "to": "1"}
	for _, reference := range file.References {
		qualifier, ok := want[reference.Name]
		if !ok {
			continue
		}
		delete(want, reference.Name)
		if reference.Role != RoleCall || reference.Qualifier != qualifier || reference.Arity != 1 || len(reference.Arguments) != 1 {
			t.Errorf("%s: role=%d qualifier=%q arity=%d arguments=%d, want a one-argument call on %q", reference.Name, reference.Role, reference.Qualifier, reference.Arity, len(reference.Arguments), qualifier)
		}
	}
	for name := range want {
		t.Errorf("no reference for infix call %s", name)
	}
}

// `val fallback = suspend { ... }` is a call of the standard library's
// suspend function. The grammar knows suspend only as a modifier, and the
// syntax error it reported swallowed every declaration after it.
func TestSuspendLambdaKeepsLaterDeclarations(t *testing.T) {
	source := "package p\nobject Helper {\n    val fallback = suspend { 1 }\n    fun after(): Int = 2\n    suspend fun real(): Int = 3\n}\nfun top() = 4\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///p/P.kt", "kotlin", 1, source))
	found := map[string]bool{}
	for _, symbol := range file.Symbols {
		found[symbol.Name] = true
	}
	for _, name := range []string{"Helper", "fallback", "after", "real", "top"} {
		if !found[name] {
			t.Errorf("declaration %s was lost", name)
		}
	}
	if len(file.Diagnostics) != 0 {
		t.Errorf("syntax diagnostics on valid code: %v", file.Diagnostics)
	}
}

// Stacked annotations in front of a bodiless `abstract class` (or a `sealed
// class` with a body) that something later extends parse as a top-level
// annotated expression in the bundled grammar. No error node marks it; the
// class was simply missing from the index.
func TestMisparsedAnnotatedDeclarationsAreRecovered(t *testing.T) {
	source := "package p\n\nimport com.fasterxml.jackson.annotation.JsonSubTypes\n\ninterface Before {\n    val x: Int\n}\n\n@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = \"type\")\n@JsonSubTypes(\n    JsonSubTypes.Type(value = Child::class, name = \"CHILD\"),\n)\n@Suppress(\"UnnecessaryAbstractClass\")\nabstract class Parent\n\ndata class Child(val id: Int) : Parent()\n\n@A\n@B\nsealed class Shape {\n    abstract val sides: Int\n}\n\nclass Square : Shape() {\n    override val sides = 4\n}\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///p/P.kt", "kotlin", 1, source))
	symbols := map[string]Symbol{}
	for _, symbol := range file.Symbols {
		if _, seen := symbols[symbol.Name]; !seen {
			symbols[symbol.Name] = symbol
		}
	}
	for name, modifier := range map[string]string{"Parent": "abstract", "Shape": "sealed"} {
		symbol, ok := symbols[name]
		if !ok {
			t.Errorf("class %s was lost", name)
			continue
		}
		if symbol.Kind != KindClass || !contains(symbol.Modifiers, modifier) {
			t.Errorf("%s: kind=%v modifiers=%v, want a class with %s", name, symbol.Kind, symbol.Modifiers, modifier)
		}
		for _, leaked := range []string{"value", "property", "class"} {
			if contains(symbol.Modifiers, leaked) {
				t.Errorf("%s: annotation argument word %q read as a modifier: %v", name, leaked, symbol.Modifiers)
			}
		}
	}
	for _, reference := range file.References {
		if reference.Name == "Child" && reference.Role == RoleRead {
			return
		}
	}
	t.Errorf("the class literal inside the annotation is no longer a reference")
}

// A primary-constructor parameter that declares no property is visible in
// the supertype list, in property initializers and in init blocks -- and in
// nothing else. Scoped to its own declaration, `: Base(page.rows)` read as an
// unresolved `page`.
func TestConstructorParameterScope(t *testing.T) {
	source := "package p\nclass Dto(\n    page: Page,\n) : Base(page.rows) {\n    val doubled = page.size * 2\n    init { check(page) }\n    fun later() = page\n}\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///p/P.kt", "kotlin", 1, source))
	var page Symbol
	for _, symbol := range file.Symbols {
		if symbol.Name == "page" {
			page = symbol
		}
	}
	at := func(marker string) int { return strings.Index(source, marker) }
	for _, visible := range []string{"page.rows", "page.size", "page) }"} {
		if !page.InScopeAt(at(visible)) {
			t.Errorf("page is not visible at %q", visible)
		}
	}
	if page.InScopeAt(at("page\n}")) {
		t.Errorf("page is visible inside a member function")
	}
}

// `assertThrows<Outer.Nested> { }` is a call whose type argument is a dotted
// type: each segment is a type reference qualified by the ones before it.
func TestGenericTrailingLambdaCallKeepsDottedTypeArguments(t *testing.T) {
	source := "fun f() { assertThrows<Outer.Nested> { g() } }\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///p/P.kt", "kotlin", 1, source))
	var call, outer, nested bool
	for _, reference := range file.References {
		switch {
		case reference.Name == "assertThrows" && reference.Role == RoleCall && reference.Arity == 1:
			call = true
		case reference.Name == "Outer" && reference.Role == RoleType && reference.Qualifier == "":
			outer = true
		case reference.Name == "Nested" && reference.Role == RoleType && reference.Qualifier == "Outer":
			nested = true
		case reference.Name == "compareTo":
			t.Errorf("a type argument list became a comparison: %#v", reference)
		}
	}
	if !call || !outer || !nested {
		t.Errorf("call=%v outer=%v nested=%v in %#v", call, outer, nested, file.References)
	}
}
