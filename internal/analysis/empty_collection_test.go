package analysis

import (
	"context"
	"strings"
	"testing"

	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func parseKotlin(t *testing.T, source string) *ParsedFile {
	t.Helper()
	return Parse(context.Background(), textdoc.NewDocument("file:///workspace/Probe.kt", "kotlin", 0, source))
}

func symbolNames(parsed *ParsedFile) []string {
	names := make([]string, 0, len(parsed.Symbols))
	for _, symbol := range parsed.Symbols {
		names = append(names, symbol.Name)
	}
	return names
}

func containsName(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// The empty array literal is ordinary Kotlin and appears in almost every
// annotation declaration, but the grammar cannot parse it. Two in one
// declaration used to collapse the entire class into a syntax error, so its own
// name was reported as an unresolved reference.
func TestEmptyCollectionLiteralDefaultsParse(t *testing.T) {
	source := "package demo\n\nimport kotlin.reflect.KClass\n\n@Target(AnnotationTarget.CLASS)\n@Retention(AnnotationRetention.RUNTIME)\n@Constraint(validatedBy = [PasswordsMatchValidator::class])\nannotation class PasswordsMatch(\n    val message: String = \"Passwords do not match\",\n    val groups: Array<KClass<*>> = [],\n    val payload: Array<KClass<*>> = [],\n)\n"
	parsed := parseKotlin(t, source)
	if len(parsed.Diagnostics) != 0 {
		t.Fatalf("valid Kotlin reported %d syntax diagnostics: %#v", len(parsed.Diagnostics), parsed.Diagnostics)
	}
	names := symbolNames(parsed)
	for _, want := range []string{"PasswordsMatch", "message", "groups", "payload"} {
		if !containsName(names, want) {
			t.Fatalf("declaration %q was lost, got %v", want, names)
		}
	}
	// The class name is a declaration, never a reference to something else.
	for _, reference := range parsed.References {
		if reference.Name == "PasswordsMatch" && reference.Role != RoleImport {
			t.Fatalf("the declared name is reported as a reference at %v", reference.Range)
		}
	}
}

func TestEmptyCollectionLiteralShapes(t *testing.T) {
	for _, source := range []string{
		"package demo\nannotation class A(val g: Array<String> = [])\n",
		"package demo\nannotation class A(val g: Array<String> =[])\n",
		"package demo\nannotation class A(val g: Array<String> = [ ])\n",
		"package demo\nannotation class A(\n    val g: Array<String> =\n        [],\n)\n",
		"package demo\n@Foo(bar = [])\nclass A\n",
		"package demo\nannotation class A(val g: Array<String> = [], val h: Array<String> = [])\n",
	} {
		parsed := parseKotlin(t, source)
		if len(parsed.Diagnostics) != 0 {
			t.Fatalf("source %q reported %#v", source, parsed.Diagnostics)
		}
		if !containsName(symbolNames(parsed), "A") {
			t.Fatalf("source %q lost its declaration, got %v", source, symbolNames(parsed))
		}
	}
}

// The recovery rewrites source before a retry parse. It must never reach inside
// a literal, where it would change what the program means.
func TestEmptyCollectionRecoveryLeavesLiteralsAlone(t *testing.T) {
	for _, source := range []string{
		"package demo\nval marker = \"= []\"\nclass A\n",
		"package demo\n// a default like = [] in a comment\nclass A\n",
		"package demo\nval raw = \"\"\"= []\"\"\"\nclass A\n",
		"package demo\n/* = [] */\nclass A\n",
	} {
		recovered := kotlinEmptyCollectionDefaultRecovery([]byte(source))
		if string(recovered) != source {
			t.Fatalf("recovery rewrote a literal or comment:\n  in:  %q\n  out: %q", source, string(recovered))
		}
	}
}

// Offsets must survive the rewrite, or every reported range would be wrong.
func TestEmptyCollectionRecoveryPreservesLayout(t *testing.T) {
	source := "package demo\nannotation class A(\n    val g: Array<String> = [],\n)\n"
	recovered := kotlinEmptyCollectionDefaultRecovery([]byte(source))
	if len(recovered) != len(source) {
		t.Fatalf("length changed: %d -> %d", len(source), len(recovered))
	}
	if strings.Count(string(recovered), "\n") != strings.Count(source, "\n") {
		t.Fatal("line count changed")
	}
	if strings.Contains(string(recovered), "[]") {
		t.Fatalf("the empty literal survived: %q", string(recovered))
	}
	if !strings.Contains(string(recovered), "val g: Array<String>") {
		t.Fatalf("recovery damaged the declaration: %q", string(recovered))
	}
}

// A comparison is not an assignment and must not be blanked.
func TestEmptyCollectionRecoverySkipsComparisons(t *testing.T) {
	source := "package demo\nfun f(a: List<Int>) = a >= []\n"
	if got := string(kotlinEmptyCollectionDefaultRecovery([]byte(source))); got != source {
		t.Fatalf("comparison operand was blanked: %q", got)
	}
}
