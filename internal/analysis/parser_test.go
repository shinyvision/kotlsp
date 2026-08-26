package analysis

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func TestParseKotlinDeclarationsAndReferences(t *testing.T) {
	source := `package demo.people

import java.time.Instant

interface Greeter {
    fun greet(name: String): String
}

data class User(val id: Long, var displayName: String) : Greeter {
    override fun greet(name: String): String {
        val now = Instant.now()
        return "$name at $now"
    }
}
`
	file := Parse(context.Background(), textdoc.NewDocument("file:///User.kt", "kotlin", 1, source))
	if file.Package != "demo.people" {
		t.Fatalf("package = %q", file.Package)
	}
	if len(file.Imports) != 1 || file.Imports[0].Path != "java.time.Instant" {
		t.Fatalf("imports = %#v", file.Imports)
	}
	want := map[string]SymbolKind{"Greeter": KindInterface, "User": KindClass, "greet": KindMethod, "id": KindProperty, "displayName": KindProperty, "now": KindVariable}
	for name, kind := range want {
		if !hasSymbol(file, name, kind) {
			t.Fatalf("missing %s/%v; symbols: %s", name, kind, symbolSummary(file.Symbols))
		}
	}
	if !hasReference(file, "Instant", RoleType) && !hasReference(file, "Instant", RoleRead) {
		t.Fatalf("missing Instant reference; references: %#v", file.References)
	}
	if !hasReference(file, "now", RoleCall) && !hasReference(file, "now", RoleRead) {
		t.Fatalf("missing now reference")
	}
	if len(file.Diagnostics) != 0 {
		t.Fatalf("valid Kotlin produced diagnostics: %#v", file.Diagnostics)
	}
}

func TestKotlinDataModifierSurvivesArbitrarilyLongComments(t *testing.T) {
	source := "data\n/*" + strings.Repeat("x", 4096) + "*/\nclass Person(val name: String)\n"
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///DataGap.kt", "kotlin", 1, source))
	for _, symbol := range parsed.Symbols {
		if symbol.Name == "Person" && symbol.Kind == KindClass {
			if !contains(symbol.Modifiers, "data") {
				t.Fatalf("data modifier missing: %#v", symbol)
			}
			return
		}
	}
	t.Fatalf("Person missing: %#v", parsed.Symbols)
}

func TestJavaPatternScopeWalkHasNoAncestorDepthCap(t *testing.T) {
	condition := "o instanceof String s"
	for range 64 {
		condition = "(" + condition + ")"
	}
	source := "class Deep { void use(Object o) { if (" + condition + ") { s.length(); } s.length(); } }"
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///Deep.java", "java", 1, source))
	inside, outside := strings.Index(source, "s.length"), strings.LastIndex(source, "s.length")
	for _, symbol := range parsed.Symbols {
		if symbol.Name == "s" && symbol.Kind == KindVariable {
			if !(symbol.ScopeStartByte <= inside && inside <= symbol.ScopeEndByte) || outside <= symbol.ScopeEndByte {
				t.Fatalf("pattern scope [%d,%d] includes inside=%d outside=%d", symbol.ScopeStartByte, symbol.ScopeEndByte, inside, outside)
			}
			return
		}
	}
	t.Fatalf("pattern variable missing: %#v", parsed.Symbols)
}

func TestParseKotlinSmartCastScopes(t *testing.T) {
	source := "open class Base\nclass Sub : Base()\nfun use(x: Base) { if (x !is Sub) return; x.hashCode() }\n"
	doc := textdoc.NewDocument(protocol.URI("file:///Smart.kt"), "kotlin", 1, source)
	parsed := Parse(context.Background(), doc)
	if len(parsed.SmartCasts) != 1 {
		t.Fatalf("smart casts = %#v", parsed.SmartCasts)
	}
	call := strings.LastIndex(source, "x.hashCode")
	if parsed.SmartCasts[0].StartByte > call || parsed.SmartCasts[0].EndByte < call {
		t.Fatalf("smart cast does not cover post-guard use at %d: %#v", call, parsed.SmartCasts[0])
	}
}

func TestValidExpressionBodiedMemberBeforeGenericClassIsNotGrammarError(t *testing.T) {
	source := "class User { fun ping() = 1 }\n" +
		"class Box<T>(val element: T) { fun item(): T = element }\n"
	uri := protocol.URI("file:///workspace/GrammarRegression.kt")
	parsed := Parse(context.Background(), textdoc.NewDocument(uri, "kotlin", 1, source))
	for _, diagnostic := range parsed.Diagnostics {
		if diagnostic.Severity == 1 {
			t.Fatalf("valid Kotlin produced an error diagnostic: %#v", parsed.Diagnostics)
		}
	}
	for _, expected := range []string{"User", "ping", "Box", "element", "item"} {
		if !hasAnyNamedSymbol(parsed, expected) {
			t.Fatalf("missing %s in symbols: %#v", expected, parsed.Symbols)
		}
	}
}

func TestKotlinAnnotationAndEnumClassKindsIncludeSiblingModifiers(t *testing.T) {
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///Kinds.kt", "kotlin", 1,
		"package p\nannotation class Ann(val x: String)\nenum class Choice { A }\n"))
	if !hasSymbol(parsed, "Ann", KindAnnotation) {
		t.Fatalf("annotation class kind is wrong: %s", symbolSummary(parsed.Symbols))
	}
	if !hasSymbol(parsed, "Choice", KindEnum) {
		t.Fatalf("enum class kind is wrong: %s", symbolSummary(parsed.Symbols))
	}
}

func TestKotlinJVMNamesAndDataConstructorPropertiesArePreserved(t *testing.T) {
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///Renamed.kt", "kotlin", 1,
		"@file:JvmName(\"CustomFacade\")\npackage demo\n"+
			"data class Person(val name: String, val age: Int) { @JvmName(\"renamed\") fun original() = 1 }\n"))
	if parsed.JVMFacadeName != "CustomFacade" {
		t.Fatalf("file JVM name = %q", parsed.JVMFacadeName)
	}
	data, constructorProperties, renamed := false, 0, ""
	for _, symbol := range parsed.Symbols {
		if symbol.Name == "Person" && symbol.Kind == KindClass {
			data = contains(symbol.Modifiers, "data")
		}
		if symbol.Kind == KindProperty && contains(symbol.Modifiers, "constructor-property") {
			constructorProperties++
		}
		if symbol.Name == "original" {
			renamed = symbol.JVMName
		}
	}
	if !data || constructorProperties != 2 || renamed != "renamed" {
		t.Fatalf("data=%v constructor properties=%d JVM name=%q; symbols=%s", data, constructorProperties, renamed, symbolSummary(parsed.Symbols))
	}
}

func hasAnyNamedSymbol(file *ParsedFile, name string) bool {
	for _, symbol := range file.Symbols {
		if symbol.Name == name {
			return true
		}
	}
	return false
}

func TestParseJavaDeclarationsAndReferences(t *testing.T) {
	source := `package demo.people;

import java.time.Instant;

public interface Greeter {
    String greet(String name);
}

final class User implements Greeter {
    private final long id;
    User(long id) { this.id = id; }
    @Override public String greet(String name) {
        Instant now = Instant.now();
        return name + now;
    }
}
`
	file := Parse(context.Background(), textdoc.NewDocument("file:///User.java", "java", 1, source))
	if file.Package != "demo.people" {
		t.Fatalf("package = %q", file.Package)
	}
	want := map[string]SymbolKind{"Greeter": KindInterface, "User": KindClass, "greet": KindMethod, "id": KindField}
	for name, kind := range want {
		if !hasSymbol(file, name, kind) {
			t.Fatalf("missing %s/%v; symbols: %s", name, kind, symbolSummary(file.Symbols))
		}
	}
	if !hasReference(file, "Instant", RoleType) && !hasReference(file, "Instant", RoleRead) {
		t.Fatalf("missing Instant reference; references: %#v", file.References)
	}
	if len(file.Diagnostics) != 0 {
		t.Fatalf("valid Java produced diagnostics: %#v", file.Diagnostics)
	}
}

func TestImportDeclarationsProduceNavigableReferences(t *testing.T) {
	for _, fixture := range []struct {
		uri, language, source, imported string
	}{
		{"file:///Use.kt", "kotlin", "package app\nimport model.Widget as Renamed\nfun use(value: Renamed) = value\n", "model.Widget"},
		{"file:///Use.java", "java", "package app;\nimport static model.Tools.make;\nclass Use {}\n", "model.Tools.make"},
	} {
		file := Parse(context.Background(), textdoc.NewDocument(protocol.URI(fixture.uri), fixture.language, 1, fixture.source))
		if len(file.Imports) != 1 || file.Imports[0].Path != fixture.imported {
			t.Fatalf("%s imports = %#v", fixture.language, file.Imports)
		}
		name := fixture.imported[strings.LastIndexByte(fixture.imported, '.')+1:]
		if !hasReference(file, name, RoleImport) {
			t.Fatalf("%s missing import reference %q: %#v", fixture.language, name, file.References)
		}
	}
}

func TestJavaImportQualifiersAreNotOrdinaryReferences(t *testing.T) {
	file := Parse(context.Background(), textdoc.NewDocument("file:///Use.java", "java", 1,
		"package app; import java.util.List; import org.example.Repository; class Use { List<String> values; Repository repository; }"))
	for _, reference := range file.References {
		if reference.Name == "java" || reference.Name == "util" || reference.Name == "org" || reference.Name == "example" {
			t.Fatalf("import qualifier leaked as an ordinary reference: %#v", reference)
		}
	}
	if !hasReference(file, "List", RoleImport) || !hasReference(file, "Repository", RoleImport) {
		t.Fatalf("missing navigable import references: %#v", file.References)
	}
}

func TestSyntaxErrorDiagnostic(t *testing.T) {
	file := Parse(context.Background(), textdoc.NewDocument("file:///Broken.kt", "kotlin", 1, "fun broken( {\n"))
	if len(file.Diagnostics) == 0 {
		t.Fatal("expected a syntax diagnostic")
	}
}

func TestCallArgumentsAreCapturedForOverloadsAndHints(t *testing.T) {
	for _, fixture := range []struct {
		uri, language, source, call string
	}{
		{"file:///Calls.kt", "kotlin", "fun target(first: Int, second: String) = first\nfun use() = target(7, \"x\")\n", "target"},
		{"file:///Calls.java", "java", "class Calls { static void target(int first, String second) {} void use() { target(7, \"x\"); } }", "target"},
	} {
		file := Parse(context.Background(), textdoc.NewDocument(protocol.URI(fixture.uri), fixture.language, 1, fixture.source))
		found := false
		for _, reference := range file.References {
			if reference.Name == fixture.call && reference.Role == RoleCall && reference.Arity == 2 && len(reference.Arguments) == 2 {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s call arguments not captured: %#v", fixture.language, file.References)
		}
	}
}

func TestSemanticTokensCoverLexicalKindsWithoutOverlap(t *testing.T) {
	source := "// comment\nclass Demo { val text = \"hello $name\"; val number = 42 + 1 }\n"
	file := Parse(context.Background(), textdoc.NewDocument("file:///Tokens.kt", "kotlin", 1, source))
	wanted := map[uint32]bool{1: false, 15: false, 17: false, 18: false, 19: false, 21: false}
	for n, token := range file.Tokens {
		if _, ok := wanted[token.Type]; ok {
			wanted[token.Type] = true
		}
		if n > 0 && token.StartByte < file.Tokens[n-1].EndByte {
			t.Fatalf("semantic tokens overlap: %#v then %#v", file.Tokens[n-1], token)
		}
	}
	for kind, found := range wanted {
		if !found {
			t.Fatalf("missing semantic token type %d: %#v", kind, file.Tokens)
		}
	}
}

func TestAnonymousCompanionIsAContainerAndKeepsJvmStatic(t *testing.T) {
	source := "class App {\n    companion object {\n        @JvmStatic fun main(args: Array<String>) {}\n    }\n}"
	file := Parse(context.Background(), textdoc.NewDocument("file:///App.kt", "kotlin", 1, source))
	var companion, main Symbol
	for _, symbol := range file.Symbols {
		if symbol.Name == "Companion" {
			companion = symbol
		}
		if symbol.Name == "main" {
			main = symbol
		}
	}
	if companion.ID == "" || main.ContainerID != companion.ID {
		t.Fatalf("companion containment = companion %#v, main %#v", companion, main)
	}
	if !contains(main.Modifiers, "JvmStatic") || !contains(companion.Modifiers, "companion") {
		t.Fatalf("main/companion modifiers = %#v / %#v", main.Modifiers, companion.Modifiers)
	}
}

func TestLargeKotlinAndJavaParsesStayBelowForegroundBudget(t *testing.T) {
	fixtures := []struct {
		uri, language, head, declaration, tail string
	}{
		{"file:///Large.kt", "kotlin", "class Large {\n", "    fun value%d(input: Int): Int = input + %d\n", "}\n"},
		{"file:///Large.java", "java", "class Large {\n", "    int value%d(int input) { return input + %d; }\n", "}\n"},
	}
	for _, fixture := range fixtures {
		var source strings.Builder
		source.WriteString(fixture.head)
		for n := 0; n < 1500; n++ {
			source.WriteString(strings.ReplaceAll(strings.ReplaceAll(fixture.declaration, "%d", integerText(n)), "%d", integerText(n)))
		}
		source.WriteString(fixture.tail)
		started := time.Now()
		parsed := Parse(context.Background(), textdoc.NewDocument(protocol.URI(fixture.uri), fixture.language, 1, source.String()))
		if elapsed := time.Since(started); elapsed >= testTimingBudget {
			t.Fatalf("%s parse took %s for %d bytes", fixture.language, elapsed, source.Len())
		}
		if len(parsed.Symbols) < 1501 {
			t.Fatalf("%s large parse lost declarations: %d", fixture.language, len(parsed.Symbols))
		}
	}
}

func TestParallelClassBodyTraversalIsCompleteAndOrdered(t *testing.T) {
	var source strings.Builder
	source.WriteString("class Parallel {\n")
	for n := 0; n < 512; n++ {
		source.WriteString("    fun value")
		source.WriteString(integerText(n))
		source.WriteString("(input: Int): Int = input + ")
		source.WriteString(integerText(n))
		source.WriteByte('\n')
	}
	source.WriteString("}\n")
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///Parallel.kt", "kotlin", 1, source.String()))
	if got, want := len(parsed.Symbols), 1025; got != want {
		t.Fatalf("parallel traversal symbols = %d, want %d", got, want)
	}
	for n, symbol := range parsed.Symbols {
		if n > 0 && symbol.StartByte < parsed.Symbols[n-1].StartByte {
			t.Fatalf("symbols are not in source order at %d", n)
		}
		if symbol.Kind == KindMethod && symbol.ContainerName != "Parallel" {
			t.Fatalf("symbol %s lost its class container", symbol.Name)
		}
	}
	for n := 1; n < len(parsed.References); n++ {
		if parsed.References[n].StartByte < parsed.References[n-1].StartByte {
			t.Fatalf("references are not in source order at %d", n)
		}
	}
}

func TestGeneratedSourceRetainsCompleteSemanticParse(t *testing.T) {
	var source strings.Builder
	source.WriteString("class Generated {\n")
	for n := 0; n < 12000; n++ {
		source.WriteString("    fun value")
		source.WriteString(integerText(n))
		source.WriteString("(input: Int): Int = input + ")
		source.WriteString(integerText(n))
		source.WriteByte('\n')
	}
	source.WriteString("}\n")
	started := time.Now()
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///Generated.kt", "kotlin", 1, source.String()))
	if elapsed := time.Since(started); elapsed >= testTimingBudget {
		t.Fatalf("generated semantic parse took %s for %d bytes", elapsed, source.Len())
	}
	// The complete parser retains both callable declarations and parameters.
	if got, want := len(parsed.Symbols), 24001; got != want {
		t.Fatalf("generated fallback symbols = %d, want %d", got, want)
	}
}

func TestLargeCommentPaddedSourceRetainsCompleteSemantics(t *testing.T) {
	var source strings.Builder
	for range 53000 {
		source.WriteString("// padding\n")
	}
	source.WriteString("class Box { operator fun plus(other: Box): Box = this }\n")
	source.WriteString("fun use(left: Box, right: Box): Box = left + right\n")
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///Padded.kt", "kotlin", 1, source.String()))
	foundConvention := false
	for _, reference := range parsed.References {
		if reference.Name == "plus" && reference.Role == RoleCall {
			foundConvention = true
		}
	}
	if !foundConvention || len(parsed.Folds) == 0 {
		t.Fatalf("padded source lost semantics: convention=%v folds=%d", foundConvention, len(parsed.Folds))
	}
}

func TestCommentCompressionPreservesLiteralContentAndOffsets(t *testing.T) {
	literal := []byte("val text = \"\"\"\n// literal one\n// literal two\n\"\"\"\n")
	if compressed := compressFullLineComments(literal); string(compressed) != string(literal) {
		t.Fatalf("raw-string contents were treated as comments:\n%s", compressed)
	}
	source := []byte("// first\n// second\nclass Kept\n")
	compressed := compressFullLineComments(source)
	if len(compressed) != len(source) || compressed[0] != '/' || compressed[1] != '*' || compressed[len("// first\n// second")-2] != '*' || compressed[len("// first\n// second")-1] != '/' {
		t.Fatalf("comment compression changed offsets or delimiters: %q", compressed)
	}
}

func TestParserRetainsDeclarationsAfterNestedScopeWalk(t *testing.T) {
	uri := protocol.URI("file:///QualifiedShadow.kt")
	source := "package audit\nclass A {\n fun hit(): Int = 1\n}\nclass B {\n fun hit(): Int = 2\n}\n" +
		"fun test() {\n val x = A()\n run {\n  val x = B()\n  x.hit()\n }\n x.hit()\n}\n"
	parsed := Parse(context.Background(), textdoc.NewDocument(uri, "kotlin", 1, source))
	names := make(map[string]int)
	for _, symbol := range parsed.Symbols {
		names[symbol.Name]++
	}
	if names["A"] != 1 || names["B"] != 1 || names["hit"] != 2 || names["x"] != 2 || names["test"] != 1 {
		t.Fatalf("declarations = %#v; symbols=%#v diagnostics=%#v", names, parsed.Symbols, parsed.Diagnostics)
	}
}

func TestJavaFieldDeclarationRetainsIndividualModifiers(t *testing.T) {
	source := "class Tokens { static final int VALUE = 1; int mutable; }"
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///Tokens.java", "java", 1, source))
	for _, symbol := range parsed.Symbols {
		if symbol.Name != "VALUE" {
			continue
		}
		if !contains(symbol.Modifiers, "static") || !contains(symbol.Modifiers, "final") {
			t.Fatalf("VALUE modifiers = %#v", symbol.Modifiers)
		}
		return
	}
	t.Fatal("missing VALUE field")
}

func integerText(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [24]byte
	n := len(digits)
	for value > 0 {
		n--
		digits[n] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[n:])
}

func hasSymbol(file *ParsedFile, name string, kind SymbolKind) bool {
	for _, symbol := range file.Symbols {
		if symbol.Name == name && symbol.Kind == kind {
			return true
		}
	}
	return false
}

func hasReference(file *ParsedFile, name string, role ReferenceRole) bool {
	for _, reference := range file.References {
		if reference.Name == name && reference.Role == role {
			return true
		}
	}
	return false
}

func symbolSummary(symbols []Symbol) string {
	result := ""
	for _, symbol := range symbols {
		result += symbol.Name + "/" + symbol.Signature + "; "
	}
	return result
}
