package index

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/classfile"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func TestCrossLanguageNavigationAndHierarchy(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	javaURI := protocol.URI("file:///workspace/src/Greeter.java")
	kotlinURI := protocol.URI("file:///workspace/src/Friendly.kt")
	javaSource := "package demo;\npublic interface Greeter { String greet(String name); }\n"
	kotlinSource := `package demo

class Friendly : Greeter {
    override fun greet(name: String): String = name
}

fun use(g: Greeter): String = g.greet("world")
`
	idx.Open(ctx, protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	idx.Open(ctx, protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})

	greeterUse := nthOffset(kotlinSource, "Greeter", 1)
	definitions := idx.Definitions(kotlinURI, textdoc.NewDocument(kotlinURI, "kotlin", 1, kotlinSource).Position(greeterUse))
	if !containsSymbol(definitions, "Greeter", analysis.KindInterface, javaURI) {
		t.Fatalf("Kotlin -> Java definition failed: %#v", definitions)
	}

	javaDoc := textdoc.NewDocument(javaURI, "java", 1, javaSource)
	implementations := idx.Implementations(javaURI, javaDoc.Position(strings.Index(javaSource, "Greeter")))
	if !containsSymbol(implementations, "Friendly", analysis.KindClass, kotlinURI) {
		t.Fatalf("Java -> Kotlin implementation failed: %#v", implementations)
	}

	references := idx.References(javaURI, javaDoc.Position(strings.Index(javaSource, "Greeter")), true)
	if len(references) < 3 {
		t.Fatalf("expected declaration and cross-language references, got %#v", references)
	}

	callOffset := strings.Index(kotlinSource, "g.greet") + len("g.")
	callDefinitions := idx.Definitions(kotlinURI, textdoc.NewDocument(kotlinURI, "kotlin", 1, kotlinSource).Position(callOffset))
	if !containsNamedSymbol(callDefinitions, "greet") {
		t.Fatalf("member call definition failed: %#v", callDefinitions)
	}
}

func TestSemanticTokensPropagateResolvedSymbolModifiers(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	fixtures := []struct {
		uri, language, source, name string
		declarationModifiers        uint32
		referenceModifiers          uint32
	}{
		{"file:///workspace/Tokens.kt", "kotlin", "val top = 1\nfun consume() = top\n", "top",
			analysis.SemanticModifierDeclaration | analysis.SemanticModifierReadonly | analysis.SemanticModifierStatic,
			analysis.SemanticModifierReadonly | analysis.SemanticModifierStatic},
		{"file:///workspace/Mutable.kt", "kotlin", "var mutable = 0\nfun read() = mutable\nfun write() { mutable = 1 }\n", "mutable",
			analysis.SemanticModifierDeclaration | analysis.SemanticModifierStatic | analysis.SemanticModifierModification,
			analysis.SemanticModifierStatic | analysis.SemanticModifierModification},
		{"file:///workspace/Tokens.java", "java", "class Tokens { static final int VALUE = 1; int consume() { return VALUE; } }", "VALUE",
			analysis.SemanticModifierDeclaration | analysis.SemanticModifierReadonly | analysis.SemanticModifierStatic,
			analysis.SemanticModifierReadonly | analysis.SemanticModifierStatic},
	}
	for _, fixture := range fixtures {
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		tokens, _, ok := idx.SemanticTokens(uri)
		if !ok {
			t.Fatalf("no tokens for %s", uri)
		}
		declaration, reference := strings.Index(fixture.source, fixture.name), strings.LastIndex(fixture.source, fixture.name)
		gotDeclaration, gotReference := uint32(0), uint32(0)
		for _, token := range tokens {
			if token.StartByte == declaration {
				gotDeclaration = token.Modifiers
			}
			if token.StartByte == reference {
				gotReference = token.Modifiers
			}
		}
		if gotDeclaration != fixture.declarationModifiers || gotReference != fixture.referenceModifiers {
			t.Fatalf("%s modifiers: declaration=%d reference=%d", fixture.language, gotDeclaration, gotReference)
		}
	}
}

func TestJavaResolvesKotlinSourceJVMProjections(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	kotlinURI := protocol.URI("file:///workspace/KotlinApi.kt")
	javaURI := protocol.URI("file:///workspace/JavaInterop.java")
	kotlinSource := "class KotlinApi {\n" +
		"companion object {\n" +
		"@JvmStatic fun make(): KotlinApi = KotlinApi()\n" +
		"@JvmField val answer: Int = 42\n" +
		"@JvmStatic @JvmOverloads fun overload(value: String, count: Int = 1): String = value\n" +
		"}\n}\n" +
		"fun topLevel(): Int = 1\n" +
		"object Singleton { fun work(): Int = 2 }\n"
	javaSource := "class JavaInterop { void use() { KotlinApi.make(); int answer = KotlinApi.answer; KotlinApi.overload(\"x\"); int top = KotlinApiKt.topLevel(); Singleton.INSTANCE.work(); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	doc := textdoc.NewDocument(javaURI, "java", 1, javaSource)
	for _, marker := range []string{"make", "answer", "overload", "KotlinApiKt", "topLevel", "INSTANCE", "work"} {
		position := strings.LastIndex(javaSource, marker)
		definitions := idx.Definitions(javaURI, doc.Position(position))
		if len(definitions) == 0 || definitions[0].URI != kotlinURI {
			t.Fatalf("JVM projection %s = %#v", marker, definitions)
		}
	}
	overload := idx.Definitions(javaURI, doc.Position(strings.LastIndex(javaSource, "overload")))
	if len(overload) != 1 || len(overload[0].Parameters) != 1 {
		t.Fatalf("@JvmOverloads one-argument projection = %#v", overload)
	}
}

func TestJavaJVMProjectionSupportsObjectJvmStaticAndHidesJvmSynthetic(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	kotlinURI := protocol.URI("file:///workspace/Api.kt")
	javaURI := protocol.URI("file:///workspace/Use.java")
	kotlinSource := "object Api { @JvmSynthetic @JvmStatic fun hidden() {}; @JvmStatic fun visible() {}; fun plain() {} }\n" +
		"class CompanionApi { companion object { @JvmSynthetic @JvmStatic fun companionHidden() {}; @JvmStatic fun companionVisible() {} } }\n"
	javaSource := "class Use { void use() { Api.hidden(); Api.visible(); Api.INSTANCE.plain(); CompanionApi.companionHidden(); CompanionApi.companionVisible(); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	doc := textdoc.NewDocument(javaURI, "java", 1, javaSource)
	for _, member := range []string{"visible", "plain", "companionVisible"} {
		definitions := idx.Definitions(javaURI, doc.Position(strings.Index(javaSource, member)))
		if len(definitions) != 1 || definitions[0].URI != kotlinURI {
			t.Errorf("visible JVM projection %s = %#v", member, definitions)
		}
	}
	for _, member := range []string{"hidden", "companionHidden"} {
		if definitions := idx.Definitions(javaURI, doc.Position(strings.Index(javaSource, member))); len(definitions) != 0 {
			t.Errorf("@JvmSynthetic projection %s leaked into Java: %#v", member, definitions)
		}
	}
}

func TestJavaCompletionUsesOnlyCallableKotlinJVMViews(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	kotlinURI := protocol.URI("file:///workspace/Views.kt")
	javaURI := protocol.URI("file:///workspace/Use.java")
	kotlinSource := "fun topLevel(): Int = 1\nobject InstanceOnly { fun member(): Int = 2 }\n"
	javaSource := "class Use { int f() { return topL; } int g() { return InstanceOnly.me; } int h() { return InstanceOnly.INSTANCE.me; } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	doc := textdoc.NewDocument(javaURI, "java", 1, javaSource)
	if items := idx.Completion(javaURI, doc.Position(strings.Index(javaSource, "topL")+len("topL")), 0); containsNamedSymbol(items, "topLevel") {
		t.Fatalf("Kotlin top-level source view leaked to Java: %#v", items)
	}
	if items := idx.Completion(javaURI, doc.Position(strings.Index(javaSource, "InstanceOnly.me")+len("InstanceOnly.me")), 0); containsNamedSymbol(items, "member") {
		t.Fatalf("Kotlin object instance member leaked through class qualifier: %#v", items)
	}
	if items := idx.Completion(javaURI, doc.Position(strings.Index(javaSource, "InstanceOnly.INSTANCE.me")+len("InstanceOnly.INSTANCE.me")), 0); !containsNamedSymbol(items, "member") {
		t.Fatalf("Kotlin object member missing through INSTANCE: %#v", items)
	}
}

func TestJavaResolvesKotlinJvmNameProjections(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	kotlinURI := protocol.URI("file:///workspace/Renamed.kt")
	javaURI := protocol.URI("file:///workspace/Use.java")
	kotlinSource := "@file:JvmName(\"CustomFacade\")\npackage demo\nfun topOriginal(): Int = 1\nclass NamedApi { @JvmName(\"renamed\") fun original(): Int = 2 }\n"
	javaSource := "package demo; class Use { int use(NamedApi api) { return CustomFacade.topOriginal() + api.renamed(); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	doc := textdoc.NewDocument(javaURI, "java", 1, javaSource)
	for _, name := range []string{"CustomFacade", "topOriginal", "renamed"} {
		definitions := idx.Definitions(javaURI, doc.Position(strings.Index(javaSource, name)))
		if len(definitions) == 0 {
			t.Fatalf("missing definition for %s; Kotlin symbols = %#v", name, idx.SymbolsInFile(kotlinURI))
		}
	}
}

func TestGeneratedDataAndEnumAPIsResolveAndComplete(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	dataURI := protocol.URI("file:///workspace/Data.kt")
	dataSource := "data class Person(val name: String, val age: Int)\nfun use(p: Person) { p.copy(name = \"next\"); p.co }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: dataURI, LanguageID: "kotlin", Version: 1, Text: dataSource})
	doc := textdoc.NewDocument(dataURI, "kotlin", 1, dataSource)
	definitions := idx.Definitions(dataURI, doc.Position(strings.Index(dataSource, "copy")))
	if len(definitions) != 1 || definitions[0].Name != "copy" || len(definitions[0].Parameters) != 2 || definitions[0].Parameters[0].Default == "" {
		t.Fatalf("generated copy definition = %#v; symbols = %#v", definitions, idx.SymbolsInFile(dataURI))
	}
	completion := idx.Completion(dataURI, doc.Position(strings.Index(dataSource, "p.co")+len("p.co")), 0)
	if !containsNamedSymbol(completion, "copy") || !containsNamedSymbol(completion, "component1") {
		t.Fatalf("generated data completion = %#v", completion)
	}

	for _, fixture := range []struct{ uri, language, source string }{
		{"file:///workspace/K.kt", "kotlin", "enum class KColor { RED }\nfun use() { KColor.values(); KColor.valueOf(\"RED\"); KColor.entries }"},
		{"file:///workspace/J.java", "java", "enum JColor { RED } class Use { void use() { JColor.values(); JColor.valueOf(\"RED\"); } }"},
	} {
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		fixtureDoc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		for _, name := range []string{"values", "valueOf"} {
			resolved := idx.Definitions(uri, fixtureDoc.Position(strings.Index(fixture.source, name)))
			if len(resolved) == 0 || resolved[0].Name != name {
				t.Fatalf("%s generated %s = %#v", fixture.language, name, resolved)
			}
		}
		if fixture.language == "kotlin" {
			resolved := idx.Definitions(uri, fixtureDoc.Position(strings.Index(fixture.source, "entries")))
			if len(resolved) == 0 || resolved[0].Name != "entries" {
				t.Fatalf("Kotlin generated entries = %#v", resolved)
			}
		}
	}
}

func TestGenericCallArgumentsInstantiateContextualLambdaParameters(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/GenericLambda.kt")
	source := "class Sub { fun special() {} }\n" +
		"fun <T> acceptGeneric(value: T, block: (T) -> Unit) {}\n" +
		"fun use() { acceptGeneric(Sub()) { it.special() } }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "special")))
	if len(definitions) != 1 || definitions[0].ContainerName != "Sub" {
		t.Fatalf("generic contextual lambda member = %#v; references = %#v; symbols = %#v", definitions, idx.files[uri].References, idx.SymbolsInFile(uri))
	}
}

func TestGenericCallableParameterizedReturnPropagatesThroughMemberChain(t *testing.T) {
	for _, fixture := range []struct {
		uri, language, source, owner string
	}{
		{"file:///workspace/GenericMethod.java", "java", "class JResult { void special() {} } class GenericMethod { static class Box<T> { T value; } static <T> Box<T> wrap(T value) { return null; } void use() { wrap(new JResult()).value.special(); } }", "JResult"},
		{"file:///workspace/GenericMethod.kt", "kotlin", "class MResult { fun special() {} }\nclass MBox<T>(val value: T)\nfun <T> wrap(value: T): MBox<T> = MBox(value)\nfun use() { wrap(MResult()).value.special() }\n", "MResult"},
	} {
		idx := New(nil)
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(fixture.source, "special")))
		if len(definitions) != 1 || definitions[0].ContainerName != fixture.owner {
			t.Fatalf("%s parameterized generic return chain = %#v; symbols = %#v", fixture.language, definitions, idx.SymbolsInFile(uri))
		}
		idx.Close()
	}
}

func TestDefinitionsResolveOverloadsAndLexicalShadowing(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Semantics.kt")
	source := "fun overloaded(v: String) = 1\nfun overloaded(v: Int) = 2\n" +
		"fun use() = overloaded(1)\n" +
		"fun shadow() { var x = 1; run { var x = 2; println(x) }; println(x) }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	overloads := idx.Definitions(uri, doc.Position(strings.Index(source, "overloaded(1)")))
	if len(overloads) != 1 || len(overloads[0].Parameters) != 1 || simpleType(overloads[0].Parameters[0].Type) != "Int" {
		t.Fatalf("integer overload definitions = %#v", overloads)
	}
	innerUse := strings.Index(source, "println(x)") + len("println(")
	inner := idx.Definitions(uri, doc.Position(innerUse))
	innerDeclaration := strings.Index(source, "var x = 2") + len("var ")
	if len(inner) != 1 || inner[0].NameStartByte != innerDeclaration {
		parsed, _ := idx.Parsed(uri)
		t.Fatalf("inner shadow definition = %#v, want declaration at %d; symbols=%#v refs=%#v", inner, innerDeclaration, parsed.Symbols, parsed.References)
	}
	outerUse := strings.LastIndex(source, "println(x)") + len("println(")
	outer := idx.Definitions(uri, doc.Position(outerUse))
	outerDeclaration := strings.Index(source, "var x = 1") + len("var ")
	if len(outer) != 1 || outer[0].NameStartByte != outerDeclaration {
		t.Fatalf("outer shadow definition = %#v, want declaration at %d", outer, outerDeclaration)
	}
}

func TestKotlinBindingFormsAndVarargsResolve(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Bindings.kt")
	source := "fun sum(vararg xs: Int) = 0\n" +
		"fun bindings(values: IntArray) {\n" +
		"  for (loop in values) println(loop)\n" +
		"  listOf(1).map { explicit -> explicit.toString() }\n" +
		"  listOf(2).map { it.toString() }\n" +
		"  val (left, right) = Pair(1, 2); println(left + right)\n" +
		"  try {} catch (caught: Exception) { println(caught) }\n" +
		"  sum(1, 2, 3)\n" +
		"}\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	for _, name := range []string{"loop", "explicit", "it", "left", "right", "caught", "sum"} {
		offset := strings.LastIndex(source, name)
		if definitions := idx.Definitions(uri, doc.Position(offset)); len(definitions) == 0 {
			t.Fatalf("definition for %s is empty; symbols=%#v", name, idx.SymbolsInFile(uri))
		}
	}
}

func TestJavaVarargsCallResolves(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Varargs.java")
	source := "class Varargs { static int sum(int... xs) { return 0; } int use() { return sum(1, 2, 3); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "sum")))
	if !containsNamedSymbol(definitions, "sum") {
		t.Fatalf("Java varargs definition = %#v", definitions)
	}
}

func TestJavaLambdaPatternAndRecordBindingsResolve(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Bindings.java")
	source := "import java.util.*; record User(String name) {} class Bindings { " +
		"void use(Object value, User user) { List.of(1).forEach(v -> System.out.println(v)); " +
		"if (value instanceof String text) System.out.println(text); System.out.println(user.name()); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	uses := map[string]int{
		"v":    strings.Index(source, "println(v)") + len("println("),
		"text": strings.Index(source, "println(text)") + len("println("),
		"name": strings.Index(source, "name())"),
	}
	for name, offset := range uses {
		definitions := idx.Definitions(uri, doc.Position(offset))
		if !containsNamedSymbol(definitions, name) {
			t.Fatalf("definition for Java %s = %#v; symbols=%#v", name, definitions, idx.SymbolsInFile(uri))
		}
	}
	components := idx.SymbolsInFile(uri)
	if !containsNamedSymbol(components, "name") {
		t.Fatalf("record component is missing: %#v", components)
	}
}

func TestJavaPatternBindingFlowsIntoShortCircuitRHSAndAfterAbruptGuard(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/PatternFlow.java")
	source := "class PatternFlow { int use(Object object) { if (!(object instanceof String text) || text.isEmpty()) return 0; return text.length(); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	for _, occurrence := range []int{1, 2} {
		offset := nthOffset(source, "text", occurrence)
		definitions := idx.Definitions(uri, doc.Position(offset))
		if len(definitions) != 1 || definitions[0].NameStartByte != nthOffset(source, "text", 0) {
			t.Fatalf("pattern flow occurrence %d = %#v", occurrence, definitions)
		}
	}
}

func TestJavaRecordPatternComponentsResolveWithinTrueBranch(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/RecordPattern.java")
	source := "record Point(int x, int y) {} class RecordPattern { int sum(Object object) { if (object instanceof Point(int left, int right)) { return left + right; } return 0; } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	for _, name := range []string{"left", "right"} {
		definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(source, name)))
		if len(definitions) != 1 || definitions[0].Name != name || definitions[0].NameStartByte != strings.Index(source, name) {
			t.Fatalf("record pattern %s = %#v", name, definitions)
		}
	}
}

func TestTypeDefinitionAndHierarchyUseQualifiedTypeIdentity(t *testing.T) {
	idx := New(nil)
	aURI := protocol.URI("file:///workspace/a/Widget.kt")
	bURI := protocol.URI("file:///workspace/b/Widget.kt")
	useURI := protocol.URI("file:///workspace/use/Use.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: aURI, LanguageID: "kotlin", Version: 1, Text: "package a\nopen class Widget\nclass Child : Widget()\n"})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: bURI, LanguageID: "kotlin", Version: 1, Text: "package b\nopen class Widget\nclass Child : Widget()\n"})
	use := "package use\nimport b.Widget\nval selected: Widget = Widget()\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: use})
	doc := textdoc.NewDocument(useURI, "kotlin", 1, use)
	types := idx.TypeDefinitions(useURI, doc.Position(strings.Index(use, "selected")))
	if len(types) != 1 || types[0].URI != bURI || types[0].FQN != "b.Widget" {
		t.Fatalf("qualified type definition = %#v; symbols=%#v", types, idx.SymbolsInFile(useURI))
	}
	aDoc := textdoc.NewDocument(aURI, "kotlin", 1, "package a\nopen class Widget\nclass Child : Widget()\n")
	implementations := idx.Implementations(aURI, aDoc.Position(strings.Index(aDoc.Text, "Widget")))
	if len(implementations) != 1 || implementations[0].URI != aURI || implementations[0].FQN != "a.Child" {
		t.Fatalf("qualified implementations = %#v", implementations)
	}
}

func TestTypeDefinitionInfersKotlinAndJavaLocalTypes(t *testing.T) {
	idx := New(nil)
	kotlinURI := protocol.URI("file:///workspace/Infer.kt")
	kotlinSource := "class Foo\nfun use() { val inferred = Foo(); println(inferred) }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	kotlinDoc := textdoc.NewDocument(kotlinURI, "kotlin", 1, kotlinSource)
	types := idx.TypeDefinitions(kotlinURI, kotlinDoc.Position(strings.LastIndex(kotlinSource, "inferred")))
	if len(types) != 1 || types[0].Name != "Foo" {
		t.Fatalf("Kotlin inferred type definition = %#v", types)
	}

	javaURI := protocol.URI("file:///workspace/Infer.java")
	javaSource := "class Bar {} class Use { void use() { var inferred = new Bar(); System.out.println(inferred); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	javaDoc := textdoc.NewDocument(javaURI, "java", 1, javaSource)
	types = idx.TypeDefinitions(javaURI, javaDoc.Position(strings.LastIndex(javaSource, "inferred")))
	if len(types) != 1 || types[0].Name != "Bar" {
		t.Fatalf("Java inferred type definition = %#v; symbols=%#v", types, idx.SymbolsInFile(javaURI))
	}
}

func TestTypeDefinitionPreservesLongInitializer(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/LongInitializer.kt")
	typeName := strings.Repeat("A", 300)
	source := "class " + typeName + "\nval inferred = " + typeName + "()\nfun use() { inferred }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	types := idx.TypeDefinitions(uri, doc.Position(strings.LastIndex(source, "inferred")))
	if len(types) != 1 || types[0].Name != typeName {
		t.Fatalf("long initializer type definition = %#v", types)
	}
}

func TestPrivateMemberDoesNotLeakAcrossTopLevelClassesInSameFile(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Privacy.kt")
	source := "class Owner { private val secret = 1; fun inside() = secret }\nclass Stranger { fun leak(owner: Owner) = owner.secret }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	insideStart := strings.Index(source, "inside")
	insideOffset := insideStart + strings.Index(source[insideStart:], "secret")
	inside := idx.Definitions(uri, doc.Position(insideOffset))
	if !containsNamedSymbol(inside, "secret") {
		t.Fatalf("private member did not resolve inside its owner: %#v", inside)
	}
	leak := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "secret")))
	if len(leak) != 0 {
		t.Fatalf("private member leaked across top-level classes: %#v", leak)
	}
}

func TestCrossPackageProtectedAccessChecksReceiverType(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	baseURI := protocol.URI("file:///workspace/a/Base.java")
	subURI := protocol.URI("file:///workspace/b/Sub.java")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: baseURI, LanguageID: "java", Version: 1, Text: "package a; public class Base { protected void secret() {} }"})
	source := "package b; import a.Base; class Sub extends Base { void test(Base other, Sub mine) { other.secret(); mine.secret(); this.secret(); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: subURI, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(subURI, "java", 1, source)
	first := idx.Definitions(subURI, doc.Position(strings.Index(source, "secret")))
	if len(first) != 0 {
		t.Fatalf("protected member resolved through Base receiver across package: %#v", first)
	}
	for _, marker := range []string{"mine.secret", "this.secret"} {
		definitions := idx.Definitions(subURI, doc.Position(strings.Index(source, marker)+len(marker)-len("secret")))
		if len(definitions) != 1 || definitions[0].Name != "secret" {
			t.Fatalf("legal protected access %s = %#v", marker, definitions)
		}
	}
}

func TestMostSpecificOverrideResolutionHierarchyRenameAndImplementationShape(t *testing.T) {
	fixtures := []struct {
		uri      protocol.URI
		language string
		source   string
	}{
		{"file:///workspace/Overrides.java", "java", "class Base { void act() {} } class Sub extends Base { @Override void act() {} void act(int value) {} } class Use { void use(Base b, Sub s) { b.act(); s.act(); } }"},
		{"file:///workspace/Overrides.kt", "kotlin", "open class Base {\n open fun act() {}\n}\nclass Sub: Base() {\n override fun act() {}\n fun act(value: Int) {}\n}\nfun use(b: Base, s: Sub) { b.act(); s.act() }\n"},
	}
	for _, fixture := range fixtures {
		idx := New(nil)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: fixture.uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(fixture.uri, fixture.language, 1, fixture.source)
		baseDeclaration := strings.Index(fixture.source, "act")
		subDeclaration := strings.Index(fixture.source[baseDeclaration+3:], "act") + baseDeclaration + 3
		baseCall := strings.LastIndex(fixture.source[:strings.LastIndex(fixture.source, "s.act")], "b.act") + len("b.")
		subCall := strings.LastIndex(fixture.source, "s.act") + len("s.")
		if definitions := idx.Definitions(fixture.uri, doc.Position(baseCall)); len(definitions) != 1 || definitions[0].NameStartByte != baseDeclaration {
			t.Fatalf("%s base receiver definition = %#v", fixture.language, definitions)
		}
		if definitions := idx.Definitions(fixture.uri, doc.Position(subCall)); len(definitions) != 1 || definitions[0].NameStartByte != subDeclaration {
			t.Fatalf("%s subclass receiver definition = %#v", fixture.language, definitions)
		}
		implementations := idx.Implementations(fixture.uri, doc.Position(baseDeclaration))
		if len(implementations) != 1 || implementations[0].NameStartByte != subDeclaration || len(implementations[0].Parameters) != 0 {
			t.Fatalf("%s implementations include overload or miss override: %#v", fixture.language, implementations)
		}
		edit := idx.Rename(fixture.uri, doc.Position(baseDeclaration), "perform")
		if changes := edit.Changes[fixture.uri]; len(changes) != 4 {
			t.Fatalf("%s hierarchy rename edits = %#v, want base+override+2 calls", fixture.language, changes)
		}
		idx.Close()
	}
}

func TestGenericMemberReturnTypeIsSubstitutedForChainedDefinition(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Generic.kt")
	source := "package p\n" +
		"class User { fun ping() = 1 }\n" +
		"class Other { fun ping() = 2 }\n" +
		"class Box<T>(val element: T) { fun item(): T = element }\n" +
		"fun test(box: Box<User>) = box.item().ping()\n" +
		"fun inferred() { val box = Box(User()); box.item().ping() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "ping")))
	if len(definitions) != 1 || definitions[0].ContainerName != "User" {
		parsed, _ := idx.Parsed(uri)
		t.Fatalf("instantiated generic member definition = %#v; symbols=%#v; refs=%#v", definitions, idx.SymbolsInFile(uri), parsed.References)
	}
	constructors := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "Box(User")))
	if len(constructors) == 0 || constructors[0].Name != "Box" {
		t.Fatalf("generic constructor definition = %#v", constructors)
	}
	for _, diagnostic := range idx.Diagnostics(uri) {
		if diagnostic.Severity == 1 && strings.Contains(diagnostic.Message, "T") {
			t.Fatalf("valid generic type parameter diagnosed: %#v", idx.Diagnostics(uri))
		}
	}
}

func TestPrimaryConstructorSelectionDoesNotCaptureParameterTypeReferences(t *testing.T) {
	idx := New(nil)
	instantURI := protocol.URI("file:///workspace/java/time/Instant.kt")
	noteURI := protocol.URI("file:///workspace/Note.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: instantURI, LanguageID: "kotlin", Version: 1, Text: "package java.time\nclass Instant\n"})
	source := "package notes\nimport java.time.Instant\ndata class Note(val createdAt: Instant)\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: noteURI, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(noteURI, "kotlin", 1, source)
	definitions := idx.Definitions(noteURI, doc.Position(strings.LastIndex(source, "Instant")))
	if len(definitions) != 1 || definitions[0].URI != instantURI || definitions[0].Kind != analysis.KindClass {
		t.Fatalf("parameter type definition was captured by constructor: %#v; symbols=%#v", definitions, idx.SymbolsInFile(noteURI))
	}
}

func TestKotlinOperatorConventionDefinitionResolvesMethod(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Vec.kt")
	source := "data class Vec(val x: Int) { operator fun plus(other: Vec): Vec = Vec(x + other.x) }\n" +
		"fun use(a: Vec, b: Vec): Vec = a + b\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	offset := strings.LastIndex(source, "+")
	definitions := idx.Definitions(uri, doc.Position(offset))
	if len(definitions) != 1 || definitions[0].Name != "plus" || definitions[0].Kind != analysis.KindMethod {
		t.Fatalf("operator convention definition = %#v", definitions)
	}
}

func TestKotlinSimpleStringTemplateReferenceResolvesAndEscapedDollarDoesNot(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Templates.kt")
	source := `fun use() { val name = "world"; println("Hello $name \$name") }
`
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	use := strings.Index(source, "$name") + 1
	definitions := idx.Definitions(uri, doc.Position(use))
	if len(definitions) != 1 || definitions[0].Name != "name" || definitions[0].Kind != analysis.KindVariable {
		t.Fatalf("simple string-template definition = %#v", definitions)
	}
	escaped := strings.LastIndex(source, "$name") + 1
	if definitions := idx.Definitions(uri, doc.Position(escaped)); len(definitions) != 0 {
		t.Fatalf("escaped dollar created a template reference: %#v", definitions)
	}
}

func TestIndexedExpressionAndDelegatedLazyResultTypesDriveChainedDefinitions(t *testing.T) {
	fixtures := []struct {
		uri, language, source string
	}{
		{"file:///workspace/Indexed.kt", "kotlin", "class Sub { fun special() {} }\nclass Box<T>(val value: T) { operator fun get(index: Int): T = value }\nfun use(box: Box<Sub>) { box[0].special() }\n"},
		{"file:///workspace/Array.java", "java", "class SubJ { void special() {} } class UseJ { void use(SubJ[] values) { values[0].special(); } }"},
		{"file:///workspace/Delegate.kt", "kotlin", "class LazySub { fun special() {} }\nfun use() { val value by lazy { LazySub() }; value.special() }\n"},
		{"file:///workspace/CustomDelegate.kt", "kotlin", "class DelegatedSub { fun special() {} }\nclass Delegate<T>(val value: T) { operator fun getValue(thisRef: Any?, property: Any): T = value }\nfun use() { val value by Delegate(DelegatedSub()); value.special() }\n"},
	}
	for _, fixture := range fixtures {
		idx := New(nil)
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(fixture.source, "special")))
		if len(definitions) != 1 || definitions[0].Name != "special" {
			t.Errorf("%s chained definition = %#v", fixture.language, definitions)
		}
		idx.Close()
	}
}

func TestJavaAndKotlinClassLiteralTypesDriveMemberDefinitions(t *testing.T) {
	fixtures := []struct {
		uri, language, source, member string
	}{
		{"file:///workspace/Literal.java", "java", "class Class<T> { String getName() { return \"\"; } } class LiteralSub {} class Use { String use() { return LiteralSub.class.getName(); } }", "getName"},
		{"file:///workspace/Literal.kt", "kotlin", "class KClass<T> { val simpleName: String = \"\" }\nclass LiteralSub\nfun use() = LiteralSub::class.simpleName\n", "simpleName"},
	}
	for _, fixture := range fixtures {
		idx := New(nil)
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(fixture.source, fixture.member)))
		if len(definitions) != 1 || definitions[0].Name != fixture.member {
			t.Errorf("%s class-literal member definition = %#v", fixture.language, definitions)
		}
		idx.Close()
	}
}

func TestKotlinTryAndJavaSwitchExpressionTypesDriveMemberDefinitions(t *testing.T) {
	fixtures := []struct {
		uri, language, source string
	}{
		{"file:///workspace/Try.kt", "kotlin", "class TrySub { fun special() {} }\nfun use() { val value = try { TrySub() } catch (failure: Exception) { TrySub() }; value.special() }\n"},
		{"file:///workspace/Switch.java", "java", "class SwitchSub { void special() {} } class Use { void use(int selector) { var value = switch (selector) { default -> new SwitchSub(); }; value.special(); } }"},
	}
	for _, fixture := range fixtures {
		idx := New(nil)
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(fixture.source, "special")))
		if len(definitions) != 1 || definitions[0].Name != "special" {
			t.Errorf("%s composite-expression member definition = %#v", fixture.language, definitions)
		}
		idx.Close()
	}
}

func TestConventionBindingsInvocationsConstructedGenericsAndAliasesPropagateTypes(t *testing.T) {
	fixtures := []struct {
		uri, language, source string
		uses                  []string
	}{
		{"file:///workspace/Inference.kt", "kotlin", `class Sub { fun special() {} }
data class Holder(val item: Sub)
class Items { operator fun iterator(): Iter = Iter() }
class Iter { operator fun hasNext(): Boolean = false; operator fun next(): Sub = Sub() }
class Factory { operator fun invoke(): Sub = Sub() }
class Box<T>(val value: T)
typealias Alias<T> = Box<T>
fun make(): Sub = Sub()
fun <T> Set<T>.first(): T = throw Exception()
fun use(factory: () -> Sub) {
  val (destructured) = Holder(Sub()); destructured.special()
  for (item in Items()) item.special()
  factory().special(); Factory()().special(); Alias(Sub()).value.special()
  val lambda = { Sub() }; lambda().special()
  val reference = ::make; reference().special()
  listOf(Sub())[0].special(); arrayOf(Sub())[0].special(); setOf(Sub()).first().special()
  mapOf("key" to Sub())["key"]?.special()
  Sub().apply {}.special(); Sub().also { it }.special(); Sub().let { it }.special()
  with(Sub()) { this }.special(); run { Sub() }.special()
  val pair = Sub() to "value"; pair.first.special()
}
`, []string{"destructured.special", "item.special", "factory().special", "Factory()().special", "Alias(Sub()).value.special", "lambda().special", "reference().special", "listOf(Sub())[0].special", "arrayOf(Sub())[0].special", "setOf(Sub()).first().special", "mapOf(\"key\" to Sub())[\"key\"]?.special", "Sub().apply {}.special", "Sub().also { it }.special", "Sub().let { it }.special", "with(Sub()) { this }.special", "run { Sub() }.special", "pair.first.special"}},
		{"file:///workspace/Inference.java", "java", "class JSub { void special() {} } class JBox<T> { T value; JBox(T value) { this.value=value; } T get() { return value; } } class Use { void use() { new JBox<>(new JSub()).get().special(); new JBox<JSub>(new JSub()).get().special(); } }", []string{"new JBox<>(new JSub()).get().special", "new JBox<JSub>(new JSub()).get().special"}},
	}
	for _, fixture := range fixtures {
		idx := New(nil)
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		for _, use := range fixture.uses {
			at := strings.Index(fixture.source, use) + strings.LastIndex(use, "special")
			definitions := idx.Definitions(uri, doc.Position(at))
			if len(definitions) != 1 || definitions[0].Name != "special" {
				t.Errorf("%s %s definition = %#v", fixture.language, use, definitions)
			}
		}
		idx.Close()
	}
}

func TestKotlinConventionDefinitionsCoverIndexInvokeUnaryContainmentIterationAndDelegation(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Conventions.kt")
	source := `class Cursor {
  operator fun hasNext(): Boolean = false
  operator fun next(): String = ""
}
class Box {
  operator fun get(index: Int): String = ""
  operator fun set(index: Int, value: String) {}
  operator fun contains(value: String): Boolean = true
  operator fun invoke(): String = ""
  operator fun unaryMinus(): Box = this
  operator fun rangeTo(other: Box): Box = this
  operator fun iterator(): Cursor = Cursor()
  operator fun component1(): String = ""
  operator fun provideDelegate(thisRef: Any?, property: Any): Box = this
  operator fun getValue(thisRef: Any?, property: Any): String = ""
  operator fun setValue(thisRef: Any?, property: Any, value: String) {}
}
fun use(box: Box) {
  box[0]
  box[0] = "value"
  "value" in box
  box()
  val negated = -box
  box..box
  for (item in box) println(item)
  val (first) = box
  var delegated by box
}
`
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	assertDefinition := func(marker string, adjustment int, expected string) {
		t.Helper()
		offset := strings.Index(source, marker)
		if offset < 0 {
			t.Fatalf("marker %q missing", marker)
		}
		definitions := idx.Definitions(uri, doc.Position(offset+adjustment))
		if len(definitions) != 1 || definitions[0].Name != expected {
			parsed, _ := idx.Parsed(uri)
			t.Fatalf("definition at %q = %#v, want %s; refs=%#v", marker, definitions, expected, parsed.References)
		}
	}
	assertDefinition("box[0]", len("box"), "get")
	assertDefinition("box[0] =", len("box"), "set")
	assertDefinition("\"value\" in box", len("\"value\" "), "contains")
	assertDefinition("box()", len("box"), "invoke")
	assertDefinition("-box", 0, "unaryMinus")
	assertDefinition("box..box", len("box"), "rangeTo")
	assertDefinition("for (item in box)", len("for (item "), "iterator")

	for _, name := range []string{"hasNext", "next", "component1", "provideDelegate", "getValue", "setValue"} {
		declaration := strings.Index(source, name)
		locations := idx.References(uri, doc.Position(declaration), false)
		if len(locations) == 0 {
			t.Fatalf("implicit convention %s has no indexed use", name)
		}
	}
}

func TestCallableAndMethodReferencesHonorDoubleColonQualifier(t *testing.T) {
	fixtures := []struct {
		uri      protocol.URI
		language string
		source   string
	}{
		{"file:///workspace/References.kt", "kotlin", "object Left { fun make() {} }\nobject Right { fun make() {} }\nval ref = Right::make\n"},
		{"file:///workspace/References.java", "java", "class Left { static void make() {} }\nclass Right { static void make() {} }\nclass Use { Runnable ref = Right::make; }\n"},
	}
	for _, fixture := range fixtures {
		idx := New(nil)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: fixture.uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(fixture.uri, fixture.language, 1, fixture.source)
		definitions := idx.Definitions(fixture.uri, doc.Position(strings.LastIndex(fixture.source, "make")))
		if len(definitions) != 1 || definitions[0].ContainerName != "Right" {
			t.Fatalf("%s double-colon definition = %#v", fixture.language, definitions)
		}
		idx.Close()
	}
}

func TestTypeAliasAndGenericFunctionReturnTypesDriveQualifiedResolution(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Aliases.kt")
	source := "class Other { fun ping() = 0 }\nclass Target { fun ping() = 1 }\n" +
		"typealias Alias = Target\nfun <T> id(value: T): T = value\n" +
		"fun make(): Target = Target()\nfun aliasUse(a: Alias) = a.ping()\n" +
		"fun genericUse() { val y = id(Target()); y.ping(); make().ping() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	for _, marker := range []string{"a.ping", "y.ping", "make().ping"} {
		offset := strings.Index(source, marker) + len(marker) - len("ping")
		definitions := idx.Definitions(uri, doc.Position(offset))
		if len(definitions) != 1 || definitions[0].ContainerName != "Target" {
			t.Fatalf("%s definition = %#v; symbols=%#v", marker, definitions, idx.SymbolsInFile(uri))
		}
	}
}

func TestUnknownQualifierNeverFallsBackToUnrelatedGlobalMember(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Unknown.kt")
	source := "class Other { fun ping() = 0 }\nfun use(unknown: Missing) = unknown.ping()\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	if definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "ping"))); len(definitions) != 0 {
		t.Fatalf("unknown qualifier resolved to unrelated member: %#v", definitions)
	}
}

func TestOverloadResolutionUsesTypedNameArguments(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Overload.kt")
	source := "fun pick(value: String) = 0\nfun pick(value: Int) = 1\nfun use(value: Int) = pick(value)\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "pick")))
	if len(definitions) != 1 || len(definitions[0].Parameters) != 1 || definitions[0].Parameters[0].Type != "Int" {
		t.Fatalf("typed-name overload definition = %#v", definitions)
	}
}

func TestLargeFallbackRetainsCallDefinitions(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Generated.kt")
	var source strings.Builder
	source.WriteString("class Generated {\n")
	for number := 0; number < 16000; number++ {
		source.WriteString("fun value")
		source.WriteString(integer(number))
		source.WriteString("(input: Int): Int = input + 1\n")
	}
	source.WriteString("fun use(): Int = value0(1)\n}\n")
	text := source.String()
	if len(text) < 512<<10 {
		t.Fatalf("fixture did not exercise large fallback: %d bytes", len(text))
	}
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: text})
	doc := textdoc.NewDocument(uri, "kotlin", 1, text)
	definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(text, "value0")))
	if len(definitions) != 1 || definitions[0].Name != "value0" {
		t.Fatalf("large fallback call definition = %#v", definitions)
	}
}

func TestFiftyThousandLocalReferencesRemainComplete(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Huge.kt")
	var source strings.Builder
	source.Grow(200024)
	source.WriteString("fun f() {\n  val x = 1\n")
	for range 50000 {
		source.WriteString("  x\n")
	}
	source.WriteString("}\n")
	text := source.String()
	opened := time.Now()
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: text})
	openElapsed := time.Since(opened)
	doc := textdoc.NewDocument(uri, "kotlin", 1, text)
	started := time.Now()
	position := doc.Position(strings.Index(text, "  x\n") + 2)
	references := idx.References(uri, position, true)
	referenceElapsed := time.Since(started)
	if len(references) != 50001 {
		parsed, _ := idx.Parsed(uri)
		t.Fatalf("local references = %d, want 50001; symbols=%d parsed_refs=%d first_symbols=%#v first_refs=%#v position=%#v", len(references), len(parsed.Symbols), len(parsed.References), parsed.Symbols[:min(len(parsed.Symbols), 8)], parsed.References[:min(len(parsed.References), 3)], position)
	}
	t.Logf("open=%s references=%s response_locations=%d", openElapsed, referenceElapsed, len(references))
}

func TestLargeGeneratedFullTextReplacementRemainsLinear(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/GeneratedReplacement.kt")
	var source strings.Builder
	source.WriteString("class Generated {\n")
	for number := range 12000 {
		source.WriteString("fun value")
		source.WriteString(integer(number))
		source.WriteString("(input: Int): Int = input + ")
		source.WriteString(integer(number))
		source.WriteByte('\n')
	}
	source.WriteString("fun use(): Int = value0(1)\n}\n")
	text := source.String()
	opened := time.Now()
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: text})
	openElapsed := time.Since(opened)
	changed := time.Now()
	if _, err := idx.Change(context.Background(), protocol.DidChangeTextDocumentParams{
		TextDocument: protocol.VersionedTextDocumentIdentifier{URI: uri, Version: 2}, ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: text}},
	}); err != nil {
		t.Fatal(err)
	}
	changeElapsed := time.Since(changed)
	doc := textdoc.NewDocument(uri, "kotlin", 2, text)
	if definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(text, "value0"))); len(definitions) != 1 || definitions[0].Name != "value0" {
		t.Fatalf("definition after full replacement = %#v", definitions)
	}
	t.Logf("bytes=%d open=%s full_change=%s", len(text), openElapsed, changeElapsed)
}

func TestQualifiedDefinitionsHonorNestedLexicalScope(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/QualifiedShadow.kt")
	source := "package audit\nclass A {\n fun hit(): Int = 1\n}\nclass B {\n fun hit(): Int = 2\n}\n" +
		"fun test() {\n val x = A()\n run {\n  val x = B()\n  x.hit()\n }\n x.hit()\n}\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	inner := idx.Definitions(uri, doc.Position(strings.Index(source, "x.hit()")+len("x.")))
	outer := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "x.hit()")+len("x.")))
	if len(inner) != 1 || inner[0].ContainerName != "B" {
		parsed, _ := idx.Parsed(uri)
		t.Fatalf("inner qualified definition = %#v; symbols=%#v refs=%#v", inner, parsed.Symbols, parsed.References)
	}
	if len(outer) != 1 || outer[0].ContainerName != "A" {
		t.Fatalf("outer qualified definition = %#v", outer)
	}
	for _, diagnostic := range idx.Diagnostics(uri) {
		if diagnostic.Code == "duplicate-declaration" {
			t.Fatalf("nested shadowing diagnosed as duplicate: %#v", diagnostic)
		}
	}
}

func TestNamedArgumentsSelectApplicableKotlinOverload(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Named.kt")
	source := "fun choose(a: String, b: Int) = a\nfun choose(x: Int, a: String) = a\nfun test() = choose(a = \"ok\", b = 1)\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	definitions := idx.Definitions(uri, doc.Position(strings.LastIndex(source, "choose")))
	if len(definitions) != 1 || len(definitions[0].Parameters) != 2 || definitions[0].Parameters[1].Name != "b" {
		t.Fatalf("named-argument overload definitions = %#v", definitions)
	}
}

func TestJavaKotlinPropertyAccessorNavigationBothDirections(t *testing.T) {
	idx := New(nil)
	kotlinURI := protocol.URI("file:///workspace/K.kt")
	javaUseURI := protocol.URI("file:///workspace/ReadK.java")
	javaURI := protocol.URI("file:///workspace/J.java")
	kotlinUseURI := protocol.URI("file:///workspace/ReadJ.kt")
	kotlinSource := "package audit\nclass K { val name: String = \"x\"; var count: Int = 0 }\n"
	javaUse := "package audit; class ReadK { String read(K k) { return k.getName(); } void write(K k) { k.setCount(2); } }"
	javaSource := "package audit; public class J { public String getName() { return \"x\"; } public void setName(String value) {} }"
	kotlinUse := "package audit\nfun read(j: J) = j.name\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaUseURI, LanguageID: "java", Version: 1, Text: javaUse})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinUseURI, LanguageID: "kotlin", Version: 1, Text: kotlinUse})
	javaDoc := textdoc.NewDocument(javaUseURI, "java", 1, javaUse)
	getter := idx.Definitions(javaUseURI, javaDoc.Position(strings.Index(javaUse, "getName")))
	setter := idx.Definitions(javaUseURI, javaDoc.Position(strings.Index(javaUse, "setCount")))
	if len(getter) != 1 || getter[0].URI != kotlinURI || getter[0].Name != "getName" || !getter[0].Synthetic {
		t.Fatalf("Java getter -> Kotlin property = %#v", getter)
	}
	if len(setter) != 1 || setter[0].URI != kotlinURI || setter[0].Name != "setCount" || !setter[0].Synthetic {
		t.Fatalf("Java setter -> Kotlin var = %#v", setter)
	}
	kotlinDoc := textdoc.NewDocument(kotlinUseURI, "kotlin", 1, kotlinUse)
	property := idx.Definitions(kotlinUseURI, kotlinDoc.Position(strings.LastIndex(kotlinUse, "name")))
	if len(property) != 1 || property[0].URI != javaURI || property[0].Name != "name" || !property[0].Synthetic {
		t.Fatalf("Kotlin property -> Java getter = %#v", property)
	}
}

func TestJavaKotlinPropertyRenameMapsAccessorNamesBothDirections(t *testing.T) {
	idx := New(nil)
	kotlinURI := protocol.URI("file:///workspace/K.kt")
	javaURI := protocol.URI("file:///workspace/ReadK.java")
	kotlinSource := "package audit\nclass K { val name: String = \"x\" }\nfun use(k: K) = k.name\n"
	javaSource := "package audit; class ReadK { String read(K k) { return k.getName(); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	kotlinDoc := textdoc.NewDocument(kotlinURI, "kotlin", 1, kotlinSource)
	fromProperty := idx.Rename(kotlinURI, kotlinDoc.Position(strings.Index(kotlinSource, "name")), "title")
	assertInteropRenameEdits(t, fromProperty, kotlinURI, javaURI)
	javaDoc := textdoc.NewDocument(javaURI, "java", 1, javaSource)
	fromAccessor := idx.Rename(javaURI, javaDoc.Position(strings.Index(javaSource, "getName")), "getTitle")
	assertInteropRenameEdits(t, fromAccessor, kotlinURI, javaURI)
}

func TestJavaKotlinPropertyReferencesUnifyAccessorFamily(t *testing.T) {
	idx := New(nil)
	kotlinURI := protocol.URI("file:///workspace/K.kt")
	javaURI := protocol.URI("file:///workspace/ReadK.java")
	kotlinSource := "package audit\nclass K { var name: String = \"x\" }\nfun use(k: K) = k.name\n"
	javaSource := "package audit; class ReadK { String read(K k) { k.setName(\"y\"); return k.getName(); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	doc := textdoc.NewDocument(kotlinURI, "kotlin", 1, kotlinSource)
	references := idx.References(kotlinURI, doc.Position(strings.Index(kotlinSource, "name")), true)
	if len(references) != 4 {
		t.Fatalf("interop reference family = %#v, want declaration plus Kotlin property/getter/setter uses", references)
	}
}

func assertInteropRenameEdits(t *testing.T, edit protocol.WorkspaceEdit, kotlinURI, javaURI protocol.URI) {
	t.Helper()
	kotlinTitles, javaGetTitles := 0, 0
	for _, value := range edit.Changes[kotlinURI] {
		if value.NewText == "title" {
			kotlinTitles++
		}
		if value.NewText == "getTitle" {
			t.Fatalf("Kotlin property was renamed to accessor spelling: %#v", edit)
		}
	}
	for _, value := range edit.Changes[javaURI] {
		if value.NewText == "getTitle" {
			javaGetTitles++
		}
	}
	if kotlinTitles != 2 || javaGetTitles != 1 {
		t.Fatalf("interop rename edits = %#v", edit)
	}
}

func TestDefinitionFindsInheritedMemberAcrossJavaKotlinBoundary(t *testing.T) {
	idx := New(nil)
	listURI := protocol.URI("jar:///spring-data.jar!/org/springframework/data/repository/ListCrudRepository.java")
	jpaURI := protocol.URI("jar:///spring-data.jar!/org/springframework/data/jpa/repository/JpaRepository.java")
	repositoryURI := protocol.URI("file:///workspace/NoteRepository.kt")
	useURI := protocol.URI("file:///workspace/Controller.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: listURI, LanguageID: "java", Version: 1, Text: "package org.springframework.data.repository; public interface ListCrudRepository<T, ID> { java.util.List<T> findAll(); }"})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: jpaURI, LanguageID: "java", Version: 1, Text: "package org.springframework.data.jpa.repository; public interface JpaRepository<T, ID> extends org.springframework.data.repository.ListCrudRepository<T, ID> {}"})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: repositoryURI, LanguageID: "kotlin", Version: 1, Text: "interface NoteRepository : org.springframework.data.jpa.repository.JpaRepository<String, Long>"})
	use := "class Controller(val repository: NoteRepository) { fun all() = repository.findAll() }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: use})
	doc := textdoc.NewDocument(useURI, "kotlin", 1, use)
	definitions := idx.Definitions(useURI, doc.Position(strings.Index(use, "findAll")))
	if !containsSymbol(definitions, "findAll", analysis.KindMethod, listURI) {
		parsed, _ := idx.Parsed(useURI)
		repository, _ := idx.Parsed(repositoryURI)
		jpa, _ := idx.Parsed(jpaURI)
		list, _ := idx.Parsed(listURI)
		t.Fatalf("inherited library member definitions = %#v; use=%#v repo=%#v jpa=%#v list=%#v", definitions, parsed, repository, jpa, list)
	}
}

func TestHotIndexOperationsStayBelowBudget(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Example.kt")
	source := "package demo\nclass Example { fun value(input: String): String = input }\n"
	idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	position := doc.Position(strings.Index(source, "Example"))
	operations := map[string]func(){
		"definition":      func() { _ = idx.Definitions(uri, position) },
		"implementation":  func() { _ = idx.Implementations(uri, position) },
		"references":      func() { _ = idx.References(uri, position, true) },
		"completion":      func() { _ = idx.Completion(uri, position, 150) },
		"workspaceSymbol": func() { _ = idx.WorkspaceSymbols("Exam", 200) },
	}
	for name, operation := range operations {
		started := time.Now()
		for range 100 {
			operation()
		}
		if elapsed := time.Since(started); elapsed >= testTimingBudget {
			t.Fatalf("%s took %s for 100 hot calls", name, elapsed)
		}
	}
}

func TestCompletionStaysBelowBudgetDuringLibraryInsertion(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Editing.kt")
	source := "package app\nfun use() { Str }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	position := doc.Position(strings.Index(source, "Str") + len("Str"))
	files := make([]LibraryFile, 300)
	for fileIndex := range files {
		parsed := analysis.ParsedFile{URI: protocol.URI("jar:///stress.jar!/stress/File" + integer(fileIndex) + ".java"), Language: analysis.LanguageJava, Package: "stress.package" + integer(fileIndex)}
		for symbolIndex := range 24 {
			name := "StressType" + integer(fileIndex) + "_" + integer(symbolIndex)
			parsed.Symbols = append(parsed.Symbols, analysis.Symbol{ID: analysis.SymbolID(parsed.URI, symbolIndex, analysis.KindClass, name), URI: parsed.URI, Language: analysis.LanguageJava, Package: parsed.Package, Name: name, FQN: parsed.Package + "." + name, Kind: analysis.KindClass})
		}
		files[fileIndex].Parsed = parsed
	}
	done := make(chan struct{})
	go func() {
		idx.AddLibraryBatch(files)
		close(done)
	}()
	requests := 0
	for {
		started := time.Now()
		_ = idx.Completion(uri, position, 150)
		if elapsed := time.Since(started); elapsed >= testTimingBudget {
			t.Fatalf("completion blocked for %s during library insertion", elapsed)
		}
		requests++
		select {
		case <-done:
			if requests < 2 {
				t.Fatalf("library insertion completed before contention was exercised")
			}
			return
		default:
		}
	}
}

func TestLibrarySummaryDropsLocalsButKeepsMembers(t *testing.T) {
	uri := protocol.URI("jar:///cache/library-sources.jar!/demo/Service.java")
	source := "package demo; class Service { String run(String input) { String local = input; return local; } }"
	doc := textdoc.NewDocument(uri, "java", 0, source)
	parsed := analysis.Parse(context.Background(), doc)
	summarizeLibraryFile(parsed)
	if !containsNamedSymbol(parsed.Symbols, "Service") || !containsNamedSymbol(parsed.Symbols, "run") {
		t.Fatalf("library summary lost public structure: %#v", parsed.Symbols)
	}
	if containsNamedSymbol(parsed.Symbols, "input") || containsNamedSymbol(parsed.Symbols, "local") {
		t.Fatalf("library summary must store callable parameters only in the public signature and drop lexical declarations: %#v", parsed.Symbols)
	}
	var run analysis.Symbol
	for _, symbol := range parsed.Symbols {
		if symbol.Name == "run" {
			run = symbol
			break
		}
	}
	if run.Name == "" || len(run.Parameters) != 1 || run.Parameters[0].Name != "input" {
		t.Fatalf("library callable signature lost parameters: %#v", parsed.Symbols)
	}
}

func TestMultiReleaseArchiveSelectsHighestCompatibleLogicalClass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multi-release.jar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entries := map[string]string{
		"META-INF/MANIFEST.MF":                "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
		"demo/Api.class":                      "base",
		"META-INF/versions/11/demo/Api.class": "v11",
		"META-INF/versions/17/demo/Api.class": "v17",
		"META-INF/versions/21/demo/Api.class": "v21",
		"demo/Other.class":                    "other",
	}
	for name, content := range entries {
		entry, createErr := writer.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := entry.Write([]byte(content)); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	selected := selectedArchiveFiles(sourceArchive{path: path, binary: true, release: 17}, reader.File)
	selectedNames := make(map[string]bool)
	for _, entry := range selected {
		selectedNames[entry.Name] = true
	}
	if len(selected) != 2 || !selectedNames["META-INF/versions/17/demo/Api.class"] || !selectedNames["demo/Other.class"] {
		t.Fatalf("multi-release selection = %#v", selectedNames)
	}
}

func TestOpeningVirtualLibraryDocumentPreservesLibraryIdentity(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("jar:///cache/library-sources.jar!/demo/Service.java")
	source := "package demo; public class Service { public String run() { return \"ok\"; } }"
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument(uri, "java", 0, source))
	idx.AddLibraryBatch([]LibraryFile{{
		Source: LibrarySource{Archive: "/cache/library-sources.jar", Entry: "demo/Service.java", LanguageID: "java"},
		Parsed: *parsed,
	}})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	for _, symbol := range idx.SymbolsInFile(uri) {
		if !symbol.Library {
			t.Fatalf("opened library symbol %s lost its library identity", symbol.Name)
		}
	}
}

func TestSemanticDiagnosticsAcrossKotlinAndJava(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	javaURI := protocol.URI("file:///workspace/src/Widget.java")
	kotlinURI := protocol.URI("file:///workspace/src/Use.kt")
	idx.Open(ctx, protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: "package model; public class Widget {}"})
	idx.Open(ctx, protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: "package app\nimport model.Widget\nimport model.Missing\nfun use(value: Widget): Unknown = makeMissing()\n"})

	diagnostics := idx.Diagnostics(kotlinURI)
	if hasDiagnostic(diagnostics, "unresolved-import", "model.Widget") {
		t.Fatalf("cross-language import was reported unresolved: %#v", diagnostics)
	}
	for _, expected := range []struct{ code, text string }{{"unresolved-import", "model.Missing"}, {"UNRESOLVED_REFERENCE", "Unknown"}, {"UNRESOLVED_REFERENCE", "makeMissing"}} {
		if !hasDiagnostic(diagnostics, expected.code, expected.text) {
			t.Fatalf("missing diagnostic %s/%s: %#v", expected.code, expected.text, diagnostics)
		}
	}
}

func TestLexicalScopeMemberCompletionAndTransitiveImplementations(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	baseURI := protocol.URI("file:///workspace/Base.java")
	midURI := protocol.URI("file:///workspace/Mid.kt")
	leafURI := protocol.URI("file:///workspace/Leaf.java")
	base := "package demo; public interface Base { void work(); } class Foreign { void shouldNotLeak() {} }"
	mid := "package demo\nopen class Mid : Base { override fun work() {}\nfun scoped() { val local = this; local.work() }\n}\n"
	leaf := "package demo; public class Leaf extends Mid { public void use() { this.work(); } }"
	idx.Open(ctx, protocol.TextDocumentItem{URI: baseURI, LanguageID: "java", Version: 1, Text: base})
	idx.Open(ctx, protocol.TextDocumentItem{URI: midURI, LanguageID: "kotlin", Version: 1, Text: mid})
	idx.Open(ctx, protocol.TextDocumentItem{URI: leafURI, LanguageID: "java", Version: 1, Text: leaf})

	baseDoc := textdoc.NewDocument(baseURI, "java", 1, base)
	implementations := idx.Implementations(baseURI, baseDoc.Position(strings.Index(base, "Base")))
	if !containsNamedSymbol(implementations, "Mid") || !containsNamedSymbol(implementations, "Leaf") {
		t.Fatalf("transitive implementations missing: %#v", implementations)
	}

	leafDoc := textdoc.NewDocument(leafURI, "java", 1, leaf)
	completion := idx.Completion(leafURI, leafDoc.Position(strings.Index(leaf, "this.work")+len("this.")), 100)
	if !containsNamedSymbol(completion, "work") {
		t.Fatalf("inherited member completion missing: %#v", completion)
	}
	if containsNamedSymbol(completion, "shouldNotLeak") {
		t.Fatalf("unrelated class member leaked into completion: %#v", completion)
	}
}

func TestKotlinExtensionFunctionCompletionAndDefinition(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	extensionURI := protocol.URI("file:///workspace/Extensions.kt")
	useURI := protocol.URI("file:///workspace/Use.kt")
	extension := "package helpers\nfun String.emphasize(times: Int): String = this\n"
	use := "package app\nimport helpers.emphasize\nfun use(value: String) = value.emphasize(2)\n"
	idx.Open(ctx, protocol.TextDocumentItem{URI: extensionURI, LanguageID: "kotlin", Version: 1, Text: extension})
	idx.Open(ctx, protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: use})
	doc := textdoc.NewDocument(useURI, "kotlin", 1, use)
	position := doc.Position(strings.Index(use, "value.emphasize") + len("value."))
	if !containsNamedSymbol(idx.Completion(useURI, position, 100), "emphasize") {
		t.Fatal("extension function missing from member completion")
	}
	definitions := idx.Definitions(useURI, doc.Position(strings.Index(use, "emphasize(2)")))
	if !containsSymbol(definitions, "emphasize", analysis.KindFunction, extensionURI) {
		t.Fatalf("extension definition failed: %#v", definitions)
	}
}

func TestQualifiedPackageAndLibraryImportCompletion(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	libraryURI := protocol.URI("jrt://java.base/java/util/List.java")
	librarySource := "package java.util; public interface List<E> {}"
	parsed := analysis.Parse(ctx, textdoc.NewDocument(libraryURI, "java", 0, librarySource))
	idx.AddLibraryBatch([]LibraryFile{{Parsed: *parsed}})

	for _, fixture := range []struct {
		source, want string
	}{
		{"import java.ut", "util"},
		{"import java.util.Li", "List"},
	} {
		uri := protocol.URI("file:///workspace/Import" + fixture.want + ".kt")
		idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, "kotlin", 1, fixture.source)
		items := idx.Completion(uri, doc.Position(len(fixture.source)), 100)
		if !containsNamedSymbol(items, fixture.want) {
			t.Fatalf("%q completion missing %q: %#v", fixture.source, fixture.want, items)
		}
	}
}

func TestImportsPackagesAndDeletedFilesRemainNavigableAndFresh(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	widgetURI := protocol.URI("file:///workspace/model/Widget.java")
	useURI := protocol.URI("file:///workspace/app/Use.kt")
	widget := "package model; public class Widget {}"
	use := "package app\nimport model.Widget\nfun use(value: Widget) = value\n"
	idx.Open(ctx, protocol.TextDocumentItem{URI: widgetURI, LanguageID: "java", Version: 1, Text: widget})
	idx.Open(ctx, protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: use})
	doc := textdoc.NewDocument(useURI, "kotlin", 1, use)
	importPosition := doc.Position(strings.Index(use, "Widget"))
	if definitions := idx.Definitions(useURI, importPosition); !containsSymbol(definitions, "Widget", analysis.KindClass, widgetURI) {
		t.Fatalf("import definition failed: %#v", definitions)
	}
	packagePosition := doc.Position(strings.Index(use, "model"))
	locations := idx.PackageDefinitions(useURI, packagePosition)
	if len(locations) != 1 || locations[0].URI != "file:///workspace/model" {
		t.Fatalf("package definitions = %#v", locations)
	}
	idx.Remove(widgetURI)
	if definitions := idx.Definitions(useURI, importPosition); len(definitions) != 0 {
		t.Fatalf("deleted declaration remained indexed: %#v", definitions)
	}
}

func TestUnimportedKotlinExtensionDoesNotResolve(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	extensionURI := protocol.URI("file:///workspace/Extensions.kt")
	useURI := protocol.URI("file:///workspace/Use.kt")
	idx.Open(ctx, protocol.TextDocumentItem{URI: extensionURI, LanguageID: "kotlin", Version: 1, Text: "package helpers\nfun String.hidden() = this\n"})
	use := "package app\nfun use(value: String) = value.hidden()\n"
	idx.Open(ctx, protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: use})
	doc := textdoc.NewDocument(useURI, "kotlin", 1, use)
	definitions := idx.Definitions(useURI, doc.Position(strings.Index(use, "hidden")))
	if len(definitions) != 0 {
		t.Fatalf("unimported extension resolved: %#v", definitions)
	}
}

func TestJavacDiagnosticsAreParsedWithoutEnteringRequestPath(t *testing.T) {
	output := "/workspace/src/Broken.java:7: error: cannot find symbol\n/workspace/src/Broken.java:9: warning: [deprecation] old() has been deprecated\n"
	diagnostics := parseJavacDiagnostics(output)["file:///workspace/src/Broken.java"]
	if len(diagnostics) != 2 || diagnostics[0].Range.Start.Line != 6 || diagnostics[0].Severity != 1 || diagnostics[1].Severity != 2 {
		t.Fatalf("javac diagnostics = %#v", diagnostics)
	}
}

func TestJavacDiagnosticsAreVisibleForOpenDocuments(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac is unavailable")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "Broken.java")
	diskSource := `class Broken { void run() { int value = 1; } }`
	openSource := `class Broken { void run() { int value = "not an int"; } }`
	if err := os.WriteFile(path, []byte(diskSource), 0o600); err != nil {
		t.Fatal(err)
	}
	idx := New(nil)
	uri := protocol.URI("file://" + path)
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: openSource})
	idx.scanJavaCompilerDiagnostics(context.Background(), idx.generation.Load())
	found := false
	for _, diagnostic := range idx.Diagnostics(uri) {
		if diagnostic.Source == "javac" && diagnostic.Severity == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("open Java document did not receive compiler diagnostics: %#v", idx.Diagnostics(uri))
	}
}

func TestKotlincDiagnosticsAreParsed(t *testing.T) {
	output := "/workspace/src/Broken.kt:2:23: error: [RETURN_TYPE_MISMATCH] Return type mismatch: expected 'String', actual 'Int'.\n" +
		"/workspace/src/Broken.kt:3:15: warning: [DEPRECATION] Deprecated declaration.\n"
	diagnostics := parseKotlincDiagnostics(output)["file:///workspace/src/Broken.kt"]
	if len(diagnostics) != 2 || diagnostics[0].Range.Start != (protocol.Position{Line: 1, Character: 22}) || diagnostics[0].Code != "RETURN_TYPE_MISMATCH" || diagnostics[1].Severity != 2 {
		t.Fatalf("kotlinc diagnostics = %#v", diagnostics)
	}
}

func TestCompilerDiagnosticParsingDoesNotStopAfterLongLine(t *testing.T) {
	longLine := strings.Repeat("x", 70<<10)
	javac := parseJavacDiagnostics(longLine + "\n/workspace/src/Later.java:8: error: complete javac result\n")
	if diagnostics := javac["file:///workspace/src/Later.java"]; len(diagnostics) != 1 || diagnostics[0].Message != "complete javac result" {
		t.Fatalf("javac diagnostics after long line = %#v", diagnostics)
	}
	kotlinc := parseKotlincDiagnostics(longLine + "\n/workspace/src/Later.kt:9:3: error: [LATER] complete kotlinc result\n")
	if diagnostics := kotlinc["file:///workspace/src/Later.kt"]; len(diagnostics) != 1 || diagnostics[0].Code != "LATER" {
		t.Fatalf("kotlinc diagnostics after long line = %#v", diagnostics)
	}
}

func TestKotlincDiagnosticsAreVisibleForOpenDocuments(t *testing.T) {
	compiler, ok := findKotlinCompiler()
	if !ok {
		t.Skip("Kotlin compiler is unavailable")
	}
	_ = compiler
	directory := t.TempDir()
	path := filepath.Join(directory, "Broken.kt")
	diskSource := "fun broken(): String = \"ok\"\n"
	openSource := "fun broken(): String = 42\n"
	if err := os.WriteFile(path, []byte(diskSource), 0o600); err != nil {
		t.Fatal(err)
	}
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file://" + path)
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: openSource})
	idx.scanKotlinCompilerDiagnostics(context.Background(), idx.generation.Load())
	found := false
	for _, diagnostic := range idx.Diagnostics(uri) {
		if diagnostic.Source == "kotlinc" && diagnostic.Code == "RETURN_TYPE_MISMATCH" && diagnostic.Severity == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("open Kotlin document did not receive compiler diagnostics: %#v", idx.Diagnostics(uri))
	}
}

func TestMixedJavaKotlinCompilerDiagnosticsShareUnsavedSourceSet(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac is unavailable")
	}
	if _, ok := findKotlinCompiler(); !ok {
		t.Skip("Kotlin compiler is unavailable")
	}
	directory := t.TempDir()
	kotlinPath := filepath.Join(directory, "CrossK.kt")
	javaPath := filepath.Join(directory, "CrossJ.java")
	kotlinSource := "package mixed\nclass CrossK\nfun useJ(j: CrossJ): Int = j.value\n"
	javaSource := "package mixed; public class CrossJ { public int value = 1; public CrossK make() { return new CrossK(); } }\n"
	if err := os.WriteFile(kotlinPath, []byte("package mixed\nclass CrossK\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(javaPath, []byte("package mixed; public class CrossJ {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	idx := New(nil)
	defer idx.Close()
	kotlinURI, javaURI := protocol.URI("file://"+kotlinPath), protocol.URI("file://"+javaPath)
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	generation := idx.generation.Load()
	idx.scanJavaCompilerDiagnostics(context.Background(), generation)
	idx.scanKotlinCompilerDiagnostics(context.Background(), generation)
	for _, uri := range []protocol.URI{kotlinURI, javaURI} {
		for _, diagnostic := range idx.Diagnostics(uri) {
			if diagnostic.Source == "javac" || diagnostic.Source == "kotlinc" {
				t.Fatalf("valid mixed unsaved sources produced compiler diagnostic for %s: %#v", uri, diagnostic)
			}
		}
	}
}

func TestCompilerUnitsRespectModuleAndSourceSetVisibility(t *testing.T) {
	root := t.TempDir()
	appDir, libDir, isolatedDir := filepath.Join(root, "app"), filepath.Join(root, "lib"), filepath.Join(root, "isolated")
	appMain := filepath.Join(appDir, "src", "main", "java")
	appTest := filepath.Join(appDir, "src", "test", "java")
	libMain := filepath.Join(libDir, "src", "main", "java")
	libTest := filepath.Join(libDir, "src", "test", "java")
	isolatedMain := filepath.Join(isolatedDir, "src", "main", "java")
	idx := New(nil)
	defer idx.Close()
	idx.setModules([]ModuleInfo{
		{Name: ":app", Root: root, Dir: appDir, SourceRoots: []string{appMain, appTest}, SourceSets: map[string][]string{"main": {appMain}, "test": {appTest}}, DependenciesBySourceSet: map[string][]string{"main": {":lib"}, "test": {":lib"}}},
		{Name: ":lib", Root: root, Dir: libDir, SourceRoots: []string{libMain, libTest}, SourceSets: map[string][]string{"main": {libMain}, "test": {libTest}}},
		{Name: ":isolated", Root: root, Dir: isolatedDir, SourceRoots: []string{isolatedMain}, SourceSets: map[string][]string{"main": {isolatedMain}}},
	})
	paths := []string{
		filepath.Join(appMain, "AppMain.java"), filepath.Join(appTest, "AppTest.java"),
		filepath.Join(libMain, "LibMain.java"), filepath.Join(libTest, "LibTest.java"),
		filepath.Join(isolatedMain, "Isolated.java"),
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".java")
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uriutil.File(path), LanguageID: "java", Version: 1, Text: "class " + name + " {}\n"})
	}
	units := idx.compilerUnits(idx.WorkspaceFiles())
	var mainInputs, testInputs map[protocol.URI]bool
	for _, unit := range units {
		if len(unit.Primary) != 1 {
			continue
		}
		inputs := make(map[protocol.URI]bool)
		for _, file := range unit.Inputs {
			inputs[file.URI] = true
		}
		switch unit.Primary[0].URI {
		case uriutil.File(paths[0]):
			mainInputs = inputs
		case uriutil.File(paths[1]):
			testInputs = inputs
		}
	}
	if !mainInputs[uriutil.File(paths[0])] || !mainInputs[uriutil.File(paths[2])] || mainInputs[uriutil.File(paths[1])] || mainInputs[uriutil.File(paths[3])] || mainInputs[uriutil.File(paths[4])] {
		t.Fatalf("app main compiler inputs leaked source sets/modules: %#v", mainInputs)
	}
	if !testInputs[uriutil.File(paths[0])] || !testInputs[uriutil.File(paths[1])] || !testInputs[uriutil.File(paths[2])] || testInputs[uriutil.File(paths[3])] || testInputs[uriutil.File(paths[4])] {
		t.Fatalf("app test compiler inputs leaked source sets/modules: %#v", testInputs)
	}
}

func TestJavacDiagnosticsDoNotResolveUnrelatedModuleSources(t *testing.T) {
	if _, err := exec.LookPath("javac"); err != nil {
		t.Skip("javac is unavailable")
	}
	root := t.TempDir()
	appRoot, unrelatedRoot := filepath.Join(root, "app", "src", "main", "java"), filepath.Join(root, "unrelated", "src", "main", "java")
	idx := New(nil)
	defer idx.Close()
	idx.setModules([]ModuleInfo{
		{Name: ":app", Root: root, Dir: filepath.Join(root, "app"), SourceRoots: []string{appRoot}, SourceSets: map[string][]string{"main": {appRoot}}},
		{Name: ":unrelated", Root: root, Dir: filepath.Join(root, "unrelated"), SourceRoots: []string{unrelatedRoot}, SourceSets: map[string][]string{"main": {unrelatedRoot}}},
	})
	appURI := uriutil.File(filepath.Join(appRoot, "Use.java"))
	unrelatedURI := uriutil.File(filepath.Join(unrelatedRoot, "Hidden.java"))
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: appURI, LanguageID: "java", Version: 1, Text: "package shared; class Use { Hidden value; }\n"})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: unrelatedURI, LanguageID: "java", Version: 1, Text: "package shared; class Hidden {}\n"})
	idx.scanJavaCompilerDiagnostics(context.Background(), idx.generation.Load())
	found := false
	for _, diagnostic := range idx.Diagnostics(appURI) {
		if diagnostic.Source == "javac" && diagnostic.Severity == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("unrelated module source leaked into javac invocation: %#v", idx.Diagnostics(appURI))
	}
}

func TestMemberCompletionInfersConstructorAndFactoryInitializerTypes(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	kotlinURI := protocol.URI("file:///workspace/Use.kt")
	kotlin := "class Service { fun execute() {} }\nfun makeService(): Service = Service()\nfun use() { val direct = Service(); direct.toString()\nval factory = makeService(); factory.toString() }\n"
	idx.Open(ctx, protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlin})
	doc := textdoc.NewDocument(kotlinURI, "kotlin", 1, kotlin)
	for _, marker := range []string{"direct.", "factory."} {
		position := doc.Position(strings.Index(kotlin, marker) + len(marker))
		if !containsNamedSymbol(idx.Completion(kotlinURI, position, 100), "execute") {
			t.Fatalf("member completion failed for %s", marker)
		}
	}

	javaURI := protocol.URI("file:///workspace/Use.java")
	java := "class Worker { void run() {} } class Use { void use() { Worker worker = new Worker(); worker.toString(); } }"
	idx.Open(ctx, protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: java})
	javaDoc := textdoc.NewDocument(javaURI, "java", 1, java)
	position := javaDoc.Position(strings.Index(java, "worker.toString") + len("worker."))
	if !containsNamedSymbol(idx.Completion(javaURI, position, 100), "run") {
		t.Fatal("Java constructor-initialized member completion failed")
	}
}

func TestKotlinCompanionMembersResolveAndCompleteThroughContainingType(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Companion.kt")
	source := "class C { companion object { fun make(): C = C() } }\nfun use() { C.make() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	call := strings.LastIndex(source, "make")
	definitions := idx.Definitions(uri, doc.Position(call))
	if len(definitions) != 1 || definitions[0].Name != "make" || definitions[0].ContainerName != "Companion" {
		t.Fatalf("companion definition = %#v", definitions)
	}
	completions := idx.Completion(uri, doc.Position(call+2), 0)
	found := false
	for _, completion := range completions {
		if completion.Name == "make" && completion.ContainerName == "Companion" {
			found = true
		}
	}
	if !found {
		t.Fatalf("companion completion missing from %#v", completions)
	}
}

func TestKotlinIfIsSmartCastRefinesOnlyTheGuardedBranch(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/SmartCast.kt")
	source := "open class Base\nclass Sub : Base() { fun special(): Int = 1 }\nfun use(x: Base) { if (x is Sub) { x.special() }; x.special() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	inside := strings.Index(source, "x.special") + 2
	definitions := idx.Definitions(uri, doc.Position(inside))
	if len(definitions) != 1 || definitions[0].Name != "special" || definitions[0].ContainerName != "Sub" {
		t.Fatalf("smart-cast definition = %#v", definitions)
	}
	outside := strings.LastIndex(source, "x.special") + 2
	if definitions := idx.Definitions(uri, doc.Position(outside)); len(definitions) != 0 {
		t.Fatalf("smart cast leaked outside guarded branch: %#v", definitions)
	}
}

func TestKotlinSmartCastFactsApplyToConjunctionRHSAndIntersectInBody(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/SmartIntersection.kt")
	source := "interface SmartLeft { fun left() {} }\n" +
		"interface SmartRight { fun right() {} }\n" +
		"fun use(value: Any) { if (value is SmartLeft && value.left()) value.left(); if (value is SmartLeft && value is SmartRight) { value.left(); value.right() } }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	for _, offset := range []int{
		strings.Index(source, "value.left()"),
		strings.LastIndex(source, "value.left()"),
		strings.LastIndex(source, "value.right()"),
	} {
		definitions := idx.Definitions(uri, doc.Position(offset+len("value.")))
		if len(definitions) != 1 {
			t.Fatalf("smart-cast member at %d = %#v", offset, definitions)
		}
	}
}

func TestKotlinWhenAndEarlyExitSmartCastsRefineTheirScopes(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/SmartCastScopes.kt")
	source := "open class Base\nclass Sub : Base() { fun special(): Int = 1 }\n" +
		"fun fromWhen(x: Base) { when (x) { is Sub -> x.special(); else -> Unit }; x.special() }\n" +
		"fun afterExit(x: Base) { if (x !is Sub) return; x.special() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	whenInside := strings.Index(source, "x.special") + 2
	if definitions := idx.Definitions(uri, doc.Position(whenInside)); len(definitions) != 1 || definitions[0].ContainerName != "Sub" {
		t.Fatalf("when smart-cast definition = %#v", definitions)
	}
	whenOutside := strings.Index(source[whenInside+1:], "x.special") + whenInside + 3
	if definitions := idx.Definitions(uri, doc.Position(whenOutside)); len(definitions) != 0 {
		t.Fatalf("when smart cast leaked past its entry: %#v", definitions)
	}
	earlyExit := strings.LastIndex(source, "x.special") + 2
	if definitions := idx.Definitions(uri, doc.Position(earlyExit)); len(definitions) != 1 || definitions[0].ContainerName != "Sub" {
		t.Fatalf("early-exit smart-cast definition = %#v", definitions)
	}
}

func TestKotlinNullCheckRefinesOnlyGuardedScopeAndRejectsUnsafeNullableCall(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/NullSmartCast.kt")
	source := "class NullableSub { fun special(): Int = 1 }\n" +
		"fun use(value: NullableSub?) { if (value != null) value.special(); value.special(); value?.special(); value!!.special() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	positions := make([]int, 0, 4)
	for offset := 0; ; {
		index := strings.Index(source[offset:], "special()")
		if index < 0 {
			break
		}
		positions = append(positions, offset+index)
		offset += index + len("special()")
	}
	if len(positions) != 5 {
		t.Fatalf("special positions = %#v", positions)
	}
	for _, index := range []int{1, 3, 4} {
		if definitions := idx.Definitions(uri, doc.Position(positions[index])); len(definitions) != 1 {
			t.Fatalf("nullable permitted call %d = %#v", index, definitions)
		}
	}
	if definitions := idx.Definitions(uri, doc.Position(positions[2])); len(definitions) != 0 {
		t.Fatalf("unsafe nullable call resolved outside smart cast: %#v", definitions)
	}
}

func TestKotlinExtensionLambdaContextProvidesImplicitReceiver(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/ReceiverLambda.kt")
	source := "class ReceiverOnly { fun receiverMember(): Int = 1 }\n" +
		"fun acceptReceiver(block: ReceiverOnly.() -> Unit) {}\n" +
		"fun use() { acceptReceiver { receiverMember() } }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	call := strings.LastIndex(source, "receiverMember")
	definitions := idx.Definitions(uri, doc.Position(call))
	if len(definitions) != 1 || definitions[0].Name != "receiverMember" || definitions[0].ContainerName != "ReceiverOnly" {
		t.Fatalf("extension-lambda receiver definition = %#v", definitions)
	}
}

func TestKotlinApplicableMemberWinsBeforeMoreSpecificExtension(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/MemberPriority.kt")
	source := "class MemberWins { fun choose(value: Any): Int = 1 }\n" +
		"fun MemberWins.choose(value: String): Int = 2\n" +
		"fun use(value: MemberWins) { value.choose(\"x\") }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	call := strings.LastIndex(source, "choose")
	definitions := idx.Definitions(uri, doc.Position(call))
	if len(definitions) != 1 || definitions[0].ReceiverType != "" || definitions[0].ContainerName != "MemberWins" {
		t.Fatalf("member-over-extension definition = %#v", definitions)
	}
}

func TestKotlinGenericExtensionsResolveAndPropagateSubstitutedResultTypes(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/GenericExtensions.kt")
	source := "class ExtensionSub { fun special(): Int = 1 }\n" +
		"class ExtensionBox<T>(val value: T)\n" +
		"fun <T> ExtensionBox<T>.unwrap(): T = value\n" +
		"val <T> List<T>.head: T get() = first()\n" +
		"val List<ExtensionSub>.fixed: ExtensionSub get() = first()\n" +
		"fun use(box: ExtensionBox<ExtensionSub>, values: List<ExtensionSub>) { box.unwrap().special(); values.head.special(); values.fixed.special() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	for _, fixture := range []struct {
		needle, want string
	}{
		{"unwrap()", "unwrap"},
		{"head.special", "head"},
		{"unwrap().special", "special"},
		{"head.special", "special"},
		{"fixed.special", "special"},
	} {
		at := strings.LastIndex(source, fixture.needle)
		if fixture.want == "special" {
			at += strings.LastIndex(fixture.needle, fixture.want)
		}
		definitions := idx.Definitions(uri, doc.Position(at))
		if len(definitions) != 1 || definitions[0].Name != fixture.want {
			t.Fatalf("%s -> %s definition = %#v", fixture.needle, fixture.want, definitions)
		}
	}
}

func TestKotlinExplicitImportWinsOverSamePackageDeclaration(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	pURI := protocol.URI("file:///workspace/p/Foo.kt")
	qURI := protocol.URI("file:///workspace/q/Foo.kt")
	useURI := protocol.URI("file:///workspace/p/Use.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: pURI, LanguageID: "kotlin", Version: 1, Text: "package p\nclass Foo\n"})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: qURI, LanguageID: "kotlin", Version: 1, Text: "package q\nclass Foo\n"})
	source := "package p\nimport q.Foo\nfun make(): Foo = Foo()\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(useURI, "kotlin", 1, source)
	call := strings.LastIndex(source, "Foo")
	definitions := idx.Definitions(useURI, doc.Position(call))
	if len(definitions) != 1 || definitions[0].Package != "q" {
		t.Fatalf("explicit-import definition = %#v", definitions)
	}
}

func TestKotlinAliasImportTokenResolvesImportedType(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	declarationURI := protocol.URI("file:///workspace/q/Alias.kt")
	useURI := protocol.URI("file:///workspace/p/UseAlias.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: declarationURI, LanguageID: "kotlin", Version: 1, Text: "package q\nclass Alias { fun member() {} }\n"})
	source := "package p\nimport q.Alias as Renamed\nfun use() { Renamed().member() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(useURI, "kotlin", 1, source)
	for _, position := range []int{strings.Index(source, "Renamed"), strings.LastIndex(source, "Renamed")} {
		definitions := idx.Definitions(useURI, doc.Position(position))
		if len(definitions) != 1 || definitions[0].URI != declarationURI || definitions[0].Name != "Alias" {
			t.Fatalf("alias-import definition at %d = %#v; symbols = %#v", position, definitions, idx.SymbolsInFile(useURI))
		}
	}
}

func TestJavaOverloadResolutionUsesInvocationConversions(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Overloads.java")
	source := "class Overloads { static void pick(long value) {} static void pick(String value) {} static void phase(long value) {} static void phase(Object value) {} void use() { pick(1); Integer boxed = 1; phase(boxed); } }"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	call := strings.LastIndex(source, "pick")
	definitions := idx.Definitions(uri, doc.Position(call))
	if len(definitions) != 1 || len(definitions[0].Parameters) != 1 || simpleType(definitions[0].Parameters[0].Type) != "long" {
		t.Fatalf("primitive-widening overload definition = %#v", definitions)
	}
	phaseCall := strings.LastIndex(source, "phase")
	definitions = idx.Definitions(uri, doc.Position(phaseCall))
	if len(definitions) != 1 || len(definitions[0].Parameters) != 1 || simpleType(definitions[0].Parameters[0].Type) != "Object" {
		t.Fatalf("strict reference phase did not precede loose unboxing: %#v", definitions)
	}
}

func TestKotlinOverloadsPreferExactArityAndNullableNullTarget(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/KotlinOverloads.kt")
	source := "fun defaulted(value: Int, other: String = \"x\"): String = other\n" +
		"fun defaulted(value: Int): String = value.toString()\n" +
		"fun nullable(value: String?): String = \"nullable\"\n" +
		"fun nullable(value: Any): String = \"any\"\n" +
		"fun use() { defaulted(1); nullable(null) }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	defaultedCall := strings.LastIndex(source, "defaulted")
	definitions := idx.Definitions(uri, doc.Position(defaultedCall))
	if len(definitions) != 1 || len(definitions[0].Parameters) != 1 {
		t.Fatalf("exact-arity overload = %#v", definitions)
	}
	nullableCall := strings.LastIndex(source, "nullable")
	definitions = idx.Definitions(uri, doc.Position(nullableCall))
	if len(definitions) != 1 || len(definitions[0].Parameters) != 1 || !strings.HasSuffix(definitions[0].Parameters[0].Type, "?") {
		t.Fatalf("nullable null overload = %#v", definitions)
	}
}

func TestExplicitLambdaParameterTypesFilterKotlinAndJavaOverloads(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	fixtures := []struct {
		uri      protocol.URI
		language string
		source   string
		wantLine int
	}{
		{
			uri: "file:///workspace/TypedLambda.kt", language: "kotlin", wantLine: 1,
			source: "fun choose(block: (Int) -> Unit) {}\nfun choose(block: (String) -> Unit, marker: Int = 0) {}\nfun use() { choose { value: String -> println(value) } }\n",
		},
		{
			uri: "file:///workspace/TypedLambda.java", language: "java", wantLine: 4,
			source: "interface IntSink { void accept(Integer value); }\ninterface StringSink { void accept(String value); }\nclass TypedLambda {\n static void choose(IntSink block) {}\n static void choose(StringSink block) {}\n void use() { choose((String value) -> System.out.println(value)); }\n}\n",
		},
	}
	for _, fixture := range fixtures {
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: fixture.uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(fixture.uri, fixture.language, 1, fixture.source)
		definitions := idx.Definitions(fixture.uri, doc.Position(strings.LastIndex(fixture.source, "choose")))
		if len(definitions) != 1 || definitions[0].SelectionRange.Start.Line != fixture.wantLine {
			t.Fatalf("%s typed-lambda overload = %#v", fixture.language, definitions)
		}
	}
}

func TestInheritedGenericMemberReturnTypesPropagateArguments(t *testing.T) {
	for _, fixture := range []struct {
		uri, language, source, marker, expected string
	}{
		{"file:///workspace/Generic.java", "java", "class Result { void special() {} } class Parent<T> { T get() { return null; } } class Child extends Parent<Result> {} class Use { void use(Child child) { child.get().special(); } }", "special();", "Result"},
		{"file:///workspace/Generic.kt", "kotlin", "class KResult {\nfun special() {}\n}\nopen class KParent<T> {\nfun get(): T = TODO()\n}\nclass KChild : KParent<KResult>()\nfun use(child: KChild) { child.get().special() }\n", "special()", "KResult"},
	} {
		idx := New(nil)
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		position := strings.LastIndex(fixture.source, fixture.marker)
		definitions := idx.Definitions(uri, doc.Position(position))
		if len(definitions) != 1 || definitions[0].ContainerName != fixture.expected {
			t.Fatalf("%s inherited generic member definition = %#v; symbols = %#v", fixture.language, definitions, idx.SymbolsInFile(uri))
		}
		idx.Close()
	}
}

func TestKotlinMetadataDecodesDefaultsAndFileFacadeFunctions(t *testing.T) {
	valueWithDefault := []byte{8, 2, 16, 0}
	valueRequired := []byte{16, 1}
	constructor := append([]byte{18, byte(len(valueWithDefault))}, valueWithDefault...)
	constructor = append(constructor, 18, byte(len(valueRequired)))
	constructor = append(constructor, valueRequired...)
	classMessage := append([]byte{66, byte(len(constructor))}, constructor...)
	classData := append([]byte{0}, classMessage...) // empty delimited JVM name table
	classData = append([]byte{0}, classData...)     // direct-byte BitEncoding marker
	decoded := decodeKotlinBinaryMetadata(&classfile.KotlinMetadata{Kind: 1, Data1: []string{string(classData)}, Data2: []string{"optional", "required"}})
	if len(decoded.Constructors) != 1 || len(decoded.Constructors[0].Parameters) != 2 || !decoded.Constructors[0].Parameters[0].HasDefault || decoded.Constructors[0].Parameters[1].HasDefault {
		t.Fatalf("decoded constructor metadata = %#v", decoded)
	}

	parameter := []byte{16, 1}
	function := []byte{16, 0, 50, byte(len(parameter))}
	function = append(function, parameter...)
	function = append(function, 64, 0) // receiver_type_id
	packageMessage := append([]byte{26, byte(len(function))}, function...)
	packageData := append([]byte{0, 0}, packageMessage...)
	metadata := &classfile.KotlinMetadata{Kind: 2, Data1: []string{string(packageData)}, Data2: []string{"extend", "value"}}
	parsed := &analysis.ParsedFile{Language: analysis.LanguageJava, Package: "demo", Symbols: []analysis.Symbol{
		{ID: "owner", Name: "FileKt", FQN: "demo.FileKt", Kind: analysis.KindClass},
		{ID: "method", Name: "extend", FQN: "demo.FileKt.extend", Kind: analysis.KindMethod, ContainerID: "owner", ContainerName: "FileKt", Type: "String", Parameters: []analysis.Parameter{{Name: "receiver", Type: "Target"}, {Name: "value", Type: "int"}}},
	}}
	applyKotlinBinaryMetadata(parsed, &classfile.Class{InternalName: "demo/FileKt", KotlinMetadata: metadata})
	if len(parsed.Symbols) != 3 {
		t.Fatalf("file facade symbols = %#v", parsed.Symbols)
	}
	topLevel := parsed.Symbols[2]
	if topLevel.FQN != "demo.extend" || topLevel.ReceiverType != "Target" || len(topLevel.Parameters) != 1 || topLevel.InteropLanguage != analysis.LanguageKotlin {
		t.Fatalf("top-level extension view = %#v", topLevel)
	}
}

func TestClassfileNullabilityAnnotationsEnrichBinarySymbols(t *testing.T) {
	parsed := &analysis.ParsedFile{Language: analysis.LanguageJava, Symbols: []analysis.Symbol{
		{ID: "owner", Name: "Model", FQN: "demo.Model", Kind: analysis.KindClass},
		{ID: "method", Name: "echo", FQN: "demo.Model.echo", Kind: analysis.KindMethod, ContainerID: "owner", ContainerName: "Model", Type: "java.lang.String", Parameters: []analysis.Parameter{{Name: "value", Type: "java.lang.String"}}},
	}}
	applyClassfileAnnotations(parsed, &classfile.Class{InternalName: "demo/Model", Methods: []classfile.Method{{
		Name: "echo", ParameterTypes: []string{"java.lang.String"}, ResultType: "java.lang.String",
		Annotations: []string{"@org.jetbrains.annotations.Nullable"}, ParameterAnnotations: [][]string{{"@org.jetbrains.annotations.Nullable"}},
	}}})
	method := parsed.Symbols[1]
	if method.Type != "java.lang.String?" || method.Parameters[0].Type != "java.lang.String?" {
		t.Fatalf("classfile nullability = %#v", method)
	}

	nested := &analysis.ParsedFile{Language: analysis.LanguageJava, Symbols: []analysis.Symbol{
		{ID: "owner", Name: "Nested", FQN: "demo.Nested", Kind: analysis.KindClass},
		{ID: "nested", Name: "values", FQN: "demo.Nested.values", Kind: analysis.KindMethod, ContainerID: "owner", ContainerName: "Nested", Type: "java.util.List<java.lang.String>", Parameters: []analysis.Parameter{{Name: "value", Type: "java.util.List<java.lang.String>"}}},
	}}
	path := []classfile.TypePathEntry{{Kind: 3, Index: 0}}
	applyClassfileAnnotations(nested, &classfile.Class{InternalName: "demo/Nested", Methods: []classfile.Method{{
		Name: "values", ParameterTypes: []string{"java.util.List<java.lang.String>"}, ResultType: "java.util.List<java.lang.String>",
		TypeAnnotations: []classfile.TypeAnnotation{
			{Annotation: "@org.jetbrains.annotations.Nullable", TargetType: 0x14, ParameterIndex: -1, TypePath: path},
			{Annotation: "@org.jetbrains.annotations.Nullable", TargetType: 0x16, ParameterIndex: 0, TypePath: path},
		},
	}}})
	if got := nested.Symbols[1]; got.Type != "java.util.List<java.lang.String?>" || got.Parameters[0].Type != "java.util.List<java.lang.String?>" {
		t.Fatalf("nested type-use nullability = %#v", got)
	}
}

func TestKotlinMetadataNestedNullabilityVisibilityAndJVMName(t *testing.T) {
	// Type.Argument.type -> Type(nullable=true).
	nestedNullable := []byte{18, 4, 18, 2, 24, 1}
	shape := decodeKotlinMetadataType(nestedNullable)
	if got := applyKotlinMetadataType("List<String>", shape); got != "List<String?>" {
		t.Fatalf("nested Kotlin metadata type = %q, shape %#v", got, shape)
	}
	// flags=INTERNAL, name=sourceName, JVM method signature name=sourceName$main.
	function := []byte{72, 0, 16, 0, 162, 6, 2, 8, 1}
	callable := decodeKotlinCallable(function, []string{"sourceName", "sourceName$main"}, false)
	if callable.Name != "sourceName" || callable.JVMName != "sourceName$main" || callable.Visibility != "internal" {
		t.Fatalf("Kotlin callable JVM metadata = %#v", callable)
	}
}

func TestKotlinNamedArgumentLabelsBindToParameters(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Named.kt")
	source := "fun greet(message: String) {}\nfun use() { greet(message = \"hello\") }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	declaration := strings.Index(source, "message")
	label := strings.LastIndex(source, "message")
	definitions := idx.Definitions(uri, doc.Position(label))
	if len(definitions) != 1 || definitions[0].Kind != analysis.KindParameter || definitions[0].NameStartByte != declaration {
		t.Fatalf("named-argument definition = %#v", definitions)
	}
	edit := idx.Rename(uri, doc.Position(declaration), "text")
	if changes := edit.Changes[uri]; len(changes) != 2 {
		t.Fatalf("named-argument rename edits = %#v", edit)
	}
}

func TestKotlinLambdaParametersUseExpectedFunctionType(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Lambdas.kt")
	source := "class Sub { fun special(): Int = 1 }\nfun accept(block: (Sub) -> Unit) {}\nfun use() { accept { it.special() }; accept { value -> value.special() } }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	first := strings.Index(source, "special() };")
	second := strings.LastIndex(source, "special()")
	for _, offset := range []int{first, second} {
		definitions := idx.Definitions(uri, doc.Position(offset))
		if len(definitions) != 1 || definitions[0].Name != "special" || definitions[0].ContainerName != "Sub" {
			parsed, _ := idx.Parsed(uri)
			t.Fatalf("lambda member definition at %d = %#v\nsymbols=%#v\nreferences=%#v", offset, definitions, parsed.Symbols, parsed.References)
		}
	}
}

func TestKotlinSafeAndNonNullCallChainsPropagateTypes(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Chains.kt")
	source := "class Sub { fun special(): Int = 1 }\nclass Child { fun next(): Sub = Sub() }\nfun use(child: Child?) { child?.next()?.special(); child!!.next().special() }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	first := strings.Index(source, "special();")
	second := strings.LastIndex(source, "special()")
	for _, offset := range []int{first, second} {
		definitions := idx.Definitions(uri, doc.Position(offset))
		if len(definitions) != 1 || definitions[0].Name != "special" || definitions[0].ContainerName != "Sub" {
			t.Fatalf("chained member definition at %d = %#v", offset, definitions)
		}
	}
}

func TestTransientTrailingDotRetainsLastValidDeclarationSnapshot(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Editing.kt")
	valid := "class Service { fun execute() {} }\nfun use() { val direct = Service(); direct.toString() }\n"
	idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: valid})
	incomplete := strings.Replace(valid, "direct.toString()", "direct.", 1)
	if _, err := idx.Change(ctx, protocol.DidChangeTextDocumentParams{
		TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: 2},
		ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: incomplete}},
	}); err != nil {
		t.Fatal(err)
	}
	doc := textdoc.NewDocument(uri, "kotlin", 2, incomplete)
	position := doc.Position(strings.Index(incomplete, "direct.") + len("direct."))
	if !containsNamedSymbol(idx.Completion(uri, position, 100), "execute") {
		t.Fatalf("completion lost declarations during transient syntax error: %#v", idx.SymbolsInFile(uri))
	}
}

func TestJavaPackagePrivateAndKotlinInternalVisibility(t *testing.T) {
	ctx := context.Background()
	idx := New(nil)
	javaURI := protocol.URI("file:///workspace/a/Hidden.java")
	useJavaURI := protocol.URI("file:///workspace/b/Use.java")
	idx.Open(ctx, protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: "package a; class Hidden {} public class PublicType {}"})
	// A type from another package is named through an import. Without one the
	// compiler rejects the reference, so neither the package-private type nor
	// the public one may resolve by simple name alone.
	javaUse := "package b;\nimport a.PublicType;\nclass Use { Hidden hidden; PublicType visible; }"
	idx.Open(ctx, protocol.TextDocumentItem{URI: useJavaURI, LanguageID: "java", Version: 1, Text: javaUse})
	doc := textdoc.NewDocument(useJavaURI, "java", 1, javaUse)
	if definitions := idx.Definitions(useJavaURI, doc.Position(strings.Index(javaUse, "Hidden"))); len(definitions) != 0 {
		t.Fatalf("package-private Java type escaped its package: %#v", definitions)
	}
	if definitions := idx.Definitions(useJavaURI, doc.Position(strings.LastIndex(javaUse, "PublicType"))); !containsNamedSymbol(definitions, "PublicType") {
		t.Fatalf("imported public Java type did not resolve: %#v", definitions)
	}
	unimportedURI := protocol.URI("file:///workspace/c/Unimported.java")
	unimported := "package c;\nclass Unimported { PublicType visible; }"
	idx.Open(ctx, protocol.TextDocumentItem{URI: unimportedURI, LanguageID: "java", Version: 1, Text: unimported})
	unimportedDoc := textdoc.NewDocument(unimportedURI, "java", 1, unimported)
	if definitions := idx.Definitions(unimportedURI, unimportedDoc.Position(strings.LastIndex(unimported, "PublicType"))); len(definitions) != 0 {
		t.Fatalf("a type that is not imported must not resolve by simple name: %#v", definitions)
	}

	internalURI := protocol.URI("file:///workspace/a/Internal.kt")
	useKotlinURI := protocol.URI("file:///workspace/b/Use.kt")
	idx.Open(ctx, protocol.TextDocumentItem{URI: internalURI, LanguageID: "kotlin", Version: 1, Text: "package a\ninternal class Shared\n"})
	kotlinUse := "package b\nimport a.Shared\nfun use(value: Shared) = value\n"
	idx.Open(ctx, protocol.TextDocumentItem{URI: useKotlinURI, LanguageID: "kotlin", Version: 1, Text: kotlinUse})
	kotlinDoc := textdoc.NewDocument(useKotlinURI, "kotlin", 1, kotlinUse)
	if definitions := idx.Definitions(useKotlinURI, kotlinDoc.Position(strings.LastIndex(kotlinUse, "Shared"))); !containsNamedSymbol(definitions, "Shared") {
		t.Fatalf("Kotlin internal type did not resolve across workspace package: %#v", definitions)
	}
}

func TestGradleModuleGraphScopesVisibilityInternalAndClasspath(t *testing.T) {
	root := t.TempDir()
	apiDir, appDir, isolatedDir := filepath.Join(root, "api"), filepath.Join(root, "app"), filepath.Join(root, "isolated")
	for _, directory := range []string{apiDir, appDir, isolatedDir} {
		if err := os.MkdirAll(filepath.Join(directory, "src", "main", "kotlin"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "build.gradle.kts"), []byte("plugins { kotlin(\"jvm\") }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(appDir, "build.gradle.kts"), []byte("dependencies { implementation(project(\":api\")) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	apiOutput := filepath.Join(apiDir, "build", "classes", "kotlin", "main")
	if err := os.MkdirAll(apiOutput, 0o700); err != nil {
		t.Fatal(err)
	}
	modules := discoverModules([]string{root})
	idx := New(nil)
	idx.setModules(modules)
	apiPath := filepath.Join(apiDir, "src", "main", "kotlin", "Api.kt")
	appPath := filepath.Join(appDir, "src", "main", "kotlin", "App.kt")
	isolatedPath := filepath.Join(isolatedDir, "src", "main", "kotlin", "Other.kt")
	apiURI, appURI, isolatedURI := uriutil.File(apiPath), uriutil.File(appPath), uriutil.File(isolatedPath)
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: apiURI, LanguageID: "kotlin", Version: 1, Text: "package api\nclass PublicApi\ninternal class InternalApi\n"})
	appSource := "package app\nimport api.PublicApi\nimport api.InternalApi\nfun publicUse(value: PublicApi) = value\nfun internalUse(value: InternalApi) = value\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: appURI, LanguageID: "kotlin", Version: 1, Text: appSource})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: isolatedURI, LanguageID: "kotlin", Version: 1, Text: "package isolated\nclass IsolatedOnly\n"})
	doc := textdoc.NewDocument(appURI, "kotlin", 1, appSource)
	if definitions := idx.Definitions(appURI, doc.Position(strings.LastIndex(appSource, "PublicApi"))); !containsNamedSymbol(definitions, "PublicApi") {
		t.Fatalf("declared project dependency is inaccessible: %#v", definitions)
	}
	if definitions := idx.Definitions(appURI, doc.Position(strings.LastIndex(appSource, "InternalApi"))); len(definitions) != 0 {
		t.Fatalf("Kotlin internal escaped its module: %#v", definitions)
	}
	module, ok := idx.ModuleFor(appURI)
	if !ok || module.Name != ":app" || len(module.Dependencies) != 1 || module.Dependencies[0] != ":api" {
		t.Fatalf("app module = %#v", module)
	}
	classpath, _, moduleName := idx.ClasspathFor(appURI)
	if moduleName != nil || !containsString(classpath, apiOutput) {
		t.Fatalf("app classpath/module = %#v, %#v", classpath, moduleName)
	}
	_ = isolatedURI
}

func TestJPMSModuleNameAndModulePathAreSeparatedFromClasspath(t *testing.T) {
	root := t.TempDir()
	appDir, libDir := filepath.Join(root, "app"), filepath.Join(root, "lib")
	appSource := filepath.Join(appDir, "src", "main", "java")
	libSource := filepath.Join(libDir, "src", "main", "java")
	for _, directory := range []string{appSource, libSource} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(appSource, "module-info.java"), []byte("module app.module { requires lib.module; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libSource, "module-info.java"), []byte("module lib.module {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{appDir, libDir} {
		if err := os.WriteFile(filepath.Join(directory, "build.gradle.kts"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(appDir, "build.gradle.kts"), []byte("dependencies { implementation(project(\":lib\")) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	modularDependency := filepath.Join(root, "modular")
	if err := os.MkdirAll(modularDependency, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modularDependency, "module-info.class"), []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	plainDependency := filepath.Join(root, "plain.jar")
	if err := os.WriteFile(plainDependency, []byte("not modular"), 0o600); err != nil {
		t.Fatal(err)
	}
	libOutput := filepath.Join(libDir, "build", "classes", "java", "main")
	if err := os.MkdirAll(libOutput, 0o700); err != nil {
		t.Fatal(err)
	}
	idx := New(nil)
	idx.setModules(discoverModules([]string{root}))
	resolution := newClasspathResolution()
	resolution.SourceSetClasspath[":app"] = map[string][]string{"main": {modularDependency, plainDependency}}
	idx.mergeModuleBuildResolution(root, resolution)
	uri := uriutil.File(filepath.Join(appSource, "App.java"))
	classpath, modulePath, moduleName := idx.ClasspathFor(uri)
	if moduleName != "app.module" || !containsString(classpath, plainDependency) || containsString(classpath, modularDependency) || !containsString(modulePath, modularDependency) {
		t.Fatalf("JPMS resolution classpath=%#v modulePath=%#v moduleName=%#v", classpath, modulePath, moduleName)
	}
	if !containsString(modulePath, libOutput) {
		t.Fatalf("named project dependency output absent from module path: %#v", modulePath)
	}
}

func TestModuleJavaHomeFollowsNearestGradleProperties(t *testing.T) {
	root := t.TempDir()
	moduleDir := filepath.Join(root, "app")
	configured := filepath.Join(root, "toolchains", "jdk-21")
	if err := os.MkdirAll(moduleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "gradle.properties"), []byte("org.gradle.java.home=toolchains/jdk-21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := moduleJavaHome(moduleDir, root); got != configured {
		t.Fatalf("module Java home = %q, want %q", got, configured)
	}
}

func TestModuleSpecificLibraryDoesNotLeakToUnrelatedModule(t *testing.T) {
	root := t.TempDir()
	aDir, bDir := filepath.Join(root, "a"), filepath.Join(root, "b")
	for _, directory := range []string{aDir, bDir} {
		if err := os.MkdirAll(filepath.Join(directory, "src", "main", "kotlin"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	idx := New(nil)
	idx.setModules([]ModuleInfo{
		{Name: ":a", Dir: aDir, SourceRoots: []string{filepath.Join(aDir, "src", "main", "kotlin")}},
		{Name: ":b", Dir: bDir, SourceRoots: []string{filepath.Join(bDir, "src", "main", "kotlin")}},
	})
	archive := filepath.Join(root, "deps", "b-only.jar")
	idx.mu.Lock()
	idx.libraryAccess[filepath.Clean(archive)] = map[string]bool{bDir: true}
	idx.mu.Unlock()
	libraryURI := protocol.URI("jar:///deps/b-only-sources.jar!/only/BOnly.java")
	libraryDoc := textdoc.NewDocument(libraryURI, "java", 0, "package only; public class BOnly {}")
	parsed := analysis.Parse(context.Background(), libraryDoc)
	idx.AddLibraryBatch([]LibraryFile{{Source: LibrarySource{Archive: archive, Entry: "only/BOnly.java", LanguageID: "java"}, Parsed: *parsed}})
	aURI := uriutil.File(filepath.Join(aDir, "src", "main", "kotlin", "Use.kt"))
	bURI := uriutil.File(filepath.Join(bDir, "src", "main", "kotlin", "Use.kt"))
	source := "package use\nimport only.BOnly\nfun use(value: BOnly) = value\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: aURI, LanguageID: "kotlin", Version: 1, Text: source})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: bURI, LanguageID: "kotlin", Version: 1, Text: source})
	aDoc, bDoc := textdoc.NewDocument(aURI, "kotlin", 1, source), textdoc.NewDocument(bURI, "kotlin", 1, source)
	position := strings.LastIndex(source, "BOnly")
	if definitions := idx.Definitions(aURI, aDoc.Position(position)); len(definitions) != 0 {
		t.Fatalf("B-only dependency leaked to module A: %#v", definitions)
	}
	if definitions := idx.Definitions(bURI, bDoc.Position(position)); !containsNamedSymbol(definitions, "BOnly") {
		t.Fatalf("B-only dependency unavailable in module B: %#v", definitions)
	}
}

func TestGradleSourceSetDependenciesDoNotLeakIntoMain(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	mainLibDir := filepath.Join(root, "mainlib")
	testLibDir := filepath.Join(root, "testlib")
	for _, path := range []string{
		filepath.Join(appDir, "src", "main", "kotlin"),
		filepath.Join(appDir, "src", "test", "kotlin"),
		filepath.Join(mainLibDir, "src", "main", "kotlin"),
		filepath.Join(testLibDir, "src", "main", "kotlin"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, directory := range []string{root, mainLibDir, testLibDir} {
		if err := os.WriteFile(filepath.Join(directory, "build.gradle.kts"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	build := "dependencies {\n  implementation(project(\":mainlib\"))\n  testImplementation(project(\":testlib\"))\n}\n"
	if err := os.WriteFile(filepath.Join(appDir, "build.gradle.kts"), []byte(build), 0o600); err != nil {
		t.Fatal(err)
	}
	idx := New(nil)
	idx.setModules(discoverModules([]string{root}))
	mainLibURI := uriutil.File(filepath.Join(mainLibDir, "src", "main", "kotlin", "MainOnly.kt"))
	testLibURI := uriutil.File(filepath.Join(testLibDir, "src", "main", "kotlin", "TestOnly.kt"))
	mainURI := uriutil.File(filepath.Join(appDir, "src", "main", "kotlin", "Use.kt"))
	testURI := uriutil.File(filepath.Join(appDir, "src", "test", "kotlin", "UseTest.kt"))
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: mainLibURI, LanguageID: "kotlin", Version: 1, Text: "package deps\nclass MainOnly\n"})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: testLibURI, LanguageID: "kotlin", Version: 1, Text: "package deps\nclass TestOnly\n"})
	source := "package app\nimport deps.MainOnly\nimport deps.TestOnly\nfun use(a: MainOnly, b: TestOnly) = b\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: mainURI, LanguageID: "kotlin", Version: 1, Text: source})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: testURI, LanguageID: "kotlin", Version: 1, Text: source})
	mainDoc := textdoc.NewDocument(mainURI, "kotlin", 1, source)
	testDoc := textdoc.NewDocument(testURI, "kotlin", 1, source)
	mainOnlyOffset := strings.LastIndex(source, "MainOnly")
	testOnlyOffset := strings.LastIndex(source, "TestOnly")
	if definitions := idx.Definitions(mainURI, mainDoc.Position(mainOnlyOffset)); !containsNamedSymbol(definitions, "MainOnly") {
		t.Fatalf("main dependency unavailable from main: %#v", definitions)
	}
	if definitions := idx.Definitions(mainURI, mainDoc.Position(testOnlyOffset)); len(definitions) != 0 {
		t.Fatalf("testImplementation leaked into main: %#v", definitions)
	}
	if definitions := idx.Definitions(testURI, testDoc.Position(testOnlyOffset)); !containsNamedSymbol(definitions, "TestOnly") {
		t.Fatalf("test dependency unavailable from test: %#v", definitions)
	}
}

func TestAndroidVariantSourceSetsOverlayMainAndComponents(t *testing.T) {
	sets := map[string][]string{
		"main":          {"/src/main"},
		"debug":         {"/src/debug"},
		"release":       {"/src/release"},
		"free":          {"/src/free"},
		"freeDebug":     {"/src/freeDebug"},
		"test":          {"/src/test"},
		"testFreeDebug": {"/src/testFreeDebug"},
	}
	module := &ModuleInfo{SourceSets: sets, SourceSetDependsOn: conventionalSourceSetDependencies(sets)}
	for _, sourceSet := range []string{"debug", "release", "free", "freeDebug", "testFreeDebug"} {
		if !sourceSetCanAccess(module, sourceSet, "main") {
			t.Fatalf("%s cannot access main: %#v", sourceSet, module.SourceSetDependsOn)
		}
	}
	for _, component := range []string{"free", "debug"} {
		if !sourceSetCanAccess(module, "freeDebug", component) {
			t.Fatalf("freeDebug cannot access %s: %#v", component, module.SourceSetDependsOn)
		}
	}
	for _, component := range []string{"test", "free", "debug"} {
		if !sourceSetCanAccess(module, "testFreeDebug", component) {
			t.Fatalf("testFreeDebug cannot access %s: %#v", component, module.SourceSetDependsOn)
		}
	}
	if sourceSetCanAccess(module, "debug", "release") {
		t.Fatalf("debug can access release: %#v", module.SourceSetDependsOn)
	}
}

func TestGeneratedSourceRootsAreDiscoveredBySourceSet(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		filepath.Join(root, "src", "main", "java"),
		filepath.Join(root, "build", "generated", "source", "kapt", "main"),
		filepath.Join(root, "build", "generated", "sources", "annotationProcessor", "java", "main"),
		filepath.Join(root, "build", "generated", "ksp", "test", "kotlin"),
		filepath.Join(root, "build", "generated", "data_binding_base_class_source_out", "debug", "out"),
		filepath.Join(root, "build", "generated", "view_binding_base_class_source_out", "debug", "out"),
		filepath.Join(root, "build", "generated", "not_namespaced_r_class_sources", "debug", "r"),
		filepath.Join(root, "build", "generated", "ap_generated_sources", "debug", "out"),
		filepath.Join(root, "target", "generated-sources", "annotations"),
		filepath.Join(root, "target", "generated-test-sources", "test-annotations"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "build.gradle"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	modules := discoverModules([]string{root})
	if len(modules) != 1 {
		t.Fatalf("modules = %#v", modules)
	}
	for set, expected := range map[string][]string{
		"main": {
			filepath.Join(root, "src", "main", "java"),
			filepath.Join(root, "build", "generated", "source", "kapt", "main"),
			filepath.Join(root, "build", "generated", "sources", "annotationProcessor", "java", "main"),
			filepath.Join(root, "target", "generated-sources", "annotations"),
		},
		"test": {
			filepath.Join(root, "build", "generated", "ksp", "test", "kotlin"),
			filepath.Join(root, "target", "generated-test-sources", "test-annotations"),
		},
		"debug": {
			filepath.Join(root, "build", "generated", "data_binding_base_class_source_out", "debug", "out"),
			filepath.Join(root, "build", "generated", "view_binding_base_class_source_out", "debug", "out"),
			filepath.Join(root, "build", "generated", "not_namespaced_r_class_sources", "debug", "r"),
			filepath.Join(root, "build", "generated", "ap_generated_sources", "debug", "out"),
		},
	} {
		for _, path := range expected {
			if !containsString(modules[0].SourceSets[set], path) {
				t.Fatalf("%s generated root %s missing: %#v", set, path, modules[0].SourceSets)
			}
		}
	}
}

func TestKMPSourceSetGraphAndExpectActualFamilies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte("plugins { kotlin(\"multiplatform\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := make(map[string]string)
	for _, set := range []string{"commonMain", "jvmMain", "commonTest", "jvmTest"} {
		roots[set] = filepath.Join(root, "src", set, "kotlin")
		if err := os.MkdirAll(roots[set], 0o700); err != nil {
			t.Fatal(err)
		}
	}
	idx := New(nil)
	defer idx.Close()
	idx.setModules(discoverModules([]string{root}))
	commonURI := uriutil.File(filepath.Join(roots["commonMain"], "Platform.kt"))
	jvmURI := uriutil.File(filepath.Join(roots["jvmMain"], "Platform.kt"))
	commonTestURI := uriutil.File(filepath.Join(roots["commonTest"], "PlatformTest.kt"))
	jvmTestURI := uriutil.File(filepath.Join(roots["jvmTest"], "PlatformTest.kt"))
	common := "package demo\nexpect class Platform { fun name(): String }\nfun commonUse(value: Platform) = value.name()\n"
	jvm := "package demo\nactual class Platform { actual fun name(): String = \"jvm\" }\nfun jvmUse(value: Platform) = value.name()\n"
	commonTest := "package demo\nfun commonTest(value: Platform) = value.name()\n"
	jvmTest := "package demo\nfun jvmTest(value: Platform) = value.name()\n"
	for _, item := range []struct {
		uri    protocol.URI
		source string
	}{{commonURI, common}, {jvmURI, jvm}, {commonTestURI, commonTest}, {jvmTestURI, jvmTest}} {
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: item.uri, LanguageID: "kotlin", Version: 1, Text: item.source})
	}
	commonDoc := textdoc.NewDocument(commonURI, "kotlin", 1, common)
	implementations := idx.Implementations(commonURI, commonDoc.Position(strings.Index(common, "Platform")))
	if len(implementations) != 1 || implementations[0].URI != jvmURI || !containsString(implementations[0].Modifiers, "actual") {
		t.Fatalf("expect implementations = %#v", implementations)
	}
	for _, use := range []struct {
		uri    protocol.URI
		source string
	}{{commonTestURI, commonTest}, {jvmTestURI, jvmTest}} {
		doc := textdoc.NewDocument(use.uri, "kotlin", 1, use.source)
		if definitions := idx.Definitions(use.uri, doc.Position(strings.Index(use.source, "Platform"))); len(definitions) != 1 {
			t.Fatalf("source-set definition for %s = %#v", use.uri, definitions)
		}
	}
	rename := idx.Rename(commonURI, commonDoc.Position(strings.Index(common, "Platform")), "RenamedPlatform")
	if len(rename.Changes[jvmURI]) == 0 || len(rename.Changes[jvmTestURI]) == 0 || len(rename.Changes[commonTestURI]) == 0 {
		t.Fatalf("expect/actual rename omitted family edits: %#v", rename.Changes)
	}
}

func TestSourceSetSpecificLibraryClasspathDoesNotLeak(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	for _, path := range []string{
		filepath.Join(appDir, "src", "main", "java"),
		filepath.Join(appDir, "src", "test", "java"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	module := ModuleInfo{
		Name: ":app", Dir: appDir, Root: root,
		SourceRoots: []string{filepath.Join(appDir, "src", "main", "java"), filepath.Join(appDir, "src", "test", "java")},
		SourceSets: map[string][]string{
			"main": {filepath.Join(appDir, "src", "main", "java")},
			"test": {filepath.Join(appDir, "src", "test", "java")},
		},
		ClasspathBySourceSet: make(map[string][]string), DependenciesBySourceSet: make(map[string][]string),
	}
	idx := New(nil)
	idx.setModules([]ModuleInfo{module})
	mainJar := filepath.Join(root, "main.jar")
	testJar := filepath.Join(root, "test.jar")
	resolution := newClasspathResolution()
	resolution.ModuleClasspath[":app"] = []string{mainJar, testJar}
	resolution.SourceSetClasspath[":app"] = map[string][]string{"main": {mainJar}, "test": {mainJar, testJar}}
	idx.mergeModuleBuildResolution(root, resolution)

	libraryURI := protocol.URI("jar:///test-sources.jar!/deps/TestOnly.java")
	libraryDoc := textdoc.NewDocument(libraryURI, "java", 0, "package deps; public class TestOnly {}")
	parsed := analysis.Parse(context.Background(), libraryDoc)
	idx.AddLibraryBatch([]LibraryFile{{Source: LibrarySource{Archive: testJar, Entry: "deps/TestOnly.java", LanguageID: "java"}, Parsed: *parsed}})
	source := "package app; import deps.TestOnly; class Use { TestOnly value; }"
	mainURI := uriutil.File(filepath.Join(appDir, "src", "main", "java", "Use.java"))
	testURI := uriutil.File(filepath.Join(appDir, "src", "test", "java", "UseTest.java"))
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: mainURI, LanguageID: "java", Version: 1, Text: source})
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: testURI, LanguageID: "java", Version: 1, Text: source})
	mainDoc, testDoc := textdoc.NewDocument(mainURI, "java", 1, source), textdoc.NewDocument(testURI, "java", 1, source)
	offset := strings.LastIndex(source, "TestOnly")
	if definitions := idx.Definitions(mainURI, mainDoc.Position(offset)); len(definitions) != 0 {
		t.Fatalf("test JAR leaked into main source set: %#v", definitions)
	}
	if definitions := idx.Definitions(testURI, testDoc.Position(offset)); !containsNamedSymbol(definitions, "TestOnly") {
		t.Fatalf("test JAR unavailable from test source set: %#v", definitions)
	}
}

func TestParameterHintsMapNamedAndRepeatedVarargArguments(t *testing.T) {
	idx := New(nil)
	uri := protocol.URI("file:///workspace/Hints.kt")
	source := "fun reordered(a: Int, b: String) = Unit\nfun many(vararg values: Int) = Unit\n" +
		"fun use() { reordered(b = \"x\", a = 1); many(1, 2, 3) }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	hints := idx.ParameterHints(uri, doc.Range(0, len(source)))
	if len(hints) != 3 {
		t.Fatalf("parameter hints = %#v, want three vararg hints and no redundant named-argument hints", hints)
	}
	for _, hint := range hints {
		if hint.Label != "values:" || hint.ParameterIndex != 0 {
			t.Fatalf("vararg hint = %#v", hint)
		}
	}
}

func TestCompletionPrefixPreservesUnicodeIdentifiers(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	fixtures := []struct{ uri, language, source, marker string }{
		{"file:///workspace/Unicode.kt", "kotlin", "fun πValue(): Int = 1\nfun use(): Int = πV\n", "πV"},
		{"file:///workspace/Unicode.java", "java", "class Unicode { static int πValue = 1; int use() { return πV; } }", "πV"},
	}
	for _, fixture := range fixtures {
		uri := protocol.URI(fixture.uri)
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		items := idx.Completion(uri, doc.Position(strings.LastIndex(fixture.source, fixture.marker)+len(fixture.marker)), 0)
		if !containsNamedSymbol(items, "πValue") {
			t.Fatalf("%s Unicode completion = %#v", fixture.language, items)
		}
	}
}

func TestCompletionIncludesEnclosingExtensionReceiverMembers(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Receiver.kt")
	source := "class Right { fun special(): Int = 1 }\nclass Wrong { fun special(): String = \"\" }\nfun Right.use(): Int = sp\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	items := idx.Completion(uri, doc.Position(strings.LastIndex(source, "sp")+2), 0)
	for _, item := range items {
		if item.Name == "special" && item.Type == "Int" {
			return
		}
	}
	t.Fatalf("extension receiver completion = %#v", items)
}

func hasDiagnostic(diagnostics []protocol.Diagnostic, code, text string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && strings.Contains(diagnostic.Message, text) {
			return true
		}
	}
	return false
}

func nthOffset(text, needle string, occurrence int) int {
	offset := 0
	for n := 0; n <= occurrence; n++ {
		found := strings.Index(text[offset:], needle)
		if found < 0 {
			return -1
		}
		offset += found
		if n < occurrence {
			offset += len(needle)
		}
	}
	return offset
}

func containsSymbol(symbols []analysis.Symbol, name string, kind analysis.SymbolKind, uri protocol.URI) bool {
	for _, symbol := range symbols {
		if symbol.Name == name && symbol.Kind == kind && symbol.URI == uri {
			return true
		}
	}
	return false
}

func containsNamedSymbol(symbols []analysis.Symbol, name string) bool {
	for _, symbol := range symbols {
		if symbol.Name == name {
			return true
		}
	}
	return false
}

func integer(value int) string {
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
