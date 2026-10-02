package lsp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/index"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// stdlibStubs are the few standard-library declarations real code reaches for
// through a dot, declared the way a library index carries them.
var stdlibStubs = []struct{ pkg, name, text string }{
	{"kotlin", "String.kt", `package kotlin
public class String {
    public val length: Int
    public fun isEmpty(): Boolean
    public fun uppercase(): String
}
public class Int
public class Char {
    public val code: Int
    public fun uppercaseChar(): Char
}
public class Boolean
public open class Any {
    public open fun toString(): String
    public open fun equals(other: Any?): Boolean
    public open fun hashCode(): Int
}
public abstract class Enum<E : Enum<E>> {
    public val name: String
    public val ordinal: Int
}
public class Array<T> {
    public val size: Int
    public operator fun get(index: Int): T
}
`},
	{"kotlin.collections", "Collections.kt", `package kotlin.collections
public interface List<out E> {
    public val size: Int
    public operator fun get(index: Int): E
    public fun isEmpty(): Boolean
}
public fun <T> listOf(element: T): List<T>
public fun <T> listOf(vararg elements: T): List<T>
public fun <T> List<T>.first(): T
public fun <T> Array<out T>.first(): T
public fun <T> Array<out T>.toList(): List<T>
`},
	{"kotlin", "EnumValues.kt", `package kotlin
public inline fun <reified T : Enum<T>> enumValues(): Array<T>
`},
}

func addStdlibStubs(s *Server) {
	for _, stub := range stdlibStubs {
		parsed := analysis.Parse(context.Background(), textdoc.NewDocument(protocol.URI("file:///libs/stdlib/"+stub.name), "kotlin", 0, stub.text))
		s.index.AddLibraryBatch([]index.LibraryFile{{
			Source: index.LibrarySource{Archive: "/deps/kotlin-stdlib.jar", Entry: stub.name, LanguageID: "kotlin"},
			Parsed: *parsed,
		}})
	}
}

// receiverFixture opens a workspace file declaring a few types and returns the
// completions offered after `expression` followed by a dot.
func receiverCompletions(t *testing.T, expression string) []string {
	t.Helper()
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	addStdlibStubs(s)

	declarations := `package app

enum class Color { RED, GREEN; fun label(): String = name }

class Box {
    fun open(): Boolean = true
    val size: Int = 1
    fun self(): Box = this
    companion object { fun standard(): Box = Box() }
}

class Holder<T>(val value: T) {
    fun get(): T = value
    fun describe(): String = "holder"
}

fun makeBox(): Box = Box()
fun <T> holder(): Holder<T> = Holder<T>(TODO())
fun <T> wrap(value: T): Holder<T> = Holder(value)

fun use() {
    `
	source := declarations + expression + ".\n}\n"
	uri := protocol.URI("file:///workspace/Use.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	offset := strings.LastIndex(source, ".\n}") + 1
	var labels []string
	for _, item := range completeAt(t, s, uri, offset) {
		labels = append(labels, item.Label)
	}
	return labels
}

func requireLabels(t *testing.T, expression string, want ...string) {
	t.Helper()
	got := receiverCompletions(t, expression)
	have := map[string]bool{}
	for _, label := range got {
		have[label] = true
	}
	for _, label := range want {
		if !have[label] {
			t.Errorf("%s. is missing %q (got %d items: %v)", expression, label, len(got), got[:min(len(got), 8)])
		}
	}
}

func TestMemberCompletionAfterTypeName(t *testing.T) {
	requireLabels(t, "Color", "RED", "GREEN", "valueOf", "entries")
	requireLabels(t, "Box", "standard")
}

func TestMemberCompletionAfterConstructorCall(t *testing.T) {
	requireLabels(t, "Box()", "open", "size")
}

func TestMemberCompletionAfterFunctionCall(t *testing.T) {
	requireLabels(t, "makeBox()", "open", "size")
}

func TestMemberCompletionAfterGenericCallWithExplicitTypeArgument(t *testing.T) {
	requireLabels(t, "holder<Color>()", "get", "describe", "value")
}

func TestMemberCompletionAfterGenericCallInferredFromArgument(t *testing.T) {
	requireLabels(t, "wrap(Color.RED)", "get", "describe", "value")
}

func TestMemberCompletionAfterChainedCall(t *testing.T) {
	requireLabels(t, "wrap(Color.RED).get()", "label", "name")
}

func TestMemberCompletionAfterStringLiteral(t *testing.T) {
	got := receiverCompletions(t, `"abc"`)
	for _, label := range got {
		if label == "nl" || label == "java" || label == "com" {
			t.Fatalf("string literal receiver offers package %q instead of String members: %v", label, got[:min(len(got), 8)])
		}
	}
}

func TestMemberCompletionAfterStringLiteralOffersStringMembers(t *testing.T) {
	requireLabels(t, `"abc"`, "length", "isEmpty", "uppercase")
}

func TestMemberCompletionAfterCharAndNumberLiterals(t *testing.T) {
	requireLabels(t, `'c'`, "code", "uppercaseChar")
}

func TestMemberCompletionAfterStdlibGenericCalls(t *testing.T) {
	requireLabels(t, "listOf(1)", "size", "isEmpty", "get", "first")
	requireLabels(t, "listOf(Color.RED)", "size", "first")
	requireLabels(t, "enumValues<Color>()", "size", "first", "toList")
}

func TestMemberCompletionAfterEnumEntriesAndValues(t *testing.T) {
	requireLabels(t, "Color.RED", "label", "name", "ordinal")
}

func TestMemberCompletionAfterMultilineChain(t *testing.T) {
	requireLabels(t, "makeBox()\n        .self()\n        ", "open", "size")
	requireLabels(t, "wrap(Color.RED)\n        .get()\n        ", "label", "name")
}

func TestMemberCompletionIncludesAnyMembers(t *testing.T) {
	requireLabels(t, "Box()", "toString", "equals", "hashCode")
	requireLabels(t, "makeBox()", "toString")
	requireLabels(t, "Color.RED", "toString", "name", "ordinal")
}

func TestMemberCompletionOnEnumValueExcludesStaticsAndEntries(t *testing.T) {
	for _, label := range receiverCompletions(t, "Color.RED") {
		switch label {
		case "RED", "GREEN", "values", "valueOf", "entries":
			t.Errorf("Color.RED. offers %q, which belongs to the type, not a value", label)
		}
	}
}

// A Java getter reads as a property in Kotlin: `date.year` for `getYear()`.
func TestMemberCompletionOffersJavaGettersAsProperties(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	addStdlibStubs(s)

	java := "package lib;\npublic class Stamp {\n    public int getYear() { return 1; }\n    public boolean isLeap() { return false; }\n    public void setZone(String zone) {}\n    public String getZone() { return \"\"; }\n    public static Stamp now() { return null; }\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: "file:///workspace/Stamp.java", LanguageID: "java", Version: 1, Text: java})
	source := "package app\n\nimport lib.Stamp\n\nfun use() {\n    Stamp.now().\n}\n"
	uri := protocol.URI("file:///workspace/Use.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	have := map[string]bool{}
	for _, item := range completeAt(t, s, uri, strings.Index(source, "now().")+len("now().")) {
		have[item.Label] = true
	}
	for _, want := range []string{"year", "isLeap", "zone"} {
		if !have[want] {
			t.Errorf("Stamp.now(). is missing the Kotlin property %q", want)
		}
	}
}

// A client that pulls workspace diagnostics asks again after every refresh the
// compiler pass sends. Evaluating every indexed file each time saturated the
// server, so the report covers the open documents only.
func TestWorkspaceDiagnosticsCoverOnlyOpenDocuments(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	open := protocol.URI("file:///workspace/Open.kt")
	closed := protocol.URI("file:///workspace/Closed.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: open, LanguageID: "kotlin", Version: 1, Text: "package app\nclass Open\n"})
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: closed, LanguageID: "kotlin", Version: 1, Text: "package app\nclass Closed\n"})
	s.index.CloseDocument(context.Background(), closed)

	result, responseErr := s.Request(context.Background(), "workspace/diagnostic", json.RawMessage(`{"previousResultIds":[]}`))
	if responseErr != nil {
		t.Fatalf("workspace/diagnostic failed: %v", responseErr)
	}
	encoded, _ := json.Marshal(result)
	text := string(encoded)
	if !strings.Contains(text, string(open)) {
		t.Errorf("the open document is missing from the report: %s", text)
	}
	if strings.Contains(text, string(closed)) {
		t.Errorf("a closed document was evaluated: %s", text)
	}
}

// "Expand selection" walks outwards through nested syntax: each range contains
// the one before it, ending at the whole file.
func TestSelectionRangeNestsOutwardsThroughTheSyntax(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	uri := protocol.URI("file:///workspace/Sel.kt")
	source := "package app\n\nfun add(a: Int, b: Int): Int {\n    return compute(a + 1, b)\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc, _ := s.index.Document(uri)
	params, _ := json.Marshal(map[string]any{"textDocument": map[string]any{"uri": uri}, "positions": []protocol.Position{doc.Position(strings.Index(source, "a + 1"))}})
	result, responseErr := s.Request(context.Background(), "textDocument/selectionRange", params)
	if responseErr != nil {
		t.Fatalf("selectionRange failed: %v", responseErr)
	}
	ranges, ok := result.([]*protocol.SelectionRange)
	if !ok || len(ranges) != 1 || ranges[0] == nil {
		t.Fatalf("unexpected result %T %v", result, result)
	}
	steps := 0
	for current := ranges[0]; current != nil; current = current.Parent {
		steps++
		if current.Parent != nil {
			inner, outer := doc.Offset(current.Range.Start), doc.Offset(current.Parent.Range.Start)
			innerEnd, outerEnd := doc.Offset(current.Range.End), doc.Offset(current.Parent.Range.End)
			if outer > inner || outerEnd < innerEnd {
				t.Fatalf("a selection step does not contain the one inside it: %+v inside %+v", current.Range, current.Parent.Range)
			}
		}
	}
	if steps < 4 {
		t.Errorf("expected several nested steps, got %d", steps)
	}
	fresh := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { fresh.Close() })
	capabilities, initializeErr := fresh.Request(context.Background(), "initialize", json.RawMessage(`{"capabilities":{}}`))
	if initializeErr != nil {
		t.Fatalf("initialize failed: %v", initializeErr)
	}
	encoded, _ := json.Marshal(capabilities)
	if !strings.Contains(string(encoded), `"selectionRangeProvider":true`) {
		t.Error("selectionRangeProvider is not advertised")
	}
}

// A client that asks only for quick fixes must not pay for organizing imports.
func TestCodeActionOnlyFilterSkipsOrganizeImports(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	uri := protocol.URI("file:///workspace/Imports.kt")
	source := "package app\n\nimport java.util.UUID\nimport java.util.Date\n\nfun use(id: UUID) = id\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	ask := func(only ...string) []protocol.CodeAction {
		params, _ := json.Marshal(map[string]any{
			"textDocument": map[string]any{"uri": uri},
			"range":        protocol.Range{},
			"context":      map[string]any{"diagnostics": []any{}, "only": only},
		})
		result, responseErr := s.Request(context.Background(), "textDocument/codeAction", params)
		if responseErr != nil {
			t.Fatalf("codeAction failed: %v", responseErr)
		}
		actions, _ := result.([]protocol.CodeAction)
		return actions
	}
	kinds := func(actions []protocol.CodeAction) string {
		var out []string
		for _, a := range actions {
			out = append(out, a.Kind)
		}
		return strings.Join(out, ",")
	}
	if got := kinds(ask()); !strings.Contains(got, "source.organizeImports") {
		t.Errorf("an unfiltered request should offer organize imports, got %q", got)
	}
	if got := kinds(ask("source")); !strings.Contains(got, "source.organizeImports") {
		t.Errorf("only=source includes organize imports, got %q", got)
	}
	if got := kinds(ask("quickfix")); strings.Contains(got, "source.organizeImports") {
		t.Errorf("only=quickfix must not offer organize imports, got %q", got)
	}
}

func TestCompletionSnippetsFollowKotlinConventions(t *testing.T) {
	kotlin := func(name string, parameters ...analysis.Parameter) analysis.Symbol {
		return analysis.Symbol{Name: name, Language: analysis.LanguageKotlin, Kind: analysis.KindMethod, Parameters: parameters}
	}
	lambda := analysis.Parameter{Name: "block", Type: "() -> Unit"}
	for _, c := range []struct {
		label string
		sym   analysis.Symbol
		want  string
	}{
		{"no parameters", kotlin("close"), "close()"},
		{"required parameters", kotlin("find", analysis.Parameter{Name: "id", Type: "Int"}), "find(${1:id})$0"},
		{"only a lambda", kotlin("let", lambda), "let { $0 }"},
		{"parameters then a lambda", kotlin("repeat", analysis.Parameter{Name: "times", Type: "Int"}, lambda), "repeat(${1:times}) { $0 }"},
		{"defaults are optional", kotlin("copy", analysis.Parameter{Name: "id", Type: "Int", Default: "0"}, analysis.Parameter{Name: "name", Type: "String", Default: `""`}), "copy()"},
		{"required before defaults", kotlin("make", analysis.Parameter{Name: "id", Type: "Int"}, analysis.Parameter{Name: "label", Type: "String", Default: `""`}), "make(${1:id})$0"},
		{"a nullable lambda is a value", kotlin("on", analysis.Parameter{Name: "callback", Type: "(() -> Unit)?"}), "on(${1:callback})$0"},
	} {
		if got := completionSnippet(c.sym); got != c.want {
			t.Errorf("%s: got %q, want %q", c.label, got, c.want)
		}
	}
	java := analysis.Symbol{Name: "add", Language: analysis.LanguageJava, Kind: analysis.KindMethod, Parameters: []analysis.Parameter{{Name: "a"}, {Name: "b"}}}
	if got := completionSnippet(java); got != "add(${1:a}, ${2:b})$0" {
		t.Errorf("java: %q", got)
	}
}

func TestSnippetCallIsNotInsertedWhereItWouldBeWrong(t *testing.T) {
	for _, c := range []struct {
		text string
		at   string // the cursor is placed right after this text
		want bool
	}{
		{"val x = fo\n", "fo", true},
		{"val x = foo(1)\n", "fo", false}, // an argument list already follows
		{"val f = ::fo\n", "::fo", false}, // a reference, not a call
		{"val x = a.fo\n", "a.fo", true},
		{"val x = fo + 1\n", "fo", true},
	} {
		offset := strings.Index(c.text, c.at) + len(c.at)
		if got := snippetCallAllowed(c.text, offset); got != c.want {
			t.Errorf("%q at %q: got %v, want %v", c.text, c.at, got, c.want)
		}
	}
}
