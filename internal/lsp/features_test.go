package lsp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

func TestExtractRefactorsProduceSyntacticallyValidKotlinAndJava(t *testing.T) {
	fixtures := []struct {
		uri, language, source, selected string
	}{
		{"file:///workspace/Calc.kt", "kotlin", "package demo\nclass Calc {\n    fun sum(): Int {\n        return 1 + 2\n    }\n}\n", "1 + 2"},
		{"file:///workspace/Calc.java", "java", "package demo;\nclass Calc {\n    int sum() {\n        return 1 + 2;\n    }\n}\n", "1 + 2"},
	}
	for _, fixture := range fixtures {
		s := NewServer(context.Background(), log.New(io.Discard, "", 0))
		uri := protocol.URI(fixture.uri)
		s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		start := strings.Index(fixture.source, fixture.selected)
		r := doc.Range(start, start+len(fixture.selected))
		actions := s.extractActions(uri, r, doc, fixture.selected)
		if len(actions) < 3 {
			t.Fatalf("%s: expected extract variable/function/field actions, got %#v", fixture.language, actions)
		}
		for _, action := range actions {
			edited := applyTextEdits(t, doc, action.Edit.Changes[uri])
			parsed := analysis.Parse(context.Background(), textdoc.NewDocument(uri, fixture.language, 2, edited))
			if len(parsed.Diagnostics) != 0 {
				t.Fatalf("%s %s produced invalid source:\n%s\n%#v", fixture.language, action.Kind, edited, parsed.Diagnostics)
			}
		}
	}
}

func TestCreateJavaMethodQuickFixInfersCallShapeAndContext(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/CreateMethod.java")
	source := "class CreateMethod {\n    static String use(int count) {\n        String result = générer(count, 1, 2L, 1.5f, true, \"x\", \"y\");\n        return result;\n    }\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	start := strings.Index(source, "générer")
	diagnostic := protocol.Diagnostic{Range: doc.Range(start, start+len("générer")), Code: "CALL_UNRESOLVED_NAME", Message: "cannot find symbol"}
	action, ok := s.createJavaMethodQuickFix(uri, doc, diagnostic)
	if !ok || action.Edit == nil || action.Title != "Create method 'générer'" {
		t.Fatalf("create method action = %#v, %v", action, ok)
	}
	edited := applyTextEdits(t, doc, action.Edit.Changes[uri])
	for _, expected := range []string{
		"private static String générer(",
		"int count", "int value", "long arg3", "float arg4", "boolean arg5", "String arg6", "String arg7",
		"throw new UnsupportedOperationException(\"TODO\")",
	} {
		if !strings.Contains(edited, expected) {
			t.Fatalf("created method missing %q:\n%s", expected, edited)
		}
	}
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument(uri, "java", 2, edited))
	if len(parsed.Diagnostics) != 0 {
		t.Fatalf("created Java method is syntactically invalid:\n%s\n%#v", edited, parsed.Diagnostics)
	}
}

func TestCreateJavaMethodQuickFixRejectsUnresolvedVariable(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/NoCreateMethod.java")
	source := "class NoCreateMethod { int use() { return missing; } }\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	start := strings.Index(source, "missing")
	diagnostic := protocol.Diagnostic{Range: doc.Range(start, start+len("missing")), Code: "CALL_UNRESOLVED_NAME"}
	if action, ok := s.createJavaMethodQuickFix(uri, doc, diagnostic); ok {
		t.Fatalf("offered method creation for variable read: %#v", action)
	}
}

func TestSignatureHelpMapsNamedArgumentAndShowsSourceDefaults(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/NamedSignature.kt")
	source := "fun signatureNamed(first: Int = 0, second: Int = 0, third: Int = 0) {}\nfun use() { signatureNamed(third = 3) }\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	position := doc.Position(strings.LastIndex(source, "third") + len("third = 3"))
	result, responseErr := s.signatureHelp(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": position}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	help, ok := result.(protocol.SignatureHelp)
	if !ok || help.ActiveParameter != 2 || len(help.Signatures) == 0 {
		t.Fatalf("named signature help = %#v", result)
	}
	pair, pairOK := help.Signatures[0].Parameters[2].Label.([]int)
	if !strings.Contains(help.Signatures[0].Label, "third: Int = 0") || !pairOK || len(pair) != 2 || pair[0] < 0 || pair[1] > len(help.Signatures[0].Label) || !strings.Contains(help.Signatures[0].Label[pair[0]:pair[1]], "= 0") {
		t.Fatalf("source defaults absent from signature help: %#v", help.Signatures[0])
	}
}

func TestConstructorSignatureHelpSelectsApplicableKotlinAndJavaOverload(t *testing.T) {
	fixtures := []struct {
		uri, language, source string
	}{
		{"file:///workspace/Constructor.kt", "kotlin", "class Choice { constructor(value: Int); constructor(value: String) }\nfun use() { Choice(\"x\") }\n"},
		{"file:///workspace/Constructor.java", "java", "class ChoiceJ { ChoiceJ(int value) {} ChoiceJ(String value) {} } class UseJ { void use() { new ChoiceJ(\"x\"); } }"},
	}
	for _, fixture := range fixtures {
		s := NewServer(context.Background(), log.New(io.Discard, "", 0))
		s.index.Open(context.Background(), protocol.TextDocumentItem{URI: protocol.URI(fixture.uri), LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(protocol.URI(fixture.uri), fixture.language, 1, fixture.source)
		position := doc.Position(strings.LastIndex(fixture.source, "\"x\"") + 2)
		result, responseErr := s.signatureHelp(mustJSON(map[string]any{"textDocument": map[string]any{"uri": fixture.uri}, "position": position}))
		if responseErr != nil {
			t.Fatal(responseErr)
		}
		help, ok := result.(protocol.SignatureHelp)
		if !ok || len(help.Signatures) != 2 || help.ActiveSignature < 0 || help.ActiveSignature >= len(help.Signatures) || !strings.Contains(help.Signatures[help.ActiveSignature].Label, "String") {
			t.Fatalf("%s constructor signature help = %#v", fixture.language, result)
		}
		if fixture.language == "java" && help.ActiveParameter != 0 || fixture.language == "kotlin" && help.ActiveParameter != nil {
			t.Fatalf("%s root activeParameter shape = %#v", fixture.language, help.ActiveParameter)
		}
		if fixture.language == "java" && !strings.Contains(help.Signatures[help.ActiveSignature].Label, "String value") {
			t.Fatalf("Java constructor signature is not Java syntax: %q", help.Signatures[help.ActiveSignature].Label)
		}
		s.Close()
	}
}

func TestExtractFunctionCapturesFreeParameters(t *testing.T) {
	fixtures := []struct {
		uri, language, source, selected string
	}{
		{"file:///workspace/Free.kt", "kotlin", "class Free { fun sum(input: Int): Int { val increment: Int = 2; return input + increment } }", "input + increment"},
		{"file:///workspace/Free.java", "java", "class Free { int sum(int input) { int increment = 2; return input + increment; } }", "input + increment"},
	}
	for _, fixture := range fixtures {
		s := NewServer(context.Background(), log.New(io.Discard, "", 0))
		uri := protocol.URI(fixture.uri)
		s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		start := strings.Index(fixture.source, fixture.selected)
		actions := s.extractActions(uri, doc.Range(start, start+len(fixture.selected)), doc, fixture.selected)
		var function protocol.CodeAction
		for _, action := range actions {
			if action.Kind == "refactor.extract.function" {
				function = action
			}
		}
		if function.Edit == nil {
			t.Fatalf("%s extract function missing", fixture.language)
		}
		edited := applyTextEdits(t, doc, function.Edit.Changes[uri])
		if !strings.Contains(edited, "input") || !strings.Contains(edited, "increment") {
			t.Fatalf("%s parameters missing:\n%s", fixture.language, edited)
		}
		parsed := analysis.Parse(context.Background(), textdoc.NewDocument(uri, fixture.language, 2, edited))
		if len(parsed.Diagnostics) != 0 {
			t.Fatalf("%s free-parameter extraction is invalid:\n%s\n%#v", fixture.language, edited, parsed.Diagnostics)
		}
	}
}

func TestExtractFunctionRejectsMutationOfCapturedBinding(t *testing.T) {
	fixtures := []struct {
		uri, language, source string
	}{
		{"file:///workspace/Mutation.kt", "kotlin", "fun f(): Int { var x = 0; x++; return x }"},
		{"file:///workspace/Mutation.java", "java", "class Mutation { int f() { int x = 0; x++; return x; } }"},
	}
	for _, fixture := range fixtures {
		s := NewServer(context.Background(), log.New(io.Discard, "", 0))
		uri := protocol.URI(fixture.uri)
		s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		doc := textdoc.NewDocument(uri, fixture.language, 1, fixture.source)
		start := strings.Index(fixture.source, "x++")
		actions := s.extractActions(uri, doc.Range(start, start+3), doc, "x++")
		for _, action := range actions {
			if action.Kind == "refactor.extract.function" {
				t.Fatalf("%s offered semantics-changing action: %#v", fixture.language, action)
			}
		}
	}
}

func TestExtractFunctionInfersImplicitCapturedLocalType(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	uri := protocol.URI("file:///workspace/Implicit.kt")
	source := "class Implicit { fun f() { val x = 1; println(x + 1) } }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	start := strings.Index(source, "x + 1")
	actions := s.extractActions(uri, doc.Range(start, start+len("x + 1")), doc, "x + 1")
	for _, action := range actions {
		if action.Kind != "refactor.extract.function" {
			continue
		}
		edited := applyTextEdits(t, doc, action.Edit.Changes[uri])
		if !strings.Contains(edited, "extractedFunction(x: Int): Int") {
			t.Fatalf("captured local type was not inferred:\n%s", edited)
		}
		return
	}
	t.Fatal("extract function action missing")
}

func TestExtractFunctionInJavaEnumStaysAfterConstants(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/E.java")
	source := "enum E { A;\n  int f(int x) { return x + 1; }\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	start := strings.Index(source, "x + 1")
	actions := s.extractActions(uri, doc.Range(start, start+len("x + 1")), doc, "x + 1")
	var extracted protocol.CodeAction
	for _, action := range actions {
		if action.Kind == "refactor.extract.function" {
			extracted = action
		}
	}
	if extracted.Edit == nil {
		t.Fatal("extract function action missing")
	}
	edited := applyTextEdits(t, doc, extracted.Edit.Changes[uri])
	if strings.Index(edited, "extractedFunction") < strings.Index(edited, "A;") {
		t.Fatalf("generated enum member precedes constants:\n%s", edited)
	}
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument(uri, "java", 2, edited))
	if len(parsed.Diagnostics) != 0 {
		t.Fatalf("enum extraction is invalid: %#v\n%s", parsed.Diagnostics, edited)
	}
}

func TestInlineVariableDoesNotDuplicateSideEffects(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	uri := protocol.URI("file:///workspace/Inline.kt")
	source := "fun next(): Int = 1\nfun use(): Int { val value = next(); return value + value }\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	position := strings.Index(source, "value =")
	if _, ok := s.inlineVariableAction(uri, doc.Range(position, position+len("value")), doc); ok {
		t.Fatal("unsafe repeated side-effecting initializer was offered for inline")
	}
}

func TestInlineVariableRemovesOnlySameLineDeclarationAndRejectsProperties(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	uri := protocol.URI("file:///workspace/InlineLine.kt")
	source := "fun f() { val x = 1; println(x) }\nval property = 2\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	variable := strings.Index(source, "x =")
	action, ok := s.inlineVariableAction(uri, doc.Range(variable, variable+1), doc)
	if !ok || action.Edit == nil {
		t.Fatal("safe local inline action is missing")
	}
	edited := applyTextEdits(t, doc, action.Edit.Changes[uri])
	if !strings.Contains(edited, "fun f()") || !strings.Contains(edited, "println((1))") || strings.Contains(edited, "val x") {
		t.Fatalf("same-line inline damaged its enclosing function:\n%s", edited)
	}
	property := strings.Index(source, "property")
	if _, offered := s.inlineVariableAction(uri, doc.Range(property, property+len("property")), doc); offered {
		t.Fatal("cross-file-capable property inline was offered as a local-only edit")
	}
}

func TestFileTemplateInterpolation(t *testing.T) {
	values := map[string]string{"NAME": "Widget", "PACKAGE_NAME": "demo"}
	got := interpolateVariables("package ${PACKAGE_NAME}\nclass $NAME\nunknown=$UNKNOWN", values)
	if got != "package demo\nclass Widget\nunknown=" {
		t.Fatalf("interpolation = %q", got)
	}
}

func TestHighWatermarkFollowsConfiguredFileWithoutDocumentNotification(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	markTestServerInitialized(s)
	path := filepath.Join(t.TempDir(), "watermark")
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, responseErr := s.Request(context.Background(), "workspace/executeCommand", mustJSON(map[string]any{
		"command": "set-highwatermark-file", "arguments": []any{path},
	})); responseErr != nil {
		t.Fatal(responseErr)
	}
	timestamp := s.watermark.Load() + 10_000
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", timestamp)), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, responseErr := s.Request(context.Background(), "workspace/executeCommand", mustJSON(map[string]any{
		"command": "wait-for-highwatermark", "arguments": []any{timestamp},
	})); responseErr != nil {
		t.Fatal(responseErr)
	}
	if elapsed := time.Since(started); elapsed >= testLatencyLimit {
		t.Fatalf("file-backed watermark wait took %s", elapsed)
	}
}

func TestFormatterPreservesRawStringContentAndIsIdempotent(t *testing.T) {
	source := "class Demo {\nfun value(\nfirst: Int,\nsecond: Int\n): String {\nval raw = \"\"\"\n  { literal brace }\n    intentionally indented\n\"\"\"\nreturn raw\n}\n}\n"
	options := protocol.FormattingOptions{TabSize: 4, InsertSpaces: true, TrimTrailingWhitespace: true, InsertFinalNewline: true}
	formatted := formatSource(source, options, true)
	if !strings.Contains(formatted, "  { literal brace }\n    intentionally indented\n") {
		t.Fatalf("raw string content changed:\n%s", formatted)
	}
	if again := formatSource(formatted, options, true); again != formatted {
		t.Fatalf("formatter is not idempotent:\nfirst:\n%s\nsecond:\n%s", formatted, again)
	}
}

func TestJavaFormatterPreservesTextBlockContentAndIsIdempotent(t *testing.T) {
	source := "class Demo {\nString value() {\nString text = \"\"\"\n  { literal brace }\n    intentionally indented\n\"\"\";\nreturn text;\n}\n}\n"
	options := protocol.FormattingOptions{TabSize: 4, InsertSpaces: true, TrimTrailingWhitespace: true, InsertFinalNewline: true}
	formatted := formatSource(source, options, false)
	if !strings.Contains(formatted, "  { literal brace }\n    intentionally indented\n") {
		t.Fatalf("Java text-block content changed:\n%s", formatted)
	}
	if again := formatSource(formatted, options, false); again != formatted {
		t.Fatalf("Java text-block formatting is not idempotent:\n%s", again)
	}
}

func TestFormatterPreservesCRLFAndIsIdempotent(t *testing.T) {
	options := protocol.FormattingOptions{TabSize: 4, InsertSpaces: true, InsertFinalNewline: true}
	for _, kotlin := range []bool{false, true} {
		source := "class Demo{\r\nfun value():Int{return 1}\r\n}\r\n"
		if !kotlin {
			source = "class Demo{\r\nint value(){return 1;}\r\n}\r\n"
		}
		formatted := formatSource(source, options, kotlin)
		if strings.Contains(strings.ReplaceAll(formatted, "\r\n", ""), "\n") || !strings.Contains(formatted, "\r\n") {
			t.Fatalf("CRLF style changed (kotlin=%v): %q", kotlin, formatted)
		}
		if again := formatSource(formatted, options, kotlin); again != formatted {
			t.Fatalf("CRLF formatting is not idempotent (kotlin=%v): %q != %q", kotlin, again, formatted)
		}
	}
}

func TestFormatterHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if formatted, completed := formatSourceContext(ctx, strings.Repeat("fun value(){if(true){println(1)}}", 12_000), protocol.FormattingOptions{TabSize: 4, InsertSpaces: true}, true); completed || formatted != "" {
		t.Fatalf("canceled formatting returned completed=%v text=%q", completed, formatted)
	}
	if elapsed := time.Since(started); elapsed >= testLatencyLimit {
		t.Fatalf("canceled formatter took %s", elapsed)
	}
}

func TestFormatterNormalizesSafeKotlinAndJavaSpacing(t *testing.T) {
	options := protocol.FormattingOptions{TabSize: 4, InsertSpaces: true}
	kotlin := formatSource("class Demo{\nfun sum(first:Int,second:Int):Int{return first+second}\n}\n", options, true)
	for _, expected := range []string{"class Demo {", "fun sum(first: Int, second: Int): Int {\n        return first + second\n    }"} {
		if !strings.Contains(kotlin, expected) {
			t.Fatalf("Kotlin formatter lacks %q:\n%s", expected, kotlin)
		}
	}
	java := formatSource("class Demo{\nint sum(int first,int second){return first+second;}\n}\n", options, false)
	for _, expected := range []string{"class Demo {", "int sum(int first, int second) {\n        return first + second;\n    }"} {
		if !strings.Contains(java, expected) {
			t.Fatalf("Java formatter lacks %q:\n%s", expected, java)
		}
	}
	if formatSource(kotlin, options, true) != kotlin || formatSource(java, options, false) != java {
		t.Fatal("spacing normalization is not idempotent")
	}
}

func TestJavaFormatterKeepsAnnotationAndSimpleArrayInitializersCompact(t *testing.T) {
	options := protocol.FormattingOptions{TabSize: 4, InsertSpaces: true}
	formatted := formatSource(`@SuppressWarnings({"a","b"}) class Arrays{int[] values={1,2,3};}`, options, false)
	expected := "@SuppressWarnings({\"a\", \"b\"})\nclass Arrays {\n    int[] values = {1, 2, 3};\n}"
	if formatted != expected {
		t.Fatalf("Java compact initializer formatting:\ngot:\n%s\nwant:\n%s", formatted, expected)
	}
	if again := formatSource(formatted, options, false); again != formatted {
		t.Fatalf("Java compact initializer formatting is not idempotent:\n%s", again)
	}
}

func TestFormatterSeparatesEnumConstantsFromMembers(t *testing.T) {
	options := protocol.FormattingOptions{TabSize: 4, InsertSpaces: true}
	java := formatSource(`enum E{A,B;int x(){return 1;}}`, options, false)
	if expected := "enum E {\n    A, B;\n    int x() {\n        return 1;\n    }\n}"; java != expected {
		t.Fatalf("Java enum formatting:\ngot:\n%s\nwant:\n%s", java, expected)
	}
	kotlin := formatSource(`enum class K{A,B;fun x():Int{return 1}}`, options, true)
	if expected := "enum class K {\n    A, B;\n    fun x(): Int {\n        return 1\n    }\n}"; kotlin != expected {
		t.Fatalf("Kotlin enum formatting:\ngot:\n%s\nwant:\n%s", kotlin, expected)
	}
}

func TestFormatterSpacesControlKeywordsAndComparisonOperators(t *testing.T) {
	options := protocol.FormattingOptions{TabSize: 4, InsertSpaces: true}
	formatted := formatSource("fun f(a:Int,b:Int){if(a<b){println(a)}else{println(b)}}", options, true)
	if !strings.Contains(formatted, "if (a < b)") {
		t.Fatalf("Kotlin control/comparison spacing is incomplete:\n%s", formatted)
	}
	generic := formatSource("fun use(values:List<String>){if(values.size>0){println(values)}}", options, true)
	if !strings.Contains(generic, "List<String>") || !strings.Contains(generic, "if (values.size > 0)") {
		t.Fatalf("generic/comparison spacing was ambiguous:\n%s", generic)
	}
}

func TestRangeFormattingPreservesLinesOutsideSelection(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/Range.kt")
	source := "class Demo{\nfun untouched( ):Int{return 1}\nfun target(value:Int):Int{return value+1}\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	start := strings.Index(source, "fun target")
	end := start + len("fun target(value:Int):Int{return value+1}")
	result, responseErr := s.rangeFormatting(context.Background(), mustJSON(map[string]any{
		"textDocument": map[string]any{"uri": uri}, "range": doc.Range(start, end),
		"options": map[string]any{"tabSize": 4, "insertSpaces": true},
	}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	edits := result.([]protocol.TextEdit)
	if len(edits) != 1 {
		t.Fatalf("range formatting edits = %#v", edits)
	}
	formatted := applyTextEdits(t, doc, edits)
	if !strings.HasPrefix(formatted, "class Demo{\nfun untouched( ):Int{return 1}\n") {
		t.Fatalf("range formatting changed text before the selection:\n%s", formatted)
	}
	if !strings.Contains(formatted, "    fun target(value: Int): Int {\n        return value + 1\n    }") {
		t.Fatalf("selected line was not formatted:\n%s", formatted)
	}
}

func TestRangeFormattingAbstainsInsideMultilineContent(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		source string
		needle string
	}{
		{"triple string", "val text = \"\"\"first\ncontent   { untouched\nlast\"\"\"\n", "content"},
		{"Java text block", "class C { String text = \"\"\"\ncontent   { untouched\n\"\"\"; }\n", "content"},
		{"nested comment", "/* outer\n/* inner */\ncontent   { untouched\n*/\nclass C\n", "content"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			s := NewServer(context.Background(), log.New(io.Discard, "", 0))
			defer s.Close()
			uri := protocol.URI("file:///workspace/Range.kt")
			languageID := "kotlin"
			if strings.HasPrefix(fixture.name, "Java") {
				uri = protocol.URI("file:///workspace/Range.java")
				languageID = "java"
			}
			s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: languageID, Version: 1, Text: fixture.source})
			doc := textdoc.NewDocument(uri, languageID, 1, fixture.source)
			start := strings.Index(fixture.source, fixture.needle)
			result, responseErr := s.rangeFormatting(context.Background(), mustJSON(map[string]any{
				"textDocument": map[string]any{"uri": uri},
				"range":        doc.Range(start, start+len(fixture.needle)),
				"options":      map[string]any{"tabSize": 4, "insertSpaces": true},
			}))
			if responseErr != nil {
				t.Fatal(responseErr)
			}
			if edits := result.([]protocol.TextEdit); len(edits) != 0 {
				t.Fatalf("multiline content was rewritten: %#v", edits)
			}
		})
	}
}

func TestFormatterTracksNestedKotlinBlockComments(t *testing.T) {
	state := formatLexState{}
	scanStructure("/* outer /* inner */", &state)
	if state.BlockCommentDepth != 1 {
		t.Fatalf("nested comment depth after inner close = %d", state.BlockCommentDepth)
	}
	scanStructure("still outer */", &state)
	if state.BlockCommentDepth != 0 {
		t.Fatalf("nested comment depth after outer close = %d", state.BlockCommentDepth)
	}
}

func TestPullDiagnosticsEncodesEmptyItemsAsArray(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/Clean.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: "class Clean\n"})
	result, responseErr := s.diagnostic(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"items":[]`) {
		t.Fatalf("empty diagnostics must encode as an array: %s", payload)
	}
}

func TestOrganizeImportsRemovesUnusedDeduplicatesAndGroupsStatic(t *testing.T) {
	source := "package demo;\n\nimport static java.util.Collections.emptyList;\nimport java.util.Map;\nimport java.util.List;\nimport java.util.List;\n\nclass Demo { List<String> values; Map<String, String> index; }\n"
	doc := textdoc.NewDocument("file:///Demo.java", "java", 1, source)
	edit, ok := organizeImports(source, doc.Range(0, len(source)), "file:///Demo.java")
	if !ok {
		t.Fatal("expected organize-imports edit")
	}
	result := applyTextEdits(t, doc, []protocol.TextEdit{edit})
	if strings.Contains(result, "emptyList") || strings.Count(result, "import java.util.List;") != 1 {
		t.Fatalf("unused/duplicate imports remain:\n%s", result)
	}
	if strings.Index(result, "import java.util.List;") > strings.Index(result, "import java.util.Map;") {
		t.Fatalf("imports are not sorted:\n%s", result)
	}
}

func TestOrganizeImportsPreservesInterleavedComments(t *testing.T) {
	source := "package demo\n\nimport zed.Zed\n// Keep this explanation attached to the group boundary.\nimport alpha.Alpha\nimport unused.Gone\n\nclass Demo(val alpha: Alpha, val zed: Zed)\n"
	doc := textdoc.NewDocument("file:///Demo.kt", "kotlin", 1, source)
	edit, ok := organizeImports(source, doc.Range(0, len(source)), "file:///Demo.kt")
	if !ok {
		t.Fatal("expected organize-imports edit")
	}
	result := applyTextEdits(t, doc, []protocol.TextEdit{edit})
	if !strings.Contains(result, "// Keep this explanation attached to the group boundary.") {
		t.Fatalf("interleaved import comment was lost:\n%s", result)
	}
	if strings.Contains(result, "unused.Gone") {
		t.Fatalf("unused import remains:\n%s", result)
	}
}

func TestOrganizeImportsIgnoresStringsCommentsQualifiedNamesAndUnusedWildcards(t *testing.T) {
	source := "import foo.Unused\nimport bar.*\nfun x() { println(\"Unused\"); /* Unused */ foo.Unused.call() }\n"
	doc := textdoc.NewDocument("file:///Imports.kt", "kotlin", 1, source)
	edit, ok := organizeImports(source, doc.Range(0, len(source)), doc.URI, map[string]bool{})
	if !ok {
		t.Fatal("expected unused imports to be removed")
	}
	result := applyTextEdits(t, doc, []protocol.TextEdit{edit})
	if strings.Contains(result, "import ") {
		t.Fatalf("non-semantic text kept imports alive:\n%s", result)
	}

	usedWildcard := "import bar.*\nfun x(value: FromBar) = value\n"
	wildcardDoc := textdoc.NewDocument("file:///Wildcard.kt", "kotlin", 1, usedWildcard)
	if _, changed := organizeImports(usedWildcard, wildcardDoc.Range(0, len(usedWildcard)), wildcardDoc.URI, map[string]bool{"bar": true}); changed {
		t.Fatal("semantically used wildcard import was removed")
	}
}

func TestJavaPostfixCompletionRewritesExpressionAndHonorsSnippetCapability(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	uri := protocol.URI("file:///workspace/Postfix.java")
	source := "class Postfix { void use(boolean flag) { flag.if } }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	s.clientCaps = map[string]any{"textDocument": map[string]any{"completion": map[string]any{"completionItem": map[string]any{"snippetSupport": true}}}}
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": doc.Position(strings.Index(source, "flag.if") + len("flag.if"))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	list := result.(protocol.CompletionList)
	var postfix *protocol.CompletionItem
	for index := range list.Items {
		item := &list.Items[index]
		if item.Label == "if" && item.TextEdit != nil {
			postfix = item
			break
		}
	}
	if postfix == nil || postfix.InsertTextFormat != 2 || !strings.Contains(postfix.TextEdit.NewText, "if (flag)") || doc.Slice(postfix.TextEdit.Range) != "flag.if" {
		t.Fatalf("Java postfix completion = %#v", postfix)
	}
}

func TestCodeLensOnlyMarksRunnableJavaAndKotlinMains(t *testing.T) {
	fixtures := []struct {
		uri, language, source string
		want                  int
	}{
		{"file:///workspace/App.java", "java", "public class App { public static void main(String[] args) {} void main() {} }", 2},
		{"file:///workspace/Top.kt", "kotlin", "fun main() {}\nclass NotRunnable { fun main() {} }\n", 2},
	}
	for _, fixture := range fixtures {
		s := NewServer(context.Background(), log.New(io.Discard, "", 0))
		s.runMainCodeLens.Store(true)
		uri := protocol.URI(fixture.uri)
		s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: fixture.language, Version: 1, Text: fixture.source})
		result, responseErr := s.codeLens(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}))
		if responseErr != nil {
			t.Fatalf("%s codeLens: %v", fixture.language, responseErr)
		}
		lenses := result.([]protocol.CodeLens)
		if len(lenses) != fixture.want {
			t.Fatalf("%s lenses = %#v", fixture.language, lenses)
		}
	}
}

func TestKotlinCompanionMainUsesOuterJvmClass(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	s.runMainCodeLens.Store(true)
	uri := protocol.URI("file:///workspace/App.kt")
	source := "package demo\nclass App {\n    companion object {\n        @JvmStatic fun main(args: Array<String>) {}\n    }\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	result, responseErr := s.codeLens(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	lenses := result.([]protocol.CodeLens)
	if len(lenses) != 2 {
		t.Fatalf("companion main lenses = %#v", lenses)
	}
	arguments := lenses[0].Command.Arguments[0].(map[string]any)
	if arguments["mainClass"] != "demo.App" {
		t.Fatalf("main class = %#v", arguments["mainClass"])
	}
}

func TestInlayHintInfersConstructorAndFactoryTypes(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	uri := protocol.URI("file:///workspace/Hints.kt")
	source := "class Service\nfun create(): Service = Service()\nfun use() { val direct = Service(); val factory = create() }\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	result, responseErr := s.inlayHints(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": doc.Range(0, len(source))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	serviceHints := 0
	for _, hint := range result.([]protocol.InlayHint) {
		if hint.Label == ": Service" {
			serviceHints++
		}
	}
	if serviceHints != 2 {
		t.Fatalf("Service inlay hints = %#v", result)
	}
}

// A java.util.function target can only be typed once the JDK is indexed; a
// remembered table of JDK shapes would be a guess outside the index, so the
// hint abstains when nothing in the index declares the interface.
func TestJavaLambdaParameterTypeInlayAbstainsWithoutIndexedJDK(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/Lambda.java")
	source := "import java.util.function.Function; class Lambda { Function<String,String> f = x -> x.trim(); }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.inlayHints(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": doc.Range(0, len(source))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	lambdaPosition := doc.Position(strings.Index(source, "x ->") + 1)
	for _, hint := range result.([]protocol.InlayHint) {
		if hint.Position == lambdaPosition {
			t.Fatalf("unindexed JDK functional interface produced a lambda parameter hint: %#v", result)
		}
	}
}

func TestJavaVarGetsImplicitTypeInlay(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/Var.java")
	source := "class Var { void use() { var text = \"hello\"; } }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.inlayHints(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": doc.Range(0, len(source))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	for _, hint := range result.([]protocol.InlayHint) {
		if hint.Label == ": String" && hint.Position == doc.Position(strings.Index(source, "text")+len("text")) {
			return
		}
	}
	t.Fatalf("Java var inlay hint missing: %#v", result)
}

func TestCustomJavaSAMParameterTypeInlay(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/CustomLambda.java")
	source := "interface MyFunc { String run(Integer value); } class Use { MyFunc f = x -> x.toString(); }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.inlayHints(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": doc.Range(0, len(source))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	if hints := result.([]protocol.InlayHint); len(hints) == 0 || hints[0].Label != ": Integer" {
		t.Fatalf("custom SAM lambda hint = %#v", hints)
	}
}

func TestJavaLambdaHintAbstainsForNonFunctionalInterface(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/NotSAM.java")
	source := "interface NotSAM { String first(Integer value); String second(Integer value); } class Use { NotSAM f = x -> x.toString(); }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.inlayHints(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "range": doc.Range(0, len(source))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	lambdaPosition := doc.Position(strings.Index(source, "x ->") + 1)
	for _, hint := range result.([]protocol.InlayHint) {
		if hint.Position == lambdaPosition {
			t.Fatalf("non-functional interface produced a lambda parameter hint: %#v", result)
		}
	}
}

func TestWillRenamePackageDirectoryUpdatesDeclarationAndImports(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	widgetURI := protocol.URI("file:///workspace/src/main/java/model/Widget.java")
	useURI := protocol.URI("file:///workspace/src/main/kotlin/app/Use.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: widgetURI, LanguageID: "java", Version: 1, Text: "package model; public class Widget {}\n"})
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: "package app\nimport model.Widget\nfun use(value: Widget) = value\n"})
	raw := mustJSON(map[string]any{"files": []any{map[string]any{"oldUri": "file:///workspace/src/main/java/model", "newUri": "file:///workspace/src/main/java/domain"}}})
	result, responseErr := s.willRenameFiles(raw)
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	edit := result.(protocol.WorkspaceEdit)
	if !hasNewText(edit.Changes[widgetURI], "package domain;") {
		t.Fatalf("package declaration edit missing: %#v", edit)
	}
	if !hasNewText(edit.Changes[useURI], "import domain.Widget") {
		t.Fatalf("import edit missing: %#v", edit)
	}
}

func TestRenameIdentifierRulesAreLanguageSpecific(t *testing.T) {
	if validIdentifierForLanguage("class", analysis.LanguageJava) || validIdentifierForLanguage("with$dollar", analysis.LanguageKotlin) {
		t.Fatal("invalid keyword/dollar identifier accepted")
	}
	if !validIdentifierForLanguage("with$dollar", analysis.LanguageJava) || !validIdentifierForLanguage("`class`", analysis.LanguageKotlin) {
		t.Fatal("valid Java dollar or Kotlin quoted identifier rejected")
	}
}

func TestRenameKotlinOperatorMatchesIntelliJStructuralEdits(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/OperatorRename.kt")
	source := "class Box { operator fun plus(other: Box): Box = this }\nfun use(left: Box, right: Box) = left + right\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	position := doc.Position(strings.Index(source, "plus"))
	params := mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": position})
	if result, responseErr := s.prepareRename(params); responseErr == nil || result != nil {
		t.Fatalf("prepare rename accepted a structural convention use: result=%#v error=%v", result, responseErr)
	}
	renameParams := mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": position, "newName": "combine"})
	result, responseErr := s.rename(renameParams)
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	workspaceEdit := result.(protocol.WorkspaceEdit)
	if len(workspaceEdit.DocumentChanges) != 1 {
		t.Fatalf("operator rename documentChanges = %#v", workspaceEdit.DocumentChanges)
	}
	documentEdit, ok := workspaceEdit.DocumentChanges[0].(protocol.TextDocumentEdit)
	if !ok || documentEdit.TextDocument.Version == nil || *documentEdit.TextDocument.Version != 1 {
		t.Fatalf("versioned operator rename = %#v", workspaceEdit.DocumentChanges[0])
	}
	edits := documentEdit.Edits
	if len(edits) != 2 || !hasNewText(edits, "combine") || !hasNewText(edits, "") {
		t.Fatalf("operator rename edits = %#v, want declaration rename plus modifier removal", edits)
	}
	for _, edit := range edits {
		if doc.Slice(edit.Range) == "+" {
			t.Fatalf("operator token was replaced structurally: %#v", edit)
		}
	}
}

func TestModCommandChoiceSessionsAreOneShot(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	choice := mustJSON(map[string]any{"type": "ChooseAction", "sessionId": 7, "title": "Choose", "entries": []any{map[string]any{"index": 0, "name": "No-op"}}, "actions": []any{map[string]any{"type": "Nothing"}}})
	if _, responseErr := s.applyModCommand(context.Background(), []json.RawMessage{choice}); responseErr != nil {
		t.Fatal(responseErr)
	}
	arguments := []json.RawMessage{json.RawMessage(`7`), json.RawMessage(`0`)}
	if result, responseErr := s.chooseModCommandAction(context.Background(), arguments); responseErr != nil || result != true {
		t.Fatalf("choose action = %#v, %v", result, responseErr)
	}
	if _, responseErr := s.chooseModCommandAction(context.Background(), arguments); responseErr == nil {
		t.Fatal("reused choice session did not expire")
	}
}

func TestExtractCodeActionUsesOpenKotlinWireAndAppliesThroughClient(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	markTestServerInitialized(s)
	uri := protocol.URI("file:///workspace/Extract.kt")
	source := "class Extract { fun value(): Int { return 1 + 2 } }\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	start := strings.Index(source, "1 + 2")
	selection := doc.Range(start, start+len("1 + 2"))
	result, responseErr := s.codeActions(mustJSON(map[string]any{
		"textDocument": map[string]any{"uri": uri}, "range": selection,
		"context": map[string]any{"diagnostics": []any{}},
	}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	var extract protocol.CodeAction
	for _, action := range result.([]protocol.CodeAction) {
		if action.Kind == "refactor.extract.variable" {
			extract = action
			break
		}
	}
	if extract.Command == nil || extract.Edit != nil || len(extract.Command.Arguments) != 2 {
		t.Fatalf("extract action wire = %#v", extract)
	}
	if extract.Command.Arguments[0] != uri {
		t.Fatalf("first extract argument = %#v, want DocumentUri %q", extract.Command.Arguments[0], uri)
	}
	payload, ok := extract.Command.Arguments[1].(map[string]any)
	if !ok || !strings.HasSuffix(fmt.Sprint(payload["type"]), "Payload.Data") || payload["selection"] != selection || payload["choice"] != extract.Title {
		t.Fatalf("second extract argument = %#v", extract.Command.Arguments[1])
	}
	applyCalls := 0
	s.clientCall = func(_ context.Context, method string, params, result any) error {
		if method != "workspace/applyEdit" {
			t.Fatalf("client method = %q", method)
		}
		applyCalls++
		setAppliedResult(t, result)
		return nil
	}
	applied, responseErr := s.Request(context.Background(), "workspace/executeCommand", mustJSON(map[string]any{
		"command": extract.Command.Command, "arguments": extract.Command.Arguments,
	}))
	if responseErr != nil || applied != true || applyCalls != 1 {
		t.Fatalf("execute extract = %#v, %v; apply calls=%d", applied, responseErr, applyCalls)
	}
}

func TestCompletionApplyUsesLanguageSpecificWireAndLiveKotlinSession(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	markTestServerInitialized(s)
	widgetURI := protocol.URI("file:///workspace/model/Widget.kt")
	useURI := protocol.URI("file:///workspace/app/Use.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: widgetURI, LanguageID: "kotlin", Version: 1, Text: "package model\nclass Widget\n"})
	useSource := "package app\nfun use() { Wid }\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: useSource})
	useDoc := textdoc.NewDocument(useURI, "kotlin", 1, useSource)
	result, responseErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": useURI}, "position": useDoc.Position(strings.Index(useSource, "Wid") + 3)}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	var widget protocol.CompletionItem
	for _, item := range result.(protocol.CompletionList).Items {
		if item.Label == "Widget" {
			widget = item
			break
		}
	}
	if widget.Command == nil || widget.Command.Command != "jetbrains.kotlin.completion.apply" || len(widget.Command.Arguments) != 1 {
		t.Fatalf("Kotlin completion command = %#v", widget.Command)
	}
	if id, ok := widget.Command.Arguments[0].(int64); !ok || id <= 0 {
		t.Fatalf("Kotlin CompletionItemId = %#v", widget.Command.Arguments[0])
	}
	// A later completion request must not invalidate an item which is still
	// visible to the client from the same document version.
	if _, secondErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": useURI}, "position": useDoc.Position(strings.Index(useSource, "Wid") + 3)})); secondErr != nil {
		t.Fatal(secondErr)
	}
	applyCalls := 0
	s.clientCall = func(_ context.Context, method string, params, result any) error {
		if method != "workspace/applyEdit" || !strings.Contains(fmt.Sprint(params), "import model.Widget") {
			t.Fatalf("completion client request = %s %#v", method, params)
		}
		applyCalls++
		setAppliedResult(t, result)
		return nil
	}
	applied, responseErr := s.Request(context.Background(), "workspace/executeCommand", mustJSON(map[string]any{"command": widget.Command.Command, "arguments": widget.Command.Arguments}))
	if responseErr != nil || applied != true || applyCalls != 1 {
		t.Fatalf("Kotlin completion apply = %#v, %v; calls=%d", applied, responseErr, applyCalls)
	}

	javaURI := protocol.URI("file:///workspace/app/Use.java")
	javaSource := "package app; class Use { Wid value; }\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: javaSource})
	javaDoc := textdoc.NewDocument(javaURI, "java", 1, javaSource)
	javaResult, javaErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": javaURI}, "position": javaDoc.Position(strings.Index(javaSource, "Wid") + 3)}))
	if javaErr != nil {
		t.Fatal(javaErr)
	}
	for _, item := range javaResult.(protocol.CompletionList).Items {
		if item.Label != "Widget" {
			continue
		}
		if item.Command == nil || item.Command.Command != "jetbrains.java.completion.apply" || len(item.Command.Arguments) != 1 {
			t.Fatalf("Java completion command = %#v", item.Command)
		}
		if len(item.AdditionalTextEdits) != 1 || !strings.Contains(item.AdditionalTextEdits[0].NewText, "import model.Widget;") {
			t.Fatalf("basic-client Java import edits = %#v", item.AdditionalTextEdits)
		}
		data, ok := item.Command.Arguments[0].(map[string]any)
		if !ok || !strings.HasSuffix(fmt.Sprint(data["type"]), "ModCommandData.Nothing") {
			t.Fatalf("Java ModCommandData = %#v", item.Command.Arguments[0])
		}
		return
	}
	t.Fatal("Java completion did not include Widget")
}

func markTestServerInitialized(s *Server) {
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
}

func TestCompletionAndWorkspaceSymbolsReturnEveryMatch(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/AllCandidates.kt")
	var source strings.Builder
	for number := range 350 {
		fmt.Fprintf(&source, "fun candidate%03d(): Int = %d\n", number, number)
	}
	source.WriteString("fun use() { candidate }\n")
	text := source.String()
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: text})
	doc := textdoc.NewDocument(uri, "kotlin", 1, text)

	result, responseErr := s.completion(mustJSON(map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     doc.Position(strings.LastIndex(text, "candidate") + len("candidate")),
	}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	completionMatches := 0
	for _, item := range result.(protocol.CompletionList).Items {
		if strings.HasPrefix(item.Label, "candidate") {
			completionMatches++
		}
	}
	if completionMatches != 350 {
		t.Fatalf("completion returned %d candidate items, want all 350", completionMatches)
	}

	workspaceResult, responseErr := s.workspaceSymbols(mustJSON(map[string]any{"query": "candidate"}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	workspaceMatches := 0
	for _, item := range workspaceResult.([]protocol.SymbolInformation) {
		if strings.HasPrefix(item.Name, "candidate") {
			workspaceMatches++
		}
	}
	if workspaceMatches != 350 {
		t.Fatalf("workspace/symbol returned %d candidates, want all 350", workspaceMatches)
	}
}

func TestQualifiedCompletionSuppressesUnrelatedKeywords(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/Qualified.kt")
	source := "class A { fun make() = A() }\nfun use(a: A) { a.ma }\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	result, responseErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": doc.Position(strings.Index(source, ".ma") + len(".ma"))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	foundMake := false
	for _, item := range result.(protocol.CompletionList).Items {
		if item.Label == "make" {
			foundMake = true
		}
		if item.Label == "class" || item.Label == "interface" || item.Label == "fun" {
			t.Fatalf("qualified completion contains keyword %#v", item)
		}
	}
	if !foundMake {
		t.Fatalf("qualified member completion missing make: %#v", result)
	}
}

func TestJavaAnnotationAttributeCompletion(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/Config.java")
	source := "@interface Config { String path(); int count(); }\n@Config(pa) class Use {}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.completion(mustJSON(map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     doc.Position(strings.Index(source, "@Config(pa") + len("@Config(pa")),
	}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	for _, item := range result.(protocol.CompletionList).Items {
		if item.Label == "path" {
			if item.InsertText != "path = " {
				t.Fatalf("annotation attribute insert text = %q", item.InsertText)
			}
			return
		}
	}
	t.Fatalf("annotation completion lacks path: %#v", result)
}

func TestJavaAnnotationCompletionOmitsAlreadyAssignedAttribute(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/AssignedConfig.java")
	source := "@interface Config { String path(); int count(); }\n@Config(path=\"x\", pa) class Use {}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": doc.Position(strings.Index(source, ", pa") + len(", pa"))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	if containsCompletionLabel(result.(protocol.CompletionList).Items, "path") {
		t.Fatalf("already assigned annotation attribute was offered: %#v", result)
	}
}

func TestJavaLabelAndModuleReferenceCompletion(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	labelURI := protocol.URI("file:///workspace/C.java")
	labelSource := "class C { void f(){ outer: while(true){ break ou; } } }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: labelURI, LanguageID: "java", Version: 1, Text: labelSource})
	labelDoc := textdoc.NewDocument(labelURI, "java", 1, labelSource)
	labelResult, responseErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": labelURI}, "position": labelDoc.Position(strings.Index(labelSource, "break ou") + len("break ou"))}))
	if responseErr != nil || !containsCompletionLabel(labelResult.(protocol.CompletionList).Items, "outer") {
		t.Fatalf("Java label completion = %#v, %v", labelResult, responseErr)
	}

	firstURI := protocol.URI("file:///workspace/first/module-info.java")
	useURI := protocol.URI("file:///workspace/use/module-info.java")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: firstURI, LanguageID: "java", Version: 1, Text: "module first.module {}"})
	useSource := "module use.module { requires fir; }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "java", Version: 1, Text: useSource})
	useDoc := textdoc.NewDocument(useURI, "java", 1, useSource)
	moduleResult, responseErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": useURI}, "position": useDoc.Position(strings.Index(useSource, "fir") + 3)}))
	if responseErr != nil || !containsCompletionLabel(moduleResult.(protocol.CompletionList).Items, "first.module") {
		t.Fatalf("Java module completion = %#v, %v", moduleResult, responseErr)
	}
}

func TestJavaLabelCompletionRespectsLabeledStatementScope(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/LabelScope.java")
	source := "class C { void a(){ first: while(true){} } void b(){ break fi; } }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": doc.Position(strings.Index(source, "break fi") + len("break fi"))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	if containsCompletionLabel(result.(protocol.CompletionList).Items, "first") {
		t.Fatalf("out-of-scope Java label was offered: %#v", result)
	}
}

func TestAmbiguousImportChooseActionRetainsRealServerSideActions(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	uri := protocol.URI("file:///workspace/app/Use.kt")
	source := "package app\nfun use(value: Widget) = value\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	diagnostic := protocol.Diagnostic{Range: protocol.Range{}, Message: "Unresolved Widget", Data: map[string]any{"candidates": []any{"alpha.Widget", "beta.Widget"}}}
	result, responseErr := s.codeActions(mustJSON(map[string]any{
		"textDocument": map[string]any{"uri": uri}, "range": protocol.Range{},
		"context": map[string]any{"diagnostics": []any{diagnostic}},
	}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	var choose protocol.CodeAction
	for _, action := range result.([]protocol.CodeAction) {
		if action.Title == "Choose import" {
			choose = action
			break
		}
	}
	if choose.Command == nil || len(choose.Command.Arguments) != 1 {
		t.Fatalf("choose action = %#v", choose)
	}
	payload, ok := choose.Command.Arguments[0].(map[string]any)
	if !ok || payload["actions"] != nil {
		t.Fatalf("ChooseAction DTO exposed server actions: %#v", choose.Command.Arguments[0])
	}
	sessionID, ok := payload["sessionId"].(int64)
	if !ok || sessionID <= 0 {
		t.Fatalf("ChooseAction session = %#v", payload["sessionId"])
	}
	if _, responseErr = s.applyModCommand(context.Background(), []json.RawMessage{mustJSON(payload)}); responseErr != nil {
		t.Fatal(responseErr)
	}
	var appliedParams any
	s.clientCall = func(_ context.Context, method string, params, result any) error {
		if method != "workspace/applyEdit" {
			t.Fatalf("client method = %q", method)
		}
		appliedParams = params
		setAppliedResult(t, result)
		return nil
	}
	chosen, responseErr := s.chooseModCommandAction(context.Background(), []json.RawMessage{mustJSON(sessionID), mustJSON(1)})
	if responseErr != nil || chosen != true || !strings.Contains(fmt.Sprint(appliedParams), "import beta.Widget") {
		t.Fatalf("selected action = %#v, %v; edit=%#v", chosen, responseErr, appliedParams)
	}
}

func setAppliedResult(t *testing.T, result any) {
	t.Helper()
	// The concrete response type is deliberately private to applyWorkspaceEdit;
	// JSON is the stable contract used by both the real transport and this mock.
	value := reflect.ValueOf(result)
	if value.Kind() != reflect.Pointer || value.Elem().Kind() != reflect.Struct {
		t.Fatalf("workspace/applyEdit response target = %T", result)
	}
	field := value.Elem().FieldByName("Applied")
	if !field.IsValid() || !field.CanSet() {
		t.Fatalf("workspace/applyEdit response target lacks Applied: %T", result)
	}
	field.SetBool(true)
}

func TestSnippetEscapingMatchesIntelliJExtension(t *testing.T) {
	if got := escapeSnippet(`a$}\b`, false); got != `a\$\}\\b` {
		t.Fatalf("snippet escaping = %q", got)
	}
	if got := escapeSnippet(`a,b|c`, true); got != `a\,b\|c` {
		t.Fatalf("choice escaping = %q", got)
	}
}

func TestFileTemplateInterpolationEvaluatesDirectives(t *testing.T) {
	values := map[string]string{"NAME": "Template"}
	template := "#if (${NAME})Hello ${NAME}#else Missing#end|#set($VALUE = 'ok')${VALUE}|${UNKNOWN}"
	if got := interpolateFileTemplateText(template, values); got != "Hello Template|ok|" {
		t.Fatalf("template interpolation = %q", got)
	}
}

func TestRenameTypeAlsoRenamesMatchingSourceFile(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	s.clientCaps = map[string]any{"workspace": map[string]any{"workspaceEdit": map[string]any{"resourceOperations": []any{"rename"}}}}
	uri := protocol.URI("file:///workspace/Widget.java")
	source := "public class Widget {}"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	doc := textdoc.NewDocument(uri, "java", 1, source)
	result, responseErr := s.rename(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": doc.Position(strings.Index(source, "Widget")), "newName": "RenamedWidget"}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	edit := result.(protocol.WorkspaceEdit)
	if len(edit.Changes) != 0 || len(edit.DocumentChanges) != 2 {
		t.Fatalf("rename edit = %#v", edit)
	}
	rename, ok := edit.DocumentChanges[1].(protocol.RenameFile)
	if !ok || rename.NewURI != "file:///workspace/RenamedWidget.java" {
		t.Fatalf("file rename = %#v", edit.DocumentChanges)
	}
	s.clientCaps = map[string]any{}
	result, responseErr = s.rename(mustJSON(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": doc.Position(strings.Index(source, "Widget")), "newName": "TextOnlyWidget"}))
	if responseErr != nil || len(result.(protocol.WorkspaceEdit).DocumentChanges) != 1 {
		t.Fatalf("unsupported resource operation was returned: result=%#v error=%v", result, responseErr)
	}
}

func TestDirectoryPackageMoveUpdatesQualifiedReferences(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	root := t.TempDir()
	oldDir := filepath.Join(root, "src", "p")
	newDir := filepath.Join(root, "src", "q")
	useDir := filepath.Join(root, "src", "use")
	for _, directory := range []string{oldDir, useDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fooURI := uriutil.File(filepath.Join(oldDir, "Foo.java"))
	useURI := uriutil.File(filepath.Join(useDir, "Use.java"))
	foo := "package p; public class Foo {}"
	use := "package use; class Use { p.Foo value; }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: fooURI, LanguageID: "java", Version: 1, Text: foo})
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "java", Version: 1, Text: use})
	result, responseErr := s.willRenameFiles(mustJSON(map[string]any{"files": []any{map[string]any{"oldUri": uriutil.File(oldDir), "newUri": uriutil.File(newDir)}}}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	edit := result.(protocol.WorkspaceEdit)
	if !hasNewText(edit.Changes[fooURI], "package q;") || !hasNewText(edit.Changes[useURI], "q") {
		t.Fatalf("directory move edits = %#v", edit.Changes)
	}
}

func TestHoverReferenceRangeBelongsToRequestedDocument(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	declarationURI := protocol.URI("file:///workspace/Target.kt")
	useURI := protocol.URI("file:///workspace/Use.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: declarationURI, LanguageID: "kotlin", Version: 1, Text: "class Target\n"})
	use := "fun use(value: Target) = value\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: useURI, LanguageID: "kotlin", Version: 1, Text: use})
	doc := textdoc.NewDocument(useURI, "kotlin", 1, use)
	result, responseErr := s.hover(mustJSON(map[string]any{"textDocument": map[string]any{"uri": useURI}, "position": doc.Position(strings.Index(use, "Target"))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	hover := result.(protocol.Hover)
	expected := doc.Range(strings.Index(use, "Target"), strings.Index(use, "Target")+len("Target"))
	if hover.Range == nil || *hover.Range != expected {
		t.Fatalf("hover range = %#v, want use-site %#v", hover.Range, expected)
	}
}

func TestKotlinCompletionEscapesJavaKeywordMember(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	javaURI := protocol.URI("file:///workspace/Weird.java")
	kotlinURI := protocol.URI("file:///workspace/Use.kt")
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: javaURI, LanguageID: "java", Version: 1, Text: "public class Weird { public void is() {} }"})
	source := "fun use(w: Weird) { w.i }"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: kotlinURI, LanguageID: "kotlin", Version: 1, Text: source})
	doc := textdoc.NewDocument(kotlinURI, "kotlin", 1, source)
	result, responseErr := s.completion(mustJSON(map[string]any{"textDocument": map[string]any{"uri": kotlinURI}, "position": doc.Position(strings.Index(source, "w.i") + len("w.i"))}))
	if responseErr != nil {
		t.Fatal(responseErr)
	}
	for _, item := range result.(protocol.CompletionList).Items {
		if item.Label == "is" {
			if item.InsertText != "`is`" {
				t.Fatalf("keyword member insertText = %q", item.InsertText)
			}
			return
		}
	}
	t.Fatal("Java keyword member completion missing")
}

func hasNewText(edits []protocol.TextEdit, expected string) bool {
	for _, edit := range edits {
		if edit.NewText == expected {
			return true
		}
	}
	return false
}

func applyTextEdits(t *testing.T, doc *textdoc.Document, edits []protocol.TextEdit) string {
	t.Helper()
	type offsetEdit struct {
		start, end int
		text       string
	}
	converted := make([]offsetEdit, len(edits))
	for n, edit := range edits {
		converted[n] = offsetEdit{doc.Offset(edit.Range.Start), doc.Offset(edit.Range.End), edit.NewText}
	}
	sort.SliceStable(converted, func(a, b int) bool {
		if converted[a].start == converted[b].start {
			return converted[a].end > converted[b].end
		}
		return converted[a].start > converted[b].start
	})
	text := doc.Text
	for _, edit := range converted {
		if edit.start < 0 || edit.end < edit.start || edit.end > len(text) {
			t.Fatalf("invalid edit %#v for %d bytes", edit, len(text))
		}
		text = text[:edit.start] + edit.text + text[edit.end:]
	}
	return text
}

func containsCompletionLabel(items []protocol.CompletionItem, label string) bool {
	for _, item := range items {
		if item.Label == label {
			return true
		}
	}
	return false
}
