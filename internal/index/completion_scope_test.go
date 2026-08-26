package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// cursorAt splits a source marked with a single '|' into the source and the
// byte offset the marker stood at.
func cursorAt(t *testing.T, marked string) (string, int) {
	t.Helper()
	at := strings.IndexByte(marked, '|')
	if at < 0 {
		t.Fatalf("no cursor marker in %q", marked)
	}
	return marked[:at] + marked[at+1:], at
}

func TestCompletionScopeInKotlin(t *testing.T) {
	for _, fixture := range []struct {
		label  string
		source string
		want   CompletionScope
	}{
		{"plain code", "val x = us|", CompletionCode},
		{"string body", `val x = "hello wor|"`, CompletionNone},
		{"empty string", `val x = "|"`, CompletionNone},
		{"before a string", `f(|"x")`, CompletionCode},
		{"after a string", `val x = "a"; y|`, CompletionCode},
		{"simple template", `val x = "$us|"`, CompletionCode},
		{"text after a simple template", `val x = "$user.em|"`, CompletionNone},
		{"braced template", `val x = "${user.em|}"`, CompletionCode},
		{"after a braced template", `val x = "${user}|"`, CompletionNone},
		{"string inside a template", `val x = "${f("in|")}"`, CompletionNone},
		{"raw string", `val x = """raw tex|"""`, CompletionNone},
		{"template in a raw string", `val x = """raw ${us|}"""`, CompletionCode},
		{"character literal", "val c = 'a|'", CompletionNone},
		{"line comment", "// a comment he|", CompletionNone},
		{"before a line comment", "val x = 1 |// c", CompletionCode},
		{"block comment", "/* a comment he| */", CompletionNone},
		{"nested block comment", "/* outer /* inner he| */ */", CompletionNone},
		{"doc prose", "/** documents the thin| */", CompletionNone},
		{"doc tag", "/** @par| */", CompletionDocTag},
		{"doc tag on a continuation line", "/**\n * text\n * @ret|\n */", CompletionDocTag},
		{"doc param", "/** @param na| */", CompletionDocParameter},
		{"doc property", "/** @property na| */", CompletionDocParameter},
		{"doc throws", "/** @throws IllegalStat| */", CompletionDocType},
		{"doc see", "/** @see Fo| */", CompletionDocReference},
		{"kdoc bracket", "/** see [Fo| */", CompletionDocReference},
		{"kdoc closed bracket", "/** see [Foo] and no| */", CompletionNone},
		{"inline link", "/** {@link Foo#ba|} */", CompletionDocReference},
		{"prose after a tag argument", "/** @param name the val| */", CompletionNone},
		{"unterminated string", "val x = \"abc|\nval y = 1", CompletionNone},
		{"code after an unterminated string", "val x = \"abc\nval y| = 1", CompletionCode},
	} {
		source, offset := cursorAt(t, fixture.source)
		if got := CompletionPositionAt(source, offset, true).Scope; got != fixture.want {
			t.Errorf("%s: scope %d, want %d", fixture.label, got, fixture.want)
		}
	}
}

func TestCompletionScopeInJava(t *testing.T) {
	for _, fixture := range []struct {
		label  string
		source string
		want   CompletionScope
	}{
		{"plain code", "int x = us|", CompletionCode},
		{"string body", `String s = "hello wor|";`, CompletionNone},
		{"a dollar in a Java string is text", `String s = "$user|";`, CompletionNone},
		{"text block", "String s = \"\"\"\n  tex|\n  \"\"\";", CompletionNone},
		{"character literal", "char c = 'a|';", CompletionNone},
		{"line comment", "int x = 1; // he|", CompletionNone},
		{"doc prose", "/** documents the thin| */", CompletionNone},
		{"doc tag", "/** @par| */", CompletionDocTag},
		{"doc param", "/** @param na| */", CompletionDocParameter},
		{"doc throws", "/** @throws IOExcep| */", CompletionDocType},
		{"inline link", "/** {@link Foo#ba|} */", CompletionDocReference},
		{"a bracket is not a KDoc reference", "/** an array[| */", CompletionNone},
	} {
		source, offset := cursorAt(t, fixture.source)
		if got := CompletionPositionAt(source, offset, false).Scope; got != fixture.want {
			t.Errorf("%s: scope %d, want %d", fixture.label, got, fixture.want)
		}
	}
}

// completionAt opens a source marked with a cursor and returns the names the
// index offers there.
func completionAt(t *testing.T, marked string, extra map[string]string) []string {
	t.Helper()
	source, offset := cursorAt(t, marked)
	language := "kotlin"
	uri := protocol.URI("file:///workspace/app/Probe.kt")
	if strings.Contains(source, ";") && !strings.Contains(source, "val ") && !strings.Contains(source, "fun ") {
		language, uri = "java", "file:///workspace/app/Probe.java"
	}
	idx := New(nil)
	t.Cleanup(idx.Close)
	openKotlinBuiltins(idx)
	for path, text := range extra {
		id := "kotlin"
		if strings.HasSuffix(path, ".java") {
			id = "java"
		}
		idx.Open(context.Background(), protocol.TextDocumentItem{URI: protocol.URI("file:///workspace/" + path), LanguageID: id, Version: 1, Text: text})
	}
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: language, Version: 1, Text: source})
	idx.markReady()
	document, _ := idx.Document(uri)
	symbols := idx.Completion(uri, document.Position(offset), 100)
	names := make([]string, 0, len(symbols))
	for _, symbol := range symbols {
		names = append(names, symbol.Name)
	}
	return names
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestCompletionIsSilentInLiteralsAndProse(t *testing.T) {
	for _, fixture := range []struct{ label, source string }{
		{"string body", "package app\nclass User { val email = \"\" }\nfun f(user: User) { println(\"the address is user.emai|\") }\n"},
		{"member access spelled in a string", "package app\nclass User { val email = \"\" }\nfun f(user: User) { println(\"$user.emai|\") }\n"},
		{"line comment", "package app\nclass User { val email = \"\" }\nfun f(user: User) { // user.emai|\n}\n"},
		{"doc prose", "package app\nclass User { val email = \"\" }\n/** the user emai| */\nfun f(user: User) {}\n"},
	} {
		if names := completionAt(t, fixture.source, nil); len(names) != 0 {
			t.Errorf("%s: offered %v", fixture.label, names)
		}
	}
}

func TestCompletionStillWorksInTemplatesAndCode(t *testing.T) {
	for _, fixture := range []struct{ label, source, want string }{
		{"code", "package app\nclass User { val email = \"\" }\nfun f(user: User) { user.emai| }\n", "email"},
		{"simple template names the identifier", "package app\nclass User { val email = \"\" }\nfun f(user: User) { println(\"$use|\") }\n", "user"},
		{"braced template resolves members", "package app\nclass User { val email = \"\" }\nfun f(user: User) { println(\"${user.emai|}\") }\n", "email"},
		{"before a string", "package app\nfun g(x: String) {}\nfun f(user: String) { g(use|\"\") }\n", "user"},
	} {
		if names := completionAt(t, fixture.source, nil); !contains(names, fixture.want) {
			t.Errorf("%s: wanted %q, got %v", fixture.label, fixture.want, names)
		}
	}
}

func TestDocCommentReferencesComplete(t *testing.T) {
	for _, fixture := range []struct {
		label, source, want string
		absent              string
	}{
		{
			label:  "param names the documented parameters",
			source: "package app\n/** @param addr| */\nfun send(address: String, subject: String) {}\n",
			want:   "address",
		},
		{
			label:  "param offers a constructor property",
			source: "package app\n/** @property lab| */\nclass Card(val label: String)\n",
			want:   "label",
		},
		{
			label:  "param does not offer unrelated declarations",
			source: "package app\nclass Elsewhere { val address = \"\" }\n/** @param zz| */\nfun send(address: String) {}\n",
			absent: "Elsewhere",
		},
		{
			label:  "throws offers a type",
			source: "package app\nclass ParseFailure\n/** @throws ParseFail| */\nfun read() {}\n",
			want:   "ParseFailure",
		},
		{
			label:  "throws does not offer a function",
			source: "package app\nfun parseFailure() {}\nclass Other\n/** @throws parseFail| */\nfun read() {}\n",
			absent: "parseFailure",
		},
		{
			label:  "see offers a declaration",
			source: "package app\nclass Card\n/** @see Car| */\nfun read() {}\n",
			want:   "Card",
		},
		{
			label:  "a kdoc bracket offers a declaration",
			source: "package app\nclass Card\n/** see [Car| */\nfun read() {}\n",
			want:   "Card",
		},
	} {
		names := completionAt(t, fixture.source, nil)
		if fixture.want != "" && !contains(names, fixture.want) {
			t.Errorf("%s: wanted %q, got %v", fixture.label, fixture.want, names)
		}
		if fixture.absent != "" && contains(names, fixture.absent) {
			t.Errorf("%s: %q should not be offered, got %v", fixture.label, fixture.absent, names)
		}
	}
}

func TestJavadocMemberReferenceCompletesThroughHash(t *testing.T) {
	source := "package app;\nclass Card { int number() { return 1; } }\n/** {@link Card#numb|} */\nclass Reader {}\n"
	names := completionAt(t, source, nil)
	if !contains(names, "number") {
		t.Errorf("wanted the member 'number', got %v", names)
	}
}

// One member of a receiver is one entry. The same declaration arrives several
// times over -- a multiplatform pair, an override and the member it overrides,
// the Kotlin and Java views of one JVM method -- and offering each copy gives
// the author a list of identical-looking choices.
func TestMemberCompletionOffersEachMemberOnce(t *testing.T) {
	idx := New(nil)
	t.Cleanup(idx.Close)
	// A receiver whose member is declared in a supertype, overridden, and
	// visible under a second language's view of the same class.
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: "file:///stdlib/kotlin/Text.kt", LanguageID: "kotlin", Version: 1,
		Text: "package kotlin\n\ninterface CharSequence { val length: Int }\nclass String : CharSequence { override val length: Int = 0\n fun take(n: Int): String = this\n fun take(s: String): String = this }\n",
	})
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: "file:///stdlib/java/lang/String.java", LanguageID: "java", Version: 1,
		Text: "package java.lang;\npublic class String { public int length() { return 0; } }\n",
	})
	uri := protocol.URI("file:///workspace/app/Probe.kt")
	source := "package app\nfun f(s: String) { s.len }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	idx.markReady()
	document, _ := idx.Document(uri)
	lengths, takes := 0, 0
	for _, symbol := range idx.Completion(uri, document.Position(strings.Index(source, "s.len")+len("s.len")), 50) {
		switch symbol.Name {
		case "length":
			lengths++
		case "take":
			takes++
		}
	}
	if lengths != 1 {
		t.Errorf("'length' offered %d times, want once", lengths)
	}
	// Overloads are different members and must all survive.
	source = "package app\nfun f(s: String) { s.tak }\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 2, Text: source})
	document, _ = idx.Document(uri)
	takes = 0
	for _, symbol := range idx.Completion(uri, document.Position(strings.Index(source, "s.tak")+len("s.tak")), 50) {
		if symbol.Name == "take" {
			takes++
		}
	}
	if takes != 2 {
		t.Errorf("'take' offered %d times, want both overloads", takes)
	}
}
