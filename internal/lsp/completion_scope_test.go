package lsp

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// scopeFixture opens a source marked with a single '|' and returns the server
// and the offset the marker stood at.
func scopeFixture(t *testing.T, name, language, marked string) (*Server, protocol.URI, int) {
	t.Helper()
	at := strings.IndexByte(marked, '|')
	if at < 0 {
		t.Fatalf("no cursor marker in %q", marked)
	}
	source := marked[:at] + marked[at+1:]
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.index.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	uri := protocol.URI("file:///workspace/" + name)
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: language, Version: 1, Text: source})
	return s, uri, at
}

// Keywords and snippets come from the server rather than the index, so the
// suppression has to hold there too: a string body offers nothing at all.
func TestCompletionOffersNothingInsideLiteralsAndProse(t *testing.T) {
	for _, fixture := range []struct{ label, name, language, source string }{
		{"kotlin string", "Probe.kt", "kotlin", "package app\nfun f() { val s = \"a val| here\" }\n"},
		{"kotlin line comment", "Probe.kt", "kotlin", "package app\n// a val| here\nfun f() {}\n"},
		{"kotlin block comment", "Probe.kt", "kotlin", "package app\n/* a val| here */\nfun f() {}\n"},
		{"kotlin doc prose", "Probe.kt", "kotlin", "package app\n/** a val| here */\nfun f() {}\n"},
		{"java string", "Probe.java", "java", "package app;\nclass C { void f() { String s = \"a fin| here\"; } }\n"},
		{"java line comment", "Probe.java", "java", "package app;\n// a fin| here\nclass C {}\n"},
		{"java doc prose", "Probe.java", "java", "package app;\n/** a fin| here */\nclass C {}\n"},
	} {
		s, uri, offset := scopeFixture(t, fixture.name, fixture.language, fixture.source)
		if items := completeAt(t, s, uri, offset); len(items) != 0 {
			labels := make([]string, 0, len(items))
			for _, item := range items {
				labels = append(labels, item.Label)
			}
			t.Errorf("%s: offered %v", fixture.label, labels)
		}
	}
}

// The counterpart: a Kotlin template is code, and everything applies there.
func TestCompletionStillOffersKeywordsInCode(t *testing.T) {
	for _, fixture := range []struct{ label, source, want string }{
		{"plain code", "package app\nfun f() { val| }\n", "val"},
		{"braced template", "package app\nfun f(x: Int) { val s = \"${if (x > 1) 1 else 2} ${wh|}\" }\n", "when"},
	} {
		s, uri, offset := scopeFixture(t, "Probe.kt", "kotlin", fixture.source)
		found := false
		for _, item := range completeAt(t, s, uri, offset) {
			if item.Label == fixture.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: %q was not offered", fixture.label, fixture.want)
		}
	}
}

// A doc comment completes its own tags. The edit spans the '@' already typed,
// so accepting one cannot produce '@@param'.
func TestDocTagsComplete(t *testing.T) {
	for _, fixture := range []struct{ label, name, language, source, want string }{
		{"kotlin", "Probe.kt", "kotlin", "package app\n/** @par| */\nfun f(name: String) {}\n", "@param"},
		{"kotlin property", "Probe.kt", "kotlin", "package app\n/** @prop| */\nclass C(val name: String)\n", "@property"},
		{"java", "Probe.java", "java", "package app;\n/** @thro| */\nclass C {}\n", "@throws"},
	} {
		s, uri, offset := scopeFixture(t, fixture.name, fixture.language, fixture.source)
		items := completeAt(t, s, uri, offset)
		var matched *protocol.CompletionItem
		for index := range items {
			if items[index].Label == fixture.want {
				matched = &items[index]
			}
		}
		if matched == nil {
			labels := make([]string, 0, len(items))
			for _, item := range items {
				labels = append(labels, item.Label)
			}
			t.Fatalf("%s: %q was not offered, got %v", fixture.label, fixture.want, labels)
		}
		if matched.TextEdit == nil {
			t.Fatalf("%s: no edit range, so accepting would double the '@'", fixture.label)
		}
		document, _ := s.index.Document(uri)
		start := document.Offset(matched.TextEdit.Range.Start)
		if document.Text[start] != '@' {
			t.Errorf("%s: the edit starts at %q, not the '@'", fixture.label, document.Text[start])
		}
	}
}

// A Java doc tag list must not offer KDoc's tags, and the other way round.
func TestDocTagsAreLanguageSpecific(t *testing.T) {
	s, uri, offset := scopeFixture(t, "Probe.java", "java", "package app;\n/** @| */\nclass C {}\n")
	for _, item := range completeAt(t, s, uri, offset) {
		if item.Label == "@property" || item.Label == "@constructor" || item.Label == "@sample" {
			t.Errorf("KDoc tag %q offered in Java", item.Label)
		}
	}
	s, uri, offset = scopeFixture(t, "Probe.kt", "kotlin", "package app\n/** @| */\nfun f() {}\n")
	for _, item := range completeAt(t, s, uri, offset) {
		if item.Label == "@implNote" || item.Label == "@serialField" {
			t.Errorf("Javadoc tag %q offered in Kotlin", item.Label)
		}
	}
}
