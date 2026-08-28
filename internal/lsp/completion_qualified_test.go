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

func qualifiedFixture(t *testing.T, capabilities map[string]any) (*Server, protocol.URI, int) {
	t.Helper()
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	t.Cleanup(func() { s.Close() })
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	s.rootMu.Lock()
	s.clientCaps = capabilities
	s.rootMu.Unlock()

	// Two unrelated libraries declaring the same simple name.
	for _, library := range []struct{ uri, pkg string }{
		{"file:///libs/a/Marker.java", "one.side"},
		{"file:///libs/b/Marker.java", "other.side"},
	} {
		text := "package " + library.pkg + ";\npublic interface Marker {}\n"
		parsed := analysis.Parse(context.Background(), textdoc.NewDocument(protocol.URI(library.uri), "java", 0, text))
		s.index.AddLibraryBatch([]index.LibraryFile{{
			Source: index.LibrarySource{Archive: "/deps/" + library.pkg + ".jar", Entry: "Marker.java", LanguageID: "java"},
			Parsed: *parsed,
		}})
	}
	uri := protocol.URI("file:///workspace/Use.kt")
	source := "package app\n\nclass Use {\n    fun run() {\n        Mark\n    }\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	return s, uri, strings.Index(source, "Mark") + len("Mark")
}

func completeAt(t *testing.T, s *Server, uri protocol.URI, offset int) []protocol.CompletionItem {
	t.Helper()
	document, ok := s.index.Document(uri)
	if !ok {
		t.Fatal("document missing")
	}
	params, err := json.Marshal(map[string]any{
		"textDocument": map[string]any{"uri": uri}, "position": document.Position(offset),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, responseErr := s.Request(context.Background(), "textDocument/completion", params)
	if responseErr != nil {
		t.Fatalf("completion failed: %v", responseErr)
	}
	list, ok := result.(protocol.CompletionList)
	if !ok {
		t.Fatalf("unexpected result type %T", result)
	}
	return list.Items
}

// Two declarations can share a simple name, and accepting one writes an import.
// Without the qualified name the list gives no way to tell them apart or to see
// what is about to be imported.
func TestCompletionShowsQualifiedNameForImportableTypes(t *testing.T) {
	s, uri, offset := qualifiedFixture(t, map[string]any{
		"textDocument": map[string]any{"completion": map[string]any{
			"completionItem": map[string]any{"labelDetailsSupport": true},
		}},
	})
	found := map[string]bool{}
	for _, item := range completeAt(t, s, uri, offset) {
		if item.Label != "Marker" {
			continue
		}
		if item.LabelDetails == nil {
			t.Fatalf("completion item %q carries no qualified name", item.Label)
		}
		description, _ := item.LabelDetails["description"].(string)
		found[description] = true
	}
	for _, want := range []string{"one.side.Marker", "other.side.Marker"} {
		if !found[want] {
			t.Fatalf("qualified name %q was not offered, got %v", want, found)
		}
	}
}

// A client that cannot render labelDetails must still be told what an accepted
// item will import.
func TestCompletionFallsBackToDetailWithoutLabelDetails(t *testing.T) {
	s, uri, offset := qualifiedFixture(t, map[string]any{"textDocument": map[string]any{}})
	qualified := 0
	for _, item := range completeAt(t, s, uri, offset) {
		if item.Label != "Marker" {
			continue
		}
		if item.LabelDetails != nil {
			t.Fatal("labelDetails was sent to a client that did not advertise support")
		}
		if strings.Contains(item.Detail, "one.side.Marker") || strings.Contains(item.Detail, "other.side.Marker") {
			qualified++
		}
	}
	if qualified == 0 {
		t.Fatal("no completion item disclosed the import it would add")
	}
}

// A library type indexed from both its own jar and its sources jar carries one
// qualified name and must be offered once.
func TestCompletionOffersOneEntryPerQualifiedType(t *testing.T) {
	s, uri, offset := qualifiedFixture(t, map[string]any{
		"textDocument": map[string]any{"completion": map[string]any{
			"completionItem": map[string]any{"labelDetailsSupport": true},
		}},
	})
	// Index the same declaration a second time, as a sources jar would.
	text := "package one.side;\npublic interface Marker {}\n"
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument("file:///libs/a-sources/Marker.java", "java", 0, text))
	s.index.AddLibraryBatch([]index.LibraryFile{{
		Source: index.LibrarySource{Archive: "/deps/one.side-sources.jar", Entry: "Marker.java", LanguageID: "java"},
		Parsed: *parsed,
	}})

	counts := map[string]int{}
	for _, item := range completeAt(t, s, uri, offset) {
		if item.Label != "Marker" {
			continue
		}
		description, _ := item.LabelDetails["description"].(string)
		counts[description]++
	}
	for description, count := range counts {
		if count != 1 {
			t.Fatalf("qualified type %q was offered %d times", description, count)
		}
	}
	if len(counts) != 2 {
		t.Fatalf("expected both distinct Marker types, got %v", counts)
	}
}
