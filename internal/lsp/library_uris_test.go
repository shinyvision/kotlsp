package lsp

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/index"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
	uriutil "github.com/shinyvision/kotlsp/internal/uri"
)

// libraryFixture indexes one real sources jar and returns the server plus the
// workspace document that navigates into it.
func libraryFixture(t *testing.T) (*Server, protocol.URI, protocol.URI) {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	librarySource := "package demo;\npublic class Service {\n    public String run() {\n        return \"ok\";\n    }\n}\n"
	archive := filepath.Join(t.TempDir(), "library-sources.jar")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create("demo/Service.java")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entry.Write([]byte(librarySource)); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}

	libraryURI := protocol.URI("jar://" + filepath.ToSlash(archive) + "!/demo/Service.java")
	parsed := analysis.Parse(context.Background(), textdoc.NewDocument(libraryURI, "java", 0, librarySource))
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	s.index.AddLibraryBatch([]index.LibraryFile{{
		Source: index.LibrarySource{Archive: archive, Entry: "demo/Service.java", LanguageID: "java"},
		Parsed: *parsed,
	}})

	workspaceURI := protocol.URI("file:///workspace/Caller.java")
	workspace := "package demo;\nclass Caller {\n    Service field;\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: workspaceURI, LanguageID: "java", Version: 1, Text: workspace})
	return s, workspaceURI, libraryURI
}

// The reported failure: a definition answered with a jar:// URI makes the
// client open an empty buffer and then fail to place the cursor. Every
// navigation target must be a file the editor can actually read.
func TestDefinitionIntoLibraryReturnsAnOpenableFile(t *testing.T) {
	s, workspaceURI, libraryURI := libraryFixture(t)
	defer s.Close()

	params, err := json.Marshal(map[string]any{
		"textDocument": map[string]any{"uri": workspaceURI},
		"position":     protocol.Position{Line: 2, Character: 6},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, responseErr := s.Request(context.Background(), "textDocument/definition", params)
	if responseErr != nil {
		t.Fatalf("definition failed: %v", responseErr)
	}
	found, ok := result.([]protocol.Location)
	if !ok || len(found) == 0 {
		t.Fatalf("definition returned no location: %#v", result)
	}
	for _, location := range found {
		if strings.HasPrefix(string(location.URI), "jar://") || strings.HasPrefix(string(location.URI), "jrt://") {
			t.Fatalf("definition leaked an archive URI the editor cannot open: %s", location.URI)
		}
		path, isFile := uriutil.Path(location.URI)
		if !isFile {
			t.Fatalf("definition target is not a file URI: %s", location.URI)
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("definition target does not exist on disk: %v", readErr)
		}
		// The client places the cursor at the reported line, so the file must
		// be long enough for that line to exist.
		if lines := strings.Count(string(content), "\n") + 1; int(location.Range.Start.Line) >= lines {
			t.Fatalf("target line %d is out of range for a %d line file", location.Range.Start.Line, lines)
		}
		if back, mapped := s.index.LibraryURIForFile(location.URI); !mapped || back != libraryURI {
			t.Fatalf("navigation target does not map back to %s: %q %v", libraryURI, back, mapped)
		}
	}
}

// Requests made from inside an opened library file arrive with the mirrored
// path. They must reach the index under its own identity.
func TestRequestsFromAMirroredLibraryFileReachTheIndex(t *testing.T) {
	s, _, libraryURI := libraryFixture(t)
	defer s.Close()

	mirrored, ok := s.index.LibraryFileURI(libraryURI)
	if !ok {
		t.Fatal("library entry produced no mirrored file")
	}
	params, err := json.Marshal(map[string]any{"textDocument": map[string]any{"uri": mirrored}})
	if err != nil {
		t.Fatal(err)
	}
	result, responseErr := s.Request(context.Background(), "textDocument/documentSymbol", params)
	if responseErr != nil {
		t.Fatalf("documentSymbol failed: %v", responseErr)
	}
	symbols, ok := result.([]protocol.DocumentSymbol)
	if !ok || len(symbols) == 0 {
		t.Fatalf("mirrored library file resolved to no symbols: %#v", result)
	}
}

// Mirrored files are read-only archive views. Opening one must not enter it
// into the workspace document set, where it would be parsed as project source.
func TestOpeningAMirroredLibraryFileIsIgnored(t *testing.T) {
	s, _, libraryURI := libraryFixture(t)
	defer s.Close()

	mirrored, ok := s.index.LibraryFileURI(libraryURI)
	if !ok {
		t.Fatal("library entry produced no mirrored file")
	}
	params, err := json.Marshal(protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{URI: mirrored, LanguageID: "java", Version: 1, Text: "package demo;\nclass Replaced {}\n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Notify(context.Background(), "textDocument/didOpen", params)
	document, found := s.index.Document(libraryURI)
	if !found {
		t.Fatal("library document disappeared")
	}
	if strings.Contains(document.Text, "Replaced") {
		t.Fatal("a didOpen on a mirrored path overwrote the indexed archive entry")
	}
}

// An editor keeps buffers open across server restarts, including mirrored
// library files written by an earlier layout version that no longer exists.
// Those are still library views: they must be dropped, never indexed as
// project sources (which handed the compiler a file no module owns).
func TestOpeningAStaleMirroredLibraryFileIsIgnored(t *testing.T) {
	s, _, libraryURI := libraryFixture(t)
	defer s.Close()
	mirrored, ok := s.index.LibraryFileURI(libraryURI)
	if !ok {
		t.Fatal("library entry produced no mirrored file")
	}
	stale := protocol.URI(strings.Replace(string(mirrored), "/sources/v2/", "/sources/v1/", 1))
	if stale == mirrored {
		t.Fatalf("mirror path has no version segment: %s", mirrored)
	}
	params, err := json.Marshal(protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{URI: stale, LanguageID: "java", Version: 1, Text: "package demo;\nclass Stale {}\n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Notify(context.Background(), "textDocument/didOpen", params)
	for _, uri := range s.index.OpenDocuments() {
		if uri == stale {
			t.Fatal("a stale mirror path entered the workspace document set")
		}
	}
	for _, file := range s.index.WorkspaceFiles() {
		if file.URI == stale {
			t.Fatal("a stale mirror path became a workspace source")
		}
	}
}
