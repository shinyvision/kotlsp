package lsp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func TestDocumentHighlightSeparatesReadsFromWrites(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	s.initializeReceived.Store(true)
	s.initialized.Store(true)
	uri := protocol.URI("file:///workspace/Highlight.java")
	source := "class Highlight {\n    int run() {\n        int total = 0;\n        total = total + 1;\n        return total;\n    }\n}\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "java", Version: 1, Text: source})
	document := textdoc.NewDocument(uri, "java", 1, source)

	at := strings.Index(source, "int total = 0") + len("int ")
	params, err := json.Marshal(map[string]any{"textDocument": map[string]any{"uri": uri}, "position": document.Position(at + 1)})
	if err != nil {
		t.Fatal(err)
	}
	result, responseErr := s.Request(context.Background(), "textDocument/documentHighlight", params)
	if responseErr != nil {
		t.Fatalf("documentHighlight failed: %v", responseErr)
	}
	highlights, ok := result.([]protocol.DocumentHighlight)
	if !ok {
		t.Fatalf("unexpected result type %T", result)
	}
	// declaration, the write target, the read in the same statement, the return
	if len(highlights) < 4 {
		t.Fatalf("expected every occurrence of `total`, got %d: %#v", len(highlights), highlights)
	}
	kinds := map[int]int{}
	for _, highlight := range highlights {
		kinds[highlight.Kind]++
		line := strings.Split(source, "\n")[highlight.Range.Start.Line]
		if !strings.Contains(line, "total") {
			t.Fatalf("highlight on a line without the symbol: %q", line)
		}
	}
	if kinds[3] == 0 || kinds[2] == 0 {
		t.Fatalf("reads and writes must be distinguished, got %#v", kinds)
	}
	for n := 1; n < len(highlights); n++ {
		previous, current := highlights[n-1].Range.Start, highlights[n].Range.Start
		if current.Line < previous.Line || current.Line == previous.Line && current.Character < previous.Character {
			t.Fatalf("highlights are not in document order: %#v", highlights)
		}
	}
}

func TestDocumentHighlightIsAdvertised(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.Close()
	result, responseErr := s.Request(context.Background(), "initialize", json.RawMessage(`{"processId":null,"rootUri":null,"capabilities":{}}`))
	if responseErr != nil {
		t.Fatalf("initialize failed: %v", responseErr)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"documentHighlightProvider":true`) {
		t.Fatal("documentHighlightProvider is not advertised")
	}
}
