package lsp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A prediction that only says "this will not compile" is half a feature. The
// finding carries the qualified names it could refer to, so the same add-import
// fix the compiler's diagnostic offers is available immediately.
func TestPredictedMissingImportOffersTheImportFix(t *testing.T) {
	s := NewServer(context.Background(), log.New(io.Discard, "", 0))
	defer s.index.Close()
	s.initializeReceived.Store(true)
	s.initialized.Store(true)

	s.index.Open(context.Background(), protocol.TextDocumentItem{
		URI: "file:///workspace/other/Reachable.kt", LanguageID: "kotlin", Version: 1,
		Text: "package other\n\nclass Reachable(val id: Int)\n",
	})
	uri := protocol.URI("file:///workspace/app/Use.kt")
	source := "package app\n\nfun use(value: Reachable): Int = value.id\n"
	s.index.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})

	// The prediction as the rule produces it, with its candidates.
	diagnostic := protocol.Diagnostic{
		Range: protocol.Range{
			Start: protocol.Position{Line: 2, Character: 15},
			End:   protocol.Position{Line: 2, Character: 24},
		},
		Severity: 1, Code: "unresolved-type", Source: "kotlsp",
		Message: "Unresolved reference: Reachable (not imported)",
		Data:    map[string]any{"name": "Reachable", "candidates": []string{"other.Reachable"}},
	}
	params, err := json.Marshal(map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"range":        diagnostic.Range,
		"context":      map[string]any{"diagnostics": []protocol.Diagnostic{diagnostic}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, responseErr := s.Request(context.Background(), "textDocument/codeAction", params)
	if responseErr != nil {
		t.Fatalf("codeAction failed: %v", responseErr)
	}
	actions, ok := result.([]protocol.CodeAction)
	if !ok {
		t.Fatalf("unexpected result type %T", result)
	}
	for _, action := range actions {
		if action.Title != "Import other.Reachable" {
			continue
		}
		if action.Edit == nil || len(action.Edit.Changes[uri]) == 0 {
			t.Fatal("the import action carries no edit")
		}
		inserted := action.Edit.Changes[uri][0].NewText
		if !strings.Contains(inserted, "import other.Reachable") {
			t.Fatalf("the action inserts %q", inserted)
		}
		return
	}
	titles := make([]string, 0, len(actions))
	for _, action := range actions {
		titles = append(titles, action.Title)
	}
	t.Fatalf("no import action was offered for the prediction, got %v", titles)
}
