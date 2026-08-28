package index

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func TestBroadIndexQueriesHonorPreCanceledContext(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Cancellation.kt")
	idx.Open(context.Background(), protocol.TextDocumentItem{
		URI: uri, LanguageID: "kotlin", Version: 1,
		Text: "class Cancellation { fun value(input: Int) = input }\nfun use() = Cancellation().value(1)\n",
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	position := protocol.Position{Line: 1, Character: 31}
	if symbols := idx.CompletionContext(ctx, uri, position, 100); len(symbols) != 0 {
		t.Fatalf("canceled completion returned %d symbols", len(symbols))
	}
	if symbols := idx.WorkspaceSymbolsContext(ctx, "Cancel", 100); len(symbols) != 0 {
		t.Fatalf("canceled workspace symbols returned %d symbols", len(symbols))
	}
	if symbols := idx.DefinitionsContext(ctx, uri, position); len(symbols) != 0 {
		t.Fatalf("canceled definitions returned %d symbols", len(symbols))
	}
	if symbols := idx.ImplementationsContext(ctx, uri, protocol.Position{Line: 0, Character: 7}); len(symbols) != 0 {
		t.Fatalf("canceled implementations returned %d symbols", len(symbols))
	}
	if references := idx.ReferencesContext(ctx, uri, position, true); len(references) != 0 {
		t.Fatalf("canceled references returned %d locations", len(references))
	}
	if tokens, _, ok := idx.SemanticTokensContext(ctx, uri); ok || len(tokens) != 0 {
		t.Fatalf("canceled semantic tokens returned ok=%v tokens=%d", ok, len(tokens))
	}
	if edit := idx.RenameContext(ctx, uri, position, "renamed"); len(edit.Changes) != 0 {
		t.Fatalf("canceled rename returned edits: %#v", edit)
	}
}

func TestDefinitionWaitsForAnImminentLibraryPublication(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	idx.generation.Store(1)
	idx.setModules([]ModuleInfo{{
		Name: ":app", Dir: "/workspace", Root: "/workspace",
		SourceRoots: []string{"/workspace"},
		SourceSets:  map[string][]string{"main": {"/workspace"}},
	}})
	uri := protocol.URI("file:///workspace/Use.kt")
	source := "package app\nimport dependency.Service\nfun use(service: Service) = service.run()\n"
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	document, ok := idx.Document(uri)
	if !ok {
		t.Fatal("workspace document was not indexed")
	}

	go func() {
		time.Sleep(40 * time.Millisecond)
		libraryURI := protocol.URI("jar:///dependency.jar!/dependency/Service.java")
		libraryDocument := textdoc.NewDocument(libraryURI, "java", 0, "package dependency; public class Service { public void run() {} }")
		parsed := analysis.Parse(context.Background(), libraryDocument)
		idx.AddLibraryBatch([]LibraryFile{{
			Source: LibrarySource{Archive: "/dependency.jar", Entry: "dependency/Service.java", LanguageID: "java"},
			Parsed: *parsed,
		}})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	definitions := idx.DefinitionsContext(ctx, uri, document.Position(strings.LastIndex(source, "run")+1))
	if len(definitions) != 1 || definitions[0].Name != "run" || !definitions[0].Library {
		t.Fatalf("definition after library publication = %#v", definitions)
	}
}
