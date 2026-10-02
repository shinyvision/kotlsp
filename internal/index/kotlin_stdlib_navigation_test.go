package index

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func TestDefinitionResolvesApplyFromKotlinBinaryMetadata(t *testing.T) {
	ctx := context.Background()
	// `apply` lives in StandardKt__StandardKt; the class is copied from
	// kotlin-stdlib 2.4.10 into testdata.
	class, err := os.ReadFile(filepath.Join("testdata", "kotlin-stdlib", "2.4.10", "kotlin", "StandardKt__StandardKt.class"))
	if err != nil {
		t.Fatal(err)
	}
	stdlib := writeTestArchive(t, "kotlin-stdlib-2.4.10.jar", map[string]string{"kotlin/StandardKt__StandardKt.class": string(class)})

	idx := New(nil)
	defer idx.Close()
	if complete := idx.indexSourceArchive(ctx, sourceArchive{path: stdlib, binary: true, release: idx.javaReleaseForLibrary(stdlib)}, 0, func(int64) {}); !complete {
		t.Fatal("Kotlin standard-library bytecode did not index completely")
	}

	uri := protocol.URI("file:///workspace/Apply.kt")
	source := "class Context\nfun use() = Context().apply { }\n"
	idx.Open(ctx, protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})
	document, ok := idx.Document(uri)
	if !ok {
		t.Fatal("workspace document was not indexed")
	}
	offset := strings.Index(source, "apply")
	definitions := idx.Definitions(uri, document.Position(offset+1))
	if len(definitions) != 1 || definitions[0].Name != "apply" || definitions[0].ReceiverType == "" || !definitions[0].Library {
		idx.mu.RLock()
		candidates := append([]string(nil), idx.byName["apply"]...)
		genericCandidates := append([]string(nil), idx.byGenericReceiverMember["apply"]...)
		candidateSymbols := make([]any, 0, len(candidates))
		for _, id := range candidates {
			if symbol := idx.symbols[id]; symbol != nil {
				candidateSymbols = append(candidateSymbols, *symbol)
			}
		}
		idx.mu.RUnlock()
		t.Fatalf("stdlib apply definition = %#v; indexed candidates = %#v; generic receiver candidates = %#v", definitions, candidateSymbols, genericCandidates)
	}
}
