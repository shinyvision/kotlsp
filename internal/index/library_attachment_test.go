package index

import (
	"context"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

func TestLibrarySourceAttachmentRequiresExactJvmDescriptor(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	file := &analysis.ParsedFile{Language: analysis.LanguageJava}
	source := analysis.Symbol{
		Name: "convert", FQN: "sample.Api.convert", Kind: analysis.KindMethod,
		Language: analysis.LanguageJava, Type: "int",
		Parameters: []analysis.Parameter{{Name: "value", Type: "int"}},
	}
	binary := source
	binary.JVMName = "convert"
	binary.JVMDescriptor = "(I)I"
	if score := idx.libraryDeclarationMatchScoreLocked(file, binary, source); score < 0 {
		t.Fatalf("exact descriptor did not attach: %d", score)
	}
	binary.JVMDescriptor = "(Ljava/lang/Integer;)I"
	if score := idx.libraryDeclarationMatchScoreLocked(file, binary, source); score >= 0 {
		t.Fatalf("boxed overload attached to primitive source: %d", score)
	}
}

func TestLibrarySummaryDropsPrivateImplementationDetails(t *testing.T) {
	uri := protocol.URI("jar:///dependency.jar!/sample/Api.java")
	document := textdoc.NewDocument(uri, "java", 0, "package sample; public class Api { public void visible() {} private void hidden() {} }")
	parsed := analysis.Parse(context.Background(), document)
	summarizeLibraryFile(parsed)
	for _, symbol := range parsed.Symbols {
		if symbol.Name == "hidden" {
			t.Fatalf("private implementation detail survived the cold library summary: %#v", symbol)
		}
	}
	foundVisible := false
	for _, symbol := range parsed.Symbols {
		foundVisible = foundVisible || symbol.Name == "visible"
	}
	if !foundVisible {
		t.Fatal("public API was removed with private implementation details")
	}
}

func TestKotlinSourceJvmDescriptorModelsReceiverSuspendAndNullablePrimitive(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	file := &analysis.ParsedFile{Language: analysis.LanguageKotlin}
	symbol := analysis.Symbol{
		Name: "load", Kind: analysis.KindFunction, Language: analysis.LanguageKotlin,
		ReceiverType: "String", Type: "Int",
		Parameters: []analysis.Parameter{{Name: "limit", Type: "Int?"}},
		Modifiers:  []string{"suspend"},
	}
	descriptor, ok := idx.sourceJvmDescriptorLocked(file, symbol)
	want := "(Ljava/lang/String;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"
	if !ok || descriptor != want {
		t.Fatalf("Kotlin JVM descriptor = %q, %v; want %q", descriptor, ok, want)
	}
}
