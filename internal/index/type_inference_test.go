package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func TestFastInferenceAbstainsWhenTargetIsNotUnique(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/Ambiguous.kt")
	source := `
class Choice {
    fun pick(value: Int): String = ""
    fun pick(value: String): Int = 0
}
interface Left
interface Right
class First : Left, Right
class Second : Left, Right
fun choose(value: Int): String = ""
fun choose(value: String): Int = 0
fun listOf(value: Int): String = "shadowed"
fun probe() = Unit
`
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files[uri]
	if file == nil {
		t.Fatal("source was not parsed")
	}
	at := strings.Index(source, "probe")
	for _, expression := range []string{
		"choose(1)",
		"Choice().pick(1)",
		"::choose",
		"{ value -> 1 }",
		"choose(1",
		"setOf(choose(1))",
		"mapOf(1)",
		"1+",
	} {
		if got := idx.inferExpressionTypeLocked(file, expression, at); got != "" {
			t.Errorf("inference for %q chose %q instead of abstaining", expression, got)
		}
	}
	if got := idx.commonExpressionTypeLocked(file, "First", "Second"); got != "" {
		t.Errorf("equal-distance unrelated common owners produced arbitrary LUB %q", got)
	}
	if got := idx.inferExpressionTypeLocked(file, "listOf(1)", at); got != "String" {
		t.Errorf("visible collection-factory shadow inferred as %q, want String", got)
	}
	if got := idx.inferExpressionTypeLocked(file, "runner { 1 }", at); got != "" {
		t.Errorf("prefix lookalike for run inferred as %q", got)
	}
}
