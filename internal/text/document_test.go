package text

import (
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func TestUTF16PositionsAndIncrementalChanges(t *testing.T) {
	doc := NewDocument("file:///Example.kt", "kotlin", 1, "val greeting = \"hi 🌍\"\nprintln(greeting)\n")
	offset := len("val greeting = \"hi 🌍")
	position := doc.Position(offset)
	if position != (protocol.Position{Line: 0, Character: 21}) {
		t.Fatalf("UTF-16 position = %+v, want line 0 character 21", position)
	}
	if got := doc.Offset(position); got != offset {
		t.Fatalf("round trip offset = %d, want %d", got, offset)
	}
	err := doc.Apply(2, []protocol.TextDocumentContentChangeEvent{{
		Range: &protocol.Range{Start: protocol.Position{Line: 1, Character: 8}, End: protocol.Position{Line: 1, Character: 16}},
		Text:  "message",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := doc.Text, "val greeting = \"hi 🌍\"\nprintln(message)\n"; got != want {
		t.Fatalf("changed text = %q, want %q", got, want)
	}
}

func TestFullDocumentChange(t *testing.T) {
	doc := NewDocument("file:///Example.java", "java", 1, "class Old {}")
	if err := doc.Apply(2, []protocol.TextDocumentContentChangeEvent{{Text: "class New {}\n"}}); err != nil {
		t.Fatal(err)
	}
	if doc.Text != "class New {}\n" || doc.Version != 2 || doc.LineCount() != 2 {
		t.Fatalf("unexpected document after full change: %#v", doc)
	}
}
