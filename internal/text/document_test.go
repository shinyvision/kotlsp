package text

import (
	"strings"
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

func TestIncrementalChangesRejectInvalidPositionsAndVersionsAtomically(t *testing.T) {
	original := "val world = \"🌍\"\nprintln(world)\n"
	for _, test := range []struct {
		name    string
		version int
		r       protocol.Range
	}{
		{"stale version", 1, protocol.Range{}},
		{"line beyond document", 2, protocol.Range{Start: protocol.Position{Line: 9}, End: protocol.Position{Line: 9}}},
		{"character beyond line", 2, protocol.Range{Start: protocol.Position{Line: 0, Character: 99}, End: protocol.Position{Line: 0, Character: 99}}},
		{"inside surrogate pair", 2, protocol.Range{Start: protocol.Position{Line: 0, Character: 14}, End: protocol.Position{Line: 0, Character: 14}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := NewDocument("file:///Example.kt", "kotlin", 1, original)
			err := doc.Apply(test.version, []protocol.TextDocumentContentChangeEvent{{Range: &test.r, Text: "broken"}})
			if err == nil {
				t.Fatal("invalid change was accepted")
			}
			if doc.Text != original || doc.Version != 1 {
				t.Fatalf("failed change mutated document: version=%d text=%q", doc.Version, doc.Text)
			}
		})
	}
}

func TestIncrementalLineIndexTracksMultilineReplacement(t *testing.T) {
	doc := NewDocument("file:///Example.kt", "kotlin", 1, "one\ntwo\nthree\n")
	err := doc.Apply(2, []protocol.TextDocumentContentChangeEvent{{
		Range: &protocol.Range{Start: protocol.Position{Line: 0, Character: 3}, End: protocol.Position{Line: 2, Character: 0}},
		Text:  "\ninserted\n",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := doc.Text, "one\ninserted\nthree\n"; got != want {
		t.Fatalf("text = %q, want %q", got, want)
	}
	if doc.LineCount() != 4 {
		t.Fatalf("line count = %d", doc.LineCount())
	}
	for offset := 0; offset <= len(doc.Text); offset++ {
		if got := doc.Offset(doc.Position(offset)); got != offset {
			t.Fatalf("offset %d round-tripped to %d", offset, got)
		}
	}
}

func TestApplyReportsTreeSitterBytePoints(t *testing.T) {
	doc := NewDocument("file:///Points.kt", "kotlin", 1, "val globe = \"🌍\"\nnext\n")
	edits, err := doc.ApplyWithEdits(2, []protocol.TextDocumentContentChangeEvent{{
		Range: &protocol.Range{Start: protocol.Position{Line: 0, Character: 15}, End: protocol.Position{Line: 1, Character: 4}},
		Text:  "x\nyz",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(edits) != 1 {
		t.Fatalf("edits = %#v", edits)
	}
	edit := edits[0]
	if edit.StartLine != 0 || edit.StartColumn != len("val globe = \"🌍") || edit.OldEndLine != 1 || edit.OldEndColumn != 4 || edit.NewEndLine != 1 || edit.NewEndColumn != 2 {
		t.Fatalf("byte points = %#v", edit)
	}
}

func TestMultipleChangesUseSequentialRangesAndOneFinalBuffer(t *testing.T) {
	doc := NewDocument("file:///Batch.kt", "kotlin", 4, "alpha\nbeta\ngamma\n")
	edits, err := doc.ApplyWithEdits(5, []protocol.TextDocumentContentChangeEvent{
		{Range: &protocol.Range{Start: protocol.Position{Line: 0, Character: 5}, End: protocol.Position{Line: 0, Character: 5}}, Text: "-one"},
		// This line number and character address the document after the first
		// edit, as required by the LSP incremental synchronization contract.
		{Range: &protocol.Range{Start: protocol.Position{Line: 1, Character: 0}, End: protocol.Position{Line: 1, Character: 4}}, Text: "two\nthree"},
		{Range: &protocol.Range{Start: protocol.Position{Line: 3, Character: 5}, End: protocol.Position{Line: 3, Character: 5}}, Text: "!"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := doc.Text, "alpha-one\ntwo\nthree\ngamma!\n"; got != want {
		t.Fatalf("text = %q, want %q", got, want)
	}
	if len(edits) != 3 || edits[1].StartLine != 1 || edits[2].StartLine != 3 {
		t.Fatalf("sequential tree edits = %#v", edits)
	}
	for offset := 0; offset <= len(doc.Text); offset++ {
		if got := doc.Offset(doc.Position(offset)); got != offset {
			t.Fatalf("offset %d round-tripped to %d", offset, got)
		}
	}
}

func TestSparseLineIndexUsesMutatedBufferForSequentialEdits(t *testing.T) {
	content := strings.Repeat("\n", maxDenseLineStarts) + "tail\n"
	doc := NewDocument("file:///Generated.kt", "kotlin", 1, content)
	if !doc.sparse || doc.LineCount() != maxDenseLineStarts+2 {
		t.Fatalf("sparse index = %t, lines = %d", doc.sparse, doc.LineCount())
	}
	edits, err := doc.ApplyWithEdits(2, []protocol.TextDocumentContentChangeEvent{
		{Range: &protocol.Range{Start: protocol.Position{Line: maxDenseLineStarts}, End: protocol.Position{Line: maxDenseLineStarts}}, Text: "x\n"},
		{Range: &protocol.Range{Start: protocol.Position{Line: maxDenseLineStarts + 1}, End: protocol.Position{Line: maxDenseLineStarts + 1, Character: 4}}, Text: "done"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(edits) != 2 || edits[0].StartLine != maxDenseLineStarts || edits[1].StartLine != maxDenseLineStarts+1 {
		t.Fatalf("sequential sparse edits = %#v", edits)
	}
	if got := doc.Slice(protocol.Range{Start: protocol.Position{Line: maxDenseLineStarts}, End: protocol.Position{Line: maxDenseLineStarts + 2}}); got != "x\ndone\n" {
		t.Fatalf("sparse tail = %q", got)
	}
	last := len(doc.Text) - 1
	if got := doc.Offset(doc.Position(last)); got != last {
		t.Fatalf("sparse offset %d round-tripped to %d", last, got)
	}
}
