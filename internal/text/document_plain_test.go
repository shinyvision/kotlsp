package text

import (
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// The ASCII fast path must agree with the general conversion on every position,
// before and after edits that introduce or remove multi-byte characters.
func TestPositionConversionFastPathAgreesWithTheGeneralPath(t *testing.T) {
	check := func(label string, d *Document) {
		t.Helper()
		general := *d
		general.plain = false
		for offset := 0; offset <= len(d.Text); offset++ {
			if got, want := d.Position(offset), general.Position(offset); got != want {
				t.Fatalf("%s: Position(%d) = %+v, general path %+v", label, offset, got, want)
			}
			position := general.Position(offset)
			if got, want := d.Offset(position), general.Offset(position); got != want {
				t.Fatalf("%s: Offset(%+v) = %d, general path %d", label, position, got, want)
			}
		}
		for _, past := range []protocol.Position{{Line: 0, Character: 999}, {Line: 1, Character: 999}, {Line: 50, Character: 0}, {Line: -1, Character: 3}} {
			if got, want := d.Offset(past), general.Offset(past); got != want {
				t.Fatalf("%s: Offset(%+v) = %d, general path %d", label, past, got, want)
			}
		}
	}
	d := NewDocument("file:///a.kt", "kotlin", 1, "package app\nfun f() = 1\n\nval s = \"abc\"\n")
	if !d.plain {
		t.Fatal("an ASCII document should take the fast path")
	}
	check("ascii", d)
	if err := d.Apply(2, []protocol.TextDocumentContentChangeEvent{{Range: &protocol.Range{Start: protocol.Position{Line: 3, Character: 9}, End: protocol.Position{Line: 3, Character: 12}}, Text: "é😀"}}); err != nil {
		t.Fatal(err)
	}
	if d.plain {
		t.Fatal("a multi-byte edit must leave the fast path")
	}
	check("after multi-byte edit", d)
	if err := d.Apply(3, []protocol.TextDocumentContentChangeEvent{{Range: &protocol.Range{Start: protocol.Position{Line: 3, Character: 9}, End: protocol.Position{Line: 3, Character: 12}}, Text: "x"}}); err != nil {
		t.Fatal(err)
	}
	if !d.plain {
		t.Fatal("removing the last multi-byte character should restore the fast path")
	}
	check("after removal", d)
	check("carriage returns", NewDocument("file:///b.kt", "kotlin", 1, "a\r\nbb\r\nccc"))
}
