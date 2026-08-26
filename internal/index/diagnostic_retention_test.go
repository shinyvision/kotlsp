package index

import (
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

func lineRange(start, end int) protocol.Range {
	return protocol.Range{
		Start: protocol.Position{Line: start, Character: 0},
		End:   protocol.Position{Line: end, Character: 5},
	}
}

func change(startLine, endLine int, text string) protocol.TextDocumentContentChangeEvent {
	r := lineRange(startLine, endLine)
	return protocol.TextDocumentContentChangeEvent{Range: &r, Text: text}
}

// Compiler validation takes seconds. Findings must follow an edit rather than
// vanish for the whole of that wait.
func TestRetainedDiagnosticsFollowAnEdit(t *testing.T) {
	for _, fixture := range []struct {
		label   string
		at      int
		edit    protocol.TextDocumentContentChangeEvent
		want    int
		dropped bool
	}{
		{"line inserted above", 10, change(2, 2, "new\n"), 11, false},
		{"two lines inserted above", 10, change(2, 2, "a\nb\n"), 12, false},
		{"line removed above", 10, change(2, 3, ""), 9, false},
		{"edit below leaves it alone", 10, change(20, 20, "x\n"), 10, false},
		{"edit on the same line drops it", 10, change(10, 10, "x"), 0, true},
		{"edit spanning it drops it", 10, change(8, 12, "x"), 0, true},
		{"replacement without a range drops it", 10, protocol.TextDocumentContentChangeEvent{Text: "whole file"}, 0, true},
		{"edit on the line above leaves it", 10, change(9, 9, "x"), 10, false},
	} {
		diagnostics := []protocol.Diagnostic{{Range: lineRange(fixture.at, fixture.at), Message: "boom"}}
		got := shiftDiagnosticsForChange(diagnostics, fixture.edit)
		if fixture.dropped {
			if len(got) != 0 {
				t.Fatalf("%s: expected the finding to be dropped, got line %d", fixture.label, got[0].Range.Start.Line)
			}
			continue
		}
		if len(got) != 1 {
			t.Fatalf("%s: the finding was dropped", fixture.label)
		}
		if got[0].Range.Start.Line != fixture.want {
			t.Fatalf("%s: moved to line %d, want %d", fixture.label, got[0].Range.Start.Line, fixture.want)
		}
	}
}

// Related information points at other positions in the same file and has to
// move with them.
func TestRetainedRelatedInformationFollowsAnEdit(t *testing.T) {
	diagnostics := []protocol.Diagnostic{{
		Range:   lineRange(20, 20),
		Message: "conflict",
		RelatedInformation: []protocol.DiagnosticRelated{
			{Location: protocol.Location{URI: "file:///a.kt", Range: lineRange(15, 15)}, Message: "first"},
			{Location: protocol.Location{URI: "file:///a.kt", Range: lineRange(1, 1)}, Message: "above the edit"},
		},
	}}
	got := shiftDiagnosticsForChange(diagnostics, change(5, 5, "x\ny\n"))
	if len(got) != 1 {
		t.Fatal("the finding was dropped")
	}
	if got[0].Range.Start.Line != 22 {
		t.Fatalf("finding moved to %d, want 22", got[0].Range.Start.Line)
	}
	related := got[0].RelatedInformation
	if len(related) != 2 {
		t.Fatalf("related information lost: %#v", related)
	}
	if related[0].Location.Range.Start.Line != 17 {
		t.Fatalf("related below the edit moved to %d, want 17", related[0].Location.Range.Start.Line)
	}
	if related[1].Location.Range.Start.Line != 1 {
		t.Fatalf("related above the edit moved to %d, want 1", related[1].Location.Range.Start.Line)
	}
}

// Several edits arrive in one notification and compose.
func TestRetainedDiagnosticsComposeAcrossChanges(t *testing.T) {
	idx := New(nil)
	defer idx.Close()
	uri := protocol.URI("file:///workspace/A.kt")
	idx.mu.Lock()
	idx.compilerDiagnostics[uri] = []protocol.Diagnostic{{Range: lineRange(30, 30), Message: "boom"}}
	idx.retainCompilerDiagnosticsLocked(uri, []protocol.TextDocumentContentChangeEvent{
		change(1, 1, "a\n"),
		change(2, 2, "b\nc\n"),
	})
	got := idx.compilerDiagnostics[uri]
	idx.mu.Unlock()
	if len(got) != 1 || got[0].Range.Start.Line != 33 {
		t.Fatalf("composed shift = %#v", got)
	}
}
