package index

import (
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
)

// A compiler finding outlives an edit elsewhere in its file, moved with its
// line, until the next pass replaces it; one on an edited line goes.
func TestCompilerFindingsShiftWithEditsAndDropOnEditedLines(t *testing.T) {
	idx := New(nil)
	t.Cleanup(func() { idx.Close() })
	uri := protocol.URI("file:///workspace/A.kt")
	at := func(line int) protocol.Diagnostic {
		return protocol.Diagnostic{Range: protocol.Range{Start: protocol.Position{Line: line}, End: protocol.Position{Line: line, Character: 4}}, Message: "line " + string(rune('0'+line))}
	}
	before := "a\nb\nc\nd\ne\n"
	for _, c := range []struct {
		label, after string
		want         []int
	}{
		{"line inserted above", "a\nnew\nb\nc\nd\ne\n", []int{0, 3, 5}},
		{"line removed above", "b\nc\nd\ne\n", []int{1, 3}},
		{"finding's own line edited", "a\nb\nC\nd\ne\n", []int{0, 4}},
		{"edit below every finding", "a\nb\nc\nd\ne\nf\n", []int{0, 2, 4}},
	} {
		idx.mu.Lock()
		idx.compilerDiagnostics[uri] = []protocol.Diagnostic{at(0), at(2), at(4)}
		idx.shiftCompilerDiagnosticsLocked(uri, before, c.after)
		var got []int
		for _, diagnostic := range idx.compilerDiagnostics[uri] {
			got = append(got, diagnostic.Range.Start.Line)
		}
		idx.mu.Unlock()
		if len(got) != len(c.want) {
			t.Errorf("%s: lines %v, want %v", c.label, got, c.want)
			continue
		}
		for index := range got {
			if got[index] != c.want[index] {
				t.Errorf("%s: lines %v, want %v", c.label, got, c.want)
				break
			}
		}
	}
}
