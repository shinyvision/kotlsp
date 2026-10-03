package index

import (
	"context"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// A file's declaration shape decides whether other files must recompile
// after an edit. Bodies other files cannot see stay out of it; bodies they
// can -- inline functions, constants, declarations whose type is inferred --
// are part of it.
func TestCompilerShapeChangesOnlyWithWhatOtherFilesSee(t *testing.T) {
	shape := func(source string) uint64 {
		parsed := analysis.Parse(context.Background(), textdoc.NewDocument(protocol.URI("file:///workspace/A.kt"), "kotlin", 0, source))
		return compilerDeclarationShape(parsed, source)
	}
	for _, c := range []struct {
		label, before, after string
		changes              bool
	}{
		{"block body", "package a\nfun f(): Int {\n    return 1\n}\n", "package a\nfun f(): Int {\n    missing()\n    return 2\n}\n", false},
		{"typed expression body", "package a\nfun f(): Int = 1\n", "package a\nfun f(): Int = 2\n", false},
		{"private inferred body", "package a\nprivate fun f() = 1\n", "package a\nprivate fun f() = \"x\"\n", false},
		{"inferred expression body", "package a\nfun f() = 1\n", "package a\nfun f() = \"x\"\n", true},
		{"inferred property", "package a\nval x = 1\n", "package a\nval x = \"x\"\n", true},
		{"inline function body", "package a\ninline fun f(): Int {\n    return 1\n}\n", "package a\ninline fun f(): Int {\n    return 2\n}\n", true},
		{"constant", "package a\nconst val X: Int = 1\n", "package a\nconst val X: Int = 2\n", true},
		{"signature", "package a\nfun f(): Int = 1\n", "package a\nfun f(): Long = 1\n", true},
	} {
		if changed := shape(c.before) != shape(c.after); changed != c.changes {
			t.Errorf("%s: shape changed = %v, want %v", c.label, changed, c.changes)
		}
	}
}
