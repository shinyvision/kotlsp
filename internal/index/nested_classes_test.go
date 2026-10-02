package index

import (
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// Nested and inner classes are reached through their outer class: a nested
// class's constructor by `Outer.Nested(...)`, an inner class's members on the
// value `outer.Inner()` returns.
func TestNestedAndInnerClassNavigation(t *testing.T) {
	source := `package app

class Outer {
    class Nested(val id: Int) {
        fun nestedWork() = id
    }
    inner class Inner {
        fun innerWork() = 1
    }
    companion object {
        fun make() = Outer()
    }
}

fun use() {
    val n = Outer.Nested(1)
    n.nestedWork()
    Outer.Nested(2).nestedWork()
    Outer().Inner().innerWork()
    val i = Outer.make().Inner()
    i.innerWork()
}
`
	idx, uri := ruleIndex(t, source)
	doc := textdoc.NewDocument(uri, "kotlin", 1, source)
	for _, c := range []struct{ needle, want string }{
		{"Nested(1)", "app.Outer.Nested"},
		{"nestedWork()\n    Outer", "app.Outer.Nested.nestedWork"},
		{"Nested(2)", "app.Outer.Nested"},
		{"nestedWork()\n    Outer()", "app.Outer.Nested.nestedWork"},
		{"Inner().innerWork", "app.Outer.Inner"},
		{"innerWork()\n    val", "app.Outer.Inner.innerWork"},
		{"make()", "app.Outer.Companion.make"},
		{"innerWork()\n}", "app.Outer.Inner.innerWork"},
	} {
		at := strings.Index(source, c.needle)
		if at < 0 {
			t.Fatalf("no %q", c.needle)
		}
		var got []string
		for _, symbol := range idx.Definitions(uri, doc.Position(at)) {
			got = append(got, symbol.FQN)
		}
		found := false
		for _, fqn := range got {
			found = found || fqn == c.want || strings.HasPrefix(fqn, c.want+".") && strings.HasSuffix(c.want, "Nested")
		}
		if !found {
			t.Errorf("definition at %q: got %v, want %s", c.needle, got, c.want)
		}
	}
	_ = protocol.Position{}
}
