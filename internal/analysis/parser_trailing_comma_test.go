package analysis

import (
	"context"
	"testing"

	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// A trailing comma in a type-argument list compiles (Kotlin 1.4) but the
// bundled grammar only accepts it in parameter and argument lists.
func TestTrailingCommaInTypeArgumentsIsNotASyntaxError(t *testing.T) {
	source := "package app\n\nimport java.util.UUID\n\ntypealias Row = Triple<\n    UUID?,\n    String?,\n    Int?,\n    >\n\nclass Use(val row: Row)\n"
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///w/Row.kt", "kotlin", 1, source))
	for _, diagnostic := range parsed.Diagnostics {
		if diagnostic.Code == "syntax" {
			t.Errorf("syntax error reported on valid Kotlin: %+v", diagnostic)
		}
	}
	found := map[string]bool{}
	for _, symbol := range parsed.Symbols {
		found[symbol.Name] = true
	}
	if !found["Row"] || !found["Use"] {
		t.Errorf("declarations around the type alias were lost: %v", found)
	}
}

func TestTrailingCommaRecoveryLeavesOtherCommasAlone(t *testing.T) {
	source := []byte("val a = listOf(1,\n    2,\n)\nval s = \"x,>\"\n// y, >\nfun f(a: Int,\n  b: Int,\n) {}\nval g = { x: Int, y: Int -> x }\n")
	if got := kotlinTrailingTypeArgumentCommaRecovery(source); string(got) != string(source) {
		t.Errorf("commas outside type-argument lists must be untouched:\n%s", got)
	}
	wanted := []byte("typealias T = Pair<A,\n  B,\n  >")
	got := kotlinTrailingTypeArgumentCommaRecovery(wanted)
	if len(got) != len(wanted) || got[len("typealias T = Pair<A,\n  B")] != ' ' || got[len("typealias T = Pair<A")] != ',' {
		t.Errorf("only the trailing comma should be blanked: %q", got)
	}
}

// An extension receiver keeps its type arguments, spaces included: the stdlib
// spells most of them `Array<out T>` or `Map<K, V>`. Reading none of them left
// the extension without a receiver, so it never applied to anything.
func TestExtensionReceiversKeepTheirTypeArguments(t *testing.T) {
	source := "package app\n\nfun <T> Array<out T>.firstOne(): T = this[0]\nfun <K, V> Map<K, V>.keyList(): List<K> = keys.toList()\nfun String.shout(): String = this\nval <T> List<T>.second: T get() = this[1]\n"
	parsed := Parse(context.Background(), textdoc.NewDocument("file:///w/Ext.kt", "kotlin", 1, source))
	got := map[string]string{}
	for _, symbol := range parsed.Symbols {
		if symbol.ReceiverType != "" {
			got[symbol.Name] = symbol.ReceiverType
		}
	}
	for name, want := range map[string]string{
		"firstOne": "Array<out T>", "keyList": "Map<K, V>", "shout": "String", "second": "List<T>",
	} {
		if got[name] != want {
			t.Errorf("%s: receiver %q, want %q (all: %v)", name, got[name], want, got)
		}
	}
}
