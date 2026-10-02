package index

import (
	"context"
	"testing"
)

// The call-shape rule must know which parameter each argument fills before it
// claims one is missing. Each of these compiles.
func TestCallShapeRuleAcceptsValidCalls(t *testing.T) {
	for _, fixture := range []struct{ label, source string }{
		{"trailing lambda fills the last parameter", "package app\nclass Failure(code: Int, cause: Throwable? = null, lazyMessage: () -> String)\nfun f() { throw Failure(1) { \"why\" } }\n"},
		{"secondary constructor", "package app\nclass Missing(code: Int, cause: Throwable?, lazyMessage: () -> String) {\n    constructor(code: Int, id: Any? = null) : this(code, null, { \"x\" })\n}\nfun f() = Missing(1)\n"},
		{"override inherits defaults", "package app\ninterface Repo { fun find(id: Int, dealer: Int? = null): Int }\nclass RepoImpl : Repo {\n    override fun find(id: Int, dealer: Int?): Int = id\n    fun use() = find(1)\n}\n"},
	} {
		idx, uri := ruleIndex(t, fixture.source)
		for _, diagnostic := range idx.Diagnostics(uri) {
			if diagnostic.Code == "NO_VALUE_FOR_PARAMETER" {
				t.Errorf("%s: %s", fixture.label, diagnostic.Message)
			}
		}
	}
	// The rule still fires where a value really is missing.
	idx, uri := ruleIndex(t, "package app\nfun g(a: Int, b: Int) = a + b\nfun f() = g(1)\n")
	found := false
	for _, diagnostic := range idx.DiagnosticsContext(context.Background(), uri) {
		found = found || diagnostic.Code == "NO_VALUE_FOR_PARAMETER"
	}
	if !found {
		t.Error("a missing argument is no longer reported")
	}
}
