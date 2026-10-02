package index

import (
	"reflect"
	"testing"
)

func TestParseKotlinFunctionType(t *testing.T) {
	for _, fixture := range []struct {
		text, receiver string
		parameters     []string
		result         string
		ok             bool
	}{
		{"(A, B) -> R", "", []string{"A", "B"}, "R", true},
		{"suspend (configuration: Configuration) -> T", "", []string{"Configuration"}, "T", true},
		{"(suspend () -> Unit)?", "", nil, "Unit", true},
		{"suspend Configuration.() -> T", "Configuration", nil, "T", true},
		{"MockKMatcherScope.(Call) -> T", "MockKMatcherScope", []string{"Call"}, "T", true},
		{"(Map<String, Int>) -> List<Pair<A, B>>", "", []string{"Map<String, Int>"}, "List<Pair<A, B>>", true},
		{"@ExtensionFunctionType Function2<Scope, Int, String>", "Scope", []string{"Int"}, "String", true},
		{"kotlin.jvm.functions.Function1<A, B>", "", []string{"A"}, "B", true},
		{"((Int) -> Unit) -> Unit", "", []string{"(Int) -> Unit"}, "Unit", true},
		{"List<String>", "", nil, "", false},
		{"Function", "", nil, "", false},
	} {
		receiver, parameters, result, ok := parseKotlinFunctionType(fixture.text)
		if receiver != fixture.receiver || !reflect.DeepEqual(parameters, fixture.parameters) || result != fixture.result || ok != fixture.ok {
			t.Errorf("%q: receiver=%q parameters=%q result=%q ok=%v", fixture.text, receiver, parameters, result, ok)
		}
	}
}

func TestKotlinizeBinaryWildcards(t *testing.T) {
	for in, want := range map[string]string{
		"java.util.Map<?, ?>":                        "Map<*, *>",
		"kotlin.reflect.KClass<?>":                   "kotlin.reflect.KClass<*>",
		"java.util.List<? extends java.lang.Number>": "List<out Number>",
	} {
		if got := kotlinizeBinaryType(in); got != want {
			t.Errorf("kotlinizeBinaryType(%q) = %q, want %q", in, got, want)
		}
	}
}
