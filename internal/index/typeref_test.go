package index

import "testing"

func TestTypeRefRoundTrips(t *testing.T) {
	for _, value := range []string{
		"String", "String?", "List<String>", "kotlin.collections.Map<K, out List<V>>?", "Array<out T>", "Comparable<in T>",
		"KClass<*>", "Map.Entry<K, V>", "() -> Unit", "(Int, String) -> Boolean", "suspend () -> T",
		"T.() -> Unit", "suspend CoroutineScope.(Int) -> R", "(() -> Unit)?", "List<(T) -> R>", "Flow<Pair<String, Int?>>",
		"org.gradle.api.Action<in org.gradle.api.Task>", "`in`",
	} {
		ref, ok := parseTypeRef(value)
		if !ok {
			t.Errorf("%q does not parse", value)
			continue
		}
		if got := ref.String(); got != value {
			t.Errorf("%q renders as %q", value, got)
		}
	}
	for _, value := range []string{"", "List<", "Map<K,>", "(Int -> Unit", "a b"} {
		if _, ok := parseTypeRef(value); ok {
			t.Errorf("%q should not parse", value)
		}
	}
	ref, _ := parseTypeRef("(name: String) -> Int")
	if ref.Function == nil || len(ref.Function.Parameters) != 1 || ref.Function.Parameters[0].Name != "String" {
		t.Errorf("a named function parameter is its type: %#v", ref)
	}
}
