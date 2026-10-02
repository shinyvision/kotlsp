package index

import "testing"

func TestLambdaResultExpression(t *testing.T) {
	for lambda, want := range map[string]string{
		"{ it.name }": "it.name",
		"{ parts ->\n  val key = parts[0]\n  key to parts[1]\n}":    "key to parts[1]",
		"{ (k, _) -> k == name }":                                   "k == name",
		"{ x: Int -> x + 1 }":                                       "x + 1",
		"{\n  list\n    .filter { it > 0 }\n    .map { it * 2 }\n}": "list\n    .filter { it > 0 }\n    .map { it * 2 }",
		"{ a; b }":       "b",
		"{ \"a -> b\" }": "\"a -> b\"",
		"{ when (x) { 1 -> \"one\"\n else -> \"many\" } }": "when (x) { 1 -> \"one\"\n else -> \"many\" }",
		"{ return@map it.id }":                             "it.id",
	} {
		got, offset, ok := lambdaResultExpression(lambda)
		if !ok || got != want {
			t.Errorf("%q: got %q ok=%v, want %q", lambda, got, ok, want)
			continue
		}
		if lambda[offset:offset+len(got)] != got {
			t.Errorf("%q: offset %d does not point at %q", lambda, offset, got)
		}
	}
	for _, lambda := range []string{"{ total += it }", "{ val x = 1 }", "{ println(it); return }", "{ unbalanced"} {
		if got, _, ok := lambdaResultExpression(lambda); ok {
			t.Errorf("%q has no value, got %q", lambda, got)
		}
	}
}

func TestStarUnboundTypeArguments(t *testing.T) {
	for value, want := range map[string]string{
		"List<R>":              "List<*>",
		"Map<String, List<V>>": "Map<String, List<*>>",
		"List<R?>":             "List<*>",
		"Pair<out R, Int>":     "Pair<*, Int>",
		"R":                    "R",
		"List<Rate>":           "List<Rate>",
	} {
		if got := starUnboundTypeArguments(value, []string{"K", "V", "R"}, map[string]string{"K": "String"}); got != want {
			t.Errorf("%q: got %q, want %q", value, got, want)
		}
	}
	if topLevelSafeCall("xs.flatMap { it?.ids }") || !topLevelSafeCall("x?.y.z") {
		t.Error("safe calls inside lambdas are not the chain's")
	}
}
