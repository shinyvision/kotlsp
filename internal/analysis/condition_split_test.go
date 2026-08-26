package analysis

import "testing"

// The split that finds a condition's operands must not be fooled by operators
// inside parentheses, string literals, or comments, where rewriting or reading
// them would change what the condition means.
func TestSplitKotlinConditionIgnoresNestedOperators(t *testing.T) {
	for _, fixture := range []struct {
		label  string
		source string
		want   []string
	}{
		{"plain chain", "a != null && b", []string{"a != null ", " b"}},
		{"parenthesised operator", "a != null && (b || c)", []string{"a != null ", " (b || c)"}},
		{"operator inside a string", "a != null && d == \"x || y\"", []string{"a != null ", " d == \"x || y\""}},
		{"mixed chain", "a == null || b == null || a.x == b.y", []string{"a == null ", " b == null ", " a.x == b.y"}},
		{"no operator", "a != null", []string{"a != null"}},
	} {
		operands := splitKotlinCondition([]byte(fixture.source), 0, len(fixture.source))
		if len(operands) != len(fixture.want) {
			t.Fatalf("%s: got %d operands, want %d", fixture.label, len(operands), len(fixture.want))
		}
		for index, want := range fixture.want {
			if operands[index].text != want {
				t.Fatalf("%s: operand %d = %q, want %q", fixture.label, index, operands[index].text, want)
			}
			if got := fixture.source[operands[index].start:operands[index].end]; got != want {
				t.Fatalf("%s: operand %d span covers %q, want %q", fixture.label, index, got, want)
			}
		}
	}
}
