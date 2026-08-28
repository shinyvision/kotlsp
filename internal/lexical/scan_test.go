package lexical

import (
	"reflect"
	"testing"
)

func TestSplitTopLevelDistinguishesComparisonsAndGenericCalls(t *testing.T) {
	for _, test := range []struct {
		name   string
		value  string
		kotlin bool
		want   []string
	}{
		{"comparison", "left < right, fallback", true, []string{"left < right", "fallback"}},
		{"generic call", "factory<Map<Key, Value>>(), fallback", true, []string{"factory<Map<Key, Value>>()", "fallback"}},
		{"literal comma", `"first,second", fallback`, false, []string{`"first,second"`, "fallback"}},
		{"nested comment", "first /* , /* nested */ still */ , second", true, []string{"first /* , /* nested */ still */", "second"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := SplitTopLevel(test.value, ",", test.kotlin); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("SplitTopLevel(%q) = %#v, want %#v", test.value, got, test.want)
			}
		})
	}
}

func TestSplitTopLevelTypesRetainsNestedArguments(t *testing.T) {
	want := []string{"Map<Key, List<Value>>", "Set<Other>"}
	if got := SplitTopLevelTypes("Map<Key, List<Value>>, Set<Other>", ",", true); !reflect.DeepEqual(got, want) {
		t.Fatalf("type arguments = %#v, want %#v", got, want)
	}
}

func TestTokenizerKeepsUnicodeBackticksAndCommentsOutOfStructure(t *testing.T) {
	tokens := Tokenize("`when value`(Δ) /* { /* nested */ } */ + 1", true)
	want := []string{"`when value`", "(", "Δ", ")", "+", "1"}
	got := make([]string, 0, len(tokens))
	for _, token := range tokens {
		got = append(got, token.Text)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens = %#v, want %#v", got, want)
	}
}

func TestJavaTextBlockIsOneLiteralTokenAndCarriesLineState(t *testing.T) {
	source := "String text = \"\"\"\nbrace { is content\n\"\"\";"
	tokens := Tokenize(source, false)
	literals := 0
	for _, token := range tokens {
		if token.Kind == String {
			literals++
			if token.Text != "\"\"\"\nbrace { is content\n\"\"\"" {
				t.Fatalf("text-block token = %q", token.Text)
			}
		}
	}
	if literals != 1 {
		t.Fatalf("Java text-block literal count = %d", literals)
	}
	state := State{}
	state.ScanStructure(`String text = """`, false)
	if !state.Triple {
		t.Fatal("Java text-block opening delimiter did not carry multiline state")
	}
	opens, _, _ := state.ScanStructure("brace { is content", false)
	if opens != 0 {
		t.Fatal("Java text-block brace was counted as structure")
	}
	state.ScanStructure(`""";`, false)
	if state.Triple {
		t.Fatal("Java text-block closing delimiter did not clear multiline state")
	}
}
