package lexical

import (
	"reflect"
	"testing"
)

// The tokenizer reads `?>` as one token, so a nullable last type argument
// closed no list: `TableField<Record, UUID?>` lost both arguments, and with
// them every member type of a jOOQ field.
func TestNullableLastTypeArgumentClosesItsList(t *testing.T) {
	for text, want := range map[string][]string{
		"Record, UUID?":           {"Record", "UUID?"},
		"List<Int?>, String?":     {"List<Int?>", "String?"},
		"A?, B<C?>?":              {"A?", "B<C?>?"},
		"Map<String, List<Int?>>": {"Map<String, List<Int?>>"},
		"Iterable<*>, Map<*, *>":  {"Iterable<*>", "Map<*, *>"},
	} {
		if got := SplitTopLevelTypes(text, ",", true); !reflect.DeepEqual(got, want) {
			t.Errorf("SplitTopLevelTypes(%q) = %q, want %q", text, got, want)
		}
	}
	text := "TableField<Record, UUID?>"
	if got := MatchingDelimiter(text, 10, "<", ">", true); got != len(text)-1 {
		t.Errorf("MatchingDelimiter = %d, want %d", got, len(text)-1)
	}
}
