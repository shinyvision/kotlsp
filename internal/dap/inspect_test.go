package dap

import (
	"strings"
	"testing"
)

func TestParseInstanceHint(t *testing.T) {
	hint, ok := parseInstanceHint("instance of Probe$Body(id=452)")
	if !ok || hint.typeName != "Probe$Body" || hint.baseType != "Probe$Body" || hint.isArray {
		t.Fatalf("object hint = %#v, ok=%v", hint, ok)
	}
	hint, ok = parseInstanceHint("instance of int[3] (id=453)")
	if !ok || !hint.isArray || hint.baseType != "int" || hint.typeName != "int[3]" || hint.length != 3 {
		t.Fatalf("primitive array hint = %#v, ok=%v", hint, ok)
	}
	hint, ok = parseInstanceHint("instance of java.lang.String[0] (id=451)")
	if !ok || !hint.isArray || hint.baseType != "java.lang.String" || hint.length != 0 {
		t.Fatalf("object array hint = %#v, ok=%v", hint, ok)
	}
	hint, ok = parseInstanceHint("instance of java.lang.Object[2] (id=470)")
	if !ok || !hint.isArray || hint.length != 2 {
		t.Fatalf("entry array hint = %#v, ok=%v", hint, ok)
	}
	for _, rejected := range []string{"null", `"scalpel"`, "42", "true", "arm=2", ""} {
		if hint, ok = parseInstanceHint(rejected); ok {
			t.Fatalf("parseInstanceHint(%q) = %#v, want not ok", rejected, hint)
		}
	}
}

func TestParseDumpFields(t *testing.T) {
	lines := strings.Split(` body = {
    parts: instance of java.util.ArrayList(id=456)
    sizes: instance of java.util.HashMap(id=457)
    tag: "body"
    missing: null
    Probe$Organ.name: "heart"
    Probe$Organ.cells: instance of int[3] (id=460)
}
main[1] `, "\n")
	fields := parseDumpFields(lines)
	if len(fields) != 6 {
		t.Fatalf("parseDumpFields returned %#v", fields)
	}
	expected := []dumpField{
		{"parts", "instance of java.util.ArrayList(id=456)"},
		{"sizes", "instance of java.util.HashMap(id=457)"},
		{"tag", `"body"`},
		{"missing", "null"},
		{"Probe$Organ.name", `"heart"`},
		{"Probe$Organ.cells", "instance of int[3] (id=460)"},
	}
	for index, want := range expected {
		if fields[index] != want {
			t.Fatalf("field %d = %#v, want %#v", index, fields[index], want)
		}
	}
}

func TestParseDumpFieldsKeepsStaticsAndQualifiedNames(t *testing.T) {
	lines := strings.Split(` body.parts = {
    serialVersionUID: 8683452581122892189
    DEFAULT_CAPACITY: 10
    EMPTY_ELEMENTDATA: instance of java.lang.Object[0] (id=463)
    elementData: instance of java.lang.Object[2] (id=465)
    size: 2
    java.util.AbstractList.modCount: 0
}`, "\n")
	fields := parseDumpFields(lines)
	if len(fields) != 6 {
		t.Fatalf("parseDumpFields returned %#v", fields)
	}
	if fields[0].name != "serialVersionUID" || fields[0].value != "8683452581122892189" {
		t.Fatalf("static field = %#v", fields[0])
	}
	if fields[5].name != "java.util.AbstractList.modCount" || fields[5].value != "0" {
		t.Fatalf("inherited field = %#v", fields[5])
	}
}

func TestSplitArrayElements(t *testing.T) {
	elements, ok := splitArrayElements(strings.Split(" nums = {\n7, 8, 9\n}", "\n"))
	if !ok || len(elements) != 3 || elements[0] != "7" || elements[2] != "9" {
		t.Fatalf("int elements = %#v, ok=%v", elements, ok)
	}
	elements, ok = splitArrayElements(strings.Split(` body.parts.toArray() = {
"arm", "leg"
}`, "\n"))
	if !ok || len(elements) != 2 || elements[0] != `"arm"` || elements[1] != `"leg"` {
		t.Fatalf("string elements = %#v, ok=%v", elements, ok)
	}
	// Commas inside quoted strings and escaped quotes must not split.
	elements, ok = splitArrayElements(strings.Split(` x = {
"a, b", "c\"d", "e"
}`, "\n"))
	if !ok || len(elements) != 3 || elements[0] != `"a, b"` || elements[1] != `"c\"d"` {
		t.Fatalf("quoted elements = %#v, ok=%v", elements, ok)
	}
	elements, ok = splitArrayElements(strings.Split(" entries = {\ninstance of java.util.HashMap$Node(id=459), instance of java.util.HashMap$Node(id=460)\n}", "\n"))
	if !ok || len(elements) != 2 || elements[0] != "instance of java.util.HashMap$Node(id=459)" {
		t.Fatalf("entry hint elements = %#v, ok=%v", elements, ok)
	}
	if elements, ok = splitArrayElements(strings.Split(" x = {\n}", "\n")); !ok || len(elements) != 0 {
		t.Fatalf("empty array elements = %#v, ok=%v", elements, ok)
	}
	if _, ok = splitArrayElements(strings.Split(` text = "scalpel"`, "\n")); ok {
		t.Fatal("non-array dump reported elements")
	}
}

func TestParseClassDetails(t *testing.T) {
	lines := strings.Split(`Class: java.util.ArrayList
extends: java.util.AbstractList
implements: java.util.List
implements: java.util.RandomAccess
implements: java.lang.Cloneable
implements: java.io.Serializable`, "\n")
	superclass, interfaces := parseClassDetails(lines)
	if superclass != "java.util.AbstractList" || len(interfaces) != 4 || interfaces[0] != "java.util.List" {
		t.Fatalf("class details = %s %#v", superclass, interfaces)
	}
}

func TestMatchKnownKind(t *testing.T) {
	cases := map[string]inspectKind{
		"java.util.List":         kindList,
		"java.util.AbstractList": kindList,
		"java.util.Map":          kindMap,
		"java.util.Set":          kindCollection,
		"java.util.Deque":        kindCollection,
		"java.lang.CharSequence": kindCharSequence,
		"Probe$Body":             kindUnknown,
		"java.lang.Object":       kindUnknown,
	}
	for name, want := range cases {
		if got := matchKnownKind(name); got != want {
			t.Fatalf("matchKnownKind(%s) = %d, want %d", name, got, want)
		}
	}
}

func TestJDBErrorText(t *testing.T) {
	lines := strings.Split("com.sun.tools.example.debug.expr.ParseException: Name unknown: nothing\n nothing = null", "\n")
	if text := jdbErrorText(lines); !strings.Contains(text, "ParseException") {
		t.Fatalf("jdbErrorText = %q", text)
	}
	if text := jdbErrorText([]string{"operation not yet supported"}); text == "" {
		t.Fatal("unsupported operation not detected")
	}
	if text := jdbErrorText([]string{` text = "scalpel"`}); text != "" {
		t.Fatalf("false positive on normal output: %q", text)
	}
}

func TestExpandableResult(t *testing.T) {
	for _, value := range []string{"instance of Probe$Body(id=452)", `"scalpel"`, `"Probe$Body@4a8b1bab"`, "arm=2"} {
		if !expandableResult(value) {
			t.Fatalf("expandableResult(%q) = false", value)
		}
	}
	for _, value := range []string{"", "null", "42", "-3.5", "true", "false", "10L"} {
		if expandableResult(value) {
			t.Fatalf("expandableResult(%q) = true", value)
		}
	}
}

func TestChildExpression(t *testing.T) {
	if got := childExpression("body", "parts"); got != "body.parts" {
		t.Fatalf("plain child = %s", got)
	}
	if got := childExpression("body", "Probe$Organ.name"); got != "body.name" {
		t.Fatalf("inherited child = %s", got)
	}
	if got := childExpression("body.parts", "java.util.AbstractList.modCount"); got != "body.parts.modCount" {
		t.Fatalf("qualified child = %s", got)
	}
	if got := childExpression("nums", "[0]"); got != "nums[0]" {
		t.Fatalf("indexed child = %s", got)
	}
}

func TestCapChildren(t *testing.T) {
	children := make([]map[string]any, maxInspectedChildren)
	for i := range children {
		children[i] = plainVariable("x", "1")
	}
	if got := capChildren(children, maxInspectedChildren); len(got) != maxInspectedChildren {
		t.Fatalf("uncapped length = %d", len(got))
	}
	got := capChildren(children, 1000)
	if len(got) != maxInspectedChildren+1 {
		t.Fatalf("capped length = %d", len(got))
	}
	last := got[len(got)-1]
	if last["name"] != "… 800 more" || last["variablesReference"] != 0 {
		t.Fatalf("overflow marker = %#v", last)
	}
}
