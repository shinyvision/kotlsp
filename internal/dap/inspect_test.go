package dap

import (
	"context"
	"testing"
)

func TestChildExpression(t *testing.T) {
	for _, test := range []struct{ parent, child, want string }{
		{"body", "parts", "body.parts"},
		{"body", "Probe$Organ.name", "body.name"},
		{"body.parts", "java.util.AbstractList.modCount", "body.parts.modCount"},
		{"nums", "[0]", "nums[0]"},
	} {
		if got := childExpression(test.parent, test.child); got != test.want {
			t.Fatalf("childExpression(%q, %q) = %q, want %q", test.parent, test.child, got, test.want)
		}
	}
}

func TestChildPagingIsBounded(t *testing.T) {
	for _, test := range []struct{ start, count, wantStart, wantCount int }{
		{-3, -1, 0, maxInspectedChildren},
		{25, 10, 25, 10},
		{1, 1000, 1, maxInspectedChildren},
	} {
		if got := normalizedChildStart(test.start); got != test.wantStart {
			t.Fatalf("start %d = %d", test.start, got)
		}
		if got := normalizedChildCount(test.count); got != test.wantCount {
			t.Fatalf("count %d = %d", test.count, got)
		}
	}
}

func TestInspectorUsesStructuredExpandability(t *testing.T) {
	s := newSession(context.Background(), nil)
	value := debugValue{name: "body", value: "instance of Body", typeName: "Body", evaluateName: "body", expandable: true, indexed: 3}
	variable := (&inspector{session: s, frameID: 1}).child(value)
	if variable["type"] != "Body" || variable["indexedVariables"] != 3 || variable["variablesReference"] == 0 {
		t.Fatalf("variable = %#v", variable)
	}
}
