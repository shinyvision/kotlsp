package analysis

import (
	"context"
	"testing"

	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// A primary-constructor parameter declares a property when it carries val or
// var. Reading that out of the parameter's text is defeated by a use-site
// target annotation, whose colon precedes the keyword: the property was demoted
// to a plain parameter, kept out of the global name index, and every reference
// to it inside the class then looked unresolved.
func TestConstructorPropertyKindSurvivesUseSiteAnnotations(t *testing.T) {
	for _, fixture := range []struct {
		label    string
		source   string
		name     string
		property bool
	}{
		{"plain val", "class A(val simple: Int)\n", "simple", true},
		{"plain var", "class A(var simple: Int)\n", "simple", true},
		{"plain parameter", "class A(simple: Int)\n", "simple", false},
		{"use-site field target", "class A(\n    @field:Column(nullable = true)\n    open var token: String? = null,\n)\n", "token", true},
		{"use-site get target", "class A(@get:JvmName(\"x\") val token: String = \"\")\n", "token", true},
		{"annotated plain parameter", "class A(@Suppress(\"x\") simple: Int)\n", "simple", false},
		{"multiple targets", "class A(\n    @field:Id\n    @field:GeneratedValue(strategy = GenerationType.IDENTITY)\n    open var id: Long? = null,\n)\n", "id", true},
		{"annotation argument mentioning var", "class A(@Column(name = \"var\") simple: Int)\n", "simple", false},
	} {
		parsed := Parse(context.Background(), textdoc.NewDocument("file:///workspace/A.kt", "kotlin", 0, fixture.source))
		var found *Symbol
		for index := range parsed.Symbols {
			if parsed.Symbols[index].Name == fixture.name {
				found = &parsed.Symbols[index]
				break
			}
		}
		if found == nil {
			t.Fatalf("%s: %q produced no symbol", fixture.label, fixture.name)
		}
		if fixture.property && found.Kind != KindProperty {
			t.Fatalf("%s: %q is a declared property, got kind %d", fixture.label, fixture.name, found.Kind)
		}
		if !fixture.property && found.Kind != KindParameter {
			t.Fatalf("%s: %q is only a parameter, got kind %d", fixture.label, fixture.name, found.Kind)
		}
	}
}
