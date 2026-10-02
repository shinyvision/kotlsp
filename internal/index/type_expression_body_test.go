package index

import (
	"context"
	"strings"
	"testing"

	"github.com/shinyvision/kotlsp/internal/analysis"
	"github.com/shinyvision/kotlsp/internal/protocol"
	textdoc "github.com/shinyvision/kotlsp/internal/text"
)

// An expression body without a declared return type is ordinary Kotlin, and
// everything downstream of a call depends on typing it: members, navigation,
// references and rename all start from the value's type.
func TestKotlinExpressionBodyGivesCallsTheirResultType(t *testing.T) {
	ctx := context.Background()
	uri := protocol.URI("file:///workspace/Bodies.kt")
	source := "package demo\n" +
		"\n" +
		"class Account {\n" +
		"    fun label(): String = \"account\"\n" +
		"}\n" +
		"\n" +
		"class Repository {\n" +
		"    private fun make() = Account()\n" +
		"\n" +
		"    fun use() {\n" +
		"        val account = make()\n" +
		"        account.label()\n" +
		"    }\n" +
		"}\n"
	idx := New(nil)
	defer idx.Close()
	idx.Open(context.Background(), protocol.TextDocumentItem{URI: uri, LanguageID: "kotlin", Version: 1, Text: source})

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	file := idx.files[uri]
	if file == nil {
		t.Fatal("the document was not indexed")
	}
	callAt := strings.Index(source, "val account = make()") + len("val account = ")
	if typ := idx.inferExpressionTypeLocked(ctx, file, "make()", callAt); typ != "Account" {
		t.Fatalf("call to an expression-bodied function typed %q, want \"Account\"", typ)
	}
	useAt := strings.Index(source, "account.label()")
	if typ := idx.typeOfNameLocked(ctx, file, "account", useAt); typ != "Account" {
		t.Fatalf("value of an expression-bodied call typed %q, want \"Account\"", typ)
	}
}

// A block body needs control-flow analysis, and a declared type is already
// carried by the symbol: neither may be mistaken for an expression body, and a
// default argument's `=` must not be read as one.
func TestKotlinExpressionBodyIgnoresBlocksAndDeclaredTypes(t *testing.T) {
	cases := []struct{ name, declaration, want string }{
		{"block body", "fun make(limit: Int = 3) { println(limit) }", ""},
		{"declared type", "fun make(limit: Int = 3): Account = Account()", ""},
		{"default argument", "fun make(limit: Int = 3) = Account()", "Account()"},
	}
	for _, test := range cases {
		source := "package demo\n\nclass Account\n\n" + test.declaration + "\n"
		file := analysis.Parse(context.Background(), textdoc.NewDocument("file:///Bodies.kt", "kotlin", 1, source))
		var symbol analysis.Symbol
		for _, candidate := range file.Symbols {
			if candidate.Name == "make" {
				symbol = candidate
				break
			}
		}
		if symbol.Name == "" {
			t.Fatalf("%s: no declaration parsed from %q", test.name, test.declaration)
		}
		if test.want == "" && symbol.Type != "" {
			continue // A declared type is carried by the symbol itself.
		}
		if body, _ := kotlinExpressionBody(source, symbol); body != test.want {
			t.Errorf("%s: body = %q, want %q", test.name, body, test.want)
		}
	}
}
